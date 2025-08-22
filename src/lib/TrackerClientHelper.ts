// TrackerClientHelper.ts — helper wrapper around TrackerClient
// Assumes TrackerClient.ts is available in your project (same methods/signatures as in your Canvas)

import { promises as fs } from 'node:fs';
import { join, dirname } from 'node:path';
import { randomUUID } from 'node:crypto';
import TrackerClient, { Issue, Attachment, User } from './TrackerClient';

const wait = (ms: number) => new Promise(res => setTimeout(res, ms));

export type SearchAllIssuesOpts = {
  filter?: Record<string, unknown>;
  query?: string;
  expand?: string | string[];
  fields?: string | string[];
  order?: string;
  perPage?: number;          // default 100
  limit?: number;            // soft cap on total items
};

export type UpsertIssueOpts = {
  find: { filter?: Record<string, unknown>; query?: string };
  create: Record<string, any>;
  update?: Record<string, any>;
  choose?: (candidates: Issue[]) => Issue | undefined; // if many found
};

export type BulkTransitionOpts = {
  issueKeys: string[];
  transitionId: string;
  payload?: Record<string, any>;
  concurrency?: number;           // default 5
  guard?: (issue: Issue) => boolean | Promise<boolean>;
  dryRun?: boolean;
  onProgress?: (ok: number, fail: number, key: string, error?: unknown) => void;
};

export type CommentAndTagOpts = {
  issueKey: string;
  text: string;
  addTags?: string[];
  removeTags?: string[];
  summonees?: Array<string | number>;
  retries?: number;               // default 2
  retryBaseDelayMs?: number;      // default 300
};

export type DownloadAllAttachmentsOpts = {
  issueKey: string;
  destDir: string;
  fileNameTemplate?: (att: Attachment, index: number) => string; // default: original or generated
  overwrite?: boolean;            // default false
};

function toArray<T>(x: T | T[] | undefined): T[] { return x == null ? [] : Array.isArray(x) ? x : [x]; }

/**
 * Heuristics to extract items array from Tracker search response,
 * since different deployments may return different shapes.
 */
function extractIssuesFromSearchResponse(resp: any): Issue[] {
  if (!resp) return [];
  if (Array.isArray(resp)) return resp as Issue[];
  if (Array.isArray(resp.issues)) return resp.issues as Issue[];
  if (Array.isArray(resp.items)) return resp.items as Issue[];
  if (Array.isArray(resp.data)) return resp.data as Issue[];
  return [];
}

function uniq<T>(arr: T[]): T[] { return Array.from(new Set(arr)); }

export class TrackerClientHelper {
  constructor(private client: TrackerClient) {}

  /**
   * Fetch all issues matching filter/query using simple page iteration.
   * Falls back to classic perPage/page pagination. Respects a soft `limit`.
   */
  async searchAllIssues(opts: SearchAllIssuesOpts = {}): Promise<Issue[]> {
    const { filter, query, expand, fields, order, limit } = opts;
    const perPage = Math.max(1, opts.perPage ?? 100);

    if (!filter && !query) throw new Error('Нужно передать либо filter, либо query');

    const expandStr = Array.isArray(expand) ? expand.join(',') : expand;
    const fieldsStr = Array.isArray(fields) ? fields.join(',') : fields;

    const all: Issue[] = [];
    let page = 1;

    // Stop condition function respecting limit
    const pushBatch = (batch: Issue[]) => {
      if (!batch || batch.length === 0) return false;
      if (typeof limit === 'number' && limit >= 0) {
        const left = Math.max(0, limit - all.length);
        if (left <= 0) return false;
        all.push(...batch.slice(0, left));
        return all.length < limit; // continue if not reached
      }
      all.push(...batch);
      return true;
    };

    while (true) {
      const resp = await this.client.searchIssues({
        filter, query, order,
        fields: fieldsStr,
        expand: expandStr,
        pagination: { perPage, page },
      });
      const items = extractIssuesFromSearchResponse(resp);
      if (!pushBatch(items)) break;
      if (items.length < perPage) break; // last page reached
      page += 1;
    }

    return all;
  }

  /** Create or update an issue based on a lookup. */
  async upsertIssue(opts: UpsertIssueOpts): Promise<{ action: 'created' | 'updated'; issue: Issue } > {
    const { find, create, update, choose } = opts;
    const foundList = await this.searchAllIssues({
      filter: find.filter,
      query: find.query,
      perPage: 100,
      limit: 2_000, // safety cap
      fields: ['key', 'id', 'summary', 'status', 'queue', 'tags'],
    });

    let target: Issue | undefined;
    if (foundList.length === 0) {
      const issue = await this.client.createIssue(create);
      return { action: 'created', issue };
    } else if (foundList.length === 1) {
      target = foundList[0];
    } else {
      target = choose ? choose(foundList) : foundList[0];
      if (!target) throw new Error('Найдено несколько задач и не удалось выбрать одну');
    }

    const patched = await this.client.updateIssue(target.key as string, update ?? {});
    return { action: 'updated', issue: patched };
  }

  /** Bulk transition with limited concurrency and optional guard. */
  async bulkTransition(opts: BulkTransitionOpts): Promise<{ ok: string[]; fail: Array<{ key: string; error: unknown }> }> {
    const { issueKeys, transitionId, payload, concurrency = 5, guard, dryRun, onProgress } = opts;
    const queue = [...issueKeys];
    const ok: string[] = [];
    const fail: Array<{ key: string; error: unknown }> = [];

    let inFlight = 0; let done = 0;
    const next = async () => {
      const key = queue.shift();
      if (!key) return;
      inFlight++;
      try {
        let allowed = true;
        if (guard) {
          const issue = await this.client.getIssue(key, { fields: ['key', 'status', 'assignee'] });
          allowed = await guard(issue);
        }
        if (!allowed) {
          ok.push(key); // treat as skipped-ok
        } else if (!dryRun) {
          await this.client.transitionIssue(key, transitionId, payload);
          ok.push(key);
        }
      } catch (e) {
        fail.push({ key, error: e });
      } finally {
        done++; inFlight--;
        onProgress?.(ok.length, fail.length, key);
      }
      await pump();
    };
    const pump = async () => {
      while (inFlight < concurrency && queue.length) await next();
    };

    await pump();
    while (inFlight > 0) await wait(10);

    return { ok, fail };
  }

  /** Add a comment and adjust tags atomically-ish (comment then patch tags). */
  async commentAndTag(opts: CommentAndTagOpts): Promise<void> {
    const { issueKey, text, addTags = [], removeTags = [], summonees, retries = 2, retryBaseDelayMs = 300 } = opts;

    // simple retry wrapper for operations sensitive to 429
    const withRetry = async (fn: () => Promise<any>) => {
      let attempt = 0;
      // eslint-disable-next-line no-constant-condition
      while (true) {
        try { return await fn(); } catch (e: any) {
          if (attempt >= retries) throw e;
          const backoff = retryBaseDelayMs * Math.pow(2, attempt) + Math.random() * 50;
          await wait(backoff);
          attempt++;
        }
      }
    };

    await withRetry(() => this.client.addComment(issueKey, { text, summonees }));

    if (addTags.length || removeTags.length) {
      // Fetch current tags, merge and update
      const issue = await this.client.getIssue(issueKey, { fields: ['tags'] });
      const current: string[] = Array.isArray((issue as any).tags) ? (issue as any).tags : [];
      const nextTags = uniq(
        current.filter(t => !removeTags.includes(t)).concat(addTags)
      );
      if (nextTags.join('\u0000') !== current.join('\u0000')) {
        await withRetry(() => this.client.updateIssue(issueKey, { tags: nextTags }));
      }
    }
  }

  /** Download all attachments of an issue into destDir. */
  async downloadAllAttachments(opts: DownloadAllAttachmentsOpts): Promise<Array<{ attachment: Attachment; path: string }>> {
    const { issueKey, destDir, fileNameTemplate, overwrite = false } = opts;
    await fs.mkdir(destDir, { recursive: true });

    // Request issue with attachments expanded
    const issue = await this.client.getIssue(issueKey, { expand: 'attachments', fields: ['attachments'] });
    const attachments: Attachment[] = (issue as any)?.attachments ?? (issue as any)?.attachments?.attachments ?? [];
    const out: Array<{ attachment: Attachment; path: string }> = [];

    for (let i = 0; i < attachments.length; i++) {
      const att = attachments[i];
      const suggested = att.name || `attachment-${i + 1}-${randomUUID().slice(0, 8)}`;
      const filename = fileNameTemplate ? fileNameTemplate(att, i) : suggested;
      const full = join(destDir, filename);

      if (!overwrite) {
        try { await fs.access(full); continue; } catch {}
      }

      const { data } = await this.client.downloadAttachment(issueKey, String(att.id), { filename });
      await fs.mkdir(dirname(full), { recursive: true });
      await fs.writeFile(full, data);
      out.push({ attachment: att, path: full });
    }
    return out;
  }
}

export default TrackerClientHelper;
