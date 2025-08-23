// TrackerClient.ts — ESM, Node.js 18+
// A production-grade TypeScript client for Yandex Tracker API v3
// Docs (selected):
// - Access & headers: https://yandex.ru/support/tracker/ru/concepts/access
// - Issues search: POST /v3/issues/_search
// - Issues CRUD: GET/POST/PATCH /v3/issues, GET /v3/issues/{key}
// - Transitions: POST /v3/issues/{issue}/transitions/{transition}/_execute
// - Comments: GET/POST/PATCH/DELETE /v3/issues/{issue}/comments
// - Attachments: /v3/issues/{issue}/attachments
// - Worklogs: /v3/issues/{issue}/worklog, /v3/worklog/_search
// - Queues: /v3/queues, /v3/queues/{id}
// - Boards/Sprints: /v3/boards, /v3/boards/{id}/sprints, /v3/sprints/{id}
// - Users/Groups: /v3/users, /v3/groups
// - Dictionaries: /v3/statuses, /v3/priorities, /v3/issuetypes, /v3/resolutions

import { setTimeout as sleep } from "node:timers/promises";
import { randomUUID } from "node:crypto";

// --------- Minimal entity typings (extend as needed) ---------
export interface Ref {
  self?: string;
  id?: string | number;
  key?: string;
  display?: string;
}
export interface Status {
  id?: string;
  key?: string;
  display?: string;
}
export interface IssueType {
  id?: string;
  key?: string;
  display?: string;
}
export interface Priority {
  id?: string;
  key?: string;
  display?: string;
}
export interface Resolution {
  id?: string;
  key?: string;
  display?: string;
}
export interface User {
  id?: string | number;
  key?: string;
  display?: string;
}
export interface Group {
  id?: string | number;
  display?: string;
}
export interface Queue {
  id?: string | number;
  key?: string;
  display?: string;
}
export interface Board {
  id?: string | number;
  version?: number;
  name?: string;
}
export interface Sprint {
  id?: string | number;
  version?: number;
  name?: string;
  board?: Ref;
}
export interface Comment {
  id?: string | number;
  text?: string;
  createdAt?: string;
  createdBy?: Ref;
}
export interface Attachment {
  id?: string | number;
  name?: string;
  content?: string;
  createdAt?: string;
}
export interface Worklog {
  id?: string | number;
  start?: string;
  duration?: string;
  comment?: string;
}
export interface Issue {
  id?: string;
  key?: string;
  summary?: string;
  description?: string;
  status?: Status;
  type?: IssueType;
  assignee?: Ref;
  queue?: Ref;
  priority?: Priority;
  [k: string]: unknown;
}

export type Logger = Pick<Console, "info" | "warn" | "error" | "debug">;
export type FetchFn = (
  input: RequestInfo,
  init?: RequestInit
) => Promise<Response>;

export interface TrackerClientOptions {
  baseUrl: string;
  oauthToken: string;
  orgId?: string;
  cloudOrgId?: string;
  defaultHeaders?: Record<string, string>;
  timeoutMs?: number; // default 30000
  retries?: number; // default 3
  retryBaseDelayMs?: number; // default 300
  enableCache?: boolean; // default false
  cacheTtlMs?: number; // default 10000
  maxRetryAfterMs?: number; // default 120000
  logger?: Logger; // default console
  fetchFn?: FetchFn; // default global fetch
}

export interface PaginationOpts {
  perPage?: number;
  page?: number;
  scrollId?: string;
}

// ---------------------- Error hierarchy ----------------------
export class TrackerError extends Error {
  status?: number;
  details?: any;
  requestId?: string;
  response?: Response;
  constructor(
    message: string,
    status?: number,
    details?: any,
    requestId?: string,
    response?: Response
  ) {
    super(message);
    this.name = new.target.name;
    this.status = status;
    this.details = details;
    this.requestId = requestId;
    this.response = response;
  }
}
export class TrackerAuthError extends TrackerError {}
export class TrackerRateLimitError extends TrackerError {}
export class TrackerNotFoundError extends TrackerError {}
export class TrackerValidationError extends TrackerError {}
export class TrackerConflictError extends TrackerError {}
export class TrackerServerError extends TrackerError {}
export class TrackerNetworkError extends TrackerError {}

// ---------------------- Utilities ----------------------
function assertString(name: string, value: unknown): asserts value is string {
  if (typeof value !== "string" || value.length === 0)
    throw new TypeError(`${name} must be a non-empty string`);
}

function buildQuery(query?: Record<string, any>): string {
  if (!query) return "";
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) {
    if (v == null) continue;
    if (Array.isArray(v))
      v.forEach((x) => x != null && sp.append(k, String(x)));
    else if (typeof v === "boolean") sp.append(k, v ? "true" : "false");
    else sp.append(k, String(v));
  }
  const s = sp.toString();
  return s ? `?${s}` : "";
}

function buildURL(
  baseUrl: string,
  path: string,
  query?: Record<string, any>
): string {
  const base = baseUrl.replace(/\/$/, "");
  const p = path.startsWith("/") ? path : `/${path}`;
  return `${base}${p}${buildQuery(query)}`;
}

function mergeHeaders(...parts: Array<HeadersInit | undefined>): Headers {
  const out = new Headers();
  for (const part of parts) {
    if (!part) continue;
    const h = part instanceof Headers ? part : new Headers(part);
    for (const [k, v] of h) out.set(k, v);
  }
  return out;
}

async function parseJSONSafe(res: Response): Promise<any> {
  const text = await res.text();
  if (!text) return undefined;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

function calcBackoff(attempt: number, baseMs: number): number {
  const exp = baseMs * Math.pow(2, attempt);
  const jitter = Math.random() * baseMs;
  return exp + jitter;
}

function normalizeExpectStatus(expect: number | number[]): Set<number> {
  return new Set(Array.isArray(expect) ? expect : [expect]);
}

class TTLCache<T = any> {
  private ttl: number;
  private map = new Map<string, { value: T; expiresAt: number }>();
  constructor(ttlMs = 10000) {
    this.ttl = ttlMs;
  }
  private now() {
    return Date.now();
  }
  private isExpired(e: { expiresAt: number }) {
    return this.now() > e.expiresAt;
  }
  get(key: string): T | undefined {
    const e = this.map.get(key);
    if (!e) return undefined;
    if (this.isExpired(e)) {
      this.map.delete(key);
      return undefined;
    }
    return e.value;
  }
  set(key: string, value: T, ttl?: number) {
    this.map.set(key, { value, expiresAt: this.now() + (ttl ?? this.ttl) });
  }
  clear() {
    this.map.clear();
  }
  stats() {
    return { size: this.map.size, ttlMs: this.ttl };
  }
}

// ---------------------- Client ----------------------
export interface RequestOptions {
  query?: Record<
    string,
    string | number | boolean | Array<string | number> | undefined
  >;
  headers?: Record<string, string>;
  body?: any; // JSON object, FormData, Buffer, string
  timeoutMs?: number;
  signal?: AbortSignal;
  parseJson?: boolean;
  expectStatus?: number | number[];
}

export class TrackerClient {
  private baseUrl: string;
  private oauthToken: string;
  private orgId?: string;
  private cloudOrgId?: string;
  private defaultHeaders: Record<string, string>;
  private timeoutMs: number;
  private retries: number;
  private retryBaseDelayMs: number;
  private maxRetryAfterMs: number;
  private logger: Logger;
  private fetchFn: FetchFn;
  private enableCache: boolean;
  private cache: TTLCache<any>;

  constructor(opts: TrackerClientOptions) {
    if (!opts || !opts.baseUrl) throw new TypeError("baseUrl is required");
    if (!opts.oauthToken) throw new TypeError("oauthToken is required");
    this.baseUrl = opts.baseUrl.replace(/\/$/, "");
    this.oauthToken = opts.oauthToken;
    this.orgId = opts.orgId;
    this.cloudOrgId = opts.cloudOrgId;
    this.defaultHeaders = opts.defaultHeaders ?? {};
    this.timeoutMs = opts.timeoutMs ?? 30000;
    this.retries = opts.retries ?? 3;
    this.retryBaseDelayMs = opts.retryBaseDelayMs ?? 300;
    this.maxRetryAfterMs = opts.maxRetryAfterMs ?? 120000;
    this.logger = opts.logger ?? console;
    this.fetchFn = opts.fetchFn ?? (globalThis.fetch as FetchFn);
    if (typeof this.fetchFn !== "function")
      throw new Error("fetch is not available. Provide fetchFn option");
    this.enableCache = !!opts.enableCache;
    this.cache = new TTLCache(opts.cacheTtlMs ?? 10000);
  }

  // ---------- Low-level request ----------
  async request<T = any>(
    method: string,
    path: string,
    {
      query,
      headers,
      body,
      timeoutMs,
      signal,
      parseJson = true,
      expectStatus = 200,
    }: RequestOptions = {}
  ): Promise<T> {
    const requestId = randomUUID();
    const url = buildURL(this.baseUrl, path, query);
    const isForm = typeof FormData !== "undefined" && body instanceof FormData;
    const isJSON =
      body &&
      !isForm &&
      typeof body === "object" &&
      !(body instanceof ArrayBuffer) &&
      !(body instanceof Uint8Array);

    const authHeader = { Authorization: `OAuth ${this.oauthToken}` };
    const orgHeaders = this.orgHeaders();
    const baseHeaders = {
      Accept: "application/json",
      "X-Request-Id": requestId,
      ...(!isForm && isJSON ? { "Content-Type": "application/json" } : {}),
    } satisfies Record<string, string>;

    const allHeaders = mergeHeaders(
      this.defaultHeaders,
      baseHeaders,
      orgHeaders,
      authHeader,
      headers
    );
    const cacheKey = this.buildCacheKey(method, url, allHeaders);

    if (this.enableCache && method.toUpperCase() === "GET") {
      const cached = this.cache.get(cacheKey);
      if (cached !== undefined) {
        this.logger.debug?.(
          `[cache hit] ${method} ${url} (reqId=${requestId})`
        );
        return cached as T;
      }
    }

    const expectSet = normalizeExpectStatus(expectStatus);
    const maxAttempts = Math.max(1, this.retries + 1);

    const controller = new AbortController();
    const onAbort = () => controller.abort((signal as any)?.reason);
    if (signal) signal.addEventListener("abort", onAbort, { once: true });
    const attemptTimeout = timeoutMs ?? this.timeoutMs;

    try {
      for (let attempt = 0; attempt < maxAttempts; attempt++) {
        const attemptId = `${requestId}:${attempt + 1}/${maxAttempts}`;
        const timer = setTimeout(
          () => controller.abort(new Error("Request timeout")),
          attemptTimeout
        ) as unknown as NodeJS.Timeout;
        try {
          const init: RequestInit = {
            method,
            headers: allHeaders,
            body: isJSON ? JSON.stringify(body) : body,
            signal: controller.signal,
          };
          this.logger.debug?.(
            `[request] ${method} ${url} (reqId=${attemptId})`
          );
          const res = await this.fetchFn(url as any, init);

          if (res.status === 429 || (res.status >= 500 && res.status <= 599)) {
            const retryAfter = this.retryAfterMs(
              res.headers.get("Retry-After")
            );
            if (attempt < maxAttempts - 1) {
              const backoff = Math.min(
                this.maxRetryAfterMs,
                retryAfter ?? calcBackoff(attempt, this.retryBaseDelayMs)
              );
              this.logger.warn?.(
                `[retry] ${method} ${url} status=${res.status} in ${backoff}ms (reqId=${attemptId})`
              );
              await sleep(backoff);
              continue;
            }
          }

          if (expectSet.has(res.status)) {
            if (!parseJson) {
              const text = await res.text();
              if (this.enableCache && method.toUpperCase() === "GET")
                this.cache.set(cacheKey, text);
              return text as unknown as T;
            }
            if (res.status === 204) {
              if (this.enableCache && method.toUpperCase() === "GET")
                this.cache.set(cacheKey, undefined);
              return undefined as unknown as T;
            }
            const data = await parseJSONSafe(res);
            if (this.enableCache && method.toUpperCase() === "GET")
              this.cache.set(cacheKey, data);
            return data as T;
          }

          const errPayload = await parseJSONSafe(res);
          const message = this.errorMessage(
            method,
            url,
            res.status,
            errPayload
          );
          throw this.toErrorClass(
            res.status,
            message,
            errPayload,
            requestId,
            res
          );
        } catch (e: any) {
          if (e?.name === "AbortError") {
            if (attempt < maxAttempts - 1) {
              const backoff = calcBackoff(attempt, this.retryBaseDelayMs);
              this.logger.warn?.(
                `[retry timeout/abort] ${method} ${url} in ${backoff}ms (reqId=${attemptId})`
              );
              await sleep(backoff);
              continue;
            }
            throw new TrackerNetworkError(
              `Network timeout/abort for ${method} ${url}`,
              undefined,
              undefined,
              requestId
            );
          }
          if (e instanceof TypeError || e?.name === "FetchError") {
            if (attempt < maxAttempts - 1) {
              const backoff = calcBackoff(attempt, this.retryBaseDelayMs);
              this.logger.warn?.(
                `[retry network] ${method} ${url} in ${backoff}ms (reqId=${attemptId}) cause=${e.message}`
              );
              await sleep(backoff);
              continue;
            }
            throw new TrackerNetworkError(
              `Network error for ${method} ${url}: ${e.message}`,
              undefined,
              e,
              requestId
            );
          }
          throw e;
        } finally {
          clearTimeout(timer);
        }
      }
      throw new TrackerError(
        `Exhausted retries for ${method} ${url}`,
        undefined,
        undefined,
        requestId
      );
    } finally {
      if (signal) signal.removeEventListener("abort", onAbort);
      if (this.enableCache && method.toUpperCase() !== "GET")
        this.cache.clear();
    }
  }

  // ---------- Helpers ----------
  private orgHeaders(): Record<string, string> {
    const h: Record<string, string> = {};
    if (this.cloudOrgId) h["X-Cloud-Org-ID"] = String(this.cloudOrgId);
    else if (this.orgId) h["X-Org-ID"] = String(this.orgId);
    return h;
  }
  private buildCacheKey(method: string, url: string, headers: Headers): string {
    const h = new Headers(headers);
    h.delete("Authorization");
    h.delete("X-Request-Id");
    const sorted = [...h.entries()].sort(([a], [b]) => a.localeCompare(b));
    return `${method.toUpperCase()} ${url}\n${JSON.stringify(sorted)}`;
  }
  private retryAfterMs(header: string | null): number | undefined {
    if (!header) return undefined;
    const sec = Number(header);
    if (!Number.isNaN(sec)) return sec * 1000;
    const ts = Date.parse(header);
    if (!Number.isNaN(ts)) return Math.max(0, ts - Date.now());
    return undefined;
  }
  private errorMessage(
    method: string,
    url: string,
    status: number,
    payload: any
  ): string {
    const short =
      payload?.message ||
      payload?.error ||
      (typeof payload === "string" ? payload : "");
    return `${method} ${url} -> ${status}${short ? `: ${short}` : ""}`;
  }
  private toErrorClass(
    status: number,
    message: string,
    details?: any,
    requestId?: string,
    response?: Response
  ): TrackerError {
    if (status === 401 || status === 403)
      return new TrackerAuthError(
        message,
        status,
        details,
        requestId,
        response
      );
    if (status === 404)
      return new TrackerNotFoundError(
        message,
        status,
        details,
        requestId,
        response
      );
    if (status === 409)
      return new TrackerConflictError(
        message,
        status,
        details,
        requestId,
        response
      );
    if (status === 422)
      return new TrackerValidationError(
        message,
        status,
        details,
        requestId,
        response
      );
    if (status === 429)
      return new TrackerRateLimitError(
        message,
        status,
        details,
        requestId,
        response
      );
    if (status >= 500)
      return new TrackerServerError(
        message,
        status,
        details,
        requestId,
        response
      );
    return new TrackerError(message, status, details, requestId, response);
  }
  clearCache() {
    this.cache.clear();
  }
  getCacheStats() {
    return this.cache.stats();
  }

  // ---------- Pagination helper ----------
  async *paginate<T>(
    fetchPageFn: (args: {
      limit?: number;
      page?: number;
      cursor?: string;
    }) => Promise<{ items: T[]; nextPage?: number; nextCursor?: string }>,
    {
      limit,
      page,
      cursor,
      maxItems,
    }: {
      limit?: number;
      page?: number;
      cursor?: string;
      maxItems?: number;
    } = {}
  ): AsyncGenerator<T, void, unknown> {
    let remaining = typeof maxItems === "number" ? maxItems : Infinity;
    let nextPage = page;
    let nextCursor = cursor;
    // eslint-disable-next-line no-constant-condition
    while (true) {
      const {
        items,
        nextPage: np,
        nextCursor: nc,
      } = await fetchPageFn({ limit, page: nextPage, cursor: nextCursor });
      for (const item of items) {
        if (remaining-- <= 0) return;
        yield item;
      }
      if (remaining <= 0) return;
      if (nc) {
        nextCursor = nc;
        continue;
      }
      if (np != null) {
        nextPage = np;
        continue;
      }
      return;
    }
  }

  // ---------------------- High-level API ----------------------
  // ---- Utilities ----
  getMyself(): Promise<User> {
    return this.request("GET", "/v3/myself");
  }
  getStatuses(): Promise<Status[]> {
    return this.request("GET", "/v3/statuses");
  }
  getPriorities(): Promise<Priority[]> {
    return this.request("GET", "/v3/priorities");
  }
  getIssueTypes(): Promise<IssueType[]> {
    return this.request("GET", "/v3/issuetypes");
  }
  getResolutions(): Promise<Resolution[]> {
    return this.request("GET", "/v3/resolutions");
  }

  // ---- Queues ----
  getQueues(
    opts: { pagination?: { perPage?: number; page?: number } } = {}
  ): Promise<Queue[]> {
    const q = {
      perPage: opts.pagination?.perPage,
      page: opts.pagination?.page,
    };
    return this.request("GET", "/v3/queues", { query: q });
  }
  getQueueByKey(queueKey: string): Promise<Queue> {
    assertString("queueKey", queueKey);
    return this.request("GET", `/v3/queues/${encodeURIComponent(queueKey)}`);
  }
  createQueue(payload: Partial<Queue> & Record<string, any>): Promise<Queue> {
    return this.request("POST", "/v3/queues", { body: payload });
  }
  updateQueue(queueKey: string, payload: Record<string, any>): Promise<Queue> {
    assertString("queueKey", queueKey);
    return this.request("PATCH", `/v3/queues/${encodeURIComponent(queueKey)}`, {
      body: payload,
    });
  }
  deleteQueue(queueKey: string): Promise<void> {
    assertString("queueKey", queueKey);
    return this.request(
      "DELETE",
      `/v3/queues/${encodeURIComponent(queueKey)}`,
      { expectStatus: [200, 204, 202] }
    );
  }

  // ---- Issues ----
  searchIssues(
    opts: {
      filter?: Record<string, any>;
      query?: string;
      fields?: string | string[];
      expand?: string | string[];
      order?: string;
      pagination?: PaginationOpts;
    } = {}
  ): Promise<any> {
    const { filter, query, fields, expand, order, pagination } = opts;
    const q = {
      perPage: pagination?.perPage,
      page: pagination?.page,
      scrollId: pagination?.scrollId,
      expand: Array.isArray(expand) ? expand.join(",") : expand,
      fields: Array.isArray(fields) ? fields.join(",") : fields,
    };
    const body = { filter, query, order };
    return this.request("POST", "/v3/issues/_search", { query: q, body });
  }
  getIssues(opts: Parameters<TrackerClient["searchIssues"]>[0]) {
    return this.searchIssues(opts);
  }

  getIssue(
    issueKey: string,
    opts: { fields?: string | string[]; expand?: string | string[] } = {}
  ): Promise<Issue> {
    assertString("issueKey", issueKey);
    const q = {
      fields: Array.isArray(opts.fields) ? opts.fields.join(",") : opts.fields,
      expand: Array.isArray(opts.expand) ? opts.expand.join(",") : opts.expand,
    };
    console.log(q);

    return this.request("GET", `/v3/issues/${encodeURIComponent(issueKey)}`, {
      query: q,
    });
  }
  createIssue(payload: Record<string, any>): Promise<Issue> {
    return this.request("POST", "/v3/issues", { body: payload });
  }
  updateIssue(issueKey: string, payload: Record<string, any>): Promise<Issue> {
    assertString("issueKey", issueKey);
    return this.request("PATCH", `/v3/issues/${encodeURIComponent(issueKey)}`, {
      body: payload,
    });
  }
  transitionIssue(
    issueKey: string,
    transitionId: string,
    payload?: Record<string, any>
  ): Promise<void> {
    assertString("issueKey", issueKey);
    assertString("transitionId", transitionId);
    return this.request(
      "POST",
      `/v3/issues/${encodeURIComponent(
        issueKey
      )}/transitions/${encodeURIComponent(transitionId)}/_execute`,
      { body: payload, expectStatus: [200, 204] }
    );
  }
  deleteIssue(issueKey: string): Promise<void> {
    assertString("issueKey", issueKey);
    throw new Error(
      "DELETE /v3/issues/{key} не поддерживается. Используйте transition (_execute)."
    );
  }

  // ---- Comments ----
  getComments(
    issueKey: string,
    opts: { pagination?: { perPage?: number; page?: number } } = {}
  ): Promise<Comment[]> {
    assertString("issueKey", issueKey);
    const q = {
      perPage: opts.pagination?.perPage,
      page: opts.pagination?.page,
    };
    return this.request(
      "GET",
      `/v3/issues/${encodeURIComponent(issueKey)}/comments`,
      { query: q }
    );
  }
  addComment(
    issueKey: string,
    data: { text: string; summonees?: Array<string | number> }
  ): Promise<Comment> {
    assertString("issueKey", issueKey);
    if (!data || typeof data.text !== "string")
      throw new TypeError("text is required");
    return this.request(
      "POST",
      `/v3/issues/${encodeURIComponent(issueKey)}/comments`,
      { body: data }
    );
  }
  updateComment(
    issueKey: string,
    commentId: string | number,
    data: { text: string }
  ): Promise<Comment> {
    assertString("issueKey", issueKey);
    if (!data || typeof data.text !== "string")
      throw new TypeError("text is required");
    return this.request(
      "PATCH",
      `/v3/issues/${encodeURIComponent(issueKey)}/comments/${encodeURIComponent(
        String(commentId)
      )}`,
      { body: data }
    );
  }
  deleteComment(issueKey: string, commentId: string | number): Promise<void> {
    assertString("issueKey", issueKey);
    return this.request(
      "DELETE",
      `/v3/issues/${encodeURIComponent(issueKey)}/comments/${encodeURIComponent(
        String(commentId)
      )}`,
      { expectStatus: [200, 204] }
    );
  }

  // ---- Attachments ----
  async uploadAttachment(
    issueKey: string,
    file: Blob | Buffer | Uint8Array | ArrayBuffer | ReadableStream | string,
    opts: { filename: string; mimeType?: string }
  ): Promise<Attachment> {
    assertString("issueKey", issueKey);
    assertString("filename", opts?.filename);
    const fd = new FormData();
    let data: any = file;
    if (typeof Blob !== "undefined" && !(file instanceof Blob)) {
      if (file instanceof ArrayBuffer)
        data = new Blob([new Uint8Array(file)], { type: opts?.mimeType });
      else if (file instanceof Uint8Array)
        data = new Blob([file as any], { type: opts?.mimeType });
      else if (typeof file === "string")
        data = new Blob([file], { type: opts?.mimeType || "text/plain" });
    }
    // @ts-ignore Node18 undici FormData supports (name, blob, filename)
    (fd as any).append("file", data, opts.filename);
    return this.request(
      "POST",
      `/v3/issues/${encodeURIComponent(issueKey)}/attachments`,
      { body: fd }
    );
  }
  async downloadAttachment(
    issueKey: string,
    attachmentId: string | number,
    opts: { filename?: string } = {}
  ): Promise<{ data: Buffer; headers: Record<string, string> }> {
    assertString("issueKey", issueKey);
    const id = encodeURIComponent(String(attachmentId));
    const namePart = opts.filename
      ? `/${encodeURIComponent(opts.filename)}`
      : "";
    const url = buildURL(
      this.baseUrl,
      `/v3/issues/${encodeURIComponent(issueKey)}/attachments/${id}${namePart}`
    );
    const headers = mergeHeaders(this.defaultHeaders, this.orgHeaders(), {
      Authorization: `OAuth ${this.oauthToken}`,
    });
    const res = await this.fetchFn(url as any, { method: "GET", headers });
    if (!res.ok) {
      const details = await parseJSONSafe(res);
      throw this.toErrorClass(
        res.status,
        this.errorMessage("GET", url, res.status, details),
        details
      );
    }
    const ab = await res.arrayBuffer();
    const h: Record<string, string> = {};
    for (const [k, v] of res.headers) h[k] = v;
    return { data: Buffer.from(ab), headers: h };
  }
  deleteAttachment(
    issueKey: string,
    attachmentId: string | number
  ): Promise<void> {
    assertString("issueKey", issueKey);
    return this.request(
      "DELETE",
      `/v3/issues/${encodeURIComponent(
        issueKey
      )}/attachments/${encodeURIComponent(String(attachmentId))}`,
      { expectStatus: [200, 204] }
    );
  }

  // ---- Worklog ----
  getWorklogs(
    issueKey: string,
    opts: { pagination?: { perPage?: number; page?: number } } = {}
  ): Promise<Worklog[]> {
    assertString("issueKey", issueKey);
    const q = {
      perPage: opts.pagination?.perPage,
      page: opts.pagination?.page,
    };
    return this.request(
      "GET",
      `/v3/issues/${encodeURIComponent(issueKey)}/worklog`,
      { query: q }
    );
  }
  addWorklog(
    issueKey: string,
    payload: { duration: string; start?: string; comment?: string }
  ): Promise<Worklog> {
    assertString("issueKey", issueKey);
    if (!payload || typeof payload.duration !== "string")
      throw new TypeError("duration is required (ISO 8601)");
    return this.request(
      "POST",
      `/v3/issues/${encodeURIComponent(issueKey)}/worklog`,
      { body: payload }
    );
  }
  updateWorklog(
    issueKey: string,
    worklogId: string | number,
    payload: { duration?: string; comment?: string; start?: string }
  ): Promise<Worklog> {
    assertString("issueKey", issueKey);
    return this.request(
      "PATCH",
      `/v3/issues/${encodeURIComponent(issueKey)}/worklog/${encodeURIComponent(
        String(worklogId)
      )}`,
      { body: payload }
    );
  }
  deleteWorklog(issueKey: string, worklogId: string | number): Promise<void> {
    assertString("issueKey", issueKey);
    return this.request(
      "DELETE",
      `/v3/issues/${encodeURIComponent(issueKey)}/worklog/${encodeURIComponent(
        String(worklogId)
      )}`,
      { expectStatus: [200, 204] }
    );
  }
  searchWorklogs(
    opts: {
      createdBy?: string | number;
      createdAt?: { from?: string; to?: string };
      pagination?: { perPage?: number; page?: number };
    } = {}
  ): Promise<any> {
    const { createdBy, createdAt, pagination } = opts;
    const q = { perPage: pagination?.perPage, page: pagination?.page };
    const body = { createdBy, createdAt };
    return this.request("POST", "/v3/worklog/_search", { query: q, body });
  }

  // ---- Boards / Sprints ----
  getBoards(
    opts: { pagination?: { perPage?: number; page?: number } } = {}
  ): Promise<Board[]> {
    const q = {
      perPage: opts.pagination?.perPage,
      page: opts.pagination?.page,
    };
    return this.request("GET", "/v3/boards", { query: q });
  }
  getBoard(boardId: string | number): Promise<Board> {
    return this.request(
      "GET",
      `/v3/boards/${encodeURIComponent(String(boardId))}`
    );
  }
  getSprints(
    boardId: string | number,
    opts: { pagination?: { perPage?: number; page?: number } } = {}
  ): Promise<Sprint[]> {
    const q = {
      perPage: opts.pagination?.perPage,
      page: opts.pagination?.page,
    };
    return this.request(
      "GET",
      `/v3/boards/${encodeURIComponent(String(boardId))}/sprints`,
      { query: q }
    );
  }
  getSprint(sprintId: string | number): Promise<Sprint> {
    return this.request(
      "GET",
      `/v3/sprints/${encodeURIComponent(String(sprintId))}`
    );
  }
  createSprint(
    boardId: string | number,
    payload: Record<string, any>
  ): Promise<Sprint> {
    return this.request(
      "POST",
      `/v3/boards/${encodeURIComponent(String(boardId))}/sprints`,
      { body: payload }
    );
  }
  updateSprint(
    sprintId: string | number,
    payload: Record<string, any>
  ): Promise<Sprint> {
    return this.request(
      "PATCH",
      `/v3/sprints/${encodeURIComponent(String(sprintId))}`,
      { body: payload }
    );
  }
  deleteSprint(sprintId: string | number): Promise<void> {
    return this.request(
      "DELETE",
      `/v3/sprints/${encodeURIComponent(String(sprintId))}`,
      { expectStatus: [200, 204] }
    );
  }

  // ---- Users / Groups ----
  getUsers(
    opts: {
      query?: string;
      pagination?: { perPage?: number; page?: number };
    } = {}
  ): Promise<User[]> {
    const q = {
      query: opts.query,
      perPage: opts.pagination?.perPage,
      page: opts.pagination?.page,
    };
    return this.request("GET", "/v3/users", { query: q });
  }
  getUserById(userId: string | number): Promise<User> {
    return this.request(
      "GET",
      `/v3/users/${encodeURIComponent(String(userId))}`
    );
  }
  getGroups(
    opts: { pagination?: { perPage?: number; page?: number } } = {}
  ): Promise<Group[]> {
    const q = {
      perPage: opts.pagination?.perPage,
      page: opts.pagination?.page,
    };
    return this.request("GET", "/v3/groups", { query: q });
  }
  getGroupById(groupId: string | number): Promise<Group> {
    return this.request(
      "GET",
      `/v3/groups/${encodeURIComponent(String(groupId))}`
    );
  }

  // ---- Saved filters ----
  getSavedFilters(
    opts: { pagination?: { perPage?: number; page?: number } } = {}
  ): Promise<any> {
    const q = {
      perPage: opts.pagination?.perPage,
      page: opts.pagination?.page,
    };
    return this.request("GET", "/v3/filters", { query: q });
  }
  getSavedFilter(filterId: string | number): Promise<any> {
    return this.request(
      "GET",
      `/v3/filters/${encodeURIComponent(String(filterId))}`
    );
  }
  applySavedFilter(
    filterId: string | number,
    opts: {
      fields?: string | string[];
      expand?: string | string[];
      perPage?: number;
      page?: number;
    } = {}
  ): Promise<any> {
    const q = {
      fields: Array.isArray(opts.fields) ? opts.fields.join(",") : opts.fields,
      expand: Array.isArray(opts.expand) ? opts.expand.join(",") : opts.expand,
      perPage: opts.perPage,
      page: opts.page,
      filterId,
    };
    return this.request("POST", "/v3/issues/_search", { query: q, body: {} });
  }
}

export default TrackerClient;

/* ------------------------- USAGE EXAMPLES -------------------------
import TrackerClient from './TrackerClient.js';

const client = new TrackerClient({
  baseUrl: 'https://api.tracker.yandex.net',
  oauthToken: process.env.TRACKER_TOKEN!,
  orgId: process.env.TRACKER_ORG_ID,
  retries: 3,
  retryBaseDelayMs: 400,
  enableCache: true,
  cacheTtlMs: 5000,
});

const me = await client.getMyself();
console.log('Hello,', me.display);

const issue = await client.createIssue({
  queue: { key: 'TEST' },
  summary: 'Demo from API',
  description: 'Hello from TrackerClient',
  type: { key: 'task' },
});

await client.transitionIssue(issue.key!, 'start_progress');

const fetchPage = async ({ limit, cursor }: { limit?: number; cursor?: string }) => {
  const perPage = limit ?? 50;
  const resp = await client.searchIssues({
    filter: { queue: 'TEST' },
    pagination: { perPage, scrollId: cursor },
    fields: ['summary', 'status', 'assignee'],
  });
  const items = Array.isArray(resp) ? resp : (resp.issues ?? resp.items ?? resp.data ?? []);
  return { items, nextCursor: undefined as string | undefined };
};
for await (const it of client.paginate(fetchPage, { limit: 50, maxItems: 200 })) {
  // process(it)
}

await client.uploadAttachment(issue.key!, Buffer.from('hello.txt contents'), { filename: 'hello.txt', mimeType: 'text/plain' });
await client.addComment(issue.key!, { text: 'Attached a file' });
await client.addWorklog(issue.key!, { duration: 'PT30M', comment: 'investigation' });
// await client.transitionIssue(issue.key!, 'cancel');
*/
