import { NextRequest, NextResponse } from 'next/server';

function buildAuthHeaders() {
  const headers: Record<string, string> = {
    Accept: 'application/json',
    'Content-Type': 'application/json',
  };

  const iam = process.env.TRACKER_IAM_TOKEN;
  const cloudOrg = process.env.TRACKER_CLOUD_ORG_ID;
  const oauth = process.env.TRACKER_OAUTH_TOKEN;
  const org = process.env.TRACKER_ORG_ID;

  if (iam && cloudOrg) {
    headers['Authorization'] = `Bearer ${iam}`;
    headers['X-Cloud-Org-ID'] = cloudOrg;
  } else {
    if (!oauth || !org) {
      throw new Error('Missing TRACKER_OAUTH_TOKEN or TRACKER_ORG_ID envs');
    }
    headers['Authorization'] = `OAuth ${oauth}`;
    headers['X-Org-ID'] = org;
  }
  return headers;
}

export async function GET(req: NextRequest) {
  try {
    const url = new URL(req.url);
    const q = url.searchParams;

    const perPage = Number(q.get('perPage') ?? 50);
    const fields = q.get('fields') ?? 'key,summary,status,assignee';
    const expandRaw = q.get('expand') ?? '';
    const expand = ['attachments', 'transitions'].includes(expandRaw)
      ? expandRaw
      : '';

    const queue = q.get('queue');
    const keys = q.getAll('keys');
    const filterRaw = q.get('filter');
    const queryStr = q.get('query');

    const present = [
      queue ? 'queue' : null,
      keys.length ? 'keys' : null,
      filterRaw ? 'filter' : null,
      queryStr ? 'query' : null,
    ].filter(Boolean) as string[];

    if (present.length === 0) {
      return NextResponse.json(
        { error: 'Provide one of queue|keys|filter|query' },
        { status: 400 }
      );
    }
    if (present.length > 1) {
      return NextResponse.json(
        { error: 'Use only one of queue|keys|filter|query' },
        { status: 400 }
      );
    }

    let body: any = {};
    if (queue) body = { queue };
    if (keys.length) body = { keys };
    if (filterRaw) {
      try {
        const filter = JSON.parse(filterRaw);
        body = { filter };
      } catch {
        return NextResponse.json(
          { error: 'filter must be valid JSON' },
          { status: 400 }
        );
      }
    }
    if (queryStr) body = { query: queryStr };

    const base =
      process.env.TRACKER_BASE_URL || 'https://api.tracker.yandex.net';
    const qs = new URLSearchParams();
    if (!Number.isNaN(perPage) && perPage > 0)
      qs.set('perPage', String(perPage));
    if (fields) qs.set('fields', fields);
    if (expand) qs.set('expand', expand);

    const upstreamUrl = `${base}/v3/issues/_search?${qs.toString()}`;

    const res = await fetch(upstreamUrl, {
      method: 'POST',
      headers: buildAuthHeaders(),
      body: JSON.stringify(body),
      // @ts-expect-error — Next 14 Node runtime
      cache: 'no-store',
    });

    const text = await res.text();
    if (!res.ok) {
      return new NextResponse(text || 'Upstream error', { status: res.status });
    }

    return new NextResponse(text, {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (e: any) {
    return NextResponse.json(
      { error: e?.message ?? 'Internal error' },
      { status: 500 }
    );
  }
}

