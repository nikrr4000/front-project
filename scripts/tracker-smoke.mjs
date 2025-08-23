#!/usr/bin/env node
const base = process.env.TRACKER_BASE_URL || 'https://api.tracker.yandex.net';
const oauth = process.env.TRACKER_OAUTH_TOKEN;
const iam = process.env.TRACKER_IAM_TOKEN;
const org = process.env.TRACKER_ORG_ID;
const cloud = process.env.TRACKER_CLOUD_ORG_ID;
const issueKey = process.env.TRACKER_ISSUE_KEY || 'DEMKA-1';
const queueKey = process.env.TRACKER_QUEUE_KEY || 'DEMKA';
const transitionId = process.env.TRACKER_TRANSITION_ID;
const transitionKey = process.env.TRACKER_TRANSITION_KEY;
const resolutionKey = process.env.TRACKER_RESOLUTION_KEY;

function authHeaders() {
  const h = { Accept: 'application/json' };
  if (iam) {
    if (!cloud) throw new Error('IAM требует TRACKER_CLOUD_ORG_ID');
    h.Authorization = `Bearer ${iam}`;
    h['X-Cloud-Org-ID'] = cloud;
  } else if (oauth) {
    h.Authorization = `OAuth ${oauth}`;
    if (cloud) h['X-Cloud-Org-ID'] = cloud;
    else if (org) h['X-Org-ID'] = org;
    else throw new Error('Для OAuth укажи ORG_ID или CLOUD_ORG_ID');
  } else {
    throw new Error('Нужен токен: OAUTH или IAM');
  }
  return h;
}

async function req(path, init={}) {
  const url = `${base}${path}`;
  const res = await fetch(url, { ...init, headers: { ...authHeaders(), ...(init.headers||{}) } });
  const text = await res.text();
  return { status: res.status, headers: Object.fromEntries(res.headers), text };
}

(async () => {
  try {
    console.log('> GET /v3/myself');
    console.log(await req('/v3/myself'));

    console.log('> DELETE /v3/issues/:key (ожидаем 405)');
    console.log(await req(`/v3/issues/${encodeURIComponent(issueKey)}`, { method: 'DELETE' }));

    if (transitionId || transitionKey) {
      const id = transitionId || transitionKey;
      const body = resolutionKey ? { resolution: { key: resolutionKey } } : {};
      console.log('> POST /v3/issues/:key/transitions/:id/_execute');
      console.log(
        await req(
          `/v3/issues/${encodeURIComponent(issueKey)}/transitions/${encodeURIComponent(id)}/_execute`,
          { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }
        )
      );
    } else {
      console.log('> transition demo пропущен. Укажи TRACKER_TRANSITION_ID или TRACKER_TRANSITION_KEY');
    }

    console.log('> POST /v3/issues/_search');
    const search = await req('/v3/issues/_search?perPage=5&fields=key,summary,status', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ queue: queueKey })
    });
    console.log(search);
  } catch (e) {
    console.error('Ошибка смоук-теста:', e.message);
  }
})();
