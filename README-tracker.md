# Yandex Tracker Integration

## ENV variables

Set one of the token pairs:

- `TRACKER_OAUTH_TOKEN` + (`TRACKER_ORG_ID` or `TRACKER_CLOUD_ORG_ID`)
- `TRACKER_IAM_TOKEN` + `TRACKER_CLOUD_ORG_ID`

Optional:

- `TRACKER_BASE_URL` (default `https://api.tracker.yandex.net`)
- `TRACKER_ISSUE_KEY` for smoke tests (default `DEMKA-1`)
- `TRACKER_QUEUE_KEY` for search (default `DEMKA`)
- `TRACKER_TRANSITION_ID` or `TRACKER_TRANSITION_KEY` (+ optional `TRACKER_RESOLUTION_KEY`) to demo soft delete

## Smoke test

```bash
node scripts/tracker-smoke.mjs
```

## Checklist

- `GET /v3/myself` → 200
- `DELETE /v3/issues/<key>` → 405
- `POST /v3/issues/_search` with `{ queue: "<QUEUE>" }` → 200
- no usage of `DELETE /v3/issues/{key}` in app code
- `_search` uses POST, single body param, no `expand=assignee`
- `X-Org-ID` / `X-Cloud-Org-ID` headers match token type
- no secrets leak to client
