import { NextRequest, NextResponse } from "next/server";
import TrackerClient from "@/lib/TrackerClient";

function getClient() {
  return new TrackerClient({
    baseUrl: process.env.TRACKER_BASE_URL || "https://api.tracker.yandex.net",
    oauthToken: process.env.TRACKER_OAUTH_TOKEN || "",
    // orgId: process.env.TRACKER_ORG_ID,
    cloudOrgId: process.env.TRACKER_CLOUD_ORG_ID,
  });
}

export async function GET(req: NextRequest) {
  try {
    const { searchParams } = new URL(req.url);
    const queue = searchParams.get("queue") || undefined;
    const query = searchParams.get("query") || undefined;
    if (!queue && !query) {
      return NextResponse.json(
        { error: "queue or query required" },
        { status: 400 }
      );
    }
    const filter: Record<string, any> = {};
    if (queue) filter.queue = queue;
    const client = getClient();
    const resp = await client.searchIssues({
      filter: Object.keys(filter).length ? filter : undefined,
      query: query || undefined,
      fields: ["key", "summary", "status"],
      expand: ["assignee"],
      pagination: { perPage: 50 },
    });
    return NextResponse.json(resp);
  } catch (e: any) {
    return NextResponse.json({ error: e?.message || "Error" }, { status: 500 });
  }
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { queue, summary, description } = body || {};
    if (!queue || !summary) {
      return NextResponse.json(
        { error: "queue and summary required" },
        { status: 400 }
      );
    }
    const client = getClient();
    const issue = await client.createIssue({
      queue: { key: queue },
      summary,
      description,
      type: { key: "task" },
    });
    return NextResponse.json(issue, { status: 201 });
  } catch (e: any) {
    return NextResponse.json({ error: e?.message || "Error" }, { status: 500 });
  }
}
