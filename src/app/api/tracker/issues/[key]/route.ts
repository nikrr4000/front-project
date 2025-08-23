import { NextRequest, NextResponse } from "next/server";
import TrackerClient from "@/lib/TrackerClient";

function getClient() {
  return new TrackerClient({
    baseUrl: process.env.TRACKER_BASE_URL || "https://api.tracker.yandex.net",
    oauthToken: process.env.TRACKER_OAUTH_TOKEN || "",
    orgId: process.env.TRACKER_ORG_ID,
  });
}

export async function GET(
  _req: NextRequest,
  { params }: { params: { key: string } }
) {
  try {
    const client = getClient();
    const issue = await client.getIssue(params.key);

    return NextResponse.json(issue);
  } catch (e: any) {
    return NextResponse.json({ error: e?.message || "Error" }, { status: 500 });
  }
}

export async function PATCH(
  req: NextRequest,
  { params }: { params: { key: string } }
) {
  try {
    const data = await req.json();
    const client = getClient();
    const issue = await client.updateIssue(params.key, data);
    return NextResponse.json(issue);
  } catch (e: any) {
    return NextResponse.json({ error: e?.message || "Error" }, { status: 500 });
  }
}

export async function DELETE(
  _req: NextRequest,
  { params }: { params: { key: string } }
) {
  return NextResponse.json(
    {
      error:
        "DELETE /v3/issues/{key} не поддерживается. Используйте transition (_execute).",
    },
    { status: 405 }
  );
}
