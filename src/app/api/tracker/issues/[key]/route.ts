// app/api/tracker/issues/[key]/route.ts
import { NextRequest, NextResponse } from "next/server";
import TrackerClient from "@/lib/TrackerClient";

function getClient() {
  const baseUrl =
    process.env.TRACKER_BASE_URL || "https://api.tracker.yandex.net";
  const oauthToken = process.env.TRACKER_OAUTH_TOKEN?.trim();
  const iamToken = process.env.TRACKER_IAM_TOKEN?.trim();
  const orgId = process.env.TRACKER_ORG_ID?.trim();
  const cloudOrgId = process.env.TRACKER_CLOUD_ORG_ID?.trim();

  // приоритет IAM
  if (iamToken) {
    if (!cloudOrgId) {
      throw new Error("IAM требует TRACKER_CLOUD_ORG_ID");
    }
    return new TrackerClient({ baseUrl, iamToken, cloudOrgId });
  }

  if (!oauthToken) {
    throw new Error("Нужен TRACKER_IAM_TOKEN или TRACKER_OAUTH_TOKEN");
  }

  if (!cloudOrgId && !orgId) {
    throw new Error("Для OAuth укажи TRACKER_CLOUD_ORG_ID или TRACKER_ORG_ID");
  }

  return new TrackerClient({
    baseUrl,
    oauthToken,
    cloudOrgId,
    orgId,
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
    return NextResponse.json(
      { error: e?.message || "Error" },
      { status: e?.status || 500 }
    );
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
    return NextResponse.json(
      { error: e?.message || "Error" },
      { status: e?.status || 500 }
    );
  }
}

export async function DELETE(
  _req: NextRequest,
  { params }: { params: { key: string } }
) {
  try {
    const client = getClient();
    await client.deleteIssue(params.key);
    return NextResponse.json({ ok: true });
  } catch (e: any) {
    return NextResponse.json(
      { error: e?.message || "Error" },
      { status: e?.status || 500 }
    );
  }
}
