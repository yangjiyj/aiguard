// records 页合并逻辑纯层：网关 upload-events + 门户 UploadEvent → 统一记录。
// 去重：按 sha256（网关权威，portal 仅补充网关未覆盖的 Phase-1 历史图片）。

export type GatewayUploadEvent = {
  id: string;
  filename: string;
  mime_type: string;
  size: number;
  sha256: string;
  reference: string;
  model: string;
  action_taken: string;
  findings: Record<string, unknown>;
  created_at: string;
};

export type PortalUploadRow = {
  id: string;
  filename: string;
  mime: string;
  size: number;
  sha256: string;
  model: string | null;
  kind: string;
  createdAt: string;
};

export type MergedRecord = {
  id: string;
  filename: string;
  mime: string;
  size: number;
  sha256: string;
  reference: string;
  model: string | null;
  actionTaken: string;
  findings: Record<string, unknown> | null;
  source: "gateway" | "portal";
  kind: string;
  createdAt: string;
};

export function mergeRecords(gateway: GatewayUploadEvent[], portal: PortalUploadRow[]): MergedRecord[] {
  const seen = new Set<string>();
  const out: MergedRecord[] = [];

  for (const e of gateway) {
    seen.add(e.sha256);
    out.push({
      id: e.id,
      filename: e.filename,
      mime: e.mime_type,
      size: e.size,
      sha256: e.sha256,
      reference: e.reference,
      model: e.model || null,
      actionTaken: e.action_taken,
      findings: e.findings,
      source: "gateway",
      kind: "file",
      createdAt: e.created_at,
    });
  }

  for (const p of portal) {
    if (seen.has(p.sha256)) continue;
    seen.add(p.sha256);
    out.push({
      id: p.id,
      filename: p.filename,
      mime: p.mime,
      size: p.size,
      sha256: p.sha256,
      reference: "",
      model: p.model,
      actionTaken: "",
      findings: null,
      source: "portal",
      kind: p.kind,
      createdAt: p.createdAt,
    });
  }

  out.sort((a,b)=>new Date(b.createdAt).getTime()-new Date(a.createdAt).getTime()||b.id.localeCompare(a.id));
  return out;
}
