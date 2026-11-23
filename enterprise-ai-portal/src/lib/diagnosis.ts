// 员工诊断助手的前后端契约（与控制面 portal-integration/diagnostics 一致）。
export type DiagnosisLevel = "confirmed" | "suspected" | "unknown";
export type DiagnosisSeverity = "ok" | "warn" | "error";

export interface DiagnosisEvidence { kind: string; ref: string; summary: string; raw?: string }
export interface DiagnosisAdvice { text: string; link?: string }
export interface DiagnosisFinding {
  check_id: string;
  severity: DiagnosisSeverity;
  level: DiagnosisLevel;
  title: string;
  impact: string;
  advice?: DiagnosisAdvice[];
  excluded?: string[];
  evidence?: DiagnosisEvidence[];
}
export interface DiagnosisStep { tool?: string; summary: string }
export interface DiagnosisReport {
  id?: string;
  tier?: string;
  degraded?: string;
  findings?: DiagnosisFinding[];
  ok_count?: number;
  steps?: DiagnosisStep[];
  model?: string;
}
export interface DiagnosisSession {
  status: "running" | "done" | "failed";
  steps?: DiagnosisStep[];
  report?: DiagnosisReport;
}
export interface DiagnosisSummary {
  id: string;
  status: DiagnosisSession["status"];
  created_at?: string;
  input?: { kind?: string; text?: string };
}

export const DIAGNOSIS_LEVEL_LABEL: Record<DiagnosisLevel, string> = {
  confirmed: "确定",
  suspected: "疑似",
  unknown: "无法判断",
};

/** 结论卡片只展示有问题的项；正常项合并成一行计数。 */
export function visibleFindings(report: DiagnosisReport): DiagnosisFinding[] {
  return (report.findings ?? []).filter((finding) => finding.severity !== "ok");
}

export function summaryLabel(item: DiagnosisSummary): string {
  const text = item.input?.text?.trim();
  if (text) return text;
  if (item.input?.kind === "health") return "一键体检";
  if (item.created_at) {
    const date = new Date(item.created_at);
    if (!Number.isNaN(date.getTime())) return date.toLocaleString("zh-CN");
  }
  return "诊断记录";
}
