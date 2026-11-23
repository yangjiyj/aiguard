// matched_summary 顶层安全键：只放已知非敏感元数据（分类/规则类型/动作/严重度/阶段/目标主机/计数）。
// 任何未在此的顶层键（含未来检测器新增的样本键）一律丢弃。
export const SAFE_SUMMARY_KEYS = new Set([
    'category',
    'rule_type',
    'action',
    'severity',
    'stage',
    'target_host',
    'count',
    'match_count',
]);
// findings 数组内每个 finding 的安全键：保留分类/规则/严重度/置信度等元数据；
// 明确剔除 matched_text_preview（命中原文片段）与 triage（内部误报治理态）等。
export const SAFE_FINDING_KEYS = new Set([
    'type',
    'category',
    'rule_type',
    'rule_id',
    'severity',
    'confidence',
]);
function isObj(v: unknown): v is Record<string, unknown> {
    return typeof v === 'object' && v !== null && !Array.isArray(v);
}
function sanitizeFinding(raw: unknown): Record<string, unknown> {
    if (!isObj(raw))
        return {};
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(raw)) {
        if (SAFE_FINDING_KEYS.has(k))
            out[k] = v;
    }
    return out;
}
/**
 * matched_summary key 白名单纯函数：非对象 → {}；顶层只留白名单键；
 * findings 数组逐项经 finding 白名单收窄（剥离原文预览）。
 */
export function sanitizeMatchedSummary(raw: unknown): Record<string, unknown> {
    if (!isObj(raw))
        return {};
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(raw)) {
        if (k === 'findings') {
            out.findings = Array.isArray(v) ? v.map(sanitizeFinding) : [];
            continue;
        }
        if (SAFE_SUMMARY_KEYS.has(k))
            out[k] = v;
    }
    return out;
}
export async function getAlerts(deps, query) {
    const limitNum = query.limit != null && query.limit !== '' ? Number(query.limit) : undefined;
    const q = {
        severity: query.severity || undefined,
        eventType: query.eventType || undefined,
        limit: typeof limitNum === 'number' && Number.isFinite(limitNum) ? limitNum : undefined,
        cursor: query.cursor || undefined,
        projectIds: query.projectIds && query.projectIds.length > 0 ? query.projectIds : undefined,
    };
    const { events, total } = await deps.getAuditEvents(q);
    const data = events.map((e) => ({
        id: e.id,
        requestId: e.requestId,
        eventType: e.eventType,
        severity: e.severity,
        ruleName: e.ruleName,
        ruleType: e.ruleType,
        actionTaken: e.actionTaken,
        matchedSummary: sanitizeMatchedSummary(e.matchedSummary),
        evidenceRef: e.evidenceRef,
        createdAt: e.createdAt,
    }));
    const severityCounts = {};
    for (const e of data)
        severityCounts[e.severity] = (severityCounts[e.severity] ?? 0) + 1;
    return { data, total, severityCounts };
}
