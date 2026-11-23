// OpenAI 目录模型（gpt-<数字>/o<数字>…）会被 LobeHub 2.2.9 内置规则强制走 Responses API
// （runtime shouldUseResponsesAPI 里 Ag(model) 最先短路，provider 配置 enableResponseApi 盖不掉），
// 而本网关上游不支持流式 Responses API（真实 UI 是流式）→ 这类模型在门户里出不了字。
// 对策：目录里用「不触发该规则」的别名 id 承载（员工看到的显示名不变），portal-proxy 转发网关前把别名还原成真 id。
// 规则触发式（据镜像 vendor-ai-runtime 实测）：/gpt-\d(?!\d)/、/^o\d/、内置集 vg。
// 自动别名：gpt-<数字> 去掉 gpt 后的连字符（gpt-5.5→gpt5.5，实测改走 chat/completions）。
// 其余需别名的（如 o1/o3 或以后新增）走 env PORTAL_MODEL_ALIASES 显式映射（JSON 真id→别名id）。
function loadExplicit() {
    try {
        const raw = process.env.PORTAL_MODEL_ALIASES;
        const obj = raw ? JSON.parse(raw) : {};
        return obj && typeof obj === 'object' && !Array.isArray(obj) ? obj : {};
    }
    catch {
        return {};
    }
}
const EXPLICIT = loadExplicit();
const EXPLICIT_REVERSE = {};
for (const [real, alias] of Object.entries(EXPLICIT))
    EXPLICIT_REVERSE[alias] = real;
/** 真 id → 目录别名（不触发 LobeHub Responses 规则）。非受影响模型原样返回。 */
export function toAlias(realId) {
    const explicit = EXPLICIT[realId];
    if (explicit !== undefined)
        return explicit;
    if (/^gpt-\d/.test(realId))
        return realId.replace(/^gpt-/, 'gpt');
    return realId;
}
/** 目录别名 → 真 id（转发网关前还原）。非别名原样返回；对真 id 幂等安全（未别名请求不被误改）。 */
export function fromAlias(catalogId) {
    const explicit = EXPLICIT_REVERSE[catalogId];
    if (explicit !== undefined)
        return explicit;
    if (/^gpt\d/.test(catalogId))
        return catalogId.replace(/^gpt/, 'gpt-');
    return catalogId;
}
