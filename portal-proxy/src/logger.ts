// 结构化日志：JSON lines 到 stdout。红线：员工网关 key 明文绝不入日志（只允许 key_prefix）。
export function log(level, msg, fields = {}) {
    process.stdout.write(`${JSON.stringify({ ts: new Date().toISOString(), level, msg, ...fields })}\n`);
}
