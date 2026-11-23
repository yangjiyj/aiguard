// body.user（LobeHub 服务端注入的 LobeChat userId）→ 员工映射的入口字段。
// 缺失即 400 user_missing：没有归因主体的请求一律不转发。
export class MappingError extends Error {
    code;
    constructor(code, message) {
        super(message);
        this.code = code;
        this.name = 'MappingError';
    }
}
export function extractLobeUserId(body) {
    if (typeof body !== 'object' || body === null || Array.isArray(body)) {
        throw new MappingError('invalid_body', '请求体必须是 JSON 对象');
    }
    const rec = body;
    // Chat Completions 走 body.user；Responses API（gpt-*/o* 被 LobeHub 内置规则强制走 responses）
    // 用 body.safety_identifier 承载同一 LobeChat userId（服务端注入，浏览器不可伪造）。二者取其一。
    const fromUser = rec.user;
    const user = (typeof fromUser === 'string' && fromUser.length > 0) ? fromUser : rec.safety_identifier;
    if (typeof user !== 'string' || user.length === 0) {
        throw new MappingError('user_missing', '缺少 body.user / safety_identifier（LobeHub 服务端注入的用户标识），无法按人归因，拒绝转发');
    }
    return user;
}
/** 转发网关前删除 body.user（不改动原对象）。网关 re-marshal 会丢弃该字段，但不依赖它。 */
export function stripUser(body) {
    const { user: _user, ...rest } = body;
    return rest;
}
