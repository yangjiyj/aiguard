// 从 IdP 落库的 id_token（原始 JWT）里解出 department 声明。
// 纯函数、绝不抛错：无 token / 结构非三段 / payload 非 JSON / 无 department / 非字符串
// 一律返回 null（上层据此走 default 组）。JWT payload 为 base64url 编码的 JSON。
export function decodeDepartment(idToken) {
    if (typeof idToken !== 'string' || idToken.length === 0)
        return null;
    const parts = idToken.split('.');
    if (parts.length !== 3)
        return null;
    try {
        const payloadJson = Buffer.from(parts[1], 'base64url').toString('utf8');
        const payload = JSON.parse(payloadJson);
        const dept = payload.department;
        return typeof dept === 'string' && dept.length > 0 ? dept : null;
    }
    catch {
        return null;
    }
}
