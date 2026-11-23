// 极简 Cookie 解析/序列化（无依赖）。OIDC 无状态会话：id_token 与短时 state/PKCE 均走 cookie。
// 纯函数、可 TDD。
export function parseCookies(header) {
    const out = {};
    if (typeof header !== 'string' || header === '')
        return out;
    for (const part of header.split(';')) {
        const idx = part.indexOf('=');
        if (idx < 0)
            continue;
        const k = part.slice(0, idx).trim();
        if (k === '')
            continue;
        const v = part.slice(idx + 1).trim();
        if (k in out)
            continue; // 首个同名 cookie 胜出
        try {
            out[k] = decodeURIComponent(v);
        }
        catch {
            out[k] = v;
        }
    }
    return out;
}
export function serializeCookie(name, value, opts = {}) {
    const parts = [`${name}=${encodeURIComponent(value)}`];
    parts.push(`Path=${opts.path ?? '/'}`);
    if (typeof opts.maxAge === 'number')
        parts.push(`Max-Age=${Math.floor(opts.maxAge)}`);
    if (opts.httpOnly)
        parts.push('HttpOnly');
    if (opts.secure)
        parts.push('Secure');
    if (opts.sameSite)
        parts.push(`SameSite=${opts.sameSite}`);
    return parts.join('; ');
}
/** 过期删除同名 cookie（path 必须与写入时一致才能命中）。 */
export function clearCookie(name, path = '/') {
    return `${name}=; Path=${path}; Max-Age=0`;
}
