// 上游（网关）响应字节流逐帧透传：SSE 与普通 JSON 一视同仁，不缓冲不改写。
export async function forwardStream(source, sink) {
    let chunks = 0;
    let bytes = 0;
    for await (const chunk of source) {
        sink.write(chunk);
        chunks += 1;
        bytes += chunk.byteLength;
    }
    sink.end();
    return { chunks, bytes };
}
// 只透传白名单响应头。注意：fetch 已自动解压，content-length/content-encoding 一旦透传会毁掉响应。
const FORWARD_HEADER_NAMES = ['content-type', 'cache-control', 'x-security-action', 'x-request-id'];
export function pickForwardHeaders(headers) {
    const out = {};
    for (const name of FORWARD_HEADER_NAMES) {
        const value = headers.get(name);
        if (value)
            out[name] = value;
    }
    return out;
}
