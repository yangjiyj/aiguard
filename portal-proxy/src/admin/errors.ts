// 管理后台统一错误：带业务 code + HTTP 状态，router 据此回结构化 JSON。
export class AdminError extends Error {
    code;
    status;
    constructor(code, message, status = 400) {
        super(message);
        this.code = code;
        this.status = status;
        this.name = 'AdminError';
    }
}
export function errMsg(e) {
    return e instanceof Error ? e.message : String(e);
}
