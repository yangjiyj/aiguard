// 门户错误码 → 中文文案映射表（W6 · 6.1/6.2/6.3）。
// 纯逻辑，无 React/IO，前端与 API 路由共用并可单测。
// 术语：W4 的 docs/ui-glossary.md 尚未发布，安全处置统一用"拦截"。
// 文案来源：标注"既有"的条目逐字取自仓内既有文件（见 docs/changelog-fragments/ws6.md），其余为新写。

export type PortalErrorKind =
  | "blocked" // 安全策略拦截
  | "quota" // 限流 / 额度 / 余额
  | "permission" // 授权 / 模型权限 / 登录
  | "unavailable" // 上游或依赖不可用、超时
  | "invalid" // 请求本身不合法
  | "interrupted"; // 停止 / 断流

export const PORTAL_ERROR_MESSAGES = {
  // 安全
  security_blocked: "本次请求已被安全策略拦截",
  file_content_blocked: "文件包含敏感内容，已被安全策略拦截",
  guardrail_detection_unavailable: "安全检测暂不可用，请稍后重试",
  // 请求体
  request_body_unavailable: "请求内容未完整接收，未发送给模型，请重试",
  request_body_too_large: "文件超过当前上传大小限制", // 既有：control-plane portal_upload_ingest.go
  file_too_large: "文件超过当前上传大小限制", // 既有：同上
  upload_rejected: "附件未通过校验",
  invalid_request: "请求格式有误，请刷新后重试",
  // 模型与路由
  provider_timeout: "模型服务响应超时，请稍后重试",
  model_route_unavailable: "当前模型暂时不可用，请稍后重试或切换其他模型",
  model_not_configured: "当前模型暂时不可用，请稍后重试或切换其他模型",
  model_not_found: "所选模型不存在或已下线，请切换其他模型",
  provider_unavailable: "模型服务暂时不可用，请稍后重试",
  provider_unsupported: "当前模型线路不支持本次请求的接口或能力，请切换模型或联系管理员检查接入配置",
  model_not_allowed: "你没有使用该模型的权限，请切换其他模型",
  forbidden_model: "你没有使用该模型的权限，请切换其他模型",
  model_price_missing: "该模型未配置价格，请联系管理员", // 既有：缺口清单 D6
  // 权限与身份
  authorization_denied: "当前账号暂无对话权限，请联系管理员",
  user_inactive: "账号已停用或已移除，请联系管理员",
  unauthorized: "登录已失效，请重新登录",
  identity_not_ready: "账号身份尚未就绪，请重新登录",
  forbidden: "无权访问该会话",
  // 限流与计费
  rate_limited: "请求过于频繁，请稍后再试", // 既有：app/api/chat/route.ts
  concurrency_limit: "同时进行的请求过多，请稍后再试",
  quota_exceeded: "已达到用量额度上限，请稍后再试或联系管理员",
  budget_exceeded: "已超出预算限额，请联系管理员",
  insufficient_balance: "余额不足，请充值", // 既有：缺口清单 D5 / 7.3
  billing_account_missing: "尚未开通计费账户，请联系管理员",
  billing_unavailable: "计费服务暂不可用，请稍后重试",
  // 依赖
  control_plane_unavailable: "服务暂时不可用，请稍后重试",
  upstream_unavailable: "服务暂时不可用，请稍后重试",
  file_policy_unavailable: "文件发送策略暂不可用，请稍后重试", // 既有：app/api/upload/route.ts
  // 会话
  not_found: "会话不存在或已删除",
  export_audit_unavailable: "导出留痕暂不可用，请稍后重试",
  export_failed: "导出失败，请稍后重试",
  delete_failed: "删除失败，请稍后重试",
  rename_failed: "重命名失败，请稍后重试",
  // 流
  stream_interrupted: "回答生成中断，已保留已生成的部分",
  stopped: "已停止生成", // 既有：components/chat/chat-panel.tsx
} as const;

export type PortalErrorCode = keyof typeof PORTAL_ERROR_MESSAGES;

const KIND: Record<string, PortalErrorKind> = {
  security_blocked: "blocked",
  file_content_blocked: "blocked",
  rate_limited: "quota",
  concurrency_limit: "quota",
  quota_exceeded: "quota",
  budget_exceeded: "quota",
  insufficient_balance: "quota",
  billing_account_missing: "quota",
  model_price_missing: "quota",
  model_not_allowed: "permission",
  forbidden_model: "permission",
  model_not_found: "invalid",
  authorization_denied: "permission",
  user_inactive: "permission",
  unauthorized: "permission",
  identity_not_ready: "permission",
  forbidden: "permission",
  provider_unsupported: "unavailable",
  request_body_unavailable: "invalid",
  request_body_too_large: "invalid",
  file_too_large: "invalid",
  upload_rejected: "invalid",
  invalid_request: "invalid",
  stream_interrupted: "interrupted",
  stopped: "interrupted",
};

/** 门户路由自有的 code 别名（历史返回值），归一到映射表的 key。 */
const ALIASES: Record<string, PortalErrorCode> = {
  missing_fields: "invalid_request",
  invalid_json: "invalid_request",
  invalid_body: "invalid_request",
  missing_file: "invalid_request",
  upstream_unreachable: "upstream_unavailable",
  upstream_error: "upstream_unavailable",
  ingest_unreachable: "upstream_unavailable",
  ingest_failed: "upstream_unavailable",
  control_plane_error: "control_plane_unavailable",
  control_plane_unreachable: "control_plane_unavailable",
  request_too_large: "request_body_too_large",
  payment_required: "insufficient_balance",
};

export type PortalError = {
  code: string;
  kind: PortalErrorKind;
  /** 给员工看的一句话 */
  message: string;
  /** 网关渲染的拦截说明（管理员可配置模板，含拦截编号）；只对 blocked 保留 */
  notice?: string;
  requestId?: string;
  blockId?: string;
  status?: number;
};

function hasMessage(code: string): code is PortalErrorCode {
  return Object.prototype.hasOwnProperty.call(PORTAL_ERROR_MESSAGES, code);
}

/** HTTP 状态在没有 code 时的兜底归类。 */
export function codeForStatus(status: number): PortalErrorCode {
  if (status === 401) return "unauthorized";
  if (status === 402) return "insufficient_balance";
  if (status === 403) return "authorization_denied";
  if (status === 413) return "request_body_too_large";
  if (status === 429) return "rate_limited";
  if (status === 504) return "provider_timeout";
  if (status >= 400 && status < 500) return "invalid_request";
  return "upstream_unavailable";
}

export function normalizeErrorCode(code: string | undefined | null, status?: number): string {
  const c = (code ?? "").trim();
  if (c && hasMessage(c)) return c;
  if (c && ALIASES[c]) return ALIASES[c];
  if (!c && typeof status === "number") return codeForStatus(status);
  return c || "upstream_unavailable";
}

/**
 * 把一个错误码（+ 可选网关说明）转成员工可读的 PortalError。
 * 未知 code：HTTP 状态可归类就按状态给文案，否则给通用文案并带上 code 便于报障。
 */
export function describePortalError(input: {
  code?: string | null;
  status?: number;
  upstreamMessage?: string | null;
  requestId?: string | null;
  blockId?: string | null;
}): PortalError {
  const code = normalizeErrorCode(input.code, input.status);
  let message: string;
  if (hasMessage(code)) {
    message = PORTAL_ERROR_MESSAGES[code];
  } else if (typeof input.status === "number") {
    message = `${PORTAL_ERROR_MESSAGES[codeForStatus(input.status)]}（${code}）`;
  } else {
    message = `${PORTAL_ERROR_MESSAGES.upstream_unavailable}（${code}）`;
  }
  const kind = KIND[code] ?? (typeof input.status === "number" && input.status < 500 ? "invalid" : "unavailable");
  const out: PortalError = { code, kind, message };
  const notice = (input.upstreamMessage ?? "").trim();
  if (kind === "blocked" && notice) out.notice = notice.slice(0, 2000);
  if (input.requestId) out.requestId = String(input.requestId);
  if (input.blockId) out.blockId = String(input.blockId);
  if (typeof input.status === "number") out.status = input.status;
  return out;
}

/**
 * 解析各方错误体：
 * - 网关 / 控制面：{"error":{"code","message","request_id"?,"block_id"?}}
 * - portal-proxy：{"error":{"code","message","trace_id"}}
 * - 门户自有路由：{"error":"code","message"?,"request_id"?}
 * 非 JSON 返回 null（调用方按 HTTP 状态兜底）。
 */
export function parseErrorBody(text: string): {
  code?: string;
  message?: string;
  requestId?: string;
  blockId?: string;
} | null {
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    return null;
  }
  if (!json || typeof json !== "object") return null;
  const root = json as Record<string, unknown>;
  const str = (v: unknown) => (typeof v === "string" && v.trim() ? v.trim() : undefined);
  if (root.error && typeof root.error === "object") {
    const e = root.error as Record<string, unknown>;
    return {
      code: str(e.code),
      message: str(e.message),
      requestId: str(e.request_id) ?? str(e.trace_id) ?? str(root.request_id),
      blockId: str(e.block_id),
    };
  }
  return {
    code: str(root.error) ?? str(root.code),
    message: str(root.message),
    requestId: str(root.request_id),
    blockId: str(root.block_id),
  };
}

/** 6.2：/api/upload 失败体 → 附件上显示的文案（按 code 查表，无 code 按 HTTP 状态兜底）。 */
export function uploadErrorMessage(status: number, body: unknown): string {
  const b = (body ?? {}) as { error?: unknown };
  return describePortalError({ code: typeof b.error === "string" ? b.error : undefined, status }).message;
}

/** 消息结果与界面提示文案。 */
export const OUTCOME_LABELS = {
  externalImageBlocked: "外链图片已屏蔽",
  blockId: "拦截编号",
  requestId: "请求 ID",
  interrupted: "已中断",
  imageNotSupported: "当前模型不支持图片输入，请切换支持视觉的模型",
  noModel: "暂无可用模型，请联系管理员",
  loadingConversation: "正在加载会话…",
  deleteConfirm: "删除后会移入回收站，可在偏好设置中恢复。确定删除？",
} as const;

/** 网关 X-Security-Action 头的员工可读说明（只陈述不阻断的动作）。 */
export const SECURITY_ACTION_LABELS: Record<string, string> = {
  mask: "本轮已脱敏",
  audit: "本轮已记录",
};

/** 上传成功后 ingest 返回的 action → 附件标签。 */
export const UPLOAD_ACTION_LABELS: Record<string, string> = {
  mask: "已脱敏",
  audit: "已记录",
};
