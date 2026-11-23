// Fixed customer-facing copy; upstream messages and credential values never enter UI.
export const PERSONAL_ACTION_ERRORS:Record<string,string>={
 key_model_not_authorized:'所选模型超出当前账号授权，请刷新模型列表后重试。',
 key_limit_reached:'启用的普通 API Key 已达上限，请先停用或吊销其他 Key。',
 created_before_encryption:'此旧 Key 未保存可恢复密文，请使用重置获取新 Key；旧 Key 将失效。',
 key_revoked:'此 Key 已失效，请重新创建。',
 invalid_origin:'请求来源校验失败，请刷新当前页面后重试；仍失败请联系管理员。',
 redemption_unavailable:'兑换码无效、已使用、已停用或已过期。',
 invalid_redemption_code:'请输入有效的兑换码。',
 invalid_input:'请输入有效的兑换码。',
 rate_limited:'操作过于频繁，请稍后重试。',
 control_plane_unreachable:'管理服务暂不可达，请稍后重试。',
 control_plane_error:'管理服务暂不可用，请稍后重试。',
 employee_key_unavailable:'个人 Key 服务暂不可用，请稍后重试。',
 keys_unavailable:'API Key 服务暂不可用，请稍后重试。',
 unauthorized:'登录已失效，请重新登录。',
};
export function personalActionError(code:unknown,fallback='操作失败，请稍后重试。'):string{
 return typeof code==='string'&&Object.hasOwn(PERSONAL_ACTION_ERRORS,code)?PERSONAL_ACTION_ERRORS[code]:fallback;
}
