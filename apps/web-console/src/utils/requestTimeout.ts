// 判定 axios 错误是否为「请求级超时」而非后端返回的错误响应。
//
// 背景：普通模型同步的后端预算是 5 分钟（control-plane
// modelSyncControlPlaneRequestTimeout），前端同预算。真正打满预算时 axios 抛出的
// 错误没有 response，只有 code=ECONNABORTED/ETIMEDOUT——此时 control-plane 往往
// 仍在执行并会成功提交结果，所以必须与「后端明确返回 4xx/5xx」区分开：
// 前者提示「后台可能仍在同步」，后者展示后端可读原因。
export function isRequestTimeout(error: any): boolean {
  if (!error || typeof error !== 'object') return false
  // 有响应说明后端已明确回包，不是请求级超时（包含 504 这类由网关判定的超时，
  // 那种情况后端链路已中断，应按后端错误展示）。
  if (error.response) return false
  return error.code === 'ECONNABORTED' || error.code === 'ETIMEDOUT'
}
