import type { Key } from 'react'

export const validateModelBatchDeleteSelection = (modelIds: readonly Key[]) => {
  if (modelIds.length < 1) return '请先选择要处理的模型'
  if (modelIds.length > 100) return '每次最多处理 100 个，请分批操作'
  return null
}

export const getModelBatchDeleteErrorMessage = (error: any) => {
  const status = error?.response?.status
  const code = error?.response?.data?.error?.code || error?.response?.data?.code
  if (status === 403 || code === 'permission_denied' || code === 'permission_check_failed') {
    return '当前账号无批量删除权限，请联系管理员'
  }
  if (status === 404 || code === 'not_found') {
    return '所选模型不存在或状态已变化，请刷新后重试'
  }
  if (status === 400 || code === 'invalid_request') {
    return '选择内容不符合要求，请刷新后分批重试'
  }
  return '批量删除失败，请稍后重试'
}
