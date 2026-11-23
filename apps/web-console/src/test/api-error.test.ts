import { describe, expect, it } from 'vitest'
import { extractApiError } from '../utils/apiError'

describe('extractApiError 透传后端原因', () => {
  it('优先取 error.code 结构里的 message', () => {
    const e = { response: { data: { error: { code: 'invalid_role', message: '非法的平台角色，只允许 platform_admin、tenant_admin、developer、viewer 之一' } } } }
    expect(extractApiError(e)).toBe('非法的平台角色，只允许 platform_admin、tenant_admin、developer、viewer 之一')
  })

  it('将外部身份源密码限制转换为中文操作指引', () => {
    const e = {
      response: {
        data: {
          error: { code: 'password_managed_externally', message: 'password is managed by an external identity source' },
        },
      },
    }
    expect(extractApiError(e)).toBe('该用户密码由企业身份源管理，请前往对应身份源修改')
  })

  it('退回到顶层 message', () => {
    const e = { response: { data: { message: '用户名已存在' } } }
    expect(extractApiError(e)).toBe('用户名已存在')
  })

  it('无可解析原因时返回 undefined（交由调用方给默认文案）', () => {
    expect(extractApiError({})).toBeUndefined()
    expect(extractApiError(undefined)).toBeUndefined()
    expect(extractApiError({ response: { data: {} } })).toBeUndefined()
  })

  it('withFallback 在无原因时给默认文案', () => {
    const e = { response: { data: { error: { message: '删除失败：存在引用' } } } }
    // 便捷：调用方常写 extractApiError(e) || '创建失败'
    expect(extractApiError(e) || '创建失败').toBe('删除失败：存在引用')
    expect(extractApiError({}) || '创建失败').toBe('创建失败')
  })

  it('后端只给英文原因时不直出：计费错误码映射中文，其余交由调用方中文默认文案', () => {
    const billing = { response: { status: 400, data: { error: { code: 'invalid_billing_request', message: 'invalid billing request' } } } }
    expect(extractApiError(billing)).toBe('计费参数不正确，请检查后重试')
    const tariff = { response: { status: 409, data: { error: { code: 'tariff_not_draft', message: 'only draft billing tariff plans can be deleted' } } } }
    expect(extractApiError(tariff)).toBe('只有草稿状态的时段方案可以删除')
    const english = { response: { status: 500, data: { error: { code: 'billing_internal_error', message: 'failed to list customer keys' } } } }
    expect(extractApiError(english)).toBeUndefined()
    expect(extractApiError(english) || '加载失败').toBe('加载失败')
    expect(extractApiError({ response: { data: { message: 'Request failed with status code 502' } } })).toBeUndefined()
  })
})
