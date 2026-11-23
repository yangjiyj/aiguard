import { useEffect, useRef } from 'react'
import { Form, message } from 'antd'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { systemSettingsApi } from '../services/api'
import { extractApiError } from '../utils/apiError'
import { changedEntries } from '../utils/settingsValue'

export const SYSTEM_SETTINGS_QUERY_KEY = ['system-settings'] as const

// 带保存按钮的系统设置表单：
// - 只在用户没改过时同步服务端值，刷新（含别的区块保存后的刷新）不覆盖未保存的输入；
// - 只提交与“上次同步到表单的值”相比本人改动过的键：GET 里环境变量或默认值折算的显示值、
//   别人在此期间改过而本人没动的键，都不回写；
// - 保存期间表单禁用（saving）；保存失败提示后端原因并保留输入；
//   保存成功后以提交时的快照为基准，再等服务端刷新同步。
export function useSettingsForm<T extends object>({
  toValues,
  toPatch,
  save,
}: {
  toValues: (settings: Record<string, unknown>) => T
  toPatch: (values: T) => Record<string, unknown>
  save: (patch: Record<string, unknown>) => Promise<unknown>
}) {
  const queryClient = useQueryClient()
  const [form] = Form.useForm<T>()
  const query = useQuery({ queryKey: SYSTEM_SETTINGS_QUERY_KEY, queryFn: () => systemSettingsApi.get().then((response) => response.data ?? {}) })
  // 上次同步到表单的值（服务端值或刚保存成功的提交快照），submit 以它为比对基准。
  const syncedRef = useRef<T | null>(null)
  useEffect(() => {
    if (!query.data || form.isFieldsTouched()) return
    const values = toValues(query.data)
    syncedRef.current = values
    form.setFieldsValue(values as never)
  }, [form, query.data, toValues])
  const mutation = useMutation({
    mutationFn: ({ patch }: { patch: Record<string, unknown>; values: T }) => save(patch),
    onSuccess: async (_response, { values }) => {
      message.success('已保存')
      syncedRef.current = values
      form.resetFields()
      form.setFieldsValue(values as never)
      await queryClient.invalidateQueries({ queryKey: SYSTEM_SETTINGS_QUERY_KEY })
    },
    onError: (error) => message.error(extractApiError(error) || '保存失败'),
  })
  const submit = (values: T) => {
    const base = syncedRef.current ?? toValues(query.data ?? {})
    const patch = changedEntries(toPatch(values), toPatch(base))
    if (Object.keys(patch).length === 0) {
      message.info('没有改动')
      return
    }
    mutation.mutate({ patch, values })
  }
  return { form, query, mutation, submit, saving: mutation.isPending }
}
