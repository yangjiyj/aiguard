import { Select, Typography, message } from 'antd'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { securitySystemSettingsApi, systemSettingsApi } from '../../services/api'
import { useAccess } from '../../hooks/useAccess'
import { SYSTEM_SETTINGS_QUERY_KEY } from '../../hooks/useSettingsForm'
import { extractApiError } from '../../utils/apiError'

type Disposition = 'observe' | 'follow_policy'
const KEY = 'model_output_classified_disposition'

// 涉密文件标记命中模型生成的内容时：只留证，或按该策略的动作处理（系统设置 model_output_classified_disposition）。
// 全平台共享的安全键，只有平台级角色能改。
export default function ClassifiedOutputDisposition({ canManage }: { canManage: boolean }) {
  const queryClient = useQueryClient()
  const access = useAccess()
  const query = useQuery({ queryKey: SYSTEM_SETTINGS_QUERY_KEY, queryFn: () => systemSettingsApi.get().then((response) => response.data ?? {}) })
  const mutation = useMutation({
    mutationFn: (next: Disposition) => securitySystemSettingsApi.update({ [KEY]: next }),
    onSuccess: async () => {
      message.success('已保存')
      await queryClient.invalidateQueries({ queryKey: SYSTEM_SETTINGS_QUERY_KEY })
    },
    onError: (error) => message.error(extractApiError(error) || '保存失败'),
  })
  const value: Disposition | undefined = query.data ? (query.data[KEY] === 'follow_policy' ? 'follow_policy' : 'observe') : undefined
  const editable = canManage && access.canManagePlatformSecuritySettings
  return (
    <span className="classified-output-disposition">
      <small>模型生成内容</small>
      <Select<Disposition>
        aria-label="模型生成内容"
        size="small"
        style={{ width: 120 }}
        value={mutation.isPending ? mutation.variables : value}
        loading={mutation.isPending}
        disabled={!editable || value === undefined || mutation.isPending}
        options={[{ value: 'observe', label: '只留证' }, { value: 'follow_policy', label: '按策略' }]}
        onChange={(next) => mutation.mutate(next)}
      />
      {query.isError ? <Typography.Text type="danger">读取失败</Typography.Text> : null}
    </span>
  )
}
