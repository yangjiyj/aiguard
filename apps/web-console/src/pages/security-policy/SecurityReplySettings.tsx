import { useEffect } from 'react'
import { Alert, Button, Form, Input, Switch, message } from 'antd'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { securityReplyApi, type SecurityReplyTemplates } from '../../services/api'
import { extractApiError } from '../../utils/apiError'

const TEMPLATE_FIELDS: Array<{ key: keyof SecurityReplyTemplates; label: string }> = [
  { key: 'default', label: '默认' },
  { key: 'prompt_injection', label: '提示词攻击' },
  { key: 'content_safety', label: '内容安全' },
  { key: 'data_leak', label: '敏感数据' },
]

type Values = { enabled: boolean; templates: SecurityReplyTemplates }

const EMPTY_TEMPLATES: SecurityReplyTemplates = { default: '', prompt_injection: '', content_safety: '', data_leak: '' }

const REPLY_POLICY_QUERY_KEY = ['security', 'reply-policy'] as const

// 拦截后给用户的固定回复（/security/reply-policy）。
export default function SecurityReplySettings({ canManage }: { canManage: boolean }) {
  const queryClient = useQueryClient()
  const [form] = Form.useForm<Values>()
  const query = useQuery({ queryKey: REPLY_POLICY_QUERY_KEY, queryFn: () => securityReplyApi.get().then((response) => response.data) })
  useEffect(() => {
    if (!query.data) return
    form.setFieldsValue({ enabled: Boolean(query.data.enabled), templates: { ...EMPTY_TEMPLATES, ...(query.data.templates ?? {}) } })
  }, [form, query.data])
  const mutation = useMutation({
    mutationFn: (values: Values) => securityReplyApi.update({ enabled: Boolean(values.enabled), templates: values.templates }),
    onSuccess: async () => { message.success('已保存'); await queryClient.invalidateQueries({ queryKey: REPLY_POLICY_QUERY_KEY }) },
    onError: (error) => message.error(extractApiError(error) || '保存失败'),
  })
  const disabled = !canManage || !query.isSuccess

  return (
    <section className="security-reply-settings" aria-label="固定回复" style={{ marginBottom: 16 }}>
      <h3>固定回复</h3>
      {query.isError ? <Alert type="error" showIcon message="固定回复读取失败" style={{ marginBottom: 12 }} /> : null}
      <Form form={form} layout="vertical" disabled={disabled} onFinish={(values) => mutation.mutate(values)} style={{ maxWidth: 640 }}>
        <Form.Item name="enabled" label="启用固定回复" valuePropName="checked">
          <Switch aria-label="启用固定回复" />
        </Form.Item>
        {TEMPLATE_FIELDS.map(({ key, label }) => (
          <Form.Item key={key} name={['templates', key]} label={label}>
            <Input.TextArea aria-label={`${label}回复`} rows={2} maxLength={500} />
          </Form.Item>
        ))}
        <Button type="primary" htmlType="submit" disabled={disabled} loading={mutation.isPending}>保存固定回复</Button>
      </Form>
    </section>
  )
}
