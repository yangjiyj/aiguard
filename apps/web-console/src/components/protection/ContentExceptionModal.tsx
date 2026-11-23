import { Button, Form, Input, Modal, Select, Space, message } from 'antd'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import dayjs, { type Dayjs } from 'dayjs'
import { contentSecurityApi } from '../../services/api'
import { extractApiError } from '../../utils/apiError'
import ExpiryField from './ExpiryField'
import { CONTENT_EXCEPTIONS_QUERY_KEY } from './constants'

type FormValues = {
  scope_type: 'tenant' | 'project'
  scope_ref?: string
  rule_id: string
  decision: 'audit' | 'allow'
  expires_at?: Dayjs
  long_term?: boolean
  reason: string
}

// 内容例外（/content-security/exceptions）：按规则 ID 降级为告警并发送或放行。
// 与智能体例外弹窗一样：要显示时才挂载，关闭即卸载。
export default function ContentExceptionModal({ ruleId, onClose }: { ruleId: string; onClose: () => void }) {
  const queryClient = useQueryClient()
  const mutation = useMutation({
    mutationFn: (values: FormValues) => contentSecurityApi.createException({
      scope_type: values.scope_type,
      scope_ref: values.scope_type === 'project' ? values.scope_ref?.trim() || '' : '',
      rule_id: values.rule_id.trim(),
      decision: values.decision,
      reason: values.reason.trim(),
      // 内容例外“长期”按后端约定传 never（存空、显示“永久”）。
      expires_at: values.long_term ? 'never' : values.expires_at?.toISOString(),
    }),
    onSuccess: async () => {
      message.success('例外已创建')
      onClose()
      await queryClient.invalidateQueries({ queryKey: CONTENT_EXCEPTIONS_QUERY_KEY })
    },
    onError: (error) => message.error(extractApiError(error) || '例外创建失败'),
  })

  return (
    <Modal title="新增内容例外" open onCancel={onClose} footer={null} destroyOnHidden>
      <Form<FormValues>
        layout="vertical"
        style={{ marginTop: 16 }}
        initialValues={{ scope_type: 'tenant', rule_id: ruleId, decision: 'audit', expires_at: dayjs().add(7, 'day'), long_term: false }}
        onFinish={(values) => mutation.mutate(values)}
      >
        <Space size={12} align="start" wrap>
          <Form.Item name="scope_type" label="适用范围">
            <Select style={{ width: 140 }} options={[{ value: 'tenant', label: '全单位' }, { value: 'project', label: '指定应用' }]} />
          </Form.Item>
          <Form.Item noStyle shouldUpdate={(prev, next) => prev.scope_type !== next.scope_type}>
            {({ getFieldValue }) => getFieldValue('scope_type') === 'project' ? (
              <Form.Item name="scope_ref" label="应用 ID" rules={[{ required: true, whitespace: true, message: '请输入应用 ID' }]}>
                <Input style={{ width: 220 }} />
              </Form.Item>
            ) : null}
          </Form.Item>
        </Space>
        <Form.Item name="rule_id" label="关联规则" rules={[{ required: true, whitespace: true, message: '请输入关联规则' }]}>
          <Input />
        </Form.Item>
        <Space size={12} align="start" wrap>
          <Form.Item name="decision" label="降级动作">
            <Select style={{ width: 160 }} options={[{ value: 'audit', label: '告警并发送' }, { value: 'allow', label: '放行' }]} />
          </Form.Item>
          <ExpiryField />
        </Space>
        <Form.Item name="reason" label="原因" rules={[{ required: true, whitespace: true, message: '请输入原因' }]}>
          <Input.TextArea rows={3} />
        </Form.Item>
        <Space style={{ width: '100%', justifyContent: 'flex-end' }}>
          <Button onClick={onClose}>取消</Button>
          <Button type="primary" htmlType="submit" loading={mutation.isPending}>创建例外</Button>
        </Space>
      </Form>
    </Modal>
  )
}
