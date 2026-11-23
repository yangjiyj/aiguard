import { Checkbox, DatePicker, Form, Space } from 'antd'

// 例外的过期时间：指定时间或“长期”。表单字段名 expires_at、long_term。
export default function ExpiryField() {
  return (
    <Form.Item label="过期时间" required style={{ marginBottom: 0 }}>
      <Space align="start" wrap>
        <Form.Item noStyle shouldUpdate={(prev, next) => prev.long_term !== next.long_term}>
          {({ getFieldValue }) => (
            <Form.Item name="expires_at" rules={[{ required: !getFieldValue('long_term'), message: '请选择过期时间' }]}>
              <DatePicker aria-label="过期时间" showTime disabled={Boolean(getFieldValue('long_term'))} />
            </Form.Item>
          )}
        </Form.Item>
        <Form.Item name="long_term" valuePropName="checked">
          <Checkbox>长期</Checkbox>
        </Form.Item>
      </Space>
    </Form.Item>
  )
}
