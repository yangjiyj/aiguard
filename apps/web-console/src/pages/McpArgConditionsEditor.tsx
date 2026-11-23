// W1 1.12：MCP 策略参数条件编辑器（Form.List，字段名 arg_conditions）。
import { Button, Form, Input, Select, Space, Typography } from 'antd'
import { DeleteOutlined, PlusOutlined } from '@ant-design/icons'
import { argConditionOps, valuelessOps } from './McpArgConditionUtils'
import type { McpArgConditionOp } from '../services/api'

const { Text } = Typography
const MAX_CONDITIONS = 8

export default function McpArgConditionsEditor() {
  const form = Form.useFormInstance()
  const rows = Form.useWatch('arg_conditions', form) as { op?: McpArgConditionOp }[] | undefined
  return (
    <Form.Item
      label="参数条件（可选）"
      extra="全部条件成立时本策略才命中；留空 = 不看参数。路径写法：$.path、$.opts.recursive、$.paths[*]、$['a b']。放行类策略要求数组里每个值都满足，其余动作任一值满足即命中。参数永不上送控制面，由网关本地判定。"
    >
      <Form.List name="arg_conditions">
        {(fields, { add, remove }) => (
          <Space direction="vertical" style={{ width: '100%' }} size={6}>
            {fields.map((field, index) => {
              const op = rows?.[index]?.op
              return (
                <Space key={field.key} align="start" style={{ width: '100%' }} wrap>
                  <Form.Item name={[field.name, 'path']} noStyle rules={[{ required: true, message: '请填写路径' }]}>
                    <Input aria-label={`参数路径 ${index + 1}`} placeholder="$.path" style={{ width: 150, fontFamily: 'monospace' }} />
                  </Form.Item>
                  <Form.Item name={[field.name, 'op']} noStyle rules={[{ required: true, message: '请选择运算' }]}>
                    <Select aria-label={`参数运算 ${index + 1}`} options={argConditionOps} style={{ width: 120 }} placeholder="运算" />
                  </Form.Item>
                  {op && valuelessOps.has(op) ? null : (
                    <Form.Item name={[field.name, 'value']} noStyle>
                      <Input aria-label={`参数取值 ${index + 1}`} placeholder={op === 'in' || op === 'not_in' ? '["a","b"]' : '取值'} style={{ width: 150 }} />
                    </Form.Item>
                  )}
                  <Button aria-label={`删除条件 ${index + 1}`} icon={<DeleteOutlined />} onClick={() => remove(field.name)} />
                </Space>
              )
            })}
            {fields.length < MAX_CONDITIONS ? (
              <Button type="dashed" icon={<PlusOutlined />} onClick={() => add({ path: '$.', op: 'eq', value: '' })}>添加参数条件</Button>
            ) : (
              <Text type="secondary" style={{ fontSize: 12 }}>最多 {MAX_CONDITIONS} 条</Text>
            )}
          </Space>
        )}
      </Form.List>
    </Form.Item>
  )
}
