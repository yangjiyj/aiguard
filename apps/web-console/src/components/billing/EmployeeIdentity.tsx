import { Button, Descriptions, Popover } from 'antd'
import { InfoCircleOutlined } from '@ant-design/icons'
import './EmployeeIdentity.css'

export type EmployeeIdentityData = {
  display_name?: string
  name?: string
  username?: string
  email?: string
  user_id?: string
  department_id?: string
  department_name?: string
}

export default function EmployeeIdentity({ employee }: { employee: EmployeeIdentityData }) {
  const label = employee.display_name?.trim() || employee.name?.trim() || employee.username?.trim() || employee.email?.trim() || '已删除或不可见员工'
  const details = [
    { key: 'employee', label: '员工', children: label },
    { key: 'username', label: '登录账号', children: employee.username },
    { key: 'user_id', label: '用户 ID', children: employee.user_id },
    { key: 'department', label: '部门', children: employee.department_name },
    { key: 'department_id', label: '部门 ID', children: employee.department_id },
    { key: 'email', label: '邮箱', children: employee.email },
  ].filter(item => item.children)
  return <span className="billing-employee-identity">
    <span className="billing-employee-name">{label}</span>
    <Popover title="员工详情" trigger="click" content={<Descriptions className="billing-employee-details" size="small" column={1} items={details} />}>
      <Button type="text" size="small" aria-label={`员工详情：${label}`} icon={<InfoCircleOutlined />} />
    </Popover>
  </span>
}
