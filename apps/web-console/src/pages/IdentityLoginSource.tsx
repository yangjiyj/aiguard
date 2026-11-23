import { Space } from "antd"
import { Link } from "react-router-dom"
import SsoConfig from "./SsoConfig"

// 登录源页复用现有 OIDC 表单（SsoConfig），只在外层加返回总览的导航。
// 规格步骤3：登录源页复用现有 OIDC 表单。
export default function IdentityLoginSource() {
  return (
    <div>
      <Space style={{ marginBottom: 12 }}>
        <Link to="/identity-sources">← 企业身份源</Link>
      </Space>
      <SsoConfig />
    </div>
  )
}
