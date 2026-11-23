import { Form, Input, Typography } from 'antd'
import ConfirmSwitch from './ConfirmSwitch'

const ADDRESS_SWITCHES = [
  { key: 'allow_loopback', label: '允许回环地址' },
  { key: 'allow_link_local', label: '允许链路本地地址' },
  { key: 'allow_metadata', label: '允许云元数据地址' },
  { key: 'allow_internal_hostnames', label: '允许内部主机名' },
] as const

// 对象级出站放行（反向代理路由、MCP 服务）。includeMcp 时多出证书与重定向三项。
// canEnable=false（租户级角色）时开关只能关不能开，证书只读。写回用 utils/egressOverrides 的 normalizeEgressOverrides。
export default function EgressOverrideFields({ includeMcp = false, canEnable = true }: { includeMcp?: boolean; canEnable?: boolean }) {
  return (
    <div className="egress-override-fields" aria-label="高级出站" role="group">
      <Typography.Text strong>高级出站</Typography.Text>
      <div className="egress-override-switches">
        {ADDRESS_SWITCHES.map(({ key, label }) => (
          <Form.Item key={key} name={['egress_overrides', key]} label={label} valuePropName="checked">
            <ConfirmSwitch ariaLabel={label} allowEnable={canEnable} confirmTitle={`${label}？`} />
          </Form.Item>
        ))}
        {includeMcp ? (
          <>
            <Form.Item name={['egress_overrides', 'allow_same_host_redirect']} label="允许同主机重定向" valuePropName="checked">
              <ConfirmSwitch ariaLabel="允许同主机重定向" allowEnable={canEnable} confirmTitle="允许同主机重定向？" />
            </Form.Item>
            <Form.Item name={['egress_overrides', 'insecure_skip_verify']} label="跳过证书校验" valuePropName="checked">
              <ConfirmSwitch ariaLabel="跳过证书校验" allowEnable={canEnable} confirmTitle="跳过证书校验？" confirmContent="网关不再校验上游证书，连接可能被冒充。" />
            </Form.Item>
          </>
        ) : null}
      </div>
      {includeMcp ? (
        <Form.Item name={['egress_overrides', 'trusted_ca_pem']} label="信任的 CA 证书">
          <Input.TextArea rows={3} placeholder="-----BEGIN CERTIFICATE-----" disabled={!canEnable} />
        </Form.Item>
      ) : null}
    </div>
  )
}
