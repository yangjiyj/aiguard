import { useEffect } from 'react'
import { Alert, Button, Form, Input, Space, Switch, Tabs, Tag, Typography, message } from 'antd'
import { GlobalOutlined, SafetyCertificateOutlined } from '@ant-design/icons'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import api, { proxyApi, type ProxyWhitelist } from '../services/api'
import CACertificateManager from '../components/CACertificateManager'
import { useAuditQueryIdentity } from '../hooks/useAuditQueryIdentity'
import { useAccess } from '../hooks/useAccess'
import { ForwardProxyEgressForm, ProxyWhitelistTable } from './ForwardProxyEgress'

const { Title, Text } = Typography

const getForwardProxyHost = () => {
  const configured = import.meta.env.VITE_FORWARD_PROXY_HOST
  if (configured) return configured
  if (typeof window === 'undefined') return '127.0.0.1'
  return window.location.hostname || '127.0.0.1'
}

const getForwardProxyPort = () => import.meta.env.VITE_FORWARD_PROXY_PORT || '3128'

function ProxySettings() {
  const queryClient = useQueryClient()
  const proxyHost = getForwardProxyHost()
  const proxyPort = getForwardProxyPort()
  const [outboundProxyForm] = Form.useForm()
  const queryIdentity = useAuditQueryIdentity()
  const access = useAccess()
  // 白名单接口仍只给系统管理员；出站限制是平台级安全键，平台级安全员也能改。
  const canManage = access.isSystemAdmin
  const canManageEgress = access.canManagePlatformSecuritySettings
  // 平台级安全员只看到“出站限制”；白名单、出网代理、CA 的接口只给系统管理员。
  const officerView = access.role === 'security_officer'

  const whitelistQ = useQuery({
    queryKey: ['proxy-whitelist-coverage', queryIdentity],
    enabled: !officerView,
    queryFn: () => proxyApi.getWhitelist().then((response) => {
      if (!Array.isArray(response.data?.data)) throw new Error('whitelist status unavailable')
      return response.data as { data: unknown[] }
    }),
  })

  const outboundProxySettingsQ = useQuery({
    queryKey: ['outbound-proxy-settings'],
    enabled: !officerView,
    queryFn: () => api.get('/system/settings').then((response) => response.data as Record<string, string>),
  })
  const outboundProxyConfigured = outboundProxySettingsQ.data?.outbound_proxy_enabled === 'true'

  useEffect(() => {
    if (!outboundProxySettingsQ.data) return
    outboundProxyForm.setFieldsValue({
      outbound_proxy_enabled: outboundProxyConfigured,
      outbound_proxy_url: '',
    })
  }, [outboundProxyConfigured, outboundProxyForm, outboundProxySettingsQ.data])

  const saveOutboundProxyMutation = useMutation({
    mutationFn: (values: { outbound_proxy_enabled?: boolean; outbound_proxy_url?: string }) => api.put('/system/settings', {
      outbound_proxy_enabled: Boolean(values.outbound_proxy_enabled),
      outbound_proxy_url: values.outbound_proxy_url?.trim() || '',
    }),
    onSuccess: () => {
      message.success('客户出网代理已保存，新的模型请求会立即使用该配置')
      outboundProxyForm.setFieldValue('outbound_proxy_url', '')
      queryClient.invalidateQueries({ queryKey: ['outbound-proxy-settings'] })
    },
    onError: (error: any) => message.error(error?.response?.data?.error?.message || '保存客户出网代理失败'),
  })

  if (officerView) {
    return (
      <div>
        <div className="page-header">
          <Title level={4} style={{ margin: 0, fontSize: 20, fontWeight: 600, color: 'var(--text-primary)' }}>网络与证书</Title>
        </div>
        <div className="table-card">
          <div style={{ padding: '0 20px 20px' }}>
            <ForwardProxyEgressForm canManage={canManageEgress} />
          </div>
        </div>
      </div>
    )
  }

  return (
    <div>
      <div className="page-header">
        <Title level={4} style={{ margin: 0, fontSize: 20, fontWeight: 600, color: 'var(--text-primary)' }}>网络与证书</Title>
        <Text style={{ fontSize: 13, color: 'var(--text-secondary)' }}>配置客户网络出口、正向代理接入地址和 HTTPS 审计证书</Text>
      </div>

      <div className="table-card">
        <Tabs
          defaultActiveKey="forward-proxy"
          items={[
            {
              key: 'outbound-proxy',
              label: '网关出网代理',
              icon: <GlobalOutlined />,
              children: (
                <div style={{ padding: '0 20px 20px', maxWidth: 720 }}>
                  <Alert
                    type="info"
                    showIcon
                    style={{ marginBottom: 16 }}
                    message="适用于客户网络要求经过统一出口代理的场景"
                    description="启用后，网关调用外部大模型 API 时经客户提供的 HTTP/HTTPS 代理出网。代理账号与口令加密保存，页面只显示是否已配置，不会回显。"
                  />
                  <Form
                    form={outboundProxyForm}
                    layout="vertical"
                    onFinish={(values) => saveOutboundProxyMutation.mutate(values)}
                    initialValues={{ outbound_proxy_enabled: false }}
                  >
                    <Form.Item
                      name="outbound_proxy_enabled"
                      label="启用客户出网代理"
                      valuePropName="checked"
                      extra="关闭并保存会清除当前出网代理配置，网关恢复使用部署环境的默认网络出口。"
                    >
                      <Switch checkedChildren="启用" unCheckedChildren="关闭" />
                    </Form.Item>
                    <Form.Item
                      name="outbound_proxy_url"
                      label="代理地址"
                      extra={outboundProxyConfigured
                        ? '当前已配置。留空保存时保留现有地址；如需更换，请填写完整的新地址。'
                        : '示例：http://proxy.customer.local:8080；如需认证，可填写 http://用户名:密码@主机:端口。'}
                      rules={[
                        ({ getFieldValue }) => ({
                          validator(_, value) {
                            if (!getFieldValue('outbound_proxy_enabled') || value || outboundProxyConfigured) return Promise.resolve()
                            return Promise.reject(new Error('启用后请填写代理地址'))
                          },
                        }),
                      ]}
                    >
                      <Input.Password autoComplete="new-password" placeholder="http://proxy.customer.local:8080" />
                    </Form.Item>
                    <Form.Item style={{ marginBottom: 0 }}>
                      <Space>
                        <Button type="primary" htmlType="submit" loading={saveOutboundProxyMutation.isPending}>保存出网代理</Button>
                        {outboundProxyConfigured && <Tag color="success">当前已配置</Tag>}
                      </Space>
                    </Form.Item>
                  </Form>
                </div>
              ),
            },
            {
              key: 'forward-proxy',
              label: '正向代理配置',
              icon: <GlobalOutlined />,
              children: (
                <div style={{ padding: '0 20px 20px' }}>
                  {whitelistQ.isError && (
                    <Alert
                      data-testid="forward-proxy-whitelist-unavailable"
                      type="warning"
                      showIcon
                      style={{ marginBottom: 16 }}
                      message="出站白名单状态暂不可用"
                      description="当前无法确认租户出站限制，请重试。"
                    />
                  )}
                  <div style={{ marginBottom: 16 }}>
                    <Title level={5} style={{ margin: 0, color: 'var(--text-primary)' }}>正向代理接入配置</Title>
                    <Text style={{ color: 'var(--text-secondary)' }}>
                      客户把电脑、浏览器、IDE、Agent 客户端或命令行工具的 HTTP/HTTPS 代理指向这里后，相关上网流量会先经过 AI算力安全网关，再由网关访问公网。
                    </Text>
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: 16 }}>
                    <div style={{ border: '1px solid var(--border-color)', borderRadius: 8, padding: 18 }}>
                      <Text style={{ display: 'block', color: 'var(--text-secondary)', marginBottom: 8 }}>代理服务器</Text>
                      <Title level={5} style={{ margin: 0, color: 'var(--text-primary)' }}>{proxyHost}</Title>
                      <div style={{ marginTop: 12, display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
                        <div style={{ padding: 10, borderRadius: 6, background: 'var(--bg-secondary)' }}>
                          <Text style={{ display: 'block', color: 'var(--text-secondary)', fontSize: 12 }}>HTTP 端口</Text>
                          <Text strong copyable>{proxyPort}</Text>
                        </div>
                        <div style={{ padding: 10, borderRadius: 6, background: 'var(--bg-secondary)' }}>
                          <Text style={{ display: 'block', color: 'var(--text-secondary)', fontSize: 12 }}>HTTPS 端口</Text>
                          <Text strong copyable>{proxyPort}</Text>
                        </div>
                      </div>
                    </div>
                    <div style={{ border: '1px solid var(--border-color)', borderRadius: 8, padding: 18 }}>
                      <Text style={{ display: 'block', color: 'var(--text-secondary)', marginBottom: 8 }}>适用流量</Text>
                      <Title level={5} style={{ margin: 0, color: 'var(--text-primary)' }}>已配置代理的 HTTP/HTTPS 访问会经过网关</Title>
                      <Text style={{ display: 'block', marginTop: 10, color: 'var(--text-secondary)' }}>没有使用系统代理的应用，需要在应用内单独填写代理地址。</Text>
                    </div>
                    <div style={{ border: '1px solid var(--border-color)', borderRadius: 8, padding: 18 }}>
                      <Text style={{ display: 'block', color: 'var(--text-secondary)', marginBottom: 8 }}>证书用途</Text>
                      <Title level={5} style={{ margin: 0, color: 'var(--text-primary)' }}>安装 CA 证书后可进行 HTTPS 审计</Title>
                      <Text style={{ display: 'block', marginTop: 10, color: 'var(--text-secondary)' }}>未信任 CA 证书时，浏览器或客户端可能提示证书不受信任。</Text>
                    </div>
                  </div>
                  <div style={{ marginTop: 16, padding: 16, border: '1px solid var(--border-color)', borderRadius: 8, background: 'var(--bg-secondary)' }}>
                    <Text style={{ color: 'var(--text-secondary)' }}>
                      客户侧可通过系统代理、PAC、MDM、GPO 或浏览器/开发工具内置代理配置下发该地址。非 HTTP/HTTPS 流量不会因为系统代理自动进入此网关。
                    </Text>
                  </div>
                  <ProxyWhitelistTable
                    canManage={canManage}
                    rows={(whitelistQ.data?.data ?? []) as ProxyWhitelist[]}
                    loading={whitelistQ.isLoading}
                    onChanged={() => queryClient.invalidateQueries({ queryKey: ['proxy-whitelist-coverage'] })}
                  />
                  <ForwardProxyEgressForm canManage={canManageEgress} />
                </div>
              ),
            },
            {
              key: 'ca',
              label: 'CA 管理',
              icon: <SafetyCertificateOutlined />,
              children: <CACertificateManager />,
            },
          ]}
        />
      </div>
    </div>
  )
}

export default ProxySettings
