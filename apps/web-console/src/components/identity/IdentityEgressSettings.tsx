import { Alert, Button, Card, Form, Select, Typography } from 'antd'
import { systemSettingsApi } from '../../services/api'
import ConfirmSwitch from '../protection/ConfirmSwitch'
import { useSettingsForm } from '../../hooks/useSettingsForm'
import { serializeList, settingBool, settingList, settingSourceNotice } from '../../utils/settingsValue'

type Values = {
  idp_allow_private: boolean
  idp_allowed_cidrs: string[]
  ldap_allowed_targets: string[]
}

// 目录服务允许的地址：每项“主机名[:端口]”，与后端 directoryldap.parseAllowedTarget 一致：
// 不接受 IP（IP 写在网段名单里），也不接受 localhost 和云元数据主机名。
const BLOCKED_DIRECTORY_HOSTS = new Set(['localhost', 'metadata.google.internal', 'metadata.goog', 'instance-data', 'metadata.azure.internal', 'metadata.oraclecloud.com'])
function validHostPort(value: string): boolean {
  const matched = /^([A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?)*)\.?(?::(\d{1,5}))?$/.exec(value)
  if (!matched) return false
  const host = matched[1].toLowerCase()
  if (/^\d+(?:\.\d+)*$/.test(host)) return false
  if (BLOCKED_DIRECTORY_HOSTS.has(host) || host.endsWith('.localhost')) return false
  return matched[2] === undefined || (Number(matched[2]) >= 1 && Number(matched[2]) <= 65535)
}

// idp_block_private 只有为 true 才拦内网，缺省视为允许（与 2.9.21 的 JJD_IDP_BLOCK_PRIVATE 一致，默认不变）。
function toValues(settings: Record<string, unknown>): Values {
  return {
    idp_allow_private: !settingBool(settings.idp_block_private, false),
    idp_allowed_cidrs: settingList(settings.idp_allowed_cidrs),
    ldap_allowed_targets: settingList(settings.ldap_allowed_targets),
  }
}

function toPatch(values: Values): Record<string, unknown> {
  return {
    idp_block_private: !values.idp_allow_private,
    idp_allowed_cidrs: serializeList(values.idp_allowed_cidrs),
    ldap_allowed_targets: serializeList(values.ldap_allowed_targets),
  }
}

// 身份源出站键写在 /system/settings（仅平台管理员可写）。
const saveIdentityEgress = (patch: Record<string, unknown>) => systemSettingsApi.update(patch)

export default function IdentityEgressSettings({ canManage }: { canManage: boolean }) {
  const { form, query: settingsQ, mutation: saveM, submit } = useSettingsForm({ toValues, toPatch, save: saveIdentityEgress })
  const disabled = !canManage || !settingsQ.isSuccess || saveM.isPending
  const notice = (key: string) => {
    const text = settingSourceNotice(settingsQ.data, key)
    return text ? <Typography.Text type="warning">{text}</Typography.Text> : undefined
  }

  return (
    <Card title="出站地址" style={{ marginTop: 16, maxWidth: 776 }}>
      {settingsQ.isError ? <Alert type="error" showIcon message="出站地址读取失败" style={{ marginBottom: 12 }} /> : null}
      <Form form={form} layout="vertical" disabled={disabled} initialValues={toValues({})} onFinish={submit}>
        <Form.Item name="idp_allow_private" label="SSO 允许内网地址" valuePropName="checked" extra={notice('idp_block_private')}>
          <ConfirmSwitch ariaLabel="SSO 允许内网地址" confirmTitle="SSO 允许内网地址？" confirmContent="控制面可被用来访问这些地址。" />
        </Form.Item>
        <Form.Item name="idp_allowed_cidrs" label="SSO 放行网段" extra={notice('idp_allowed_cidrs')}>
          <Select aria-label="SSO 放行网段" mode="tags" open={false} tokenSeparators={[',', ' ']} placeholder="10.20.0.0/16" />
        </Form.Item>
        <Form.Item name="ldap_allowed_targets" label="目录服务允许的地址" extra={notice('ldap_allowed_targets')} rules={[{ validator: async (_, value: unknown) => {
          const bad = (Array.isArray(value) ? value : []).map((item) => String(item).trim()).find((item) => !validHostPort(item))
          if (bad !== undefined) throw new Error(`地址格式应为 主机名[:端口]：${bad}`)
        } }]}>
          <Select aria-label="目录服务允许的地址" mode="tags" open={false} tokenSeparators={[',', ' ']} placeholder="ldap.corp.example:636" />
        </Form.Item>
        <Button type="primary" htmlType="submit" disabled={disabled} loading={saveM.isPending}>保存出站地址</Button>
      </Form>
    </Card>
  )
}
