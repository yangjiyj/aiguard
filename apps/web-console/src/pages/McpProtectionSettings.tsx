import ProtectionGroupSection from '../components/protection/ProtectionGroupSection'

// MCP 组防护项：准入、漂移、投毒、同名、扫描超时、超长、确认失败、重放变化等。
export default function McpProtectionSettings({ canEdit }: { canEdit: boolean }) {
  return <ProtectionGroupSection group="mcp" title="调用防护" ariaLabel="MCP 调用防护" canManage={canEdit} style={{ marginBottom: 16 }} />
}
