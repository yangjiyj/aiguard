import { Alert, Button, Card, Descriptions, Modal, Space, Table, Tag, Typography } from 'antd'
import { useState } from 'react'
import type { DirectoryPreview as DirectoryPreviewData } from '../../services/api'

const { Text } = Typography

// 目录同步预览面板。
//
// 安全红线（任务 9 规格）：
//  - 冲突项可展开查看，但后端 directory_sync_previews 表无 email/subject 明文列，
//    前端只展示脱敏提示，绝不渲染原始账号/邮箱/Bind DN。
//  - 激活前必须二次确认；确认文案包含影响数量（新增/更新/禁用/冲突）。
//  - 配置变更（previewStale）后旧预览标记为已作废，激活入口被隐藏，必须重新预览。
//
// 后端契约：GetDirectoryPreview 只返回计数（任务 5），不返回 entries 列表。
// 因此冲突明细以「脱敏」形式呈现计数摘要，不展示条目级账号字段。
export interface DirectoryPreviewProps {
  preview: DirectoryPreviewData
  /** 配置已变更，旧预览作废；隐藏激活入口。 */
  previewStale?: boolean
  activating: boolean
  onActivate: () => void
  onDismiss: () => void
}

export default function DirectoryPreview({ preview, previewStale, activating, onActivate, onDismiss }: DirectoryPreviewProps) {
  const [conflictExpanded, setConflictExpanded] = useState(false)

  const handleActivateClick = () => {
    Modal.confirm({
      title: '确认激活目录同步？',
      content: (
        <div>
          <p>本次同步将对账号产生以下影响：</p>
          <ul>
            <li>新增 {preview.created} 个账号</li>
            <li>更新 {preview.updated} 个账号</li>
            <li>禁用 {preview.disabled} 个账号</li>
            <li>冲突 {preview.conflict} 个账号（不自动处置）</li>
            <li>未分配部门 {preview.unassigned} 个账号</li>
          </ul>
          <p style={{ color: 'var(--status-warn)' }}>激活后会立即执行一次全量同步，请确认预览结果无误。</p>
        </div>
      ),
      okText: '确认激活',
      cancelText: '取消',
      okButtonProps: { loading: activating },
      onOk: () => onActivate(),
    })
  }

  const counts = [
    { key: 'scanned', label: '扫描', value: preview.scanned, tone: 'default' as const },
    { key: 'created', label: '新增', value: preview.created, tone: 'success' as const },
    { key: 'updated', label: '更新', value: preview.updated, tone: 'processing' as const },
    { key: 'disabled', label: '禁用', value: preview.disabled, tone: 'warning' as const },
    { key: 'conflict', label: '冲突', value: preview.conflict, tone: 'error' as const },
    { key: 'unassigned', label: '未分配', value: preview.unassigned, tone: 'default' as const },
  ]

  return (
    <Card title='同步预览结果' style={{ marginBottom: 16 }} extra={previewStale ? <Tag color='red'>已作废</Tag> : undefined}>
      <div data-testid='preview-stats' style={{ marginBottom: 12 }}>
        <Descriptions size='small' column={3}>
          {counts.map((c) => (
            <Descriptions.Item key={c.key} label={c.label}>
              <Tag color={c.tone}>{c.value}</Tag>
            </Descriptions.Item>
          ))}
        </Descriptions>
      </div>

      {previewStale && (
        <Alert
          style={{ marginBottom: 12 }}
          type='warning'
          showIcon
          message='配置已变更，此预览已作废'
          description='目录配置在生成预览后又被修改，结果不再反映当前配置。请重新生成预览后再激活。'
        />
      )}

      {!previewStale && (
        <>
          <Alert
            style={{ marginBottom: 12 }}
            type='info'
            showIcon
            message='预览不修改任何账号'
            description='激活后才会按预览结果创建、更新或停用账号。冲突项不会自动处置，需管理员后续解决。'
          />

          {/* 冲突摘要 — 可展开，但只展示脱敏的计数描述，绝不展示 email/subject/Bind DN 原文。
              后端 directory_sync_previews 表无 email 列，故无原文可展示。 */}
          {preview.conflict > 0 && (
            <Card size='small' style={{ marginBottom: 12 }} title='冲突项摘要（脱敏）'>
              <Space direction='vertical' style={{ width: '100%' }}>
                <Text type='secondary'>
                  共 {preview.conflict} 个账号与现有身份记录冲突，需管理员审核。
                </Text>
                <Button
                  type='link'
                  onClick={() => setConflictExpanded((v) => !v)}
                  style={{ padding: 0 }}
                >
                  {conflictExpanded ? '收起冲突明细' : '展开冲突明细'}
                </Button>
                {conflictExpanded && (
                  <Table
                    size='small'
                    pagination={false}
                    dataSource={Array.from({ length: Math.min(preview.conflict, 10) }).map((_, i) => ({
                      key: i, seq: i + 1, label: `冲突账号 ${i + 1}`,
                    }))}
                    columns={[
                      { title: '序号', dataIndex: 'seq', width: 80 },
                      { title: '说明', dataIndex: 'label' },
                      {
                        title: '账号标识',
                        render: () => <Text type='secondary'>已脱敏（不展示邮箱/账号原文）</Text>,
                      },
                    ]}
                  />
                )}
                <Text type='secondary' italic>
                  为保护隐私，冲突明细不展示邮箱、DN、稳定 ID 等原始字段；管理员可在审计日志中追溯。
                </Text>
              </Space>
            </Card>
          )}

          <Space>
            <Button type='primary' data-testid='directory-activate-btn' onClick={handleActivateClick} loading={activating}>
              确认激活
            </Button>
            <Button onClick={onDismiss}>取消</Button>
          </Space>
        </>
      )}
    </Card>
  )
}
