import { useState, useEffect } from 'react'
import { Button, Transfer, message, Divider, Statistic, Row, Col, Spin, Descriptions, Radio } from 'antd'
import { ControlOutlined } from '@ant-design/icons'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { orgApi, modelApi, policyApi } from '../../services/api'
import { formatCountQuota, formatMoneyQuota } from '../ai-permissions/quotaDisplay'

interface BudgetModelsTabProps {
  teamId: string
}

// 部门未配置时动态开放全部可调用模型，明确名单和全禁独立保存。也被“钱包与限流 → 限流与模型范围”复用。
export function TeamModelWhitelist({ teamId, readOnly = false }: { teamId: string; readOnly?: boolean }) {
  const qc = useQueryClient()
  const [targetModelKeys, setTargetModelKeys] = useState<string[]>([])
  const [modelMode,setModelMode]=useState<'all_active'|'allowlist'|'deny_all'>('allowlist')
  const effectiveQ = useQuery({ queryKey: ['team-effective', teamId], queryFn: () => orgApi.getEffective(teamId), enabled: !!teamId })
  const modelsQ = useQuery({ queryKey: ['models', 'available'], queryFn: () => modelApi.list({ available_only: true }) })
  const rawModels = modelsQ.data?.data
  const allModels = Array.isArray(rawModels?.data) ? rawModels.data : Array.isArray(rawModels) ? rawModels : []
  useEffect(() => {
    const eff = effectiveQ.data?.data
    const teamModels = Array.isArray(eff?.models) ? eff.models : []
    const mode=eff?.model_access_mode==='all_active'?'all_active':eff?.model_access_mode==='deny_all'?'deny_all':'allowlist'
    setModelMode(mode)
    const raw=modelsQ.data?.data
    const catalog=Array.isArray(raw?.data)?raw.data:Array.isArray(raw)?raw:[]
    setTargetModelKeys(mode==='all_active'?catalog.map((m:{id:string})=>m.id):mode==='deny_all'?[]:teamModels.filter((m: any) => m.allowed).map((m: any) => m.model_id))
  }, [effectiveQ.data,modelsQ.data])
  const modelsMutation = useMutation({
    mutationFn: ({keys,mode}:{keys:string[];mode:'all_active'|'allowlist'|'deny_all'}) => orgApi.updateModels(teamId, {mode,models: mode==='allowlist'?keys.map(k => ({ model_id: k, allowed: true })):[]}),
    onSuccess: (res: any) => {
      const warning = res?.data?.warning
      if (warning) {
        message.warning(warning)
      } else {
        const n = Array.isArray(res?.data?.propagated_project_ids) ? res.data.propagated_project_ids.length : 0
        message.success(n > 1 ? `模型白名单已更新（该部门 ${n} 个应用共享同一名单）` : '模型白名单已更新')
      }
      qc.invalidateQueries({ queryKey: ['team-effective', teamId] })
    },
    onError: () => message.error('更新失败'),
  })
  const transferDataSource = allModels.map((m: any) => ({ key: m.id, title: m.model_label || m.model_name || m.id }))
  return <Spin spinning={effectiveQ.isLoading||modelsQ.isLoading}>
    <Radio.Group value={modelMode} disabled={readOnly} style={{marginBottom:16}} onChange={event=>{
      const mode=event.target.value as 'all_active'|'allowlist'|'deny_all'
      setModelMode(mode)
      if(mode==='all_active')setTargetModelKeys(allModels.map((m:{id:string})=>m.id))
      if(mode==='deny_all')setTargetModelKeys([])
    }}>
      <Radio value="all_active">默认开放全部模型</Radio><Radio value="allowlist">指定模型名单</Radio><Radio value="deny_all">禁止全部模型</Radio>
    </Radio.Group>
    <Transfer
      dataSource={transferDataSource}
      targetKeys={targetModelKeys}
      onChange={(keys) => {setModelMode('allowlist');setTargetModelKeys(keys as string[])}}
      render={item => String(item.title || item.key)}
      showSearch
      disabled={readOnly}
      titles={['全部模型', '已授权模型']}
      style={{ marginBottom: 16 }}
      listStyle={{ width: '45%', height: 300 }}
      locale={{ itemUnit: '个', itemsUnit: '个', notFoundContent: '无数据', searchPlaceholder: '搜索模型' }}
    />
    {readOnly ? null : <Button type="primary" onClick={() => modelsMutation.mutate({keys:targetModelKeys,mode:modelMode})} loading={modelsMutation.isPending}>保存模型白名单</Button>}
  </Spin>
}

export function BudgetModelsTab({ teamId }: BudgetModelsTabProps) {
  const effectiveQ = useQuery({ queryKey: ['team-effective', teamId], queryFn: () => orgApi.getEffective(teamId), enabled: !!teamId })
  const quotaQ = useQuery({ queryKey: ['quota-policy', 'team', teamId], queryFn: () => policyApi.getQuota({ scope_type: 'team', scope_id: teamId }), enabled: !!teamId })
  const quota: any = quotaQ.data?.data?.data ?? quotaQ.data?.data ?? {}
  const modelsQ=useQuery({queryKey:['models','available'],queryFn:()=>modelApi.list({ available_only: true })})
  const catalog=modelsQ.data?.data
  const allModels=Array.isArray(catalog?.data)?catalog.data:Array.isArray(catalog)?catalog:[]
  const eff = effectiveQ.data?.data
  const memberCount = Array.isArray(eff?.members) ? eff.members.length : 0
  const projectCount = Array.isArray(eff?.projects) ? eff.projects.length : 0
  const allowedCount = eff?.model_access_mode==='all_active'?allModels.length:Array.isArray(eff?.models) ? eff.models.filter((m: any) => m.allowed).length : 0

  return (
    <Spin spinning={effectiveQ.isLoading||modelsQ.isLoading}>
      <Row gutter={24} style={{ marginBottom: 24 }}>
        <Col span={8}><Statistic title="成员数" value={memberCount} /></Col>
        <Col span={8}><Statistic title="应用数" value={projectCount} /></Col>
        <Col span={8}><Statistic title="授权模型数" value={allowedCount} /></Col>
      </Row>

      <Divider orientation="left">预算与限流（只读）</Divider>
      <Descriptions column={2} size="small" bordered style={{ marginBottom: 12 }}>
        <Descriptions.Item label="月费用预算">{quotaQ.isError ? '读取失败' : formatMoneyQuota(quota, 'monthly')}</Descriptions.Item>
        <Descriptions.Item label="每分钟请求数">{quotaQ.isError ? '读取失败' : formatCountQuota(quota.rpm_limit, quota.rpm_blocked)}</Descriptions.Item>
        <Descriptions.Item label="每分钟 Token">{quotaQ.isError ? '读取失败' : formatCountQuota(quota.tpm_limit, quota.tpm_blocked)}</Descriptions.Item>
        <Descriptions.Item label="并发请求数">{quotaQ.isError ? '读取失败' : formatCountQuota(quota.concurrency_limit, quota.concurrency_blocked)}</Descriptions.Item>
      </Descriptions>
      <Button
        icon={<ControlOutlined />}
        href={'/cost/budgets?scope_type=team&scope_id=' + encodeURIComponent(teamId)}
        style={{ marginBottom: 24 }}
      >
        去配置
      </Button>

      <Divider orientation="left">部门模型权限</Divider>
      <TeamModelWhitelist teamId={teamId} />
    </Spin>
  )
}
