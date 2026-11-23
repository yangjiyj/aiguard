import { useEffect, useState } from 'react'
import { Alert, Button, Card, Descriptions, Drawer, Empty, Input, Modal, Select, Space, Table, Tag, Typography, message } from 'antd'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link, useSearchParams } from 'react-router-dom'
import { useAuthStore } from '../../stores/auth'
import { agentEndpointApi, agentKeys } from '../../services/agentEndpoint'
import type { AgentAsset, AgentEndpoint, AgentEndpointFilters } from '../../services/agentEndpoint.types'
import { assetTypes, canWriteAgent, captureLevels, endpointState, endpointStatuses, label, modeColors, modes, products, time } from './dict'
import { ControlBoundaryPanel } from './ControlBoundary'
import { readControlBoundary } from './controlBoundaryReport'

const server = (import.meta.env.VITE_AGENT_GATEWAY_URL || (import.meta.env.DEV ? "http://" + window.location.hostname + ":28080" : "<网关地址>"))
const setupCommand = `hookd enroll --server ${server} --token <注册令牌>`
const columnsWidth = { whiteSpace: 'nowrap' as const }
function assetErrorMessage(error: unknown) {
  const status = (error as { response?: { status?: number } })?.response?.status
  if (status === 403) return '无权查看此端点资产（403）'
  if (status === 402) return '当前服务额度不足，无法查看端点资产（402）'
  return '端点资产加载失败，请检查服务状态后重试'
}
export default function AgentEndpoints() {
  const [filters, setFilters] = useState<AgentEndpointFilters>({page:1,page_size:20})
  const [kitAvailable, setKitAvailable] = useState(false)
  useEffect(() => {
    let active = true
    fetch('/agent-kit/', { method: 'HEAD' }).then(response => {
      if (active) setKitAvailable(response.ok && response.headers.get('content-type')?.includes('text/html') === true)
    }).catch(() => { if (active) setKitAvailable(false) })
    return () => { active = false }
  }, [])
  const [searchParams] = useSearchParams()
  const [selected, setSelected] = useState<string | undefined>(()=>searchParams.get('endpoint')??undefined)
  const [assetPage, setAssetPage] = useState(1)
  const [secret, setSecret] = useState<string>()
  const writable = canWriteAgent(useAuthStore(s => s.user?.role))
  const qc = useQueryClient()
  const list = useQuery({queryKey:agentKeys.endpoints(filters),queryFn:() => agentEndpointApi.endpoints(filters)})
  const detail = useQuery({queryKey:agentKeys.endpoint(selected ?? ''),queryFn:() => agentEndpointApi.endpoint(selected!),enabled:!!selected})
  const assets = useQuery({queryKey:agentKeys.assets(selected ?? '',assetPage),queryFn:() => agentEndpointApi.assets(selected!,assetPage,100),enabled:!!selected})
  const sessions = useQuery({queryKey:agentKeys.sessions({endpoint_id:selected,page:1,page_size:5}),queryFn:() => agentEndpointApi.sessions({endpoint_id:selected,page:1,page_size:5}),enabled:!!selected})
  const mutate = useMutation({mutationFn:(operation:() => Promise<unknown>)=>operation(),onSuccess:()=>{void qc.invalidateQueries({queryKey:['agent']});message.success('操作成功')},onError:()=>message.error('操作失败，请重试')})
  const setFilter = (key:keyof AgentEndpointFilters,value:string|boolean|undefined) => setFilters(prev => ({...prev,[key]:value || undefined,page:1}))
  const updateMode = (id:string, mode:string|null) => mutate.mutate(() => agentEndpointApi.updateMode(id,{mode}))
  const updateCapture = (id:string, capture_level:string|null) => {
    const perform = () => mutate.mutate(() => agentEndpointApi.updateMode(id,{capture_level}))
    if (capture_level === 'full') Modal.confirm({title:'启用完整内容采集？',content:'完整内容采集具有较高侵入性，可能采集用户输入和输出。请确认已取得授权。',onOk:perform})
    else perform()
  }
  const rotate = (id:string) => Modal.confirm({title:'轮换端点令牌？',content:'旧令牌会立即失效，请妥善保存新令牌。',onOk:async()=>{try {const response=await agentEndpointApi.rotateToken(id);setSecret(response.endpoint_token);void qc.invalidateQueries({queryKey:['agent']})} catch {message.error('轮换失败，请重试')}}})
  const revoke = (id:string) => Modal.confirm({title:'确定吊销此端点？',content:'吊销后该端点将无法继续接入。',onOk:()=>mutate.mutateAsync(()=>agentEndpointApi.revokeEndpoint(id))})
  const rows = list.data?.items ?? []
  return <div style={{display:'grid',gap:16}}>
    <Typography.Title level={3}>智能体端点</Typography.Title>
    <Alert type="info" showIcon message="端侧组件下载" description={kitAvailable ? <a href="/agent-kit/" target="_blank" rel="noopener noreferrer">查看已部署的安装包及校验信息</a> : '当前未发布端侧安装包；部署包与校验信息发布后可在 /agent-kit/ 查看。'} />
    <Space wrap>
      <Select allowClear placeholder="产品" style={{width:155}} options={products} onChange={value=>setFilter('product',value)} />
      <Select allowClear placeholder="状态" style={{width:130}} options={endpointStatuses} onChange={value=>{setFilters(prev=>({...prev,status:value==='stale'?'active':value==='offline'?undefined:value,stale:value==='stale'?true:undefined,page:1}))}} />
      <Select allowClear placeholder="模式" style={{width:130}} options={modes} onChange={value=>setFilter('mode',value)} />
      <Select allowClear placeholder="操作系统" style={{width:135}} options={['linux','windows','darwin'].map(value=>({value,label:value==='darwin'?'苹果系统':value==='windows'?'微软系统':'Linux'}))} onChange={value=>setFilter('os',value)} />
      <Input.Search placeholder="主机名、用户或端点编号" style={{width:255}} allowClear onSearch={value=>setFilter('q',value)} />
    </Space>
    <Card>
      {list.isError && <Alert type="error" showIcon message="端点加载失败，请检查权限和服务状态" style={{marginBottom:12}} />}
      {!list.isLoading && !list.isError && !list.data?.total ? <Empty description="暂无智能体端点"><Card title="如何接入" size="small" style={{textAlign:'left',maxWidth:540}}><ol><li><Link to="/agent/enrollment">创建注册令牌</Link></li><li>安装智能体插件并执行接入命令</li><li>确认端点心跳在线</li></ol><Typography.Paragraph copyable={{text:setupCommand}} code>{setupCommand}</Typography.Paragraph></Card></Empty> :
      <Table size="small" rowKey="id" loading={list.isLoading} scroll={{x:1900}} dataSource={rows} pagination={{current:filters.page,pageSize:20,total:list.data?.total ?? 0,showTotal:total=>`共 ${total} 个端点`,onChange:page=>setFilters(prev=>({...prev,page}))}} columns={[
        {title:'产品',render:(_:unknown,x:AgentEndpoint)=><Space><Tag color="blue">{label(products,x.product).slice(0,1)}</Tag>{label(products,x.product)}</Space>},
        {title:'版本',dataIndex:'agent_version'}, {title:'主机名',dataIndex:'hostname'}, {title:'系统用户',dataIndex:'os_user'},
        {title:'操作系统',dataIndex:'os'}, {title:'状态',render:(_:unknown,x:AgentEndpoint)=><Tag color={endpointState(x.status,x.last_heartbeat_at)==='active'?'green':'default'}>{label(endpointStatuses,endpointState(x.status,x.last_heartbeat_at))}</Tag>},
        {title:'最后心跳',render:(_:unknown,x:AgentEndpoint)=>time(x.last_heartbeat_at)},
        {title:'模式',render:(_:unknown,x:AgentEndpoint)=><Tag color={modeColors[x.mode??'monitor']}>{x.mode?label(modes,x.mode):'继承 · 监控'}</Tag>},
        {title:'采集级别',render:(_:unknown,x:AgentEndpoint)=>label(captureLevels,x.capture_level)},
        {title:'策略版本',dataIndex:'last_policy_version'},
        {title:'控制边界',render:(_:unknown,x:AgentEndpoint)=>{const cb=readControlBoundary(x.control_boundary);return cb?<Tag color={cb.config_error?'red':'blue'}>{cb.config_error?'配置不可用':'已上报'}</Tag>:<Tag>未上报</Tag>}},
        {title:'积压 / 丢弃',render:(_:unknown,x:AgentEndpoint)=>`${x.health?.queue_events ?? "—"} / ${x.health?.dropped_events ?? "—"}`},
        {title:'最近事件',render:(_:unknown,x:AgentEndpoint)=>time(x.last_event_at)},
        {title:'操作',fixed:'right' as const,render:(_:unknown,x:AgentEndpoint)=><Space style={columnsWidth}><Button type="link" size="small" onClick={()=>{setSelected(x.id);setAssetPage(1)}}>详情</Button>{writable && <><Select size="small" style={{width:112}} placeholder="修改模式" value={undefined} options={[{label:'继承',value:'inherit'},...modes]} onChange={v=>updateMode(x.id,v==='inherit'?null:(v??null))} /><Select size="small" style={{width:112}} placeholder="采集级别" value={undefined} options={captureLevels} onChange={v=>updateCapture(x.id,v??null)} /><Button size="small" onClick={()=>rotate(x.id)}>轮换令牌</Button><Button size="small" danger onClick={()=>revoke(x.id)}>吊销</Button></>}</Space>},
      ]} />}
    </Card>
    <Drawer title="端点详情" width={700} open={!!selected} onClose={()=>setSelected(undefined)} loading={detail.isLoading}>
      {detail.data && <><Descriptions bordered size="small" column={2} items={[
        {key:'id',label:'端点编号',children:detail.data.id,span:2},{key:'product',label:'产品',children:label(products,detail.data.product)},{key:'host',label:'主机',children:detail.data.hostname},
        {key:'user',label:'系统用户',children:detail.data.os_user},{key:'os',label:'操作系统',children:`${detail.data.os} ${detail.data.os_version}`},
        {key:'mode',label:'模式',children:detail.data.mode?label(modes,detail.data.mode):'继承 · 监控'},{key:'capture',label:'采集',children:label(captureLevels,detail.data.capture_level)},
        {key:'heartbeat',label:'最后心跳',children:time(detail.data.last_heartbeat_at)},{key:'policy',label:'策略版本',children:detail.data.last_policy_version},
      ]}/><Typography.Title level={5}>采集健康</Typography.Title><Descriptions size="small" items={Object.entries(detail.data.health??{}).filter(([key])=>key!=='control_boundary').map(([key,value])=>({key,label:({queue_events:'积压事件',queue_bytes:'队列字节',dropped_events:'丢弃事件',last_upload_error:'最近上传错误'} as Record<string,string>)[key]??key,children:String(value)}))}/>
      <Typography.Title level={5}>控制边界</Typography.Title><ControlBoundaryPanel value={detail.data.control_boundary} />
      <Typography.Title level={5}>端侧能力</Typography.Title><Space wrap>{detail.data.capabilities?.map(cap=><Tag key={cap}>{cap}</Tag>)}</Space>
      <Typography.Title level={5}>运行时资产</Typography.Title>{assets.isLoading ? <Typography.Text type="secondary">资产加载中…</Typography.Text> : assets.isError ? <Alert type="error" showIcon message={assetErrorMessage(assets.error)} /> : !assets.data?.total ? <Empty description="暂无运行时资产" /> : <Table size="small" rowKey="id" dataSource={assets.data.items} pagination={{current:assetPage,pageSize:assets.data.page_size,total:assets.data.total,showTotal:total=>`共 ${total} 个资产`,onChange:page=>setAssetPage(page)}} columns={[{title:'类型',render:(_:unknown,x:AgentAsset)=>label(assetTypes,x.asset_type)},{title:'名称',dataIndex:'name'},{title:'版本',render:(_:unknown,x:AgentAsset)=>x.version||'未记录'},{title:'来源',render:(_:unknown,x:AgentAsset)=>x.source||'未记录'},{title:'状态',render:(_:unknown,x:AgentAsset)=><Tag color={x.present?'green':'default'}>{x.present?'存在':'已移除'}</Tag>},{title:'扫描状态',render:(_:unknown,x:AgentAsset)=>x.scan_status||'未记录'},{title:'扫描判定',render:(_:unknown,x:AgentAsset)=>x.scan_decision||'未记录'},{title:'首次发现',render:(_:unknown,x:AgentAsset)=>time(x.first_seen)},{title:'最近发现',render:(_:unknown,x:AgentAsset)=>time(x.last_seen)}]} />}
      <Typography.Title level={5}>最近会话</Typography.Title>{sessions.data?.items.map(session=><div key={session.id}><Link to={`/agent/sessions/${encodeURIComponent(session.session_id)}`}>{session.session_id}</Link> · {time(session.last_request_at)}</div>)}
      <Typography.Title level={5}>最近告警</Typography.Title><Typography.Text type="secondary">请从关联会话查看告警</Typography.Text></>}
    </Drawer>
    <Modal open={!!secret} title="新端点令牌（仅本次显示）" onCancel={()=>setSecret(undefined)} onOk={()=>setSecret(undefined)} destroyOnHidden><Typography.Paragraph copyable={{text:secret}} code>{secret}</Typography.Paragraph></Modal>
  </div>
}
