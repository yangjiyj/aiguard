import { useEffect, useMemo, useState } from 'react'
import { Alert, Button, Card, Empty, DatePicker, Input, Modal, Popconfirm, Radio, Select, Space, Spin, Tag, Typography, message } from 'antd'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import type { Dayjs } from 'dayjs'
import { modelApi } from '../../services/api'
import { userModelAccessApi, type UserModelPolicyInput } from '../../services/userModelAccess'

const { Text } = Typography

function saveError(error: unknown): string {
 const code = (error as {response?:{data?:{error?:{code?:string}}}})?.response?.data?.error?.code
 const messages: Record<string,string> = {
  model_access_conflict: '授权配置已变化，请刷新后重试',
  model_outside_department: '个人授权不能超出当前部门允许的模型',
  chat_unavailable: '该账号不可使用 Chat 模型',
  model_unavailable: '账号或模型线路当前不可用',
  invalid_request: '授权原因必填，到期时间必须晚于当前时间',
  forbidden: '没有管理用户模型权限的权限',
 }
 return code && messages[code] ? messages[code] : '模型权限保存失败，请稍后重试'
}

export function UserModelAccessCard({userId,canEdit=false}:{userId:string;canEdit?:boolean}) {
 const qc=useQueryClient()
 const accessQ=useQuery({queryKey:['user-model-access',userId],queryFn:()=>userModelAccessApi.get(userId),enabled:!!userId})
 const modelsQ=useQuery({queryKey:['models','available'],queryFn:()=>modelApi.list({ available_only: true })})
 const access=accessQ.data?.data.data
 const [adding,setAdding]=useState(false)
 const [extraModel,setExtraModel]=useState<string>()
 const [reason,setReason]=useState('')
 const [expires,setExpires]=useState<Dayjs|null>(null)
 const refresh=()=>{void qc.invalidateQueries({queryKey:['user-model-access',userId]});void qc.invalidateQueries({queryKey:['user-detail',userId]})}
 const addExtra=useMutation({mutationFn:()=>userModelAccessApi.addExtra(userId,{model:extraModel||'',reason:reason.trim(),expires_at:expires?.toISOString()||null}),
  onSuccess:()=>{refresh();setAdding(false);setExtraModel(undefined);setReason('');setExpires(null);message.success('个人额外授权已新增')},onError:error=>message.error(saveError(error))})
 const revokeExtra=useMutation({mutationFn:(id:string)=>userModelAccessApi.revokeExtra(userId,id),onSuccess:()=>{refresh();message.success('个人额外授权已撤销')},onError:error=>message.error(saveError(error))})
 const [mode,setMode]=useState<UserModelPolicyInput['mode']>('inherit')
 const [selected,setSelected]=useState<string[]>([])
 useEffect(()=>{setMode(access?.mode??'inherit');setSelected(access?.model_names??[])},[access,userId])
 const labels=useMemo(()=>{
  const raw=modelsQ.data?.data
  const models=Array.isArray(raw?.data)?raw.data:Array.isArray(raw)?raw:[]
  const result=new Map<string,string>()
  for(const m of models) {
   if(typeof m.model_name==='string' && m.model_name) {
    result.set(m.model_name, m.model_label || m.model_name)
   }
  }
  return result
 },[modelsQ.data])
 const mutation=useMutation({
  mutationFn:({id,policy}:{id:string;policy:UserModelPolicyInput})=>userModelAccessApi.set(id,policy),
  onSuccess:(response,variables)=>{
   qc.setQueryData(['user-model-access',variables.id],response)
   void qc.invalidateQueries({queryKey:['user-model-access',variables.id]})
   void qc.invalidateQueries({queryKey:['user-detail',variables.id]})
   message.success('模型权限已保存')
  },
  onError:(error)=>message.error(saveError(error)),
 })
 if(accessQ.isLoading) return <Card size="small" title="模型使用权限"><Spin /></Card>
 if(accessQ.isError||!access) return <Card size="small" title="模型使用权限"><Alert type="error" showIcon message="模型权限读取失败" description="请重试以核实该用户当前可用的模型。" action={<Button onClick={()=>void accessQ.refetch()}>重试</Button>} /></Card>
 return <Card size="small" title="模型使用权限">
  <Space direction="vertical" size={16} style={{width:'100%'}}>
   <Text type="secondary">个人名单可收窄部门权限，个人额外授权可增加部门外模型。所属部门：{access.department_name||'未分配'}</Text>
   {!access.chat_allowed ? <Alert type="info" showIcon message="该账号不可使用 Chat 模型" description="应急管理或已停用的账号没有业务模型使用权限。"/> : null}
   <Radio.Group aria-label="模型授权方式" value={mode} disabled={!canEdit||!access.chat_allowed||mutation.isPending} onChange={event=>setMode(event.target.value)}>
    <Radio value="inherit">继承部门权限</Radio><Radio value="allowlist">单独指定模型</Radio>
   </Radio.Group>
   {mode==='allowlist' ? <>
    <Select aria-label="个人可用模型" mode="multiple" allowClear showSearch optionFilterProp="label" placeholder="选择该用户可用的模型" style={{width:'100%'}} value={selected} disabled={!canEdit||!access.chat_allowed||mutation.isPending}
     options={access.department_models.map(name=>({value:name,label:labels.get(name)||name}))} onChange={setSelected}/>
    {selected.length===0 ? <Alert type="warning" showIcon message="空名单表示基础模型权限全部禁用" description="保存后，部门模型全部禁用，已有个人额外授权仍按有效期生效；需要恢复部门默认时请选择“继承部门权限”。"/> : null}
   </> : <Text type="secondary">该用户随部门模型权限变化自动更新，无需逐个授权。</Text>}
   <div>
    <Text strong>已授权模型</Text>
    <div style={{marginTop:8}}>{access.effective_models.length===0 ? <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="当前未授权任何模型"/> :
     <Space direction="vertical">{(['department','personal_extra','personal_narrowed'] as const).map(source=>{
      const names=access.effective_models.filter(name=>(access.model_sources?.[name]||(access.mode==='allowlist'?'personal_narrowed':'department'))===source)
      if(names.length===0)return null
      return <div key={source}><Text strong>{source==='department'?'部门授权':source==='personal_extra'?'个人额外授权':'个人已收窄'}</Text><Space wrap style={{marginLeft:8}}>{names.map(name=><Tag color="blue" key={name}>{labels.get(name)||name}</Tag>)}</Space></div>
     })}</Space>}</div>
   </div>
   {(access.stale_models??access.model_names.filter(name=>!access.department_models.includes(name))).map(name=><Alert key={name} type="warning" showIcon message={`${labels.get(name)||name}：已不在当前部门范围，不产生授权`} />)}
   {(access.extra_grants??[]).length>0 ? <div><Text strong>额外授权记录</Text><Space direction="vertical" style={{width:'100%',marginTop:8}}>{access.extra_grants?.map(grant=>{
    const expired=!!grant.expires_at&&Date.parse(grant.expires_at)<=Date.now()
    return <div key={grant.id}><Tag>{labels.get(grant.model)||grant.model}</Tag><Text>{grant.reason}</Text><Text type="secondary" style={{marginLeft:8}}>{grant.revoked_at?'已撤销':expired?'已到期':grant.expires_at?`到期：${new Date(grant.expires_at).toLocaleString('zh-CN')}`:'长期有效'}</Text>
     {canEdit&&!grant.revoked_at&&!expired ? <Popconfirm title="确认撤销此项额外授权？" description="已有 Key 的下一次请求立即按新权限检查。" okText="撤销" cancelText="取消" onConfirm={()=>revokeExtra.mutateAsync(grant.id)}><Button danger size="small" loading={revokeExtra.isPending} style={{marginLeft:8}}>撤销额外授权</Button></Popconfirm>:null}</div>
   })}</Space></div>:null}
   {canEdit&&access.chat_allowed?<Button onClick={()=>setAdding(true)}>新增个人额外授权</Button>:null}
   <Modal title="新增个人额外授权" open={adding} onCancel={()=>setAdding(false)} okText="新增授权" cancelText="取消" confirmLoading={addExtra.isPending} okButtonProps={{disabled:!extraModel||!reason.trim()}} onOk={()=>addExtra.mutate()}>
    <Space direction="vertical" style={{width:'100%'}}>
     <Text>模型</Text><Select aria-label="额外授权模型" style={{width:'100%'}} value={extraModel} onChange={setExtraModel} showSearch optionFilterProp="label" options={[...labels].map(([name,label])=>({value:name,label}))}/>
     <Text>授权原因（必填）</Text><Input.TextArea aria-label="授权原因" value={reason} maxLength={2000} onChange={event=>setReason(event.target.value)} />
     <Text>到期时间（可选）</Text><DatePicker aria-label="授权到期时间" showTime value={expires} onChange={setExpires} style={{width:'100%'}}/>
     <Text type="secondary">服务端会核验模型启用状态、线路可调用、账号状态与租户；保存后才生效。</Text>
    </Space>
   </Modal>
   {canEdit&&access.chat_allowed ? <Button type="primary" loading={mutation.isPending} onClick={()=>mutation.mutate({id:userId,policy:{mode,model_names:mode==='inherit'?[]:selected,version:access.version}})}>保存模型权限</Button> : null}
  </Space>
 </Card>
}
