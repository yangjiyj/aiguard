import {useState} from 'react'
import {Alert,Button,Card,Descriptions,Popconfirm,Select,Space,Typography,message} from 'antd'
import {useQuery,useMutation,useQueryClient} from '@tanstack/react-query'
import {userApi} from '../services/api'
import {userAccountMergeApi,type AccountMergePreview} from '../services/userAccountMerge'
const LABELS:Record<string,string>={department:'所属部门',personal_policy:'个人模型策略',extra_grants:'个人额外授权',api_keys:'源账号 API Key',employee_key:'员工 Key',wallet_balance:'源账号钱包余额'}
function fieldLabel(field:string){return field.startsWith('extra:')?'同模型额外授权：'+field.slice(6):LABELS[field]||'身份配置'}
function options(field:string){
 if(field==='api_keys')return [{value:'revoke_source',label:'吊销源账号的 Key'},{value:'move_source',label:'迁移源账号的 Key 到目标账号'}]
 if(field==='employee_key')return [{value:'target',label:'保留目标账号员工 Key，吊销源账号 Key'},{value:'source',label:'保留源账号员工 Key，吊销目标账号 Key'},{value:'revoke_both',label:'吊销双方员工 Key，合并后重新领取'}]
 if(field==='wallet_balance')return [{value:'retain_read_only',label:'保留源钱包，只追加历史归属，不自动转移余额'}]
 return [{value:'target',label:'保留目标账号配置'},{value:'source',label:'采用源账号配置'},...(field==='extra_grants'?[{value:'union',label:'合并双方额外授权；同模型冲突另行选择'}]:[])]
}
export function UserAccountMergeCard({userId}:{userId:string}){
 const qc=useQueryClient();const [source,setSource]=useState<string>();const [preview,setPreview]=useState<AccountMergePreview>();const [choices,setChoices]=useState<Record<string,string>>({})
 const usersQ=useQuery({queryKey:['merge-users'],queryFn:()=>userApi.list()})
 const raw=usersQ.data?.data;const users=Array.isArray(raw?.data)?raw.data:[]
 const previewM=useMutation({mutationFn:()=>userAccountMergeApi.preview(userId,source||''),onSuccess:response=>{setPreview(response.data.data);setChoices({})},onError:()=>message.error('无法预览，请核实账号状态与当前租户')})
 const mergeM=useMutation({mutationFn:()=>userAccountMergeApi.merge(userId,source||'',preview?.preview_version||'',choices),onSuccess:()=>{message.success('账号已合并，源账号已停用');setPreview(undefined);setSource(undefined);void qc.invalidateQueries({queryKey:['users']});void qc.invalidateQueries({queryKey:['user-detail',userId]});void qc.invalidateQueries({queryKey:['merge-users']})},onError:()=>{message.error('合并失败或资料已变化，请重新预览');setPreview(undefined)}})
 const rebindM=useMutation({mutationFn:(linkId:string)=>userAccountMergeApi.rebind(source||'',linkId,userId,preview?.preview_version||''),onSuccess:()=>{message.success('身份链接已换绑，原账号旧登录立即失效');setPreview(undefined);void qc.invalidateQueries({queryKey:['users']})},onError:()=>message.error('换绑失败，请重新预览并核实身份')})
 const policyText=(owner:string)=>(preview?.personal_policies??[]).filter(p=>p.user_id===owner).map(p=>p.mode==='allowlist'?'指定名单：'+(p.model_names.join('、')||'全部禁用'):'继承部门').join('；')||'继承部门'
 const extraText=(owner:string)=>(preview?.extra_grants??[]).filter(g=>g.user_id===owner&&!g.revoked_at).map(g=>g.model+'（'+g.reason+(g.expires_at?'；到期 '+new Date(g.expires_at).toLocaleString('zh-CN'):'；无到期时间')+'）').join('；')||'无'
 const ready=!!preview&&preview.required_choices.every(field=>!!choices[field])
 return <Card title="账号合并" size="small"><Space direction="vertical" style={{width:'100%'}}>
  <Alert type="warning" showIcon message="合并前必须预览并逐项处理冲突" description="目标账号的管理角色保持不变。源账号停用而不删除；已结算金额和账本不改写。"/>
  <Select aria-label="待合并账号" showSearch optionFilterProp="label" style={{width:'100%'}} placeholder="选择需要合并到当前账号的源账号" value={source} loading={usersQ.isLoading} onChange={value=>{setSource(value);setPreview(undefined);setChoices({})}} options={users.filter((user:{id:string;status:string})=>user.id!==userId&&user.status==='active').map((user:{id:string;username:string})=>({value:user.id,label:user.username}))}/>
  <Button disabled={!source} loading={previewM.isPending} onClick={()=>previewM.mutate()}>预览合并</Button>
  {preview?<><Descriptions column={1} size="small"><Descriptions.Item label="源账号">{preview.source.username}</Descriptions.Item><Descriptions.Item label="目标账号">{preview.target.username}</Descriptions.Item><Descriptions.Item label="源账号部门">{preview.source.department_name||'未分配部门'}</Descriptions.Item><Descriptions.Item label="目标账号部门">{preview.target.department_name||'未分配部门'}</Descriptions.Item><Descriptions.Item label="源账号个人模型策略">{policyText(preview.source_user_id)}</Descriptions.Item><Descriptions.Item label="目标账号个人模型策略">{policyText(preview.target_user_id)}</Descriptions.Item><Descriptions.Item label="源账号额外授权">{extraText(preview.source_user_id)}</Descriptions.Item><Descriptions.Item label="目标账号额外授权">{extraText(preview.target_user_id)}</Descriptions.Item><Descriptions.Item label="待迁移身份链接">{preview.source_identity_count}</Descriptions.Item><Descriptions.Item label="源账号有效 Key">{preview.source_key_count}</Descriptions.Item><Descriptions.Item label="源钱包余额">{(preview.wallets??[]).filter(w=>w.user_id===preview.source_user_id).map(w=>`余额 ${(w.balance_micros/1000000).toFixed(6)} ${w.currency}，预留 ${(w.reserved_micros/1000000).toFixed(6)} ${w.currency}`).join('；')||'无源钱包余额'}</Descriptions.Item><Descriptions.Item label="计费历史">{preview.billing_history}</Descriptions.Item><Descriptions.Item label="会话历史">{preview.session_history}</Descriptions.Item></Descriptions>
   {(preview.identity_links??[]).map(link=><div key={link.id}><Typography.Text>{({local:'本地账号',oidc:'企业登录',ldap:'LDAP 目录',ad:'AD 目录'} as Record<string,string>)[link.source_type]||'身份源'}：{link.external_subject}</Typography.Text><Popconfirm title="仅换绑此身份到目标账号？" description="此操作不合并账单或授权；原账号该身份的旧登录立即失效。" okText="换绑" cancelText="取消" onConfirm={()=>rebindM.mutateAsync(link.id)}><Button size="small" loading={rebindM.isPending}>仅换绑身份</Button></Popconfirm></div>)}
   {preview.required_choices.map(field=><div key={field}><Typography.Text>{fieldLabel(field)}</Typography.Text><Select aria-label={fieldLabel(field)} style={{width:'100%',marginTop:4}} placeholder="请选择处理规则" value={choices[field]} options={options(field)} onChange={value=>setChoices(current=>({...current,[field]:value}))}/></div>)}
   <Popconfirm title="确认按预览合并账号？" description="源账号将停用，旧登录立即失效。" okText="合并" cancelText="取消" disabled={!ready} onConfirm={()=>mergeM.mutateAsync()}><Button danger disabled={!ready} loading={mergeM.isPending}>确认合并账号</Button></Popconfirm>
  </>:null}
 </Space></Card>
}
