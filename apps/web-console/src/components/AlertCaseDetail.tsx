import { SEVERITY_LABELS } from '../utils/risk'
import { useState } from 'react'
import { Alert, Button, Collapse, Descriptions, Empty, Input, Modal, Pagination, Space, Spin, Tabs, Tag, Typography, message } from 'antd'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { alertOccurrencesApi, type AlertOccurrence, type AlertOccurrenceParams } from '../services/alertOccurrences'
import { accessRetentionApi, contentSecurityApi } from '../services/api'
import { useAuditQueryIdentity } from '../hooks/useAuditQueryIdentity'
import { alertIdentityDetails, alertOriginSummary } from '../utils/alertIdentity'
import { credentialAssessment } from '../utils/alertOccurrenceDisplay'
import PolicyRuleLink from './PolicyRuleLink'
import RawEvidenceInline from './RawEvidenceInline'
import { rawEvidenceDirection } from '../utils/rawEvidence'
import { useAuthStore } from '../stores/auth'
import { canViewRawEvidenceRole } from '../utils/access'
import { RAW_EVIDENCE_OMITTED_TEXT, RAW_EVIDENCE_TRUNCATED_SUFFIX } from '../utils/alertEvidence'
import RawEvidenceText from './RawEvidenceText'
import { alertActionResult, alertActionResultIfRecorded, alertCaseSource, alertCaseTitle, alertHitText, alertRuleDisplayName, readableReasonCode, stripSeverityExplanation, STAGE_LABELS } from '../utils/alertReadable'
const { Text, Paragraph } = Typography
const dates = (value?: string) => value ? new Date(value).toLocaleString() : '未记录'
const severity = (value: string) => SEVERITY_LABELS[value] || '未分级'
const sourceText = (item: Pick<AlertOccurrence,'content_source'|'matched_location'|'message_role'>) => alertCaseSource(item) || '未记录消息来源'

const evidenceText = (value?: string) => ['<deterministic-catalog-match>', '<MASKED>'].includes(value?.trim() || '') ? '' : value || ''
const semanticFailureLabel = (value?: string) => ({judge_timeout:'裁判超时',judge_unavailable:'裁判不可用',breaker_open:'裁判暂时熔断',tier1_timeout:'初筛超时',tier1_unavailable:'初筛不可用',window_budget_exceeded:'部分内容尚未完成检测'}[value || ''] || '检测未完成')

function HitText({ text, truncated, rows }: {text: string; truncated?: boolean; rows: number}) {
  return <Paragraph className="alert-case-hit-text" style={{whiteSpace:'pre-wrap',overflowWrap:'anywhere',marginBottom:0}} ellipsis={{rows,expandable:true,symbol:'展开'}}>{text}{truncated ? RAW_EVIDENCE_TRUNCATED_SUFFIX : ''}</Paragraph>
}

function MatchText({ text, needle }: {text: string; needle?: string}) {
  const at = needle && needle.length < 500 ? text.indexOf(needle) : -1
  return <Paragraph className="alert-case-evidence-text">{at >= 0 && needle
    ? <>{text.slice(0,at)}<mark>{needle}</mark>{text.slice(at+needle.length)}</> : text}</Paragraph>
}

export default function AlertCaseDetail({ item, params, identityLabel, canManage, saving, onDisposition, canReadContent }: {
 item: AlertOccurrence
 // 能否看内容证据（命中原文）：决定命中明细是否带 include_raw。
 canReadContent: boolean
 params: AlertOccurrenceParams
 identityLabel: string
 canManage: boolean
 saving: boolean
 onDisposition: (status: string) => void
}) {
 const identity = useAuditQueryIdentity()
 const [tab,setTab]=useState('overview')
 const [page,setPage]=useState(1)
 const [hit,setHit]=useState(item)
 const [exceptionOpen,setExceptionOpen]=useState(false)
 const [reason,setReason]=useState('')
 const [exceptionSaving,setExceptionSaving]=useState(false)
 // The parent keys this view by case_id; refreshing a case must not replace the user's selected hit.
 const members=useQuery({
  queryKey:['alert-case-members',identity,item.case_id,page,params],
  queryFn:({signal})=>alertOccurrencesApi.list({...params,grouping:'hits',case_id:item.case_id,recent_limit:undefined,disposition:undefined,severity:undefined,category:undefined,include_suppressed:true,include_raw:canReadContent,limit:20,offset:(page-1)*20,signal}),
  enabled:tab==='hits',retry:false,
 })
 const evidence=useQuery({
  queryKey:['alert-case-hit-evidence',identity,hit.event_id,hit.finding_index],
  queryFn:({signal})=>alertOccurrencesApi.getEvidence(hit,{project_id:hit.project_id,signal}),
  enabled:tab==='evidence',retry:false,
 })
 const selected=evidence.data || hit
 const at=Date.parse(hit.occurred_at || hit.created_at)
 const from=new Date(at-86400000).toISOString(),to=new Date(at+86400000).toISOString()
 const retained=useQuery({
  queryKey:['alert-case-retention',identity,hit.request_id,from,to],
  queryFn:({signal})=>accessRetentionApi.getContent(hit.request_id,undefined,{from,to,signal}),
  enabled:tab==='evidence' && Boolean(hit.request_id),retry:false,
 })
 const body=retained.data?.data
 const link='/audit/access-retention?'+new URLSearchParams({request_id:hit.request_id,from,to,alert_case:item.case_id || '',alert_event:hit.event_id}).toString()
 const choose=(row:AlertOccurrence)=>{setHit(row);setTab('evidence')}
 const content=body?.user_input || body?.request_content || ''
 const output=body?.model_output || body?.response_content || ''
 const excerpt=evidenceText(selected.raw_evidence) || evidenceText(selected.redacted_evidence)
 const contextEvidence=evidenceText(selected.evidence_context)
 const canViewRawEvidence=canViewRawEvidenceRole(useAuthStore((state)=>state.user?.role))
 const hasRawEvidence=canViewRawEvidence && (selected.raw_evidence_count || 0) > 0
 const rawDirection=rawEvidenceDirection(selected.stage,selected.content_source)
 const hitSource=selected.content_source || selected.message_role
 const toolEvidence=['tool','tool_result','tool_output','assistant_history','system_prompt','developer_prompt'].includes(hitSource)
 const assessment=credentialAssessment(selected)
 const origin=alertOriginSummary(item)
 const reasonText=selected.reason_status==='restricted' ? '无权查看检测理由' : stripSeverityExplanation(readableReasonCode(selected.reason))
 const contextMasked=/已打码|已隐藏|<MASKED>/.test(contextEvidence || '') || /<MASKED>|\*{2,}/.test(excerpt || '')
 const reviewIncomplete=selected.semantic_status==='incomplete'
 const semantic=selected.type==='semantic_attack' || selected.category.startsWith('semantic_')
 const exportEvidence=()=>{
  const payload={case_id:item.case_id,case_review:{status:item.disposition_status,first_seen:item.first_seen,last_seen:item.last_seen,review_snapshot:item.last_detected_at},occurrence:selected,retained_request:body || null,exported_at:new Date().toISOString()}
  const url=URL.createObjectURL(new Blob([JSON.stringify(payload,null,2)],{type:'application/json'}))
  const a=document.createElement('a');a.href=url;a.download=`命中证据-${hit.event_id}.json`;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000)
 }
 const createException=async()=>{
  if(!selected.rule_id || !reason.trim()) return
  setExceptionSaving(true)
  // 没有项目的命中按全单位范围加例外。
  try {await contentSecurityApi.createException({scope_type:selected.project_id?'project':'tenant',scope_ref:selected.project_id||'',rule_id:selected.rule_id,decision:'audit',reason:reason.trim(),expires_at:new Date(Date.now()+86400000).toISOString()});setExceptionOpen(false);setReason('');message.success(selected.project_id?'已保存该项目和规则的24小时审计例外':'已保存全单位该规则的24小时审计例外')}
  catch {message.error('保存例外失败，请检查权限与规则范围')} finally {setExceptionSaving(false)}
 }
 return <>
  <div className="alert-workbench-detail-actions">
   <Space wrap><Tag color="orange">最高 {severity(item.severity)}</Tag><Tag>{({open:'待处置',resolved:'已处理',false_positive:'误报',accepted:'已接受风险',escalated:'已升级'}[item.disposition_status] || '状态未记录')}</Tag><Text>{item.hit_count} 次命中 · {item.request_count ? `${item.request_count} 个请求` : '请求关联缺失'}</Text></Space>
   {canManage ? <Space wrap><Button loading={saving} type="primary" onClick={()=>onDisposition('resolved')}>标为已处理</Button><Button loading={saving} onClick={()=>onDisposition('false_positive')}>标为误报</Button>{item.disposition_status!=='open' ? <Button onClick={()=>onDisposition('open')}>重新打开</Button> : null}</Space> : null}
  </div>
  <div className="alert-workbench-detail-body alert-case-detail-body">
   <Tabs activeKey={tab} onChange={setTab} items={[
    {key:'overview',label:'1. 问题概况',children:<Space direction="vertical" size={16} style={{width:'100%'}}>
      <div className="alert-case-title-block">
       <Text strong className="alert-case-title" data-testid="alert-case-title">{alertCaseTitle(item)}</Text>
      </div>
      <section className="alert-case-why" aria-label="为什么触发" data-testid="alert-case-why">
       <Descriptions size="small" column={1} items={[
        {label:'命中规则',children:<PolicyRuleLink link={item.policy_link} name={alertRuleDisplayName(item)} eventId={item.event_id} />},
        {label:'命中内容',children:<HitText text={alertHitText(item,200) || '未记录'} truncated={Boolean(item.raw_evidence && item.raw_evidence_truncated)} rows={4}/>},
        {label:'处置结果',children:alertActionResultIfRecorded(item.event_action_taken) || '未记录'},
        {label:'告警级别',children:severity(item.severity)+(item.severity_downgrade_reason ? `（${item.severity_downgrade_reason}）` : '')},
       ]}/>
      </section>
      <Descriptions size="small" column={1} items={[
       {label:'首次发生',children:item.time_known===false?'原请求时间未记录':dates(item.first_seen)},
       {label:'最近发生',children:item.time_known===false?'原请求时间未记录':dates(item.last_seen)},
       {label:'影响范围',children:`${item.request_count ? item.request_count + ' 个请求' : '请求关联缺失'}，累计 ${item.hit_count} 次命中；${item.blocked_count || 0} 个已关联请求有阻断记录`},
      ]}/>
      {item.type==='semantic_attack' || item.category.startsWith('semantic_') ? <Alert type="warning" showIcon message="语义模型给出的疑似风险，尚需人工核对证据。" /> : null}
      <div className="alert-origin" data-testid="alert-origin-summary">
       {origin.sentence ? <Text strong className="alert-origin-sentence">{origin.sentence}</Text> : <Text type="secondary">没有任何来源线索被记录。</Text>}
       {origin.missing.length ? <ul className="alert-origin-missing">{origin.missing.map(line=><li key={line}>{line}</li>)}</ul> : null}
       {item.request_id ? <Text type="secondary" copyable={{text:item.request_id}}>请求编号 {item.request_id}</Text> : null}
      </div>
      <Collapse ghost size="small" items={[{key:'identity',label:identityLabel,children:<Descriptions size="small" column={1} items={[
       ...alertIdentityDetails(item),
       {label:'目标',children:item.model_name || (item.target_host?.startsWith('model_') ? '' : item.target_host) || '未记录模型或目标'},
       {label:'检测环节',children:sourceText(item)+' / '+(STAGE_LABELS[item.stage] || '阶段未记录')},
       {label:'最近检测入库',children:dates(item.last_detected_at)},
       {label:'合并依据',children:item.grouping_basis==='conversation'?'同一身份、会话、目标、风险类别和检测来源':'缺少会话标识，按同一身份、目标、风险类别和日期归为一个排查问题'},
      ]}/>}]} />
      <Button type="primary" onClick={()=>setTab('hits')}>查看 {item.hit_count} 次命中明细</Button>
    </Space>},
    {key:'hits',label:'2. 命中明细',children:<Space direction="vertical" size={10} style={{width:'100%'}}>
      <Text type="secondary">选择一次命中，再核对该次请求的证据和留存；各条等级、动作独立显示。</Text>
      {members.isFetching ? <Space><Spin size="small"/><Text type="secondary">读取命中明细…</Text></Space> : null}
      {members.isError ? <Alert type="error" message="命中明细读取失败" action={<Button onClick={()=>void members.refetch()}>重试</Button>} /> : null}
      {(members.data?.data.items || []).map(row=><section key={row.id} className="alert-case-member">
       <Space wrap>{row.duplicate_count>1 ? <Tag>{row.rule_ids?.length>1 ? `同一证据关联 ${row.rule_ids.length} 条策略` : `同一证据重复检测 ${row.duplicate_count} 次`}</Tag> : null}<Tag>{severity(row.severity)}</Tag><Text>{alertActionResult(row.event_action_taken)}</Text><Text type="secondary">{sourceText(row)}</Text></Space>
       <div>请求发生：{row.time_known===false?'未记录':dates(row.occurred_at)} · 检测入库：{dates(row.created_at)}</div>
       <RawEvidenceText className="alert-case-hit-text" raw={row.raw_evidence} truncated={row.raw_evidence_truncated} omitted={row.raw_evidence_omitted} fallback={row.redacted_evidence || '未记录命中内容，打开证据核对'} rows={2}/>
       <Text type="secondary" copyable={{text:row.request_id}}>请求 {row.request_id}</Text>
       <Button type="link" onClick={()=>choose(row)}>查看这条证据</Button>
       {row.agent_session_id ? <Link to={`/agent/sessions/${encodeURIComponent(row.agent_session_id)}`}>查看会话</Link> : null}
      </section>)}
      {!members.isFetching && !members.isError && !members.data?.data.items.length ? <Empty description="当前范围没有命中明细"/> : null}
      <Pagination current={page} pageSize={20} total={members.data?.data.total || 0} showSizeChanger={false} onChange={setPage}/>
    </Space>},
    {key:'evidence',label:'3. 证据与留痕',children:<Space direction="vertical" size={16} style={{width:'100%'}}>
      <Alert type="info" showIcon message={`本条命中来自${sourceText(selected)}${selected.message_index!=null?`（检测消息索引 ${selected.message_index}）`:''}。${toolEvidence?'下方用户/模型正文是本次请求摘要，历史上下文命中请以上方原始片段为准。':'以下展示当前选中命中对应的请求。'}`} />
      {assessment ? <Alert type="info" showIcon message="此处为凭据候选；风险等级表示潜在影响，不代表已确认发生泄露。" /> : null}
      {contextMasked ? <Alert type="info" showIcon data-testid="alert-evidence-guide" message="这条是历史命中，入库时秘密本体已隐藏。"
        description={<ul className="alert-origin-missing"><li>判断真假：看打码前后的文字，例如 key=、secret=、password= 这类赋值线索，或是否出现在示例、测试、文档里。</li><li>{contextEvidence ? '下方「检测时保存的附近内容」就是命中点前后的原文，秘密处显示为「已隐藏」。' : '这条命中没有保存附近内容，只能依据下方的命中位置和规则判断。'}</li><li>{hasRawEvidence ? '被阻断或改写前的原文另存在原文留证里，可在下方查看。' : (content || output) ? '原请求正文已留存，可在下方核对。' : '该请求的正文没有留存，无法回看原话；如需判断，请用请求编号到「请求留存」核对。'}</li></ul>} /> : null}
      {reviewIncomplete ? <Alert type="warning" showIcon message={`语义复核未完成：${semanticFailureLabel(selected.semantic_reason)}。该规则命中不能视为语义模型已确认。`} /> : null}
      {selected.evidence_recovered ? <Alert type="success" showIcon message="原始命中片段已按事件哈希从本次请求留存恢复。" /> : null}
      {evidence.isSuccess && !excerpt && !contextEvidence && !selected.raw_evidence_omitted ? <Alert type="warning" showIcon message="未留存可核验的命中片段。位置或内部占位符不能证明该风险，需补证或进行误报处置。" /> : null}
      <Descriptions size="small" column={1} items={[
       {label:'当前请求',children:<Text copyable>{hit.request_id || '未关联请求'}</Text>},
       ...(assessment ? [{label:'判定依据',children:assessment.validation},{label:'模型复核',children:assessment.review},{label:'凭据有效性',children:assessment.validity},{label:'分数含义',children:assessment.confidence}] : []),
       {label:'本条风险',children:`${alertCaseTitle(hit)} · ${severity(hit.severity)}`},
       ...alertIdentityDetails(selected),
       {label:'实际动作',children:alertActionResult(hit.event_action_taken)},
       {label:'发生 / 入库',children:dates(hit.occurred_at)+' / '+dates(hit.created_at)},
       {label:'命中位置',children:hit.matched_location || (hit.message_index!=null?`消息索引 ${hit.message_index}；未记录精确片段位置`:'未记录精确位置')},
      ]}/>
      {evidence.isError ? <Alert type="warning" message="本次命中证据读取失败" action={<Button onClick={()=>void evidence.refetch()}>重试证据</Button>} /> : null}
      {evidence.isSuccess && !evidence.data ? <Alert type="warning" showIcon message="该条命中已不在当前有效风险清单，可能已被复核撤回；下方保留此前选中的摘要供核对。" /> : null}
      <section aria-label="选中命中证据"><Text strong>{semantic?'语义判断引用的内容':'本次命中片段'}</Text><MatchText text={excerpt || (selected.raw_evidence_omitted ? RAW_EVIDENCE_OMITTED_TEXT : '未留存命中片段')}/>{reasonText ? <Text type="secondary">{reasonText}</Text> : null}</section>
      {!selected.raw_evidence && excerpt && selected.raw_evidence_status==='missing' ? <Text type="secondary">这条历史命中只存了打码片段，请求留存里也没有找到能核验的原文。</Text> : null}
      {selected.raw_evidence && selected.raw_evidence_truncated ? <Text type="secondary">命中原文超过 4096 字，已截断。</Text> : null}
      {contextEvidence ? <section><Text strong>{selected.evidence_recovered?'按原事件哈希核验的附近内容':'检测时保存的附近内容'}</Text><MatchText text={contextEvidence} needle={semantic?undefined:selected.raw_evidence}/></section> : null}
      {hasRawEvidence ? <section aria-label="原文留证"><Text strong>原文留证</Text><div><RawEvidenceInline key={selected.id} requestId={selected.request_id} direction={rawDirection} messageIndex={selected.message_index} matchedLocation={selected.matched_location} rawEvidenceSha256={selected.raw_evidence_sha256}/></div></section> : null}
      <section aria-label="当前请求留存"><Text strong>原请求留存</Text><Paragraph type="secondary">这里显示本次请求的用户与模型正文，可能经过解码、脱敏或截断。历史工具或系统上下文的具体命中请核对上方证据与来源。</Paragraph>
       {!semantic && selected.raw_evidence && (content || output) && !(content+output).includes(selected.raw_evidence) ? <Alert type="info" showIcon message="当前留存正文中没有相同的原始片段；请对照上方检测时保存的证据，不据此推断发生了其他请求。" /> : null}
       {retained.isError ? <Alert type="warning" message="该请求的完整留存暂不可读；上方命中证据独立保留。" /> : null}
       {retained.isFetching ? <Text>正在读取该请求留存…</Text> : null}
       {content ? <><Text type="secondary">用户 / 请求内容</Text><MatchText text={content} needle={semantic?undefined:selected.raw_evidence}/></> : null}
       {output ? <><Text type="secondary">模型 / 返回内容</Text><MatchText text={output} needle={semantic?undefined:selected.raw_evidence}/></> : null}
       {!retained.isFetching && !content && !output && !hasRawEvidence ? <Text type="secondary">未读取到该请求的正文。不能用同会话的其他请求代替。</Text> : null}
      </section>
      <Space wrap><Button disabled={!evidence.data} onClick={exportEvidence}>导出这条证据</Button>{canManage ? <Button disabled={!evidence.data || !selected.rule_id} onClick={()=>setExceptionOpen(true)}>对这条规则设置例外</Button> : null}</Space>
      {hit.request_id ? <Link to={link}>在请求留存页核对完整记录 →</Link> : null}
    </Space>},
   ]}/>
  </div>
  <Modal title="为选中命中设置例外" open={exceptionOpen} onCancel={()=>setExceptionOpen(false)} onOk={()=>void createException()} okText="保存24小时审计例外" confirmLoading={exceptionSaving} okButtonProps={{disabled:!reason.trim()}}>
   <p>项目：{selected.project_id || '全单位'}；规则：{selected.rule_name || selected.rule_id}。该范围改为仅审计，24小时后自动到期。</p>
   <Input.TextArea aria-label="例外原因" value={reason} onChange={e=>setReason(e.target.value)} maxLength={2000}/>
  </Modal>
 </>
}

