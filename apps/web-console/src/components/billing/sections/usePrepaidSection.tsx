import { useEffect, useRef, useState } from 'react'
import { Alert, Button, Card, DatePicker, Descriptions, Form, Input, InputNumber, Modal, Select, Space, Table, Tag, Typography, message } from 'antd'
import dayjs from 'dayjs'
import { DollarOutlined, PlusOutlined, SearchOutlined } from '@ant-design/icons'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { CURSOR_PAGE_SIZE, useCursorPager } from '../../../hooks/useCursorPager'
import { billingAdminApi } from '../../../services/api'
import { useAuthStore } from '../../../stores/auth'
import { extractApiError } from '../../../utils/apiError'
import TwoDecimalInput from '../TwoDecimalInput'
import { invalidateBillingQueries, type BillingContext } from '../useBillingContext'
import { MICROS_PER_YUAN, displayLabel, formatMicros, statusLabels, toMicros, toYuan, unwrap } from '../billingFormat'
import { CursorPagerBar } from '../BillingWidgets'
import { useCurrencyStore } from '../../../stores/currency'
import { currencyUnitLabel } from '../../../utils/currencyUnit'

const { Text } = Typography

// 预付费账户（高级）分区：客户账户、客户组、充值/调账、兑换码。
// 代码从原 BillingOperations.tsx 原样迁出，幂等与待确认操作逻辑一字未改。
// 待确认钱包操作（充值/调账）：提交时冻结 payload 与幂等键并持久化，
// 同一幂等键重试，服务端可据此去重；入账成功后清除，失败/冲突保留待核查。
// 使用 sessionStorage（按浏览器标签页隔离）且按租户分作用域，切换租户绝不
// 发送其他租户的冻结操作。只保存幂等键与业务字段，不含任何密钥明文。
export type PendingWalletOp = {
  idempotency_key: string
  payload: Record<string, any> | null
  owner_user_id?: string
  scope?: string
}
const PENDING_WALLET_OPS_STORAGE_KEY = 'billing-console-pending-wallet-ops-v2'
// 读取待确认操作。读取失败必须与「没有记录」严格区分：
// 若把失败当成空 map 继续写回，就会用「空 map + 一个新 op」覆盖整个存储，
// 把其它租户/其它管理员的待确认记录全部抹掉 —— 那等于销毁了资金操作凭证。
type PendingStorageState =
  | { status: 'absent'; ops: Record<string, PendingWalletOp> }
  | { status: 'valid'; ops: Record<string, PendingWalletOp> }
  | { status: 'invalid' | 'read-failed'; ops: null }
const validPendingOp = (scope: string, value: any): value is PendingWalletOp => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false
  if (typeof value.idempotency_key !== 'string' || !value.idempotency_key.trim()) return false
  if (typeof value.owner_user_id !== 'string' || !value.owner_user_id) return false
  const kind = scope.split(':').slice(-1)[0]
  if (kind !== 'credit' && kind !== 'adjust') return false
  if (value.scope !== undefined && value.scope !== scope) return false
  const payload = value.payload
  if (payload === null) return scope.endsWith(`:${value.owner_user_id}:${kind}`)
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return false
  if (scope !== `${payload.tenant_id}:${value.owner_user_id}:${kind}`) return false
  if (typeof payload.reason !== 'string' || !payload.reason.trim() || payload.reason !== payload.reason.trim()) return false
  if (!Number.isSafeInteger(payload.amount_micros) || payload.amount_micros === 0 || (kind === 'credit' && payload.amount_micros < 0)) return false
  return typeof payload[kind === 'credit' ? 'user_id' : 'wallet_id'] === 'string' && !!payload[kind === 'credit' ? 'user_id' : 'wallet_id']
}
const readPendingWalletOps = (): PendingStorageState => {
  let raw: string | null
  try { raw = window.sessionStorage.getItem(PENDING_WALLET_OPS_STORAGE_KEY) }
  catch { return { status: 'read-failed', ops: null } }
  if (raw === null) return { status: 'absent', ops: {} }
  try {
    const ops = JSON.parse(raw)
    if (!ops || typeof ops !== 'object' || Array.isArray(ops) || !Object.entries(ops).every(([scope, op]) => validPendingOp(scope, op))) {
      return { status: 'invalid', ops: null }
    }
    return { status: 'valid', ops }
  } catch { return { status: 'invalid', ops: null } }
}
const clearPendingWalletOp = (scope: string, idempotencyKey: string): boolean => {
  const state = readPendingWalletOps()
  if (!state.ops) return false
  const existing = state.ops[scope]
  if (!existing) return true
  if (existing.idempotency_key !== idempotencyKey) return false
  const ops = { ...state.ops }
  delete ops[scope]
  try { window.sessionStorage.setItem(PENDING_WALLET_OPS_STORAGE_KEY, JSON.stringify(ops)); return true }
  catch { return false }
}
const writePendingWalletOp = (scope: string, op: PendingWalletOp): boolean => {
  const state = readPendingWalletOps()
  if (!state.ops || !validPendingOp(scope, op)) return false
  const existing = state.ops[scope]
  if (existing && existing.idempotency_key !== op.idempotency_key) return false
  if (existing?.payload && JSON.stringify(existing.payload) !== JSON.stringify(op.payload)) return false
  try {
    window.sessionStorage.setItem(PENDING_WALLET_OPS_STORAGE_KEY, JSON.stringify({ ...state.ops, [scope]: op }))
    return true
  } catch { return false }
}

export function usePrepaidSection(ctx: BillingContext) {
  const moneyUnit = currencyUnitLabel(useCurrencyStore((state) => state.tenantCurrency))
  const queryClient = useQueryClient()
  const { tenantID } = ctx
  const refresh = () => invalidateBillingQueries(queryClient, tenantID)
  // 待确认操作按「租户 + 认证管理员」双维度隔离：同一浏览器上不同管理员
  // 登录各自持有自己的待确认队列，互不可见、互不代发
  const authRole = useAuthStore((state: any) => state.user?.role)
  const [copyingRedemption,setCopyingRedemption]=useState('')
  const [copyFallback,setCopyFallback]=useState('')
  useEffect(()=>{if(!copyFallback)return;const timer=window.setTimeout(()=>setCopyFallback(''),60000);return()=>window.clearTimeout(timer)},[copyFallback])
  const copyCodeText=async(value:string)=>{
    try{if(navigator.clipboard?.writeText){await navigator.clipboard.writeText(value);return true}}catch { /* Use the browser fallback when clipboard access is blocked. */ }
    const field=document.createElement('textarea');field.value=value;field.style.position='fixed';field.style.opacity='0';document.body.appendChild(field);
    try{field.select();return document.execCommand('copy')}catch{return false}finally{field.remove()}
  }
  const copyRedemption=async(id:string)=>{
    if(copyingRedemption)return;setCopyingRedemption(id)
    try{
      const pending=billingAdminApi.revealRedemption(tenantID,id).then(response=>{const body=unwrap(response);if(typeof body?.code!=='string'||!body.code)throw new Error('invalid_response');return body.code as string})
      let copied=false
      if(typeof ClipboardItem!=='undefined'&&navigator.clipboard?.write){try{await navigator.clipboard.write([new ClipboardItem({'text/plain':pending.then(code=>new Blob([code],{type:'text/plain'}))})]);copied=true}catch { /* Use the browser fallback when clipboard access is blocked. */ }}
      const code=await pending
      if(copied||await copyCodeText(code))message.success('兑换码已复制');else setCopyFallback(code)
    }catch(error:any){message.error(error?.response?.status===409?'历史兑换码仅保存哈希，无法恢复完整内容；请生成新码。':'复制兑换码失败，请检查连接或权限后重试。')}finally{setCopyingRedemption('')}
  }
  const authUserID = useAuthStore((state: any) => state.user?.id) || 'anon'
  const [creditOpen, setCreditOpen] = useState(false)
  const [adjustOpen, setAdjustOpen] = useState(false)
  const [groupOpen, setGroupOpen] = useState(false)
  const [editingGroup, setEditingGroup] = useState<any>(null)
  const [groupAssignmentOpen, setGroupAssignmentOpen] = useState(false)
  const [assignmentCustomer, setAssignmentCustomer] = useState<any>(null)
  const [creditForm] = Form.useForm()
  // 当前弹窗对应的待确认操作；从持久化恢复或打开时新建
  const [creditPending, setCreditPendingState] = useState<PendingWalletOp | null>(null)
  const [adjustPending, setAdjustPendingState] = useState<PendingWalletOp | null>(null)
  // 提交被本地校验/持久化拦下时的原因。资金操作被拦必须留下持久可见的证据，
  // 不能只靠 3 秒自动消失的 toast —— 否则管理员事后无法判断钱到底发没发出去。
  const [creditBlocked, setCreditBlocked] = useState('')
  const [adjustBlocked, setAdjustBlocked] = useState('')
  // ref 镜像当前弹窗操作身份：迟到响应（例如旧租户操作延迟成功）用它判断
  // 是否允许清理界面，绝不误清新弹窗、误关新操作
  const creditPendingRef = useRef<PendingWalletOp | null>(null)
  const adjustPendingRef = useRef<PendingWalletOp | null>(null)
  const updateCreditPending = (op: PendingWalletOp | null) => { creditPendingRef.current = op; setCreditPendingState(op) }
  const updateAdjustPending = (op: PendingWalletOp | null) => { adjustPendingRef.current = op; setAdjustPendingState(op) }
  // 作用域 = 租户 + 认证用户 + 操作类型
  const pendingScope = (kind: 'credit' | 'adjust', tenant?: string) => `${tenant || tenantID}:${authUserID}:${kind}`
  // 迟到响应清理专用：按操作自身冻结的租户与管理员定位作用域，绝不用当前上下文
  const opScope = (kind: 'credit' | 'adjust', op: PendingWalletOp) =>
    `${(op.payload?.tenant_id as string) || tenantID}:${op.owner_user_id || authUserID}:${kind}`
  useEffect(() => {
    setCreditOpen(false)
    setAdjustOpen(false)
    updateCreditPending(null)
    updateAdjustPending(null)
    setCreditBlocked('')
    setAdjustBlocked('')
  }, [tenantID, authUserID])
  const [redemptionOpen, setRedemptionOpen] = useState(false)
  const [generatedCodes, setGeneratedCodes] = useState<any[]>([])
  const [codesOpen, setCodesOpen] = useState(false)
  const [redemptionForm] = Form.useForm()
  const [redemptionPage,setRedemptionPage]=useState(1)
  // keyword = 兑换码片段检索（后端按 code_hint ILIKE 过滤），与状态/批次/兑换人/时间筛选叠加
  const [redemptionFilters,setRedemptionFilters]=useState({status:'',batch:'',redeemer:'',keyword:'',from:'',to:''})
  const [selectedRedemptionIDs,setSelectedRedemptionIDs]=useState<string[]>([])
  const [redemptionDetail,setRedemptionDetail]=useState<any>(null)
  const [exporting,setExporting]=useState(false)
  const redemptionTenant=useRef(tenantID)
  useEffect(()=>{
    redemptionTenant.current=tenantID
    setRedemptionPage(1);setSelectedRedemptionIDs([]);setRedemptionDetail(null);setCodesOpen(false);setGeneratedCodes([])
    setRedemptionFilters({status:'',batch:'',redeemer:'',keyword:'',from:'',to:''})
    setCustomerSearch('')
  },[tenantID])
  const changeRedemptionFilter=(field:keyof typeof redemptionFilters,value:string)=>{
    setRedemptionFilters(current=>({...current,[field]:value}));setRedemptionPage(1);setSelectedRedemptionIDs([])
  }

  const [adjustForm] = Form.useForm()
  const [groupForm] = Form.useForm()
  const [groupAssignmentForm] = Form.useForm()
  // 钱包账户（客户）列表检索：按用户名/邮箱/客户组过滤当前已加载页
  const [customerSearch, setCustomerSearch] = useState('')
  const customersPager = useCursorPager({
    scopeKey: tenantID,
    queryKey: ['billing-customers', tenantID],
    fetchPage: (cursor?: string) => billingAdminApi.customers(tenantID, cursor, CURSOR_PAGE_SIZE),
    enabled: !!tenantID,
  })
  const customersQuery = customersPager.query
  const groupsQuery = useQuery({
    queryKey: ['billing-customer-groups', tenantID],
    queryFn: () => billingAdminApi.customerGroups(tenantID),
    enabled: !!tenantID,
  })
  const redemptionsQuery = useQuery({
    queryKey: ['billing-redemptions', tenantID,redemptionPage,redemptionFilters],
    queryFn: () => billingAdminApi.redemptions(tenantID,{page:redemptionPage,page_size:20,
      ...redemptionFilters,from:redemptionFilters.from?new Date(redemptionFilters.from).toISOString():undefined,to:redemptionFilters.to?new Date(redemptionFilters.to).toISOString():undefined}),
    enabled: !!tenantID,
  })
  const creditMutation = useMutation({
    mutationFn: (op: PendingWalletOp) => billingAdminApi.credit({ ...op.payload, idempotency_key: op.idempotency_key }),
    onSuccess: (_result, op) => {
      message.success('余额充值已入账')
      // 清理只针对这笔操作自己的作用域（用它冻结时的租户与管理员定位），
      // 且必须核对幂等键后才删：若同作用域已换成更晚的一笔，删掉它就丢了凭证
      const cleared = clearPendingWalletOp(opScope('credit', op), op.idempotency_key)
      if (!cleared) {
        message.warning('已成功入账但本地记录未清除')
        if (creditPendingRef.current?.idempotency_key === op.idempotency_key) setCreditBlocked('已成功入账但本地记录未清除')
      }
      // 迟到响应隔离：只有当前弹窗仍是这笔操作时才关窗清态
      if (cleared && creditPendingRef.current?.idempotency_key === op.idempotency_key) {
        setCreditOpen(false)
        creditForm.resetFields()
        setCreditBlocked('')
        updateCreditPending(null)
      }
      refresh()
    },
    // 响应未知或失败（含幂等键冲突）：保留冻结操作与同一幂等键，供管理员
    // 核查后重试；只有确认入账成功才清除
    onError: (error: any) => { message.error(extractApiError(error) || '充值失败') },
  })
  const adjustMutation = useMutation({
    mutationFn: (op: PendingWalletOp) => billingAdminApi.adjust({ ...op.payload, idempotency_key: op.idempotency_key }),
    onSuccess: (_result, op) => {
      message.success('调账已入账')
      const cleared = clearPendingWalletOp(opScope('adjust', op), op.idempotency_key)
      if (!cleared) {
        message.warning('已成功入账但本地记录未清除')
        if (adjustPendingRef.current?.idempotency_key === op.idempotency_key) setAdjustBlocked('已成功入账但本地记录未清除')
      }
      if (cleared && adjustPendingRef.current?.idempotency_key === op.idempotency_key) {
        setAdjustOpen(false)
        adjustForm.resetFields()
        setAdjustBlocked('')
        updateAdjustPending(null)
      }
      refresh()
    },
    // 响应未知或失败（含幂等键冲突）：保留冻结操作与同一幂等键，供管理员
    // 核查后重试；只有确认入账成功才清除
    onError: (error: any) => { message.error(extractApiError(error) || '调账失败') },
  })
  // 拦截资金操作时：既弹 toast（当下可见），也在弹窗里留下持久警示（事后可查）。
  // toast 3 秒后自动消失，不能作为「这笔钱到底发没发出去」的唯一证据。
  const blockCredit = (reason: string) => { setCreditBlocked(reason); message.error(reason) }
  const blockAdjust = (reason: string) => { setAdjustBlocked(reason); message.error(reason) }
  // 提交：首次提交冻结 payload + 幂等键并持久化；此后重试一律发送冻结值。
  // 已提交 payload 不可改：租户、客户、金额、原因以冻结值为准；空幂等键或
  // 空白原因（trim 后）拒绝发送，绝不产生无身份的资金请求。
  const submitCreditOp = (values: any) => {
    const state = readPendingWalletOps()
    if (!state.ops || !creditPending || creditPending.scope !== pendingScope('credit') || (state.ops[pendingScope('credit')] && state.ops[pendingScope('credit')].idempotency_key !== creditPending.idempotency_key)) {
      blockCredit('待确认操作本地保存失败（存储不可用），已停止发送；请恢复存储后重试')
      return
    }
    if (!creditPending?.idempotency_key) {
      blockCredit('幂等键缺失，请关闭弹窗后重新打开')
      return
    }
    // 冻结操作的所有者必须是当前登录管理员：切换账号后绝不代发他人操作
    if (creditPending.owner_user_id && creditPending.owner_user_id !== authUserID) {
      blockCredit('该待确认操作属于其他登录管理员，已停止发送，请核查')
      return
    }
    if (creditPending.payload) {
      const frozen = creditPending.payload
      if (frozen.tenant_id !== tenantID) {
        blockCredit('该待确认操作属于其他租户，已停止发送，请核查')
        return
      }
      if (!String(frozen.reason || '').trim()) {
        blockCredit('冻结的充值原因为空白，请核查后处理')
        return
      }
      if (!writePendingWalletOp(pendingScope('credit'), creditPending)) { blockCredit('待确认操作本地保存失败（存储不可用），已停止发送；请恢复存储后重试'); return }
      creditMutation.mutate(creditPending)
      return
    }
    const reason = String(values.reason || '').trim()
    if (!reason) {
      blockCredit('请填写充值原因')
      return
    }
    const op: PendingWalletOp = {
      idempotency_key: creditPending.idempotency_key,
      owner_user_id: authUserID,
      scope: pendingScope('credit'),
      payload: {
        tenant_id: tenantID,
        user_id: values.user_id,
        amount_micros: toMicros(values.amount_yuan),
        reason,
      },
    }
    // 首次提交必须先成功持久化：存储写失败就停止发送，否则幂等键只存在于
    // 内存，刷新后既无法凭同键重试，也无法核查这笔资金操作
    if (!writePendingWalletOp(pendingScope('credit'), op)) {
      blockCredit('待确认操作本地保存失败（存储不可用），已停止发送；请恢复存储后重试')
      return
    }
    updateCreditPending(op)
    creditMutation.mutate(op)
  }
  const submitAdjustOp = (values: any) => {
    const state = readPendingWalletOps()
    if (!state.ops || !adjustPending || adjustPending.scope !== pendingScope('adjust') || (state.ops[pendingScope('adjust')] && state.ops[pendingScope('adjust')].idempotency_key !== adjustPending.idempotency_key)) {
      blockAdjust('待确认操作本地保存失败（存储不可用），已停止发送；请恢复存储后重试')
      return
    }
    if (!adjustPending?.idempotency_key) {
      blockAdjust('幂等键缺失，请关闭弹窗后重新打开')
      return
    }
    if (adjustPending.owner_user_id && adjustPending.owner_user_id !== authUserID) {
      blockAdjust('该待确认操作属于其他登录管理员，已停止发送，请核查')
      return
    }
    if (adjustPending.payload) {
      const frozen = adjustPending.payload
      if (frozen.tenant_id !== tenantID) {
        blockAdjust('该待确认操作属于其他租户，已停止发送，请核查')
        return
      }
      if (!String(frozen.reason || '').trim()) {
        blockAdjust('冻结的调账原因为空白，请核查后处理')
        return
      }
      if (!writePendingWalletOp(pendingScope('adjust'), adjustPending)) { blockAdjust('待确认操作本地保存失败（存储不可用），已停止发送；请恢复存储后重试'); return }
      adjustMutation.mutate(adjustPending)
      return
    }
    const reason = String(values.reason || '').trim()
    if (!reason) {
      blockAdjust('请填写调账原因')
      return
    }
    const op: PendingWalletOp = {
      idempotency_key: adjustPending.idempotency_key,
      owner_user_id: authUserID,
      scope: pendingScope('adjust'),
      payload: {
        tenant_id: tenantID,
        wallet_id: values.wallet_id,
        amount_micros: toMicros(values.amount_yuan),
        reason,
      },
    }
    if (!writePendingWalletOp(pendingScope('adjust'), op)) {
      blockAdjust('待确认操作本地保存失败（存储不可用），已停止发送；请恢复存储后重试')
      return
    }
    updateAdjustPending(op)
    adjustMutation.mutate(op)
  }
  const groupMutation = useMutation({
    mutationFn: (values: any) => {
      const payload = {
        tenant_id: tenantID, name: values.name, description: values.description || '',
        ratio_ppm: Math.round((values.ratio ?? 1) * MICROS_PER_YUAN),
      }
      return editingGroup
        ? billingAdminApi.updateCustomerGroup(editingGroup.id, { ...payload, status: editingGroup.status })
        : billingAdminApi.createCustomerGroup({ ...payload, code: values.code })
    },
    onSuccess: () => { message.success(editingGroup ? '客户组已更新' : '客户组已创建'); setGroupOpen(false); setEditingGroup(null); groupForm.resetFields(); refresh() },
    onError: (error: any) => message.error(extractApiError(error) || (editingGroup ? '更新客户组失败' : '创建客户组失败')),
  })
  const groupStatusMutation = useMutation({
    mutationFn: (group: any) => billingAdminApi.updateCustomerGroup(group.id, {
      tenant_id: tenantID, name: group.name, description: group.description || '',
      status: group.status === 'active' ? 'disabled' : 'active', ratio_ppm: group.ratio_ppm,
    }),
    onSuccess: () => { message.success('客户组状态已更新'); refresh() },
    onError: (error: any) => message.error(extractApiError(error) || '更新客户组失败'),
  })
  const groupAssignmentMutation = useMutation({
    mutationFn: (values: any) => billingAdminApi.assignCustomerGroup(assignmentCustomer.user_id, {
      tenant_id: tenantID, customer_group: values.customer_group,
    }),
    onSuccess: () => { message.success('客户归组已更新'); setGroupAssignmentOpen(false); setAssignmentCustomer(null); groupAssignmentForm.resetFields(); refresh() },
    onError: (error: any) => message.error(extractApiError(error) || '更新客户归组失败'),
  })
  const redemptionMutation = useMutation({
    mutationFn: (values: any) => billingAdminApi.createRedemptions({
      tenant_id: tenantID, label: values.label, amount_micros: toMicros(values.amount_yuan),
      count: values.count, ...(values.expires_at ? { expires_at: values.expires_at.toISOString() } : {}),
    }),
    onSuccess: (response: any) => {
      const codes = unwrap(response)
      setRedemptionOpen(false)
      redemptionForm.resetFields()
      setGeneratedCodes(Array.isArray(codes) ? codes : [])
      setCodesOpen(true)
      message.success('兑换码已生成，请立即保存'),
      refresh()
    },
    onError: (error: any) => message.error(extractApiError(error) || '生成兑换码失败'),
  })
  const redemptionStatusMutation = useMutation({
    mutationFn: (input: { id: string; status: string }) => billingAdminApi.updateRedemption(input.id, { tenant_id: tenantID, status: input.status }),
    onSuccess: () => { message.success('兑换码状态已更新'); refresh() },
    onError: (error: any) => message.error(extractApiError(error) || '更新兑换码状态失败'),
  })
  const deleteRedemptionMutation = useMutation({
    mutationFn: ({ tenant, id }: { tenant: string; id: string }) => billingAdminApi.deleteRedemption(tenant, id),
    onSuccess: (_result, input) => {
      queryClient.invalidateQueries({ queryKey: ['billing-redemptions', input.tenant] })
      if (redemptionTenant.current === input.tenant) {
        setSelectedRedemptionIDs(ids => ids.filter(id => id !== input.id))
        setRedemptionDetail((current: any) => current?.id === input.id ? null : current)
        message.success('兑换码已删除')
      }
    },
    onError: (error: any) => message.error(extractApiError(error) || '删除兑换码失败'),
  })
  const customers = customersPager.rows
  const customerSearchLower = customerSearch.trim().toLowerCase()
  const filteredCustomers = customerSearchLower
    ? customers.filter((item: any) => [item.username, item.email, item.customer_group_name, item.customer_group]
        .some((value) => typeof value === 'string' && value.toLowerCase().includes(customerSearchLower)))
    : customers
  const customerGroups = unwrap(groupsQuery.data)

  const bulkRedemptionMutation=useMutation({
    mutationFn:(ids:string[])=>billingAdminApi.bulkDisableRedemptions(tenantID,ids),
    onSuccess:()=>{setSelectedRedemptionIDs([]);message.success('所选未使用兑换码已停用');refresh()},
    onError:(error:any)=>message.error(extractApiError(error)||'批量停用失败'),
  })
  const showRedemptionDetail=async(id:string)=>{
    const owner=tenantID
    try{const response=await billingAdminApi.redemptionDetails(owner,id);if(redemptionTenant.current===owner)setRedemptionDetail(response.data?.data)}
    catch(error){message.error(extractApiError(error)||'读取兑换详情失败')}
  }
  const exportRedemptionHints=async()=>{
    if(!redemptionFilters.batch.trim()){message.info('请先填写要导出的批次名称');return}
    setExporting(true)
    try{
      const response=await billingAdminApi.exportRedemptionHints(tenantID,redemptionFilters.batch.trim())
      const url=URL.createObjectURL(response.data),link=document.createElement('a')
      link.href=url;link.download='redemption-hints.csv';link.click();URL.revokeObjectURL(url)
    }catch(error){message.error(extractApiError(error)||'导出兑换码提示位失败')}finally{setExporting(false)}
  }
  const redemptions = unwrap(redemptionsQuery.data)
  const customerOptions = customers.filter((item: any) => item.user_id && (item.username || item.email)).map((item: any) => ({ value: item.user_id, label: item.username || item.email }))
  const walletOptions = customers.filter((item: any) => item.wallet_id).map((item: any) => ({ value: item.wallet_id, label: `${item.username || item.email || '已删除或不可见客户'} · ${toYuan(item.available_micros)}` }))
  // 冻结 payload 的本地引用：供弹窗展示待确认原值并禁用表单
  const creditFrozenPayload = creditPending?.payload || null
  const adjustFrozenPayload = adjustPending?.payload || null
  const groupNameByCode = new Map<string, string>(customerGroups.map((item: any): [string, string] => [item.code, item.name]))
  const groupOptions = customerGroups.filter((item: any) => item.status === 'active').map((item: any) => ({
    value: item.code, label: item.code === 'default' ? '默认客户组（default）' : `${item.name}（${item.code}）`,
  }))
  const openGroupEditor = (group?: any) => {
    setEditingGroup(group || null)
    groupForm.resetFields()
    groupForm.setFieldsValue(group ? {
      name: group.name, code: group.code, description: group.description || '', ratio: (group.ratio_ppm || MICROS_PER_YUAN) / MICROS_PER_YUAN,
    } : { ratio: 1 })
    setGroupOpen(true)
  }
  // 打开弹窗：有持久化的待确认操作则恢复（含冻结 payload 预填），否则新建幂等键
  const openCreditModal = (userId?: string) => {
    creditForm.resetFields()
    setCreditBlocked('')
    const state = readPendingWalletOps()
    if (!state.ops) {
      updateCreditPending(null)
      setCreditBlocked('待确认操作存储格式异常' + ' (' + state.status + ')')
      setCreditOpen(true)
      return
    }
    const stored = state.ops[pendingScope('credit')]
    if (stored) {
      updateCreditPending({ ...stored, scope: pendingScope('credit') })
      if (stored.payload) {
        creditForm.setFieldsValue({
          user_id: stored.payload.user_id,
          amount_yuan: Number(stored.payload.amount_micros) / MICROS_PER_YUAN,
          reason: stored.payload.reason,
        })
      } else if (userId) {
        creditForm.setFieldsValue({ user_id: userId })
      }
    } else {
      const op: PendingWalletOp = { idempotency_key: `console-credit:${crypto.randomUUID()}`, payload: null, owner_user_id: authUserID, scope: pendingScope('credit') }
      updateCreditPending(op)
      if (!writePendingWalletOp(pendingScope('credit'), op)) setCreditBlocked('待确认操作本地保存失败（存储不可用），已停止发送；请恢复存储后重试')
      if (userId) creditForm.setFieldsValue({ user_id: userId })
    }
    setCreditOpen(true)
  }
  const openAdjustModal = (walletId?: string) => {
    adjustForm.resetFields()
    setAdjustBlocked('')
    const state = readPendingWalletOps()
    if (!state.ops) {
      updateAdjustPending(null)
      setAdjustBlocked('待确认操作存储格式异常' + ' (' + state.status + ')')
      setAdjustOpen(true)
      return
    }
    const stored = state.ops[pendingScope('adjust')]
    if (stored) {
      updateAdjustPending({ ...stored, scope: pendingScope('adjust') })
      if (stored.payload) {
        adjustForm.setFieldsValue({
          wallet_id: stored.payload.wallet_id,
          amount_yuan: Number(stored.payload.amount_micros) / MICROS_PER_YUAN,
          reason: stored.payload.reason,
        })
      } else if (walletId) {
        adjustForm.setFieldsValue({ wallet_id: walletId })
      }
    } else {
      const op: PendingWalletOp = { idempotency_key: `console-adjustment:${crypto.randomUUID()}`, payload: null, owner_user_id: authUserID, scope: pendingScope('adjust') }
      updateAdjustPending(op)
      if (!writePendingWalletOp(pendingScope('adjust'), op)) setAdjustBlocked('待确认操作本地保存失败（存储不可用），已停止发送；请恢复存储后重试')
      if (walletId) adjustForm.setFieldsValue({ wallet_id: walletId })
    }
    setAdjustOpen(true)
  }

  const customerColumns = [
    { title: '客户', dataIndex: 'username', render: (value: string, row: any) => <Space direction="vertical" size={0}><Text strong>{value || row.email || '已删除或不可见客户'}</Text>{row.email && <Text type="secondary" style={{ fontSize: 12 }}>{row.email}</Text>}</Space> },
    { title: '客户组', dataIndex: 'customer_group', render: (value: string, row: any) => <Tag color={row.customer_group_status === 'disabled' ? 'default' : 'blue'}>{value === 'default' ? '默认客户组' : row.customer_group_name || groupNameByCode.get(value) || value}</Tag> },
    { title: '账户余额（含预占）', dataIndex: 'balance_micros', render: (value: unknown, row: any) => <Text strong>{formatMicros(value, row.currency)}</Text> },
    { title: '调用预占', dataIndex: 'reserved_micros', render: (value: unknown, row: any) => formatMicros(value, row.currency) },
    { title: '可用余额', dataIndex: 'available_micros', render: (value: unknown, row: any) => <Tag color={typeof value === 'number' && value > 0 ? 'green' : 'default'}>{formatMicros(value, row.currency)}</Tag> },
    { title: '操作', key: 'action', render: (_: any, row: any) => <Space><Button type="link" size="small" onClick={() => { groupAssignmentForm.setFieldsValue({ customer_group: row.customer_group || 'default' }); setAssignmentCustomer(row); setGroupAssignmentOpen(true) }}>调整分组</Button><Button type="link" size="small" onClick={() => openCreditModal(row.user_id)}>充值</Button>{row.wallet_id && <Button type="link" size="small" onClick={() => openAdjustModal(row.wallet_id)}>调账</Button>}</Space> },
  ]
  const groupColumns = [
    { title: '客户组', dataIndex: 'name', render: (value: string, row: any) => <Space><Text strong>{row.code === 'default' ? '默认客户组' : value}</Text><Text code>{row.code}</Text>{row.is_default && <Tag color="blue">默认</Tag>}</Space> },
    { title: '计费倍率', dataIndex: 'ratio_ppm', render: (value: number) => <Tag color="purple">{((value || MICROS_PER_YUAN) / MICROS_PER_YUAN).toFixed(2)}×</Tag> },
    { title: '说明', dataIndex: 'description', render: (value: string) => value || '-' },
    { title: '客户数', dataIndex: 'member_count' },
    { title: '状态', dataIndex: 'status',width:110, render: (value: string) => <Tag color={value === 'active' ? 'green' : 'default'}>{displayLabel(statusLabels, value)}</Tag> },
    { title: '操作', key: 'action', render: (_: any, row: any) => <Space><Button type="link" size="small" onClick={() => openGroupEditor(row)}>编辑</Button>{row.is_default ? <Text type="secondary">始终启用</Text> : <Button type="link" size="small" loading={groupStatusMutation.isPending} onClick={() => groupStatusMutation.mutate(row)}>{row.status === 'active' ? '停用' : '启用'}</Button>}</Space> },
  ]
  const redemptionTime = (value?: string) => value && dayjs(value).isValid() ? dayjs(value).format('YYYY-MM-DD HH:mm:ss') : '—'
  const redemptionColumns = [
    {title:'兑换码',dataIndex:'code_hint',width:180,render:(value:string)=><Text code style={{whiteSpace:'nowrap'}}>{value}</Text>},
    {title:'批次',dataIndex:'label',width:150,ellipsis:true},
    {title:'面值',dataIndex:'amount_micros',width:90,render:(value:number)=><span style={{whiteSpace:'nowrap',fontVariantNumeric:'tabular-nums'}}>{toYuan(value)}</span>},
    {title:'状态',dataIndex:'status',width:130,render:(value:string,row:any)=><Space direction="vertical" size={3}><Tag color={value==='active'?'green':value==='redeemed'?'blue':'default'}>{({active:'可用',redeemed:'已兑换',disabled:'已停用',expired:'已过期',voided:'已作废'} as Record<string,string>)[value]||'未知状态'}</Tag><Text type="secondary" style={{fontSize:12,whiteSpace:'nowrap'}} title="有效期">{row.expires_at?redemptionTime(row.expires_at):'长期有效'}</Text></Space>},
    {title:<span>创建人<span style={{display:'block',fontSize:12,fontWeight:400}}>创建时间</span></span>,key:'created',width:155,render:(_:unknown,row:any)=><Space direction="vertical" size={3}><Text ellipsis style={{maxWidth:123}}>{row.created_by_name||row.created_by||'—'}</Text><Text type="secondary" style={{fontSize:12,whiteSpace:'nowrap'}}>{redemptionTime(row.created_at)}</Text></Space>},
    {title:<span>兑换人<span style={{display:'block',fontSize:12,fontWeight:400}}>兑换时间</span></span>,key:'redeemed',width:150,render:(_:unknown,row:any)=>row.redeemed_by?<Space direction="vertical" size={2}><Text ellipsis style={{maxWidth:118}}>{row.redeemed_by}</Text><Text type="secondary" ellipsis style={{maxWidth:118,fontSize:12}}>{row.redeemed_department||'—'}</Text><Text type="secondary" style={{fontSize:12,whiteSpace:'nowrap'}}>{redemptionTime(row.redeemed_at)}</Text></Space>:'—'},
    { title: '操作', key: 'action',width:270,fixed:'right' as const, render: (_: any, row: any) => <Space>
      {authRole==='platform_admin'&&<Button type="link" style={{paddingInline:0}} size="small" loading={copyingRedemption===row.id} disabled={Boolean(copyingRedemption)&&copyingRedemption!==row.id} onClick={()=>void copyRedemption(row.id)}>复制兑换码</Button>}
      <Button type="link" style={{paddingInline:0}} size="small" onClick={()=>void showRedemptionDetail(row.id)}>详情</Button>
      {['active','disabled'].includes(row.status)&&<Button type="link" style={{paddingInline:0}} size="small" loading={redemptionStatusMutation.isPending} onClick={() => redemptionStatusMutation.mutate({ id: row.id, status: row.status === 'active' ? 'disabled' : 'active' })}>{row.status === 'active' ? '停用' : '启用'}</Button>}
      {!['redeemed','voided'].includes(row.status)&&<Button type="link" style={{paddingInline:0}} danger size="small" onClick={()=>Modal.confirm({title:'确认作废未使用兑换码？',content:'作废后永久无法兑换，也不能重新启用。',okText:'确认作废',cancelText:'取消',onOk:()=>redemptionStatusMutation.mutateAsync({id:row.id,status:'voided'})})}>作废</Button>}
      {authRole === 'platform_admin' && <Button type="link" style={{ paddingInline: 0 }} danger size="small" loading={deleteRedemptionMutation.isPending && deleteRedemptionMutation.variables?.id === row.id} onClick={() => Modal.confirm({
        title: '删除兑换码？', content: '删除后从列表移除，未使用的兑换码立即失效，已入账的充值和资金流水保留。',
        okText: '删除', okType: 'danger', cancelText: '取消',
        onOk: () => deleteRedemptionMutation.mutateAsync({ tenant: tenantID, id: row.id }),
      })}>删除</Button>}
    </Space> },
  ]
  const redemptionManagement=<Card style={{minWidth:0,overflow:'hidden'}} extra={<Button type="primary" icon={<PlusOutlined />} aria-label="生成兑换码" onClick={() => { redemptionForm.resetFields(); redemptionForm.setFieldsValue({ count: 1 }); setRedemptionOpen(true) }}>生成兑换码</Button>}>
    <Space wrap style={{marginBottom:16,gap:12}}>
      <Input style={{width:220}} aria-label="兑换码检索" placeholder="兑换码片段，如 97137" value={redemptionFilters.keyword} onChange={event=>changeRedemptionFilter('keyword',event.target.value)} maxLength={64} allowClear/>
      <Select aria-label="兑换码状态筛选" value={redemptionFilters.status||undefined} allowClear placeholder="全部状态" style={{width:140}} options={[{value:'active',label:'可用'},{value:'redeemed',label:'已兑换'},{value:'disabled',label:'已停用'},{value:'expired',label:'已过期'},{value:'voided',label:'已作废'}]} onChange={value=>changeRedemptionFilter('status',value||'')}/>
      <Input style={{width:200}} aria-label="批次筛选" placeholder="批次名称" value={redemptionFilters.batch} onChange={event=>changeRedemptionFilter('batch',event.target.value)} maxLength={80}/>
      <Input style={{width:200}} aria-label="兑换人筛选" placeholder="兑换人或部门" value={redemptionFilters.redeemer} onChange={event=>changeRedemptionFilter('redeemer',event.target.value)} maxLength={256}/>
      <Input type="datetime-local" style={{width:210}} aria-label="创建时间起" value={redemptionFilters.from} onChange={event=>changeRedemptionFilter('from',event.target.value)}/>
      <Input type="datetime-local" style={{width:210}} aria-label="创建时间止" value={redemptionFilters.to} onChange={event=>changeRedemptionFilter('to',event.target.value)}/>
      <Button disabled={!selectedRedemptionIDs.length} loading={bulkRedemptionMutation.isPending} onClick={()=>Modal.confirm({title:'确认批量停用所选未用兑换码？',okText:'确认停用',cancelText:'取消',onOk:()=>bulkRedemptionMutation.mutateAsync(selectedRedemptionIDs)})}>批量停用</Button>
      <Button loading={exporting} onClick={()=>void exportRedemptionHints()}>按批次导出 CSV</Button>
    </Space>
    <Table rowKey="id" columns={redemptionColumns} dataSource={redemptions} loading={redemptionsQuery.isLoading} tableLayout="fixed" scroll={{x:1157}}
      rowSelection={{selectedRowKeys:selectedRedemptionIDs,onChange:keys=>setSelectedRedemptionIDs(keys.map(String)),getCheckboxProps:(row:any)=>({disabled:['redeemed','voided'].includes(row.status)})}}
      pagination={{current:redemptionPage,pageSize:20,total:redemptionsQuery.data?.data?.meta?.total??redemptions.length,showSizeChanger:false,onChange:page=>{setRedemptionPage(page);setSelectedRedemptionIDs([])}}} locale={{ emptyText: '暂无兑换码' }} />
  </Card>

  const items = [
      { key: 'customers', label: '钱包账户', children: <Card extra={<Space><Input allowClear prefix={<SearchOutlined />} aria-label="客户检索" placeholder="搜索客户 / 邮箱 / 客户组" value={customerSearch} onChange={(event) => setCustomerSearch(event.target.value)} style={{ width: 240 }} /><Button type="primary" icon={<DollarOutlined />} aria-label="钱包充值" onClick={() => openCreditModal()}>钱包充值</Button></Space>}><Table rowKey="user_id" columns={customerColumns} dataSource={filteredCustomers} loading={customersQuery.isLoading} pagination={false} locale={{ emptyText: customerSearch.trim() ? '没有匹配的客户账户' : '暂无客户账户' }} />
        <CursorPagerBar pager={customersPager} unit="客户" />
      </Card> },
      { key: 'customer-groups', label: '客户组管理', children: <Card extra={<Button type="primary" icon={<PlusOutlined />} onClick={() => openGroupEditor()}>新增客户组</Button>}><Table rowKey="id" columns={groupColumns} dataSource={customerGroups} loading={groupsQuery.isLoading} pagination={false} locale={{ emptyText: '暂无客户组' }} /></Card> },
      { key: 'redemptions', label: '兑换码管理', children:redemptionManagement },
  ]
  const modals = <>


    <Modal title="钱包充值" okText={creditFrozenPayload ? '按原值重发' : '确认充值'} cancelText="取消" open={creditOpen} onCancel={() => setCreditOpen(false)} onOk={() => creditForm.submit()} confirmLoading={creditMutation.isPending}>
      {creditBlocked ? (
        <Alert type="error" showIcon style={{ marginBottom: 12 }} message={creditBlocked === '已成功入账但本地记录未清除' ? creditBlocked : '本次提交已被拦截，未发送任何资金请求'}
          description={creditBlocked === '已成功入账但本地记录未清除' ? creditPending?.idempotency_key : creditBlocked} />
      ) : null}
      {creditFrozenPayload && creditBlocked !== '已成功入账但本地记录未清除' && (
        <Alert type="warning" showIcon style={{ marginBottom: 12 }}
          message={<Space size={6} wrap><Tag color="gold">待确认</Tag><span>已有待确认的原值，重试将原样重发</span></Space>}
          description={<>
            <div style={{ marginBottom: 8 }}>这笔充值的入账结果尚未确认（可能是响应丢失、失败或与他人操作冲突）。金额、客户和原因已冻结且不可修改；请先到账本与客户账户核查是否已入账，再决定是否按同一幂等键重发。</div>
            <Descriptions size="small" column={1} style={{ marginTop: 4 }}>
              <Descriptions.Item label="客户">{customerOptions.find((item) => item.value === creditFrozenPayload.user_id)?.label || creditFrozenPayload.user_id}</Descriptions.Item>
              <Descriptions.Item label="金额">{toYuan(creditFrozenPayload.amount_micros)}</Descriptions.Item>
              <Descriptions.Item label="备注">{creditFrozenPayload.reason}</Descriptions.Item>
              <Descriptions.Item label="幂等键"><Text code style={{ fontSize: 12 }}>{creditPending?.idempotency_key}</Text></Descriptions.Item>
            </Descriptions>
          </>} />
      )}
      {/* 已提交 payload 不可改：冻结后表单禁用，只能原样重试或关闭核查 */}
      <Form form={creditForm} name="creditOp" layout="vertical" disabled={!!creditFrozenPayload} onFinish={submitCreditOp}>
        <Form.Item name="user_id" label="客户" rules={[{ required: true, message: '请选择客户' }]}><Select showSearch optionFilterProp="label" options={customerOptions} placeholder="选择客户账户" /></Form.Item>
        <Form.Item name="amount_yuan" label={`充值金额（${moneyUnit}）`} rules={[{ required: true, message: '请输入金额' }]}><TwoDecimalInput min={0.000001} style={{ width: '100%' }} /></Form.Item>
        <Form.Item name="reason" label="备注" rules={[{ required: true, whitespace: true, message: '请填写充值原因' }]}><Input maxLength={200} placeholder="例如：合同预付款" /></Form.Item>
      </Form>
    </Modal>
    <Modal title="钱包调账" okText={adjustFrozenPayload ? '按原值重发' : '确认调账'} cancelText="取消" open={adjustOpen} onCancel={() => setAdjustOpen(false)} onOk={() => adjustForm.submit()} confirmLoading={adjustMutation.isPending}>
      {adjustBlocked ? (
        <Alert type="error" showIcon style={{ marginBottom: 12 }} message={adjustBlocked === '已成功入账但本地记录未清除' ? adjustBlocked : '本次提交已被拦截，未发送任何资金请求'}
          description={adjustBlocked === '已成功入账但本地记录未清除' ? adjustPending?.idempotency_key : adjustBlocked} />
      ) : null}
      {adjustFrozenPayload && adjustBlocked !== '已成功入账但本地记录未清除' && (
        <Alert type="warning" showIcon style={{ marginBottom: 12 }}
          message={<Space size={6} wrap><Tag color="gold">待确认</Tag><span>已有待确认的原值，重试将原样重发</span></Space>}
          description={<>
            <div style={{ marginBottom: 8 }}>这笔调账的入账结果尚未确认（可能是响应丢失、失败或与他人操作冲突）。钱包、金额和原因已冻结且不可修改；请先到账本与客户账户核查是否已入账，再决定是否按同一幂等键重发。</div>
            <Descriptions size="small" column={1} style={{ marginTop: 4 }}>
              <Descriptions.Item label="钱包">{walletOptions.find((item) => item.value === adjustFrozenPayload.wallet_id)?.label || adjustFrozenPayload.wallet_id}</Descriptions.Item>
              <Descriptions.Item label="金额">{toYuan(adjustFrozenPayload.amount_micros)}</Descriptions.Item>
              <Descriptions.Item label="调账原因">{adjustFrozenPayload.reason}</Descriptions.Item>
              <Descriptions.Item label="幂等键"><Text code style={{ fontSize: 12 }}>{adjustPending?.idempotency_key}</Text></Descriptions.Item>
            </Descriptions>
          </>} />
      )}
      <Form form={adjustForm} name="adjustOp" layout="vertical" disabled={!!adjustFrozenPayload} onFinish={submitAdjustOp}>
        <Form.Item name="wallet_id" label="客户钱包" rules={[{ required: true, message: '请选择钱包' }]}><Select showSearch optionFilterProp="label" options={walletOptions} placeholder="选择已开通的钱包" /></Form.Item>
        <Form.Item name="amount_yuan" label={`调账金额（${moneyUnit}，负数为扣减）`} rules={[{ required: true, message: '请输入非零金额' }]}><TwoDecimalInput style={{ width: '100%' }} /></Form.Item>
        <Form.Item name="reason" label="调账原因" rules={[{ required: true, whitespace: true, message: '请填写调账原因' }]}><Input maxLength={200} /></Form.Item>
      </Form>
    </Modal>
    <Modal title={editingGroup ? '编辑客户组' : '新增客户组'} okText={editingGroup ? '确认保存' : '确认创建'} cancelText="取消" open={groupOpen} onCancel={() => { setGroupOpen(false); setEditingGroup(null) }} onOk={() => groupForm.submit()} confirmLoading={groupMutation.isPending}>
      <Form form={groupForm} layout="vertical" onFinish={(values) => groupMutation.mutate(values)}>
        <Form.Item name="name" label="客户组名称" rules={[{ required: true, message: '请输入客户组名称' }]}><Input maxLength={120} placeholder="例如：VIP 客户" /></Form.Item>
        <Form.Item name="code" label="客户组编码" rules={[{ required: true, message: '请输入客户组编码' }, { pattern: /^[a-z0-9][a-z0-9._-]{0,63}$/, message: '仅支持小写字母、数字、点、下划线和短横线' }]}><Input disabled={!!editingGroup} maxLength={64} placeholder="例如：vip" /></Form.Item>
        <Form.Item name="ratio" label="统一计费倍率" extra="该倍率自动应用于本组客户使用的所有模型。" rules={[{ required: true, message: '请输入计费倍率' }]}><TwoDecimalInput min={0.000001} max={1000} style={{ width: '100%' }} /></Form.Item>
        <Form.Item name="description" label="说明"><Input maxLength={255} placeholder="例如：合同 VIP 客户统一按 0.8 倍计费" /></Form.Item>
      </Form>
    </Modal>
    <Modal title={`调整客户组${assignmentCustomer ? ` - ${assignmentCustomer.username || assignmentCustomer.email}` : ''}`} okText="确认调整" cancelText="取消" open={groupAssignmentOpen} onCancel={() => { setGroupAssignmentOpen(false); setAssignmentCustomer(null) }} onOk={() => groupAssignmentForm.submit()} confirmLoading={groupAssignmentMutation.isPending}>
      <Form form={groupAssignmentForm} layout="vertical" onFinish={(values) => groupAssignmentMutation.mutate(values)}>
        <Form.Item name="customer_group" label="客户组" rules={[{ required: true, message: '请选择客户组' }]}>
          <Select showSearch optionFilterProp="label" options={groupOptions} placeholder="选择客户组" />
        </Form.Item>
      </Form>
    </Modal>
    <Modal title="生成兑换码" okText="确认生成" cancelText="取消" open={redemptionOpen} onCancel={() => setRedemptionOpen(false)} onOk={() => redemptionForm.submit()} confirmLoading={redemptionMutation.isPending}>
      <Form form={redemptionForm} layout="vertical" initialValues={{ count: 1 }} onFinish={(values) => redemptionMutation.mutate(values)}>
        <Form.Item name="label" label="批次名称" rules={[{ required: true, message: '请输入批次名称' }]}><Input maxLength={80} placeholder="例如：2026 年合同充值" /></Form.Item>
        <Form.Item name="amount_yuan" label={`单张面值（${moneyUnit}）`} rules={[{ required: true, message: '请输入单张面值' }]}><TwoDecimalInput min={0.000001} style={{ width: '100%' }} /></Form.Item>
        <Form.Item name="count" label="生成数量" rules={[{ required: true, message: '请输入生成数量' }]}><InputNumber min={1} max={500} precision={0} style={{ width: '100%' }} /></Form.Item>
        <Form.Item name="expires_at" label="有效期（可选）" rules={[{ validator: (_rule, value) => !value || value.isAfter(dayjs()) ? Promise.resolve() : Promise.reject(new Error('有效期必须晚于当前时间')) }]}><DatePicker showTime format="YYYY-MM-DD HH:mm:ss" placeholder="选择到期日期和时间" style={{ width: '100%' }} /></Form.Item>
      </Form>
    </Modal>
    <Modal title="请保存兑换码" open={codesOpen} onCancel={() => { setCodesOpen(false); setGeneratedCodes([]) }} footer={<Button onClick={() => { setCodesOpen(false); setGeneratedCodes([]) }}>我已保存</Button>}>
        <Input.TextArea readOnly autoSize={{ minRows: 8, maxRows: 18 }} value={generatedCodes.map((item) => item.code).join('\n')} />
    </Modal>
    <Modal title="复制兑换码" open={Boolean(copyFallback)} onCancel={()=>setCopyFallback('')} footer={<Button type="primary" onClick={()=>void copyCodeText(copyFallback).then(ok=>{if(ok){message.success('兑换码已复制');setCopyFallback('')}else message.info('请手动选择并复制')})}>复制完整兑换码</Button>}>
      <p>浏览器限制自动复制，请再次点击复制或手动选择。60 秒后自动隐藏。</p><Input.Password aria-label="完整兑换码" data-sensitive="redemption-code" readOnly value={copyFallback} autoComplete="off"/>
    </Modal>
    <Modal title="兑换详情" open={!!redemptionDetail} onCancel={()=>setRedemptionDetail(null)} footer={<Button onClick={()=>setRedemptionDetail(null)}>关闭</Button>}>
      {redemptionDetail&&<Descriptions column={1} size="small">
        <Descriptions.Item label="兑换码提示">{redemptionDetail.code_hint}</Descriptions.Item>
        <Descriptions.Item label="面值">{toYuan(redemptionDetail.amount_micros)}</Descriptions.Item>
        <Descriptions.Item label="兑换人">{redemptionDetail.redeemed_by||'—'}</Descriptions.Item>
        <Descriptions.Item label="部门">{redemptionDetail.department||'—'}</Descriptions.Item>
        <Descriptions.Item label="兑换时间">{redemptionTime(redemptionDetail.redeemed_at)}</Descriptions.Item>
        <Descriptions.Item label="账本记录">{redemptionDetail.ledger_id||'尚未兑换'}</Descriptions.Item>
        <Descriptions.Item label="钱包">{redemptionDetail.wallet_id||'—'}</Descriptions.Item>
      </Descriptions>}
    </Modal>
  </>
  return { items, modals, customers, customersQuery, groupsQuery, redemptionsQuery }
}
