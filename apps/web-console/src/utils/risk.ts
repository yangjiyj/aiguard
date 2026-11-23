import { isKnownAgentType } from './agents'
import policyCatalogLabels from './policy_catalog_labels.json'
import { GATEWAY_CODE_LIKE, GATEWAY_REASON_LABELS, translateGatewayReason } from './gatewayReasonLabels'
export const RISK_CATEGORY_LABELS: Record<string, string> = {
  // 策略目录名称来自迁移 156-165；下方人工名称优先覆盖已有客户口径。
  ...policyCatalogLabels,
  // Claude Code 客户端 Unicode 隐写后门指纹（prompt_stego 检测器）— 专属中文，不落入泛化“其他风险”
  prompt_stego: 'Prompt隐写（客户端指纹后门）',
  apostrophe_variant: 'Prompt隐写：撇号同形字(U+2019/02BC/02B9)',
  date_separator_variant: 'Prompt隐写：日期分隔符指纹(时区)',
  zero_width_char: 'Prompt隐写：零宽字符',
  prompt_injection: 'Prompt 注入',
  prompt_input_semantic_risk: 'Prompt 注入语义风险',
  semantic_jailbreak: '语义越狱',
  semantic_roleplay: '语义角色扮演绕过',
  semantic_instruction_override: '语义指令篡改',
  semantic_exfil_induce: '语义数据诱导外泄',
  semantic_harassment: '语义骚扰',
  semantic_threat: '语义威胁',
  semantic_hate: '语义仇恨',
  eval_content_safety: '大模型评估内容风险',
  content_safety: '内容与数据',
  agent_detect: '智能体行为',
  data_leak: '数据泄露',
  pii: '个人信息泄露',
  secret: '敏感凭据泄露',
  prompt_leak: '提示词泄露',
  code_security: '代码安全',
  code_config: '代码安全',
  fraud_detect: '欺诈风险',
  dos_protection: '资源耗尽',
  plugin_security: '插件/MCP 风险',
  tool_call_policy: '工具调用',
  agent_permission_policy: '智能体权限',
  network_egress_policy: '网络外联',
  file_access_policy: '文件访问',
  database_access_policy: '数据库访问',
  model_access_policy: '模型访问',
  exception_policy: '例外规则',
  alert_disposition_policy: '告警处置',
  provenance: '来源可信度',
  argument_tainted: '参数来源不可信',
  command: '命令参数',
  command_shell_metacharacter: '命令包含特殊字符',
  illegal_trade: '违规交易',
  copyright_protect: '版权风险',
  rag_security: 'RAG 风险',
  supply_chain: '供应链风险',
  tool_call: '工具风险',
  tool_risk: '工具风险',
  security_check: '安全检测',
  // 收件箱日聚合卡类型可能作为告警分组/风险原因流入本字典，补中文防露英文
  security_event: '安全事件',
  runtime_fault: '运行故障',
  access_governance: '访问治理',
  security_check_failed: '检测未完成',
  security_event_daily_summary: '安全事件日聚合',
  keyword_classic_injection: 'Prompt 注入',
  aws_secret_key: '敏感凭据泄露',
  aws_access_key: '敏感凭据泄露',
  github_token: '敏感凭据泄露',
  openai_key: '敏感凭据泄露',
  jwt_token: '敏感凭据泄露',
  ssh_private_key: '敏感凭据泄露',
  generic_api_key: '敏感凭据泄露',
  config_file: '配置文件风险',
  env_file: '配置文件风险',
  phone_cn: '手机号',
  id_card_cn: '身份证号',
  bank_card_cn: '银行卡号',
  email: '邮箱地址',
  passport_cn: '护照号码',
  hk_macao_taiwan_id: '港澳台居民证件',
  officer_id_cn: '军警人员证件',
  driver_license_cn: '驾驶证号码',
  social_security_cn: '社会保障卡号',
  home_address_cn: '家庭住址',
  ip_address: 'IP 地址',
  birth_date: '出生日期',
  communication_record: '通信记录',
  gps_location: 'GPS 位置数据',
  plain_password: '明文密码',
  cloud_credential: '云平台凭据',
  credit_card_cvv: '信用卡安全码',
  bank_statement: '银行流水',
  insurance_info: '保险与理赔信息',
  medical_record: '医疗病历',
  genetic_data: '基因数据',
  biometric_data: '生物特征数据',
  internal_project_code: '内部项目代号',
  sensitive_code: '敏感源代码',
  education_background: '教育背景',
  criminal_record: '犯罪与刑事记录',
  // 数据安全 / 自定义企业敏感数据识别
  data_security: '数据安全',
  custom: '客户敏感数据',
  // 行业预置数据安全规则包（迁移 068）category→中文大类：
  // 配置页「类型」列、访问留存与安全告警共用同一字典回显；用大类而非具体规则名，避免与规则名重复。
  pii_idcard: '个人信息',
  pii_phone: '个人信息',
  pii_bankcard: '个人信息',
  pii_email: '个人信息',
  pii_passport: '个人信息',
  medical_record_id: '医疗数据',
  medical_insurance_id: '医疗数据',
  medical_dicom_accession: '医学影像',
  medical_dicom_uid: '医学影像',
  medical_diagnosis: '医疗数据',
  medical_device_serial: '医疗设备',
  finance_account: '金融数据',
  finance_txn: '金融数据',
  finance_uscc: '金融数据',
  // 文件格式管控（engine 文件检视器）
  file_security: '文件安全',
  file_fingerprint: '文件指纹',
  file_archive: '压缩包外发审计',
  file_type_mismatch: '文件类型不符审计',
  file_unknown_type: '未知文件类型审计',
  file_oversized: '超大文件外发审计',
  file_policy_not_allowed: '非常用文件类型审计',
  file_policy_review_type: '文件类型复核审计',
  file_policy_blocked_type: '禁用文件类型',
  file_path_traversal: '异常文件路径',
  file_script: '脚本文件',
  file_id_unverified: '未核验的文件引用',
  file_id_lookup_failed: '文件引用核验失败',
  structured_html_comment: 'HTML 注释结构审计',
  structured_template_injection: '模板结构审计',
  private_key: '私钥外发',
  credential_path: '系统凭证路径',
  malicious_script: '恶意脚本外发',
  cloud_metadata: '云元数据地址',
  internal_endpoint: '内网高危地址',
  // MCP 安全网关：事件/来源枚举中文，保证 MCP 事件流入安全告警收件箱不露英文
  mcp_manifest_changed: 'MCP 能力变更',
  mcp_tool_call: 'MCP 工具调用',
  mcp_tool_call_blocked: 'MCP 工具调用阻断',
  mcp_tool_call_confirm: 'MCP 工具调用待确认',
  mcp_gateway: 'MCP 安全网关',
  gateway_mcp: 'MCP 安全网关',
  // 客户现场 2.9.15 告警组 class_key 中缺失或被子串规则误判的类别
  keyword_classic_injection_en: 'Prompt 注入',
  customer_sensitive_data: '客户敏感数据',
  tool_attempt_blocked: '智能体工具调用拦截',
  agent_tool_failure_loop: '智能体工具连续失败',
  unapproved_model_egress: '未批准的模型调用',
  mcp_policy: 'MCP 禁用策略命中',
  agent_behavior_policy: '智能体行为策略告警',
  restricted_file_access: '受限文件访问',
  agentguard_confirmation: '人工确认后放行一次',
  agent_permission_governance: '智能体权限治理',
  destructive_change: '删除与破坏操作',
  skill_invocation_risk: 'Skill 调用风险',
  // === class_key 对账补全（engine_categories.json 全量枚举，缺失即单测失败）===
  // data_leak 检测器（category = <大类>_<type>）
  classified_classified_cn: '涉密标识外发（中文）',
  classified_classified_en: '涉密标识外发（英文）',
  sensitive_file_internal_doc: '内部文档外发',
  sensitive_file_customer_data: '客户资料外发',
  sensitive_file_hr_data: 'HR 数据外发',
  sensitive_file_financial_data: '财务数据外发',
  code_leak_password_in_code: '代码中的明文密码',
  code_leak_access_key: '代码中的访问密钥',
  code_leak_database_url: '数据库连接串外泄',
  code_leak_api_key_leak: '代码中的 API 密钥',
  code_leak_token_leak: '代码中的令牌泄露',
  code_leak_cloud_credential: '云平台凭据外泄',
  // content_safety 二级标签（不折进泛化"内容合规风险"，设计 3b 明确要求）
  political_leader_name: '涉国家领导人敏感内容',
  political_territory_taiwan: '涉台分裂内容',
  political_territory_split: '涉藏疆港分裂内容',
  political_sensitive_event: '政治敏感事件',
  political_historical_nihilism: '历史虚无主义内容',
  political_ethnic_separatism: '民族分裂内容',
  illegal_pornography: '色情低俗内容',
  illegal_violence_terror: '暴力恐怖内容',
  illegal_gambling: '赌博相关内容',
  illegal_fraud: '诈骗相关内容',
  illegal_drugs: '毒品相关内容',
  // 内置“辱骂脏话”能力（迁移 992）；旧的“操你妈”强辱骂规则同属此策略
  content_profanity_abuse: '辱骂脏话',
  harassment_profanity_cn: '中文强辱骂组合',
  illegal_cyber_attack: '网络攻击工具/手法',
  illegal_hazardous_chemical_instructions: '危险化学品/爆炸物制备指导',
  illegal_system_command_instructions: '高危系统命令/提权指令',
  self_harm_actionable_guidance: '自伤自杀可操作指导',
  debug_secret_template: '密钥/凭据套取模板',
  ssrf_metadata_instruction: 'SSRF 元数据探测指令',
  agent_canary_token_leak: 'Agent 蜜签令牌外泄',
  discrimination_racial_discrimination: '种族歧视内容',
  discrimination_regional_discrimination: '地域歧视内容',
  discrimination_gender_discrimination: '性别歧视内容',
  multilingual_uyghur_kazakh: '维哈语小语种内容',
  multilingual_tibetan: '藏文小语种内容',
  multilingual_mongolian: '蒙古文小语种内容',
  multilingual_cyrillic: '西里尔文小语种内容',
  multilingual_arabic: '阿拉伯文小语种内容',
  // prompt_injection 语义/结构层（semantic_ 前缀会被"语义攻击"兜底吃掉，需精确二级名）
  semantic_step_by_step_bypass: 'Prompt 注入：分步绕过',
  semantic_hypothetical_bypass: 'Prompt 注入：假设场景绕过',
  semantic_negation_bypass: 'Prompt 注入：否定式绕过',
  semantic_translation_bypass: 'Prompt 注入：翻译绕过',
  structured_code_block_injection: 'Prompt 注入：代码块注入',
  // prompt_stego 补漏
  quote_variant: 'Prompt隐写：引号同形字',
  // engine 内置密钥类补漏
  anthropic_key: '敏感凭据泄露：Anthropic 密钥',
}

// MCP 工具风险标注中文：服务管理工具清单 / 审计详情共用（自动标注五类）
export const MCP_RISK_TAG_LABELS: Record<string, string> = {
  destructive: '破坏性',
  network_egress: '外联',
  data_export: '数据导出',
  cred_access: '凭证访问',
  file_write: '文件写入',
}

export const MCP_RISK_TAG_COLORS: Record<string, string> = {
  destructive: 'red',
  network_egress: 'blue',
  data_export: 'orange',
  cred_access: 'magenta',
  file_write: 'gold',
}

// 兜底也走中文字典（getRiskCategoryLabel 未知值收敛到“其他风险”），杜绝裸英文标签
export const getMcpRiskTagLabel = (value?: string) => {
  if (!value) return '未标注'
  return MCP_RISK_TAG_LABELS[value] || getRiskCategoryLabel(value)
}

// MCP 工具风险标签「图例」文案：服务管理工具清单抽屉 + 审计详情图例共用，
// 让客户看懂五类自动风险标注各代表什么能力（只加不改，供新页与打磨页复用）。
export const MCP_RISK_TAG_DESCRIPTIONS: Record<string, string> = {
  destructive: '具备删除、覆盖、重置等破坏性副作用的工具',
  network_egress: '会主动发起外部网络请求，存在数据外联通道',
  data_export: '可批量导出、下载或转储数据',
  cred_access: '会读取令牌、密钥、口令等敏感凭据',
  file_write: '可写入或修改本地/远端文件',
}
export const getMcpRiskTagDescription = (value?: string) => {
  if (!value) return '未归类的工具能力'
  return MCP_RISK_TAG_DESCRIPTIONS[value] || '其他需关注的工具能力'
}
// 图例遍历顺序固定，避免每次渲染顺序抖动
export const MCP_RISK_TAG_ORDER = ['destructive', 'cred_access', 'network_egress', 'data_export', 'file_write'] as const
// 高危标签集合：破坏性 / 凭证访问计入「高危工具」计数
export const MCP_HIGH_RISK_TAGS = new Set(['destructive', 'cred_access'])

// 二期「描述投毒」标记中文（observe-only）：车道A 扫描 MCP 工具描述命中的投毒模式类别，
// 附在工具的 poison_flags 上。这里给每个类别中文名 + 说明，供工具清单抽屉红标 tooltip 复用。
// 语气为「风险提示」而非「已拦截」——observe-only 只提示不阻断。
export const MCP_POISON_FLAG_LABELS: Record<string, string> = {
  instruction_override: '指令覆盖',
  role_manipulation: '角色操纵',
  jailbreak: '越狱诱导',
  hidden_instruction: '隐藏指令',
  fake_system_marker: '伪系统标记',
  covert: '隐蔽规避',
  anti_detection: '反侦测规避',
  exfil_induce: '数据外传诱导',
  data_exfiltration: '数据外传诱导',
  mcp_description_poison: '描述投毒',
  mcp_description_poison_semantic: '描述投毒（语义复核）',
  tool_definition_drift: '工具定义漂移',
}
export const MCP_POISON_FLAG_DESCRIPTIONS: Record<string, string> = {
  instruction_override: '工具描述中试图覆盖或忽略调用方 agent 的系统指令',
  role_manipulation: '工具描述中试图重设 agent 的角色或人格',
  jailbreak: '工具描述中含越狱、开发者模式等绕过诱导',
  hidden_instruction: '工具描述中夹带面向 agent 的隐藏指令',
  fake_system_marker: '工具描述中伪造 <system>/<important> 等系统标记',
  covert: '工具描述中要求隐瞒用户、规避其察觉',
  anti_detection: '工具描述中含反侦测、规避审计的诱导',
  exfil_induce: '工具描述中诱导外传密钥、令牌、凭证等敏感数据',
  data_exfiltration: '工具描述中诱导外传密钥、令牌、凭证等敏感数据',
  mcp_description_poison: '工具描述整体疑似投毒（藏有操纵调用方 agent 的指令）',
  mcp_description_poison_semantic: '经语义模型复核，工具描述疑似投毒（藏有操纵调用方 agent 的指令）',
  tool_definition_drift: '工具定义指纹发生漂移，可能被替换或篡改',
}
export const getMcpPoisonFlagLabel = (value?: string) => {
  if (!value) return '疑似投毒'
  return MCP_POISON_FLAG_LABELS[value] || getRiskCategoryLabel(value)
}
export const getMcpPoisonFlagDescription = (value?: string) => {
  if (!value) return '工具描述中检测到疑似操纵调用方的内容'
  return MCP_POISON_FLAG_DESCRIPTIONS[value] || '工具描述中检测到疑似操纵调用方的内容'
}

// MCP 服务信任级别语义说明：注册/编辑表单与列表 Tooltip 共用（对齐 allow_private_egress 的 SSRF 说明范式）。
export const MCP_TRUST_LEVEL_DESCRIPTIONS: Record<string, string> = {
  low: '低信任：默认档位，工具调用一律从严审计，适合外部/第三方 MCP 服务。',
  medium: '中信任：经初步核验的服务，仍保留完整留痕与安全策略约束。',
  high: '高信任：企业自建、已充分验证的服务；仍受安全与权限策略约束，信任级别不等于放行。',
  trusted: '可信：已充分验证的服务，仍受安全策略约束。',
  verified: '已验证：通过验证流程的服务。',
  untrusted: '不可信：来源存疑，建议停用或从严管控。',
}
export const getMcpTrustLevelDescription = (value?: string) =>
  value ? MCP_TRUST_LEVEL_DESCRIPTIONS[value] || '自定义信任级别，按低信任从严处理。' : ''

// MCP 服务状态语义说明。
export const MCP_SERVER_STATUS_DESCRIPTIONS: Record<string, string> = {
  active: '启用：允许经网关路由该服务的工具调用。',
  disabled: '停用：网关拒绝路由该服务，已注册资产与工具清单保留不删。',
  inactive: '停用：网关拒绝路由该服务。',
}
export const getMcpServerStatusDescription = (value?: string) =>
  value ? MCP_SERVER_STATUS_DESCRIPTIONS[value] || '自定义服务状态。' : ''

// MCP「测试连接」结构化错误分类中文回显：把探测失败归因为可读的运维原因，
// 杜绝界面裸露 error_kind 英文枚举（DNS/超时/401/TLS 等）。
export const MCP_TEST_CONN_ERROR_LABELS: Record<string, string> = {
  dns: '域名解析失败：服务地址的主机名无法解析，请核对地址拼写与 DNS 配置。',
  timeout: '连接超时：限定时间内未建立连接，请确认服务在线且网络可达。',
  connection_refused: '连接被拒绝：目标端口未监听或被防火墙拦截。',
  tls: 'TLS 握手失败：证书不受信任或协议不匹配，请核对 HTTPS 证书。',
  unauthorized: '鉴权失败（401）：鉴权令牌缺失或无效，请更新该服务的鉴权令牌。',
  forbidden: '访问被拒（403）：当前令牌无权访问该 MCP 服务。',
  http_error: '服务返回错误：目标返回非成功状态码。',
  protocol: '协议不符：目标未按 MCP 协议应答，可能不是有效的 MCP 服务地址。',
  http_401: '鉴权失败（401）：密钥无效，或鉴权位置、参数名、值格式与厂商要求不一致，请核对「上游连接」中的鉴权设置。',
  http_403: '访问被拒（403）：密钥无权访问该服务，或缺少厂商要求的额外请求头（如账户标识）。',
  http_429: '上游限流（429）：请求过于频繁，请按提示的等待时间稍后重试。',
  http_5xx: '上游服务端错误（5xx）：厂商服务暂时不可用，请稍后重试。',
  http: '上游返回非成功状态码，请查看下方响应摘要。',
  not_jsonrpc: '上游返回 HTTP 200 但不是合法的 MCP 响应（疑似鉴权失败）：请核对密钥与鉴权位置。',
  oauth_required: '上游要求 OAuth 2.1 授权，当前版本暂不支持，请改用 API Key 方式或联系厂商。',
  rpc_error: '上游在握手阶段返回了错误响应，请查看下方说明。',
  cross_origin: '上游 SSE 返回的消息端点与服务地址不同源，已按 SSRF 防护拒绝。',
  sse_endpoint: '无法获得上游 SSE 的消息端点：地址可能不是旧版 SSE 端点，或鉴权未通过。',
  not_streamable: '上游不是 Streamable HTTP 端点（返回了网页或其它格式），可尝试改用「SSE（旧版）」或「自动识别」。',
  redirect: '上游返回了重定向，网关不跟随重定向，请直接填写最终服务地址。',
  stream_closed: '上游 SSE 连接已断开。',
  capacity: '上游响应超过容量上限。',
  connect: '无法连接上游：请确认地址与网络可达。',
  parse: '上游响应无法解析，或协议版本不受支持，请查看下方说明。',
  auth: '鉴权配置无效：请检查鉴权位置、参数名、值模板与额外请求头设置。',
  url: '服务地址未通过出站安全校验：内网/环回地址需在服务配置中显式放行。',
  private_egress_blocked: '内网地址被封禁：目标指向内网/环回地址，需在服务配置中显式放行后重试（防 SSRF）。',
  unknown: '连接失败：请确认服务地址可达、鉴权令牌有效。',
}
export const getMcpTestConnErrorLabel = (kind?: string, fallback?: string) => {
  if (kind && MCP_TEST_CONN_ERROR_LABELS[kind]) return MCP_TEST_CONN_ERROR_LABELS[kind]
  if (fallback) return fallback
  return MCP_TEST_CONN_ERROR_LABELS.unknown
}
// 后端 message 已脱敏且为中文，含响应摘要等关键信息，应与分类说明一并展示。
export const getMcpTestConnErrorDetail = (kind?: string, message?: string) => {
  const label = getMcpTestConnErrorLabel(kind, message)
  return message && message !== label ? message : ''
}

// MCP 审计明细 JSON-RPC 报文字段中文标签：调用详情抽屉展示原始 method/id/arguments 时用，避免裸英文键。
export const MCP_JSONRPC_FIELD_LABELS: Record<string, string> = {
  method: 'JSON-RPC 方法',
  id: '请求 ID',
  jsonrpc: '协议版本',
  params: '调用参数',
  arguments: '原始入参',
  name: '工具名',
}
export const getMcpJsonRpcFieldLabel = (key: string) => MCP_JSONRPC_FIELD_LABELS[key] || key

export const DECISION_LABELS: Record<string, string> = {
  allow: '放行',
  audit: '仅记录',
  confirm: '人工确认',
  block: '阻断',
}

export const EXECUTION_MODE_LABELS: Record<string, string> = {
  observe: '观察模式',
  audit: '审计模式',
  strict: '严格模式',
  enforce: '强制模式',
  shadow: '影子模式',
}

export const PROVENANCE_LABELS: Record<string, string> = {
  tainted: '来源不可信',
  trusted: '来源可信',
  user: '用户输入',
  model: '模型生成',
  system: '系统生成',
}

export const TOOL_STATUS_LABELS: Record<string, string> = {
  success: '执行成功',
  blocked: '已阻断',
  audited: '仅记录',
  failed: '执行失败',
  error: '执行异常',
  pending: '等待确认',
}

export const TOOL_EVIDENCE_RULE_LABELS: Record<string, string> = {
  argument_tainted: '参数来源不可信',
  command_shell_metacharacter: '命令包含特殊字符',
  provenance: '来源可信度异常',
  command: '命令参数',
  normalized_target: '风险目标',
}

export const TOOL_PARAMETER_LABELS: Record<string, string> = {
  command: '命令内容',
  cmd: '命令内容',
  input: '输入内容',
  url: '目标地址',
  uri: '目标地址',
  endpoint: '目标地址',
  path: '文件路径',
  file: '文件路径',
  body: '请求正文',
  method: '请求方法',
  headers: '请求头',
  query: '查询条件',
  database: '数据库',
  _audit_notes: '审计补全说明',
}

// 网关为保证审计记录能入库而补过默认值时，在参数里留下 _audit_notes 标记（见 gateway-core tool_interceptor.go）。
export const TOOL_AUDIT_NOTE_LABELS: Record<string, string> = {
  tool_name_missing: '上游未提供工具名称，已记为“unknown”',
  tool_type_missing: '上游未提供工具类型，已按工具名称推断或记为“unknown”',
}
export const getToolAuditNoteLabel = (value?: string) =>
  value ? TOOL_AUDIT_NOTE_LABELS[value] || '审计补全说明（未识别）' : '审计补全说明（未识别）'

export const TOOL_NAME_LABELS: Record<string, string> = {
  bash: '系统命令工具',
  shell: '系统命令工具',
  terminal: '系统命令工具',
  read: '文件读取工具',
  write: '文件写入工具',
  edit: '文件编辑工具',
  multiedit: '批量文件编辑工具',
  glob: '文件检索工具',
  grep: '内容检索工具',
  webfetch: '网络请求工具',
  websearch: '网络搜索工具',
  'network.fetch': '网络请求工具',
  'network.upload': '网络上传工具',
  'file.read': '文件读取工具',
  'file.write': '文件写入工具',
}

export const getToolNameLabel = (value?: string) => {
  if (!value) return '未知工具'
  const text = String(value).trim()
  if (!text) return '未知工具'
  const normalized = text.toLowerCase()
  if (TOOL_NAME_LABELS[normalized]) return TOOL_NAME_LABELS[normalized]
  if (normalized.startsWith('network.')) return '网络访问工具'
  if (normalized.startsWith('file.')) return '文件操作工具'
  if (normalized.startsWith('mcp.')) return 'MCP 工具调用'
  if (/^[a-z0-9_.:-]+$/i.test(text)) return '自定义工具调用'
  return text
}

export const getDecisionLabel = (value?: string) =>
  value
    ? DECISION_LABELS[value] || GATEWAY_REASON_LABELS[value] || '未知动作'
    : '未记录'
export const getExecutionModeLabel = (value?: string) =>
  value ? EXECUTION_MODE_LABELS[value] || '自定义模式' : '未记录'
export const getProvenanceLabel = (value?: string) =>
  value ? PROVENANCE_LABELS[value] || '来源待核验' : '未记录'
export const getToolStatusLabel = (value?: string) =>
  value ? TOOL_STATUS_LABELS[value] || '状态待核验' : '未记录'
export const getReadableToolReason = (value?: string) => {
  if (!value) return '按策略命中'
  const translated = translateGatewayReason(String(value))
  if (translated) return translated
  const toolMatch = String(value).match(/^工具名称精确匹配[:：]\s*(.+)$/)
  if (toolMatch) return `工具名称精确匹配：${getToolNameLabel(toolMatch[1])}`
  if (GATEWAY_CODE_LIKE.test(String(value))) return '按工具安全策略命中'
  return String(value)
}
export const getToolEvidenceRuleLabel = (value?: string) =>
  value
    ? TOOL_EVIDENCE_RULE_LABELS[value] ||
      RISK_CATEGORY_LABELS[value] ||
      '安全证据'
    : '安全证据'
export const getToolParameterLabel = (value?: string) =>
  value ? TOOL_PARAMETER_LABELS[value] || '参数项' : '参数项'

export const TOOL_TYPE_RISK_LABELS: Record<string, string> = {
  file: '文件操作',
  network: '网络外联',
  database: '数据库访问',
  mcp: 'MCP 风险',
  system: '系统命令',
}

export const TOOL_MATCH_DESCRIPTIONS: Record<string, string> = {
  file: '按工具名称精确匹配文件读写策略',
  network: '按工具名称精确匹配网络外联策略',
  database: '按工具名称精确匹配数据库访问策略',
  mcp: '按工具名称精确匹配 MCP 工具策略',
  system: '按工具名称精确匹配系统命令策略',
}

const RULE_LABELS: Record<string, string> = {
  prompt_injection_classic_injection: 'Prompt 注入：经典指令绕过',
  prompt_injection_roleplay: 'Prompt 注入：角色扮演绕过',
  prompt_injection_forget_restriction: 'Prompt 注入：忽略限制诱导',
  prompt_injection_reverse_induction: 'Prompt 注入：反向诱导',
  prompt_injection_conditional_bypass: 'Prompt 注入：条件绕过',
  prompt_injection_base64: 'Prompt 注入：编码混淆',
  prompt_injection_hex_escape: 'Prompt 注入：十六进制混淆',
  prompt_injection_unicode_escape: 'Prompt 注入：Unicode 混淆',
  prompt_injection_zero_width: 'Prompt 注入：零宽字符混淆',
  prompt_injection_step_by_step_bypass: 'Prompt 注入：分步绕过',
  prompt_injection_hypothetical_bypass: 'Prompt 注入：假设场景绕过',
  prompt_injection_negation_bypass: 'Prompt 注入：否定式绕过',
  prompt_injection_translation_bypass: 'Prompt 注入：翻译绕过',
  prompt_injection_html_comment: 'Prompt 注入：HTML 注释混淆',
  prompt_injection_template_injection: 'Prompt 注入：模板注入',
  prompt_injection_code_block_injection: 'Prompt 注入：代码块注入',
  // 凭据/配置/数据外泄类常见规则的中文名（避免界面回显英文规则 ID）
  secret_aws_secret_key: '敏感凭据泄露：AWS 密钥',
  secret_aws_access_key: '敏感凭据泄露：AWS Access Key',
  secret_github_token: '敏感凭据泄露：GitHub Token',
  secret_openai_key: '敏感凭据泄露：OpenAI 密钥',
  secret_generic_api_key: '敏感凭据泄露：通用 API 密钥',
  secret_ssh_private_key: '敏感凭据泄露：SSH 私钥',
  secret_jwt_token: '敏感凭据泄露：JWT 令牌',
  code_config_file: '配置文件外泄',
  code_env_file: '环境变量文件外泄',
  config_file: '配置文件外泄',
  env_file: '环境变量文件外泄',
  sensitive_file_hr_data: 'HR 敏感文件',
  data_leak_hr_data: 'HR 数据外泄',
  data_leak_financial: '财务数据外泄',
  data_leak_customer: '客户数据外泄',
  // 内容安全规则中文名（与 security-engine RULE_NAMES 对齐；历史记录无 rule_name 时回显这里）
  content_safety_illegal_pornography: '色情低俗内容',
  content_safety_illegal_violence_terror: '暴力恐怖内容',
  content_safety_illegal_gambling: '赌博相关内容',
  content_safety_illegal_fraud: '诈骗相关内容',
  content_safety_illegal_drugs: '毒品相关内容',
  content_safety_illegal_cyber_attack: '网络攻击工具/手法',
  content_safety_political_leader_name: '涉国家领导人敏感内容',
  content_safety_political_territory_taiwan: '涉台分裂内容',
  content_safety_political_territory_split: '涉藏疆港分裂内容',
  content_safety_political_sensitive_event: '政治敏感事件',
  content_safety_political_historical_nihilism: '历史虚无主义内容',
  content_safety_political_ethnic_separatism: '民族分裂内容',
  content_safety_discrimination_racial_discrimination: '种族歧视内容',
  content_safety_discrimination_regional_discrimination: '地域歧视内容',
  content_safety_discrimination_gender_discrimination: '性别歧视内容',
  content_safety_multilingual_uyghur_kazakh: '维哈语小语种内容',
  content_safety_multilingual_tibetan: '藏文小语种内容',
  content_safety_multilingual_mongolian: '蒙古文小语种内容',
  content_safety_multilingual_cyrillic: '西里尔文小语种内容',
  content_safety_multilingual_arabic: '阿拉伯文小语种内容',
  content_safety_illegal_hazardous_chemical_instructions: '危险化学品/爆炸物制备指导',
  content_safety_self_harm_actionable_guidance: '自伤自杀可操作指导',
  content_safety_illegal_system_command_instructions: '高危系统命令/提权指令',
  content_safety_debug_secret_template: '密钥/凭据套取模板',
  content_safety_ssrf_metadata_instruction: 'SSRF 元数据探测指令',
  content_safety_agent_canary_token_leak: 'Agent 蜜签令牌外泄',
  content_safety_profanity_abuse: '辱骂脏话',
  content_safety_harassment_profanity_cn: '中文强辱骂内容',
}

const CATEGORY_FAMILY_LABELS: Record<string, string> = {
  agent: '智能体安全',
  code: '代码安全',
  content: '内容安全',
  content_safety: '内容安全',
  copyright: '版权风险',
  discrimination: '歧视与偏见',
  dos: '资源耗尽防护',
  fraud: '欺诈风险',
  illegal: '违法违规内容',
  injection: '提示注入',
  keyword: '提示注入',
  encoding: '提示注入',
  context: '提示注入',
  markup: '提示注入',
  multilingual: '多语言内容',
  political: '政治敏感内容',
  plugin: '插件与工具安全',
  prompt: '提示词安全',
  rag: 'RAG 安全',
  semantic: '语义安全',
  supply: '模型供应链安全',
}

// 对未单独登记的引擎分类保留中文大类，并把细分类拆成可读标签，避免回显原始 snake_case key。
export const getSpecificRiskCategoryLabel = (value: string) => {
  const normalized = String(value || '').trim().toLowerCase()
  if (!normalized) return ''
  const contentSafetyPrefix = 'content_safety_'
  const familyKey = normalized.startsWith(contentSafetyPrefix)
    ? 'content_safety'
    : normalized.split('_', 1)[0]
  const family = CATEGORY_FAMILY_LABELS[familyKey]
  if (!family) return ''
  const detail = normalized.startsWith(contentSafetyPrefix)
    ? normalized.slice(contentSafetyPrefix.length)
    : normalized.slice(familyKey.length).replace(/^_/, '')
  return detail ? `${family}：${detail.replace(/_/g, ' · ')}` : family
}

export const getRiskCategoryLabel = (value?: string) => {
  if (!value) return '未分类'
  if (RISK_CATEGORY_LABELS[value]) return RISK_CATEGORY_LABELS[value]
  if (RULE_LABELS[value]) return RULE_LABELS[value]
  const specific = getSpecificRiskCategoryLabel(value)
  if (specific) return specific
  if (value.startsWith('file_')) return '文件安全'
  if (value.startsWith('custom_')) return '客户敏感数据'
  if (
    value.includes('secret') ||
    value.includes('token') ||
    value.includes('key') ||
    value.includes('password')
  )
    return '敏感凭据泄露'
  if (value.includes('config') || value.includes('env_file'))
    return '配置文件风险'
  if (
    value.includes('phone') ||
    value.includes('card') ||
    value.includes('email') ||
    value.includes('id_card')
  )
    return '个人信息泄露'
  if (
    value.includes('data_leak') ||
    value.includes('sensitive') ||
    value.includes('hr_data') ||
    value.includes('leak')
  )
    return '数据泄露'
  // 绝不回显原始英文：未知分类给通用中文
  return (
    RISK_CATEGORY_LABELS[value] || TOOL_TYPE_RISK_LABELS[value] || '其他风险'
  )
}

export const formatRuleLabel = (ruleId?: string, category?: string) => {
  if (!ruleId) return ''
  if (RULE_LABELS[ruleId]) return RULE_LABELS[ruleId]
  // 绝不回显原始英文规则 ID：先用 category 的中文分类，再从 ruleId 结构推断中文，都不行给通用中文。
  const byCategory = getRiskCategoryLabel(category)
  if (byCategory && byCategory !== '未分类' && byCategory !== category)
    return byCategory
  const byRule = getRiskCategoryLabel(ruleId)
  if (byRule && byRule !== '未分类' && byRule !== ruleId) return byRule
  return '安全规则命中'
}

export const getToolRiskCategory = (toolType?: string) =>
  TOOL_TYPE_RISK_LABELS[toolType || ''] || getRiskCategoryLabel(toolType)

export const getToolMatchReason = (item: any) => {
  if (item?.match_reason) return getReadableToolReason(item.match_reason)
  if (item?.matched_policy_name)
    return `命中工具策略：${getToolPolicyName(item)}`
  if (item?.tool_name)
    return `工具名称精确匹配：${getToolNameLabel(item.tool_name)}`
  return '按工具调用审计规则记录'
}

export const getToolPolicyName = (item: any) => {
  if (item?.matched_policy_name) {
    const name = String(item.matched_policy_name)
      .replace(/AgentGuard\s*/gi, '')
      .trim()
    return name || '工具权限策略'
  }
  if (item?.tool_name) return `${getToolNameLabel(item.tool_name)}策略`
  return '默认工具审计策略'
}

export const getEventRiskCategories = (event: any): string[] => {
  const categories = new Set<string>()
  if (event?.rule_type) categories.add(getRiskCategoryLabel(event.rule_type))
  const summary = event?.matched_summary || {}
  if (summary.category) categories.add(getRiskCategoryLabel(summary.category))
  if (Array.isArray(summary.findings)) {
    summary.findings.forEach((finding: any) => {
      if (finding?.category)
        categories.add(getRiskCategoryLabel(finding.category))
      else if (finding?.type) categories.add(getRiskCategoryLabel(finding.type))
    })
  }
  if (!categories.size && event?.event_type)
    categories.add(getRiskCategoryLabel(event.event_type))
  return Array.from(categories)
}

export const getEventMatchedRules = (event: any): string[] => {
  const rules = new Set<string>()
  if (event?.rule_name) rules.add(event.rule_name)
  else if (event?.rule_id)
    rules.add(formatRuleLabel(event.rule_id, event.rule_type))

  const summary = event?.matched_summary || {}
  if (Array.isArray(summary.findings)) {
    summary.findings.forEach((finding: any) => {
      if (finding?.rule_name) rules.add(finding.rule_name)
      else if (finding?.rule_id)
        rules.add(
          formatRuleLabel(finding.rule_id, finding.category || finding.type),
        )
    })
  }
  return Array.from(rules)
}

export const getEventEvidenceSummary = (event: any) => {
  const summary = event?.matched_summary || {}
  if (summary.summary) return String(summary.summary)
  if (Array.isArray(summary.findings) && summary.findings.length > 0) {
    const first = summary.findings[0]
    if (first?.matched_text_preview)
      return `命中内容：${first.matched_text_preview}`
  }
  if (event?.evidence_ref) return `证据引用：${event.evidence_ref}`
  return '已记录安全检测证据'
}

export const getAgentRuleInfo = (agentType?: string) => {
  if (agentType === 'agent-tool-call') {
    return {
      rule: '工具调用记录反推',
      categories: ['工具越权', 'MCP 风险', '系统命令'],
    }
  }
  if (isKnownAgentType(agentType)) {
    return {
      rule: '客户端请求头/特征指纹',
      categories: ['智能体行为', '工具越权', '数据泄露'],
    }
  }
  return {
    rule: '内容特征推断',
    categories: ['智能体行为', '异常调用'],
  }
}

// 严重级别中文回显：安全告警 / 工具审计详情共用，避免详情抽屉里裸露英文 enum
export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low'
export const CORE_SEVERITY_LABELS = {
  critical: '严重',
  high: '高危',
  medium: '中危',
  low: '低危',
} as const satisfies Record<SeverityLevel, string>
export const SEVERITY_LABELS: Record<string, string> = {
  ...CORE_SEVERITY_LABELS,
  info: '提示',
  warning: '提醒',
}
export const severityLabel = (value?: string) => {
  if (!value) return '-'
  return SEVERITY_LABELS[String(value).toLowerCase()] || value
}
export const SEVERITY_ORDER: readonly SeverityLevel[] = ['critical', 'high', 'medium', 'low']
export const severityOptions = (order: readonly SeverityLevel[] = SEVERITY_ORDER) =>
  order.map((value) => ({ value, label: CORE_SEVERITY_LABELS[value] }))

// 严重度 → 语义色调（红=风险 / 橙=预警 / 绿=安全 / 灰=中性提示）。
// 全局只允许这四种语义色，杜绝彩虹标签。critical/high 收红，medium/low 收橙，
// 正常放行收绿，info/未知/审计线索等中性信息一律收灰。供 StatusPill 的 tone 直接消费。
export type SemanticTone = 'red' | 'orange' | 'green' | 'gray'
export const severityTone = (value?: string): SemanticTone => {
  const s = String(value || '').toLowerCase()
  if (s === 'critical' || s === 'high') return 'red'
  if (s === 'medium' || s === 'low' || s === 'warning') return 'orange'
  if (s === 'normal' || s === 'safe' || s === 'pass' || s === 'allow') return 'green'
  return 'gray'
}

// 风险结论态 → 语义色调：已阻断=红，需复核=橙，正常放行=绿，其余（审计线索等）=灰。
export const riskStateTone = (state?: string): SemanticTone => {
  const s = String(state || '').toLowerCase()
  if (s === 'blocked') return 'red'
  if (s === 'risk') return 'orange'
  if (s === 'normal') return 'green'
  return 'gray'
}

// 对话角色中文回显：内容留存 / 安全告警详情共用
export const ROLE_LABELS: Record<string, string> = {
  user: '用户',
  assistant: '助手',
  system: '系统',
  tool: '工具',
  function: '工具',
}
export const roleLabel = (value?: string) => {
  if (!value) return '-'
  return ROLE_LABELS[String(value).toLowerCase()] || value
}

// 团队/部门成员角色中文回显：用户详情部门归属标签共用
export const TEAM_ROLE_LABELS: Record<string, string> = {
  owner: '负责人',
  admin: '管理员',
  manager: '负责人',
  member: '成员',
  viewer: '只读',
  guest: '访客',
}
export const teamRoleLabel = (value?: string) => {
  if (!value) return ''
  return TEAM_ROLE_LABELS[String(value).toLowerCase()] || value
}

// 来源 IP 诚实回显：安全告警 / 访问留存的「来源」列共用。
// 当连接经环回到达（127.0.0.1，如本机 / SSH 隧道 / frp 等），宿主机的 Docker userland-proxy
// 会把源地址改写成网桥网关 IP（172.26.0.1），真实客户端 IP 在应用层已不可得。此时不再把网关 IP
// 当成「来源」误导排查，而是诚实标注。外部网卡（LAN / tailscale）连接经 iptables DNAT 保留真实
// 源 IP，原样回显。这是展示层的诚实标注，不改任何留存数据。
export const MASQUERADE_GATEWAY_IP = '172.26.0.1'
export function sourceIpDisplay(ip?: string): { text: string; masqueraded: boolean; tooltip?: string } {
  if (!ip) return { text: '-', masqueraded: false }
  if (ip === MASQUERADE_GATEWAY_IP) {
    return {
      text: '本机/隧道接入',
      masqueraded: true,
      tooltip: `经本机或隧道（环回）接入，源地址被网关改写为 ${MASQUERADE_GATEWAY_IP}，真实客户端 IP 在应用层不可得。`,
    }
  }
  return { text: ip, masqueraded: false }
}

export type ResponsibilityDisplayInput = {
  username?: string
  userId?: string
  clientName?: string
  clientId?: string
  sourceIp?: string
  direction?: string
  credentialType?: string
  /** principal_context_json.principal_key，形如 upstream:openai_account:<id>。 */
  principalKey?: string
  /** 后端 principal_proxy_nat：source_ip 只留下网关出口地址，无法定位到人。 */
  proxyNat?: boolean
}

export type ResponsibilityDisplay = {
  primary: string
  secondary: string
  kind: 'user' | 'api_key' | 'channel' | 'upstream'
}

// 上游主体与 proxy-server 的 upstream_principal.go 同口径：账号取前 8 位便于人读，
// 凭据只以 sha256 指纹出现（原始值不落库也不会到这里）。
export const UPSTREAM_PRINCIPAL_PREFIX = 'upstream:'
export const UPSTREAM_ACCOUNT_LABEL_PREFIX = '上游账号 '
export const UPSTREAM_CREDENTIAL_LABEL_PREFIX = '上游凭据指纹 '
export const NAT_SOURCE_NOTE = '（经 NAT，不能定位到人）'

export function upstreamPrincipalLabel(principalKey?: string): string {
  const key = String(principalKey || '').trim()
  if (!key.startsWith(UPSTREAM_PRINCIPAL_PREFIX)) return ''
  const separator = key.indexOf(':', UPSTREAM_PRINCIPAL_PREFIX.length)
  if (separator < 0) return ''
  const kind = key.slice(UPSTREAM_PRINCIPAL_PREFIX.length, separator)
  const value = key.slice(separator + 1).trim()
  if (!kind || !value) return ''
  if (kind.endsWith('_account')) {
    // upstream:openai_account:<id> / upstream:anthropic_account:<uuid>
    return UPSTREAM_ACCOUNT_LABEL_PREFIX + kind.slice(0, -'_account'.length) + ':' + value.slice(0, 8)
  }
  if (kind === 'credential') {
    return UPSTREAM_CREDENTIAL_LABEL_PREFIX + value
  }
  return ''
}

const RESPONSIBILITY_CHANNEL_LABELS: Record<string, string> = {
  forward: '正向代理',
  reverse: '反向代理',
  chat_completion: '模型中转',
  mcp: 'MCP 网关',
  device: '经过设备',
}

export function responsibilitySearchText(input: ResponsibilityDisplayInput): string {
  const direction = String(input.direction || "").trim().toLowerCase()
  const credentialType = String(input.credentialType || "").trim().toLowerCase()
  const upstreamLabel = upstreamPrincipalLabel(input.principalKey)
  return [
    input.username,
    input.clientName,
    upstreamLabel,
    input.proxyNat ? NAT_SOURCE_NOTE : "",
    input.sourceIp,
    RESPONSIBILITY_CHANNEL_LABELS[direction],
    input.clientName ? "API Key 密钥" : "",
    credentialType === "api_key" ? "API Key 密钥 未绑定" : "",
    direction,
  ].filter(Boolean).join(" ").toLowerCase()
}

export function responsibilityDisplay(input: ResponsibilityDisplayInput): ResponsibilityDisplay {
  const username = String(input.username || "").trim()
  const clientName = String(input.clientName || "").trim()
  const sourceIpBase = sourceIpDisplay(input.sourceIp).text
  const sourceIp = input.proxyNat && sourceIpBase !== "-" && !sourceIpBase.includes(NAT_SOURCE_NOTE)
    ? sourceIpBase + NAT_SOURCE_NOTE
    : sourceIpBase
  const direction = String(input.direction || "").trim().toLowerCase()
  const credentialType = String(input.credentialType || "").trim().toLowerCase()
  const channel = RESPONSIBILITY_CHANNEL_LABELS[direction] || ""
  const sourceDetail = sourceIp !== "-" ? sourceIp : ""

  if (clientName) {
    const secondary = [`API Key：${clientName}`, sourceDetail].filter(Boolean).join(" · ")
    return {
      primary: username || "未绑定用户",
      secondary: secondary || "API Key",
      kind: "api_key",
    }
  }

  if (credentialType === "api_key") {
    return {
      primary: "未绑定 API Key",
      secondary: [channel, sourceDetail].filter(Boolean).join(" · ") || "源 IP 未记录",
      kind: "api_key",
    }
  }

  if (username) {
    const secondary = [channel, sourceDetail].filter(Boolean).join(" · ") || "源 IP 未记录"
    return { primary: username, secondary, kind: "user" }
  }

  const upstreamLabel = upstreamPrincipalLabel(input.principalKey)
  if (upstreamLabel) {
    const secondary = [channel, sourceDetail].filter(Boolean).join(" · ") || "源 IP 未记录"
    return { primary: upstreamLabel, secondary, kind: "upstream" }
  }

  return {
    primary: channel || "未关联账号",
    secondary: sourceDetail || "源 IP 未记录",
    kind: "channel",
  }
}
export const EVAL_VERDICT_LABELS: Record<string, string> = {
  pass: '通过', fail: '未通过', error: '执行异常', blocked: '已阻断',
  malicious: '恶意', suspicious: '疑似攻击', benign: '正常', unknown: '无法判定',
}
export const verdictLabel = (v?: string) => (v ? EVAL_VERDICT_LABELS[v.toLowerCase()] || v : '未记录')

// 语义裁判「外置大脑」后端中文回显：语义检测控制台用，杜绝界面露 bundled/provider/custom 英文枚举。
export const JUDGE_BACKEND_LABELS: Record<string, string> = {
  bundled: '自带 CPU 模型',
  provider: '已接入模型上游',
  custom: '自定义端点',
}
export const judgeBackendLabel = (v?: string) => (v ? JUDGE_BACKEND_LABELS[v.toLowerCase()] || v : '未配置')
