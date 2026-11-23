// 防护相关组件共用的常量（单独成文件，组件文件只导出组件）。

// 防跳板出站的统一后果说明：打开前必须看到。
export const EGRESS_RISK_CONTENT = '网关可被用来访问这些地址。'

export const AGENT_EXCEPTION_SCOPE_OPTIONS = [
  { value: 'tenant', label: '全租户' },
  { value: 'project', label: '指定应用' },
  { value: 'key', label: '指定密钥' },
  { value: 'user', label: '指定用户' },
  { value: 'agent', label: '指定智能体' },
  { value: 'session', label: '指定会话' },
]

export const FILE_TARGET_RULE = '不含 / 只比文件名，区分大小写；以 / 结尾是目录；其余写完整路径或以 / 为界的后缀。~/.ssh/ 匹配不到 /home/u/.ssh/…，写文件名最稳。'

// 文件类防护项：例外目标按文件名、目录或路径匹配。
export const FILE_PROTECTION_KEYS = new Set([
  'agent.cloud_credential',
  'agent.ssh_private_key',
  'agent.env_file',
  'agent.system_secret_file',
  'agent.secret_mount',
  'agent.git_credential',
  'agent.sensitive_name',
  'agent.restricted_file',
])

export const CONTENT_EXCEPTIONS_QUERY_KEY = ['content-security', 'exceptions'] as const
