// W1 1.11：内置红线处置配置。默认全部「仅告警」（与升级前一致），管理员可逐条改为「阻断」。
export const REDLINE_LABELS: Record<string, { title: string; hint: string }> = {
  destructive_command: { title: '\u7834\u574f\u6027\u547d\u4ee4', hint: 'rm -rf /; DROP TABLE/DATABASE; TRUNCATE TABLE; mkfs; dd if=' },
  cloud_metadata: { title: '云元数据端点访问', hint: '169.254.169.254、100.100.100.200、metadata.google.internal 等' },
  private_key_egress: { title: '私钥外传', hint: 'PEM 私钥、PuTTY 私钥' },
  cloud_credential_file: { title: '云/集群凭据文件', hint: '~/.aws/credentials、~/.kube/config、ServiceAccount token 等' },
  system_secret_file: { title: '系统口令/进程环境', hint: '/etc/shadow、/proc/*/environ' },
  container_runtime_socket: { title: '容器运行时套接字', hint: 'docker.sock、containerd.sock（容器逃逸）' },
  reverse_shell: { title: '反弹 Shell', hint: '/dev/tcp、nc -e、socat exec' },
  remote_script_pipe: { title: '下载即执行', hint: 'curl/wget … | sh' },
}
