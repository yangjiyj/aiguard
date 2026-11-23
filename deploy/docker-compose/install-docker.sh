#!/bin/sh
# install-docker.sh — 离线安装与交付包架构一致的 Docker 引擎
#
# 仅在目标主机「没有可用的 Docker 引擎」时，由 install.sh 自动调用；
# 也可由实施人员手动执行：sudo sh install-docker.sh
#
# 设计要点：
#   - 幂等：docker 已可用则直接跳过；二进制已就位则不重复安装。
#   - 纯离线：只用随包内置的静态二进制，不访问任何网络。
#   - 需要 root：非 root 时尝试用 sudo 重新执行，否则给出明确提示。
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/lib-arch.sh"
DOCKER_TGZ="${DOCKER_STATIC_TGZ:-$SCRIPT_DIR/docker-engine/docker-static.tgz}"
INSTALL_BIN_DIR="${DOCKER_INSTALL_BIN_DIR:-/usr/local/bin}"

log() { echo "[docker-install] $*"; }
err() { echo "[docker-install][error] $*" >&2; }

TEST_MODE="${DOCKER_INSTALL_TEST_MODE:-0}"
validate_test_path() {
  value="$1"
  case "$value" in /*) : ;; *) err "测试路径不安全：$value"; exit 1 ;; esac
  case "$value" in
    *[!A-Za-z0-9_./-]* | */../* | */.. | ../* | ..) err "测试路径不安全：$value"; exit 1 ;;
  esac
}
case "$TEST_MODE" in
  0)
    if [ -n "${DOCKER_STATIC_TGZ-}" ] || [ -n "${DOCKER_INSTALL_BIN_DIR-}" ] || \
       [ -n "${DOCKER_SYSTEMD_RUN_DIR-}" ] || [ -n "${DOCKER_SYSTEMD_UNIT_DIR-}" ] || \
       [ -n "${DOCKER_INITD_DIR-}" ] || [ -n "${DOCKER_RUN_DIR-}" ] || \
       [ -n "${DOCKER_LOG_DIR-}" ] || [ -n "${DOCKER_SOCKET_PATH-}" ]; then
      err "生产模式禁止路径覆盖。"
      exit 1
    fi
    DOCKER_TGZ="$SCRIPT_DIR/docker-engine/docker-static.tgz"
    INSTALL_BIN_DIR="/usr/local/bin"
    SYSTEMD_RUN_DIR="/run/systemd/system"
    SYSTEMD_UNIT_DIR="/etc/systemd/system"
    INITD_DIR="/etc/init.d"
    RUN_DIR="/var/run"
    LOG_DIR="/var/log"
    ;;
  1)
    DOCKER_TGZ="${DOCKER_STATIC_TGZ:-$SCRIPT_DIR/docker-engine/docker-static.tgz}"
    INSTALL_BIN_DIR="${DOCKER_INSTALL_BIN_DIR:-/usr/local/bin}"
    SYSTEMD_RUN_DIR="${DOCKER_SYSTEMD_RUN_DIR:-/run/systemd/system}"
    SYSTEMD_UNIT_DIR="${DOCKER_SYSTEMD_UNIT_DIR:-/etc/systemd/system}"
    INITD_DIR="${DOCKER_INITD_DIR:-/etc/init.d}"
    RUN_DIR="${DOCKER_RUN_DIR:-/var/run}"
    LOG_DIR="${DOCKER_LOG_DIR:-/var/log}"
    for test_path in "$DOCKER_TGZ" "$INSTALL_BIN_DIR" "$SYSTEMD_RUN_DIR" "$SYSTEMD_UNIT_DIR" "$INITD_DIR" "$RUN_DIR" "$LOG_DIR"; do validate_test_path "$test_path"; done
    ;;
  *) err "DOCKER_INSTALL_TEST_MODE 只能为 0 或 1。"; exit 1 ;;
esac
DOCKER_SOCKET="$RUN_DIR/docker.sock"

# 1) 已可用则跳过（幂等）
if docker info >/dev/null 2>&1; then
  log "检测到 Docker 引擎已可用，跳过安装。"
  exit 0
fi

# 2) 需要 root；非 root 则尝试用 sudo 重新执行
if [ "$(id -u)" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1; then
    log "安装 Docker 引擎需要 root 权限，正在通过 sudo 重新执行……"
    exec sudo sh "$0" "$@"
  fi
  err "安装 Docker 引擎需要 root 权限，且未找到 sudo。请用 root 重新运行：sh $0"
  exit 1
fi

# 3) 架构校验。target-arch 由发布脚本写入，禁止错架构二进制落盘。
EXPECTED_ARCH="${OFFLINE_EXPECTED_ARCH:-$(cat "$SCRIPT_DIR/docker-engine/target-arch" 2>/dev/null || true)}"
[ -n "$EXPECTED_ARCH" ] || { err "离线包缺少目标架构声明。"; exit 1; }
assert_host_arch "$EXPECTED_ARCH" || exit 1

# 4) 校验静态包存在
if [ ! -s "$DOCKER_TGZ" ]; then
  err "未找到内置的 Docker 静态二进制包：$DOCKER_TGZ"
  err "该离线包可能未打入 Docker 引擎，请确认目标机器已预装 Docker。"
  exit 1
fi

# 5) 在写入任何文件前确认 init 系统受支持，避免留下半安装状态。
init_system=""
if command -v systemctl >/dev/null 2>&1 && [ -d "$SYSTEMD_RUN_DIR" ]; then
  init_system="systemd"
elif command -v rc-service >/dev/null 2>&1 && command -v rc-update >/dev/null 2>&1; then
  init_system="openrc"
elif command -v service >/dev/null 2>&1 && command -v update-rc.d >/dev/null 2>&1; then
  init_system="sysv-update-rc-d"
elif command -v service >/dev/null 2>&1 && command -v chkconfig >/dev/null 2>&1; then
  init_system="sysv-chkconfig"
else
  err "未检测到受支持的 init 系统（systemd、OpenRC 或 SysV init）。"
  err "为确保 Docker 开机自启，本安装器不会直接后台启动 dockerd。"
  exit 1
fi

# 6) 解压二进制到 INSTALL_BIN_DIR
log "解压 Docker 静态二进制到 $INSTALL_BIN_DIR ……"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
tar -xzf "$DOCKER_TGZ" -C "$tmp_dir"
# 解压后内容位于 $tmp_dir/docker/ 下
if [ ! -d "$tmp_dir/docker" ]; then
  err "静态包结构异常：解压后未找到 docker/ 目录。"
  exit 1
fi
for f in "$tmp_dir"/docker/*; do
  [ -f "$f" ] || continue
  install -m 0755 "$f" "$INSTALL_BIN_DIR/$(basename "$f")"
done
log "已安装二进制：$(ls "$tmp_dir/docker" | tr '\n' ' ')"

# 7) docker 用户组（docker.sock 归属 root:docker）
if ! getent group docker >/dev/null 2>&1; then
  groupadd docker 2>/dev/null || true
fi

# 8) 注册持久服务并启动守护进程。
#    Docker 29 的 containerd image store 会让部分旧式离线 archive 的
#    `docker load` 无进度卡住；离线交付统一使用经典 image store。
#    静态版 dockerd 不带 systemd notify 支持，故使用 Type=simple；
#    dockerd 会把 containerd 作为子进程自管，无需单独的 containerd.service。
DOCKER_DAEMON_ARGS="--host=unix://$DOCKER_SOCKET --feature containerd-snapshotter=false"
case "$init_system" in
systemd)
  log "写入 systemd 单元并启动 docker 服务……"
  install -d -m 0755 "$SYSTEMD_UNIT_DIR"
  cat >"$SYSTEMD_UNIT_DIR/docker.service" <<UNIT
[Unit]
Description=Docker Application Container Engine (offline static install)
Documentation=https://docs.docker.com
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=PATH=$INSTALL_BIN_DIR:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ExecStart=$INSTALL_BIN_DIR/dockerd $DOCKER_DAEMON_ARGS
ExecReload=/bin/kill -s HUP \$MAINPID
TimeoutStartSec=0
RestartSec=2
Restart=always
LimitNOFILE=1048576
LimitNPROC=infinity
LimitCORE=infinity
TasksMax=infinity
Delegate=yes
# Stop the managed containerd with dockerd.  Leaving it behind makes a
# retry after an interrupted install loop until systemd's short readiness
# window expires.
KillMode=control-group
OOMScoreAdjust=-500

[Install]
WantedBy=multi-user.target
UNIT
  # An interrupted static install may leave Docker's managed containerd in
  # the old service cgroup.  Stop and explicitly kill that cgroup before
  # reloading the replacement unit so a retry starts from a clean runtime.
  systemctl stop docker.service >/dev/null 2>&1 || true
  systemctl kill --kill-who=all docker.service >/dev/null 2>&1 || true
  systemctl daemon-reload
  systemctl enable docker.service
  systemctl restart docker.service
  ;;
openrc)
  log "写入 OpenRC 服务并启动 docker 服务……"
  install -d -m 0755 "$INITD_DIR" "$RUN_DIR" "$LOG_DIR"
  cat >"$INITD_DIR/docker" <<OPENRC
#!/sbin/openrc-run
description="Docker Application Container Engine (offline static install)"
command="$INSTALL_BIN_DIR/dockerd"
command_args="$DOCKER_DAEMON_ARGS --pidfile=$RUN_DIR/docker.pid"
supervisor=supervise-daemon
pidfile="$RUN_DIR/docker-supervise.pid"
output_log="$LOG_DIR/dockerd.log"
error_log="$LOG_DIR/dockerd.log"
respawn_delay=2
respawn_max=0

depend() {
    need net
    after firewall
}
OPENRC
  chmod 0755 "$INITD_DIR/docker"
  rc-update add docker default
  rc-service docker restart
  ;;
sysv-update-rc-d | sysv-chkconfig)
  log "写入 SysV init 服务并启动 docker 服务……"
  install -d -m 0755 "$INITD_DIR" "$RUN_DIR" "$LOG_DIR"
  cat >"$INITD_DIR/docker" <<SYSV
#!/bin/sh
# chkconfig: 2345 20 80
# description: Docker Application Container Engine
### BEGIN INIT INFO
# Provides:          docker
# Required-Start:    \$network \$remote_fs
# Required-Stop:     \$network \$remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Docker Application Container Engine
### END INIT INFO

DAEMON=$INSTALL_BIN_DIR/dockerd
PIDFILE=$RUN_DIR/docker.pid
LOGFILE=$LOG_DIR/dockerd.log
DAEMON_ARGS="$DOCKER_DAEMON_ARGS --pidfile=$RUN_DIR/docker.pid"

read_pid() {
    [ -s "\$PIDFILE" ] || return 1
    pid="\$(cat "\$PIDFILE" 2>/dev/null)" || return 1
    case "\$pid" in ''|*[!0-9]*) return 1 ;; esac
    echo "\$pid"
}

is_dockerd_pid() {
    check_pid="\$1"
    kill -0 "\$check_pid" 2>/dev/null || return 1
    process_exe="\$(readlink "/proc/\$check_pid/exe" 2>/dev/null || true)"
    case "\$process_exe" in
        "\$DAEMON" | "\$DAEMON (deleted)") return 0 ;;
        *) return 1 ;;
    esac
}

wait_for_start() {
    attempts=0
    while [ "\$attempts" -lt 10 ]; do
        if pid="\$(read_pid)" && is_dockerd_pid "\$pid"; then return 0; fi
        attempts=\$((attempts + 1)); sleep 1
    done
    echo "dockerd 未创建有效 PID 文件：\$PIDFILE" >&2
    return 1
}

do_start() {
    if pid="\$(read_pid)"; then
        if is_dockerd_pid "\$pid"; then return 0; fi
        if kill -0 "\$pid" 2>/dev/null; then
            echo "PID 文件指向非 dockerd 进程，拒绝启动：\$pid" >&2
            return 1
        fi
        rm -f "\$PIDFILE"
    fi
    if command -v start-stop-daemon >/dev/null 2>&1; then
        ssd_help="\$(start-stop-daemon --help 2>&1 || true)"
        case "\$ssd_help" in
            *--output*)
                start-stop-daemon --start --background --startas "\$DAEMON" --pidfile "\$PIDFILE" --exec "\$DAEMON" --output "\$LOGFILE" -- \$DAEMON_ARGS
                ;;
            *--no-close*)
                start-stop-daemon --start --background --no-close --startas "\$DAEMON" --pidfile "\$PIDFILE" --exec "\$DAEMON" -- \$DAEMON_ARGS >>"\$LOGFILE" 2>&1
                ;;
            *)
                "\$DAEMON" \$DAEMON_ARGS >>"\$LOGFILE" 2>&1 &
                ;;
        esac
    else
        "\$DAEMON" \$DAEMON_ARGS >>"\$LOGFILE" 2>&1 &
    fi
    wait_for_start
}

do_stop() {
    if ! pid="\$(read_pid)"; then
        rm -f "\$PIDFILE"
        return 0
    fi
    if ! kill -0 "\$pid" 2>/dev/null; then
        rm -f "\$PIDFILE"
        return 0
    fi
    if ! is_dockerd_pid "\$pid"; then
        echo "PID 文件指向非 dockerd 进程，拒绝停止：\$pid" >&2
        return 1
    fi
    if command -v start-stop-daemon >/dev/null 2>&1; then
        start-stop-daemon --stop --retry TERM/10/KILL/5 --pidfile "\$PIDFILE" --exec "\$DAEMON"
    else
        kill "\$pid" || return 1
        attempts=0
        while [ "\$attempts" -lt 10 ] && is_dockerd_pid "\$pid"; do
            attempts=\$((attempts + 1)); sleep 1
        done
        if is_dockerd_pid "\$pid"; then
            kill -KILL "\$pid" || return 1
            attempts=0
            while [ "\$attempts" -lt 5 ] && kill -0 "\$pid" 2>/dev/null; do
                attempts=\$((attempts + 1)); sleep 1
            done
        fi
    fi
    if kill -0 "\$pid" 2>/dev/null && is_dockerd_pid "\$pid"; then
        echo "dockerd 未在超时内退出：\$pid" >&2
        return 1
    fi
    rm -f "\$PIDFILE"
}

case "\${1:-}" in
    start) do_start ;;
    stop) do_stop ;;
    restart|force-reload) do_stop; do_start ;;
    status)
        if pid="\$(read_pid)" && is_dockerd_pid "\$pid"; then exit 0; fi
        if [ -n "\${pid:-}" ] && kill -0 "\$pid" 2>/dev/null; then exit 1; fi
        exit 3
        ;;
    *) echo "Usage: \$0 {start|stop|restart|force-reload|status}" >&2; exit 2 ;;
esac
SYSV
  chmod 0755 "$INITD_DIR/docker"
  if [ "$init_system" = "sysv-update-rc-d" ]; then
    update-rc.d docker defaults
  else
    chkconfig --add docker
    chkconfig docker on
  fi
  service docker restart
  ;;
esac

# 9) 等待守护进程就绪并最终校验。首次启动可能需要加载旧的
# containerd 元数据；窗口必须覆盖该有界启动过程，同时不能无限等待。
wait_attempts="${DOCKER_INSTALL_WAIT_ATTEMPTS:-120}"
wait_interval="${DOCKER_INSTALL_WAIT_INTERVAL_SECONDS:-1}"
case "$wait_attempts" in
  ''|*[!0-9]*) err "Docker 等待参数无效：DOCKER_INSTALL_WAIT_ATTEMPTS"; exit 1 ;;
esac
case "$wait_interval" in
  ''|*[!0-9]*) err "Docker 等待参数无效：DOCKER_INSTALL_WAIT_INTERVAL_SECONDS"; exit 1 ;;
esac
[ "$wait_attempts" -ge 1 ] && [ "$wait_attempts" -le 300 ] || {
  err "Docker 等待参数无效：DOCKER_INSTALL_WAIT_ATTEMPTS 应为 1-300"; exit 1
}
[ "$wait_interval" -le 5 ] || {
  err "Docker 等待参数无效：DOCKER_INSTALL_WAIT_INTERVAL_SECONDS 应为 0-5"; exit 1
}
i=0
while [ "$i" -lt "$wait_attempts" ]; do
  if docker info >/dev/null 2>&1; then
    log "Docker 引擎安装并启动成功：$(docker --version 2>/dev/null || echo 'docker')"
    exit 0
  fi
  i=$((i + 1))
  sleep "$wait_interval"
done

err "Docker 引擎已安装但守护进程未在 ${wait_attempts} 秒内就绪。"
err "请检查日志：journalctl -u docker  或  $LOG_DIR/dockerd.log"
exit 1
