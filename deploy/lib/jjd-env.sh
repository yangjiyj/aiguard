#!/bin/sh
# deploy/lib/jjd-env.sh — 安全读取 .env 的共享函数（POSIX sh：可被 sh/dash/bash 以 `.` 引入）。
#
# 为什么要有它
#   运维脚本过去用 `set -a; . ./.env; set +a` 读配置。但 .env 同时是 docker compose 的
#   dotenv 文件：compose 把 `KEY=--a b` 的整行等号后面都当成值，shell 却把它解析成
#   “以 KEY 为环境变量去执行命令 b”。客户现场 .env 第 84 行
#       REDIS_EXTRA_ARGS=--no-appendfsync-on-rewrite yes
#   就是这样被 jjdctl / backup-db.sh / diagnose.sh / ensure-web-tls.sh / smoke-test.sh
#   执行成了命令 `yes`：无限输出 y，命令卡死刷屏，输出重定向到文件时写满过根分区。
#   source 一个 .env 还意味着值里的 $(...)、反引号、分号都会被当成代码执行。
#   所以：读 .env 必须逐行按字面 KEY=VALUE 解析，绝不执行、绝不展开。
#
# 用法
#   . "$SCRIPT_DIR/../lib/jjd-env.sh"
#   jjd_load_env_file ./.env            # 变量设进当前 shell 并 export（等价于 set -a; . .env）
#   jjd_load_env_file ./.env noexport   # 只设 shell 变量不 export（jjdctl 原本的语义）；带 `export ` 前缀的行仍会 export
#   返回 0：读完（个别行被跳过会在 stderr 给警告，不算失败）；返回 1：文件不可读。
#   警告只写变量名和行号，绝不打印值（值可能是密钥）。
#
# 解析语义（有意的取舍，改动前请连同 deploy/tests/test_jjd_env_loader.sh 一起看）
#   1. 逐行读；去掉 CRLF 行尾的 CR；行首空白忽略；空行、# 开头的注释行忽略；`export KEY=VALUE` 的 `export ` 前缀被接受，
#      并且无论哪种模式都会 export 这个变量（与 source 一致：回滚测试夹具就靠它把变量传给子进程）。
#   2. 第一个 `=` 之前必须是合法变量名 [A-Za-z_][A-Za-z0-9_]*，否则警告并跳过该行
#      （不是整个文件失败）。`=` 前后不允许空白（`KEY = v` 视为非法变量名，shell 原本也不认）。
#      值里可以再含 `=`（取第一个 `=` 之后的全部）。
#   3. 值：不做任何 shell 展开——$VAR、${VAR}、$(...)、反引号、反斜杠转义都按原字符保留。
#      这与 docker compose 不同（compose 会插值 $VAR），也与旧的 source 不同；取舍理由：
#      仓库里 .env.example 与各安装器写出的 .env 没有任何值依赖 $VAR 展开，
#      而 compose 本身用 `$$` 才表示字面 `$`，字面保留对随机口令、JSON、URL 都是最安全的。
#   4. 成对的外层引号剥一层（单引号或双引号），引号内不处理转义；这与升级器里已有的
#      parse_literal_dotenv_value 一致。引号值后面允许跟 `空白 + #注释`。
#      引号不成对时整个值按字面保留（含引号），不报错。
#   5. 未加引号的值：去掉首尾空白，并去掉行内 ` #注释`（# 前必须有空白，与 compose 和旧 source
#      的行为一致）；值中间的空格原样保留，所以 `REDIS_EXTRA_ARGS=--a yes` 的值就是 `--a yes`。
#   6. 同一个变量出现多次，后者覆盖前者（与 source、compose 一致）。
#   7. 这些名字不会被设置（会改变 shell 自身行为或是只读变量，设了只会把调用脚本搞坏），
#      命中时给警告并跳过：IFS PS1 PS2 PS4 PROMPT_COMMAND BASH_ENV ENV SHELLOPTS BASHOPTS
#      GLOBIGNORE CDPATH UID EUID PPID，以及以 _jjd_env_ 开头的本库内部变量。
#
# 注意：本库内部变量一律以 _jjd_env_ 为前缀；函数里不使用 local（dash 不是都支持）。

_jjd_env_cr="$(printf '\r')"

# 去掉 $1 的首尾空白，结果放进 _jjd_env_trimmed。
_jjd_env_trim() {
  _jjd_env_trimmed=$1
  _jjd_env_trimmed=${_jjd_env_trimmed#"${_jjd_env_trimmed%%[![:space:]]*}"}
  _jjd_env_trimmed=${_jjd_env_trimmed%"${_jjd_env_trimmed##*[![:space:]]}"}
}

# 解析一行。成功时设置 _jjd_env_key / _jjd_env_value / _jjd_env_quote(n|s|d) / _jjd_env_exported(0|1)。
# 返回 0：是赋值；1：空行或注释（忽略）；2：非法（缺 = 或变量名不合法）。
_jjd_env_parse_line() {
  _jjd_env_line=$1
  _jjd_env_exported=0
  _jjd_env_line=${_jjd_env_line%"$_jjd_env_cr"}
  _jjd_env_line=${_jjd_env_line#"${_jjd_env_line%%[![:space:]]*}"}
  case $_jjd_env_line in
    '' | '#'*) return 1 ;;
    export[[:space:]]*)
      _jjd_env_exported=1
      _jjd_env_line=${_jjd_env_line#export}
      _jjd_env_line=${_jjd_env_line#"${_jjd_env_line%%[![:space:]]*}"}
      ;;
  esac
  case $_jjd_env_line in
    *=*) ;;
    *) return 2 ;;
  esac
  _jjd_env_key=${_jjd_env_line%%=*}
  case $_jjd_env_key in
    '' | [0-9]* | *[!A-Za-z0-9_]*) return 2 ;;
  esac
  _jjd_env_trim "${_jjd_env_line#*=}"
  _jjd_env_raw=$_jjd_env_trimmed
  _jjd_env_quote=n
  _jjd_env_value=$_jjd_env_raw
  case $_jjd_env_raw in
    '"'* | "'"*)
      _jjd_env_q=${_jjd_env_raw%"${_jjd_env_raw#?}"}
      _jjd_env_rest=${_jjd_env_raw#?}
      case $_jjd_env_rest in
        *"$_jjd_env_q"*)
          _jjd_env_inner=${_jjd_env_rest%%"$_jjd_env_q"*}
          _jjd_env_after=${_jjd_env_rest#*"$_jjd_env_q"}
          _jjd_env_trim "$_jjd_env_after"
          case $_jjd_env_trimmed in
            '' | '#'*)
              _jjd_env_value=$_jjd_env_inner
              _jjd_env_set_quote "$_jjd_env_q"
              return 0
              ;;
          esac
          # 值里自己含引号（如 "pa"ss"）：只要首尾引号成对，就剥外层一对。
          case $_jjd_env_rest in
            *"$_jjd_env_q")
              _jjd_env_value=${_jjd_env_rest%?}
              _jjd_env_set_quote "$_jjd_env_q"
              return 0
              ;;
          esac
          ;;
      esac
      # 引号不成对：按字面保留整个值。
      return 0
      ;;
  esac
  # 未加引号：去掉行内 ` #注释`（# 前必须是空白），再去尾部空白。
  _jjd_env_value=${_jjd_env_raw%%[[:space:]]#*}
  _jjd_env_trim "$_jjd_env_value"
  _jjd_env_value=$_jjd_env_trimmed
  return 0
}

_jjd_env_set_quote() {
  case $1 in
    '"') _jjd_env_quote=d ;;
    *) _jjd_env_quote=s ;;
  esac
}

# 0：这个名字允许被 .env 设置；1：保留名。
_jjd_env_name_allowed() {
  case $1 in
    IFS | PS1 | PS2 | PS4 | PROMPT_COMMAND | BASH_ENV | ENV | SHELLOPTS | BASHOPTS | \
      GLOBIGNORE | CDPATH | UID | EUID | PPID | _jjd_env_*) return 1 ;;
  esac
  return 0
}

_jjd_env_warn() {
  printf '[jjd-env] 警告: %s\n' "$*" >&2
}

# jjd_load_env_file FILE [export|noexport]
jjd_load_env_file() {
  _jjd_env_file=$1
  _jjd_env_mode=${2:-export}
  if [ ! -f "$_jjd_env_file" ] || [ ! -r "$_jjd_env_file" ]; then
    _jjd_env_warn "无法读取环境文件: $_jjd_env_file"
    return 1
  fi
  _jjd_env_n=0
  while IFS= read -r _jjd_env_raw_line || [ -n "$_jjd_env_raw_line" ]; do
    _jjd_env_n=$((_jjd_env_n + 1))
    _jjd_env_rc=0
    _jjd_env_parse_line "$_jjd_env_raw_line" || _jjd_env_rc=$?
    case $_jjd_env_rc in
      0) ;;
      1) continue ;;
      *)
        _jjd_env_warn "$_jjd_env_file 第 $_jjd_env_n 行不是合法的 KEY=VALUE（变量名非法或缺少 =），已跳过"
        continue
        ;;
    esac
    if ! _jjd_env_name_allowed "$_jjd_env_key"; then
      _jjd_env_warn "$_jjd_env_file 第 $_jjd_env_n 行的变量名 $_jjd_env_key 是 shell 保留名，已跳过"
      continue
    fi
    # 变量名已校验为 [A-Za-z_][A-Za-z0-9_]*；eval 的字符串里只有 `名字=$内部变量`，
    # 值经参数展开进入赋值，不会被再次当成命令解析。
    eval "$_jjd_env_key=\$_jjd_env_value"
    if [ "$_jjd_env_mode" != noexport ] || [ "$_jjd_env_exported" = 1 ]; then
      export "$_jjd_env_key"
    fi
  done <"$_jjd_env_file"
  return 0
}

# jjd_env_warn_unquoted_whitespace FILE
# 只检查、只警告、不改文件：列出“值含空白且未加引号”的变量。compose 能正确读取这种写法，
# 但任何用 `source .env` 的脚本（客户自己的、或旧版本的运维脚本）会把它当命令执行。
# 只输出变量名和行号，不输出值。永远返回 0。
jjd_env_warn_unquoted_whitespace() {
  _jjd_env_file=$1
  [ -f "$_jjd_env_file" ] && [ -r "$_jjd_env_file" ] || return 0
  _jjd_env_n=0
  while IFS= read -r _jjd_env_raw_line || [ -n "$_jjd_env_raw_line" ]; do
    _jjd_env_n=$((_jjd_env_n + 1))
    _jjd_env_rc=0
    _jjd_env_parse_line "$_jjd_env_raw_line" || _jjd_env_rc=$?
    [ "$_jjd_env_rc" -eq 0 ] || continue
    [ "$_jjd_env_quote" = n ] || continue
    case $_jjd_env_value in
      *[[:space:]]*)
        _jjd_env_warn "$_jjd_env_file 第 $_jjd_env_n 行 $_jjd_env_key 的值含空格且未加引号：docker compose 能正确读取，但用 source 读 .env 的脚本会把它当命令执行（旧版 jjdctl 就因此卡死）；建议改成加引号的写法 $_jjd_env_key=\"...\"，升级器不会自动修改你的 .env"
        ;;
    esac
  done <"$_jjd_env_file"
  return 0
}
