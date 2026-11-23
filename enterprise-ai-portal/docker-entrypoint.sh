#!/bin/sh
set -e

# 数据库初始化：先于 Web 服务执行
# --skip-generate：client 已在构建时生成，无需运行时 generate
# 初始化失败时 set -e 会阻止后续 Web 服务启动，容器以非零码退出
# 离线兜底：禁用 Prisma 联网校验/下载引擎，避免断网部署失败
export PRISMA_ENGINES_CHECKSUM_IGNORE_MISSING="${PRISMA_ENGINES_CHECKSUM_IGNORE_MISSING:-1}"
./node_modules/.bin/prisma db push --skip-generate

# 初始化成功后启动 Next.js standalone 服务
export PORT="${PORT:-3100}"
# Docker 会自动注入 HOSTNAME=容器 ID；这里必须覆盖，保证 localhost 健康检查可达。
export HOSTNAME="${PORTAL_BIND_HOST:-0.0.0.0}"
exec node ./server.js
