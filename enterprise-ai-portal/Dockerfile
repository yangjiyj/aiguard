# syntax=docker.1ms.run/docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
# 企业 AI 对话门户 运行镜像（standalone 瘦身版）

FROM docker.1ms.run/library/node:22-alpine@sha256:e58326d0d441090181ac150dc2078d3e2cf6a0d42e809aebba3ef5880935ffdd AS base
ENV npm_config_registry=https://registry.npmjs.org
ENV PRISMA_ENGINES_CHECKSUM_IGNORE_MISSING=1

# ---- 1. deps: 完整安装依赖（仅用于构建）----
FROM base AS deps
WORKDIR /app
COPY package.json package-lock.json* ./
RUN --mount=type=bind,from=release-npm-cache,source=.,target=/tmp/npm-cache-input,readonly \
    mkdir -p /root/.npm \
    && tar -xf /tmp/npm-cache-input/npm-cache.tar -C /root/.npm \
    && npm ci --offline --legacy-peer-deps --cache /root/.npm --no-audit --no-fund
ARG TARGETARCH
COPY --from=release-prisma-engine . /tmp/release-prisma-engine/
RUN case "$TARGETARCH" in \
      amd64) query_engine=libquery_engine-linux-musl-openssl-3.0.x.so.node; \
             schema_engine=schema-engine-linux-musl-openssl-3.0.x ;; \
      arm64) query_engine=libquery_engine-linux-musl-arm64-openssl-3.0.x.so.node; \
             schema_engine=schema-engine-linux-musl-arm64-openssl-3.0.x ;; \
      *) echo "unsupported Prisma target architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac \
    && install -m 0555 "/tmp/release-prisma-engine/$query_engine" "node_modules/@prisma/engines/$query_engine" \
    && install -m 0555 "/tmp/release-prisma-engine/$schema_engine" "node_modules/@prisma/engines/$schema_engine" \
    && rm -rf /tmp/release-prisma-engine

# ---- 2. build: prisma generate + next build（产出 standalone）----
FROM base AS build
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
ARG NEXT_PUBLIC_BILLING_ENABLED=false
ENV NEXT_PUBLIC_BILLING_ENABLED=$NEXT_PUBLIC_BILLING_ENABLED

ARG TARGETARCH
RUN case "$TARGETARCH" in \
      amd64) query_engine=libquery_engine-linux-musl-openssl-3.0.x.so.node ;; \
      arm64) query_engine=libquery_engine-linux-musl-arm64-openssl-3.0.x.so.node ;; \
      *) echo "unsupported Prisma target architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac \
    && export PRISMA_QUERY_ENGINE_LIBRARY="/app/node_modules/@prisma/engines/$query_engine" \
    && npx prisma generate \
    && npm run build

# ---- 3. prisma-cli: 从锁定构建依赖提取 Prisma 闭包（db push 用）----
FROM deps AS prisma-cli
WORKDIR /app
# Next standalone 已带业务运行依赖。这里仅保留启动时 db push 所需的
# Prisma CLI、Prisma 运行时和生成的 client，不能把完整开发 node_modules 带入。
# 注意：保留 libquery_engine* 与 *.wasm，否则 prisma CLI 在离线环境执行
# db push 时会去 binaries.prisma.sh 联网校验/下载引擎，断网部署直接失败。
RUN mv node_modules /tmp/full-node_modules \
    && mkdir -p node_modules/.bin \
    && node - /tmp/full-node_modules /app/node_modules <<'NODE'
const fs = require('fs');
const path = require('path');
const [source, destination] = process.argv.slice(2);
const copied = new Set();

function packagePath(name) {
  return path.join(source, ...name.split('/'));
}

function copyPackage(name) {
  if (copied.has(name)) return;
  copied.add(name);
  const packageRoot = packagePath(name);
  const manifestPath = path.join(packageRoot, 'package.json');
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  fs.cpSync(packageRoot, path.join(destination, ...name.split('/')), {
    recursive: true,
    dereference: false,
  });
  for (const dependency of Object.keys({
    ...(manifest.dependencies || {}),
    ...(manifest.optionalDependencies || {}),
  })) {
    copyPackage(dependency);
  }
}

copyPackage('prisma');
NODE
RUN cp -a /tmp/full-node_modules/.prisma node_modules/.prisma \
    && cp -a /tmp/full-node_modules/.bin/prisma node_modules/.bin/prisma \
    && rm -rf /tmp/full-node_modules \
    && find node_modules/prisma/build \
       \( -name '*mysql*' -o -name '*sqlite*' -o -name '*sqlserver*' -o -name '*cockroach*' \) \
       -delete \
    && rm -rf node_modules/prisma/prisma-client

# ---- 4. runtime: standalone + 最小 prisma CLI + 非 root ----
FROM base AS runtime
WORKDIR /app
ENV NODE_ENV=production

RUN addgroup -S portal && adduser -S portal -G portal

# 先放入 prisma CLI 依赖
COPY --from=prisma-cli --chown=portal:portal /app/node_modules ./node_modules

# 再覆盖 standalone 产物（server.js + 精简运行时 node_modules + .prisma/client）
COPY --from=build --chown=portal:portal /app/.next/standalone ./
COPY --from=build --chown=portal:portal /app/.next/static ./.next/static
COPY --from=build --chown=portal:portal /app/public ./public
COPY --from=build --chown=portal:portal /app/prisma ./prisma

# 精简 runtime node_modules：
# - 删除 @prisma/client 的 wasm-base64 引擎和 sourcemap（native engine 模式不需要）
# - 删除 glibc 版 sharp 二进制（alpine 使用 musl 版）
RUN find node_modules/@prisma/client/runtime \
      \( -name '*wasm*' -o -name '*.map' \) -delete \
    && rm -rf node_modules/@img/sharp-libvips-linux-x64 \
             node_modules/@img/sharp-linux-x64

COPY --chmod=755 docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

USER portal
EXPOSE 3100

ENTRYPOINT ["docker-entrypoint.sh"]
