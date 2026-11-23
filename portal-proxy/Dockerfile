# syntax=docker.1ms.run/docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

ARG NODE_IMAGE=docker.1ms.run/library/node:22-alpine@sha256:e58326d0d441090181ac150dc2078d3e2cf6a0d42e809aebba3ef5880935ffdd
ARG PNPM_VERSION=10.10.0

FROM ${NODE_IMAGE} AS build
ARG PNPM_VERSION
WORKDIR /app

RUN apk add --no-cache openssl \
    && corepack enable \
    && corepack prepare "pnpm@${PNPM_VERSION}" --activate
COPY package.json pnpm-lock.yaml ./
COPY prisma ./prisma
RUN pnpm install --frozen-lockfile \
    && DATABASE_URL=file:/tmp/portal-proxy-build.db pnpm prisma generate
COPY tsconfig.json ./
COPY src ./src
RUN pnpm run build

FROM ${NODE_IMAGE} AS runtime
ARG PNPM_VERSION
ENV NODE_ENV=production
WORKDIR /app

RUN apk add --no-cache openssl \
    && corepack enable \
    && corepack prepare "pnpm@${PNPM_VERSION}" --activate
COPY package.json pnpm-lock.yaml ./
COPY prisma ./prisma
RUN pnpm install --prod --frozen-lockfile \
    && DATABASE_URL=file:/tmp/portal-proxy-runtime.db pnpm prisma generate \
    && pnpm store prune
COPY --from=build /app/dist ./dist
RUN mkdir -p /data

EXPOSE 8788
CMD ["sh", "-c", "./node_modules/.bin/prisma migrate deploy && exec node dist/server.js"]
