# syntax=docker.1ms.run/docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

FROM docker.1ms.run/library/node:22-alpine@sha256:e58326d0d441090181ac150dc2078d3e2cf6a0d42e809aebba3ef5880935ffdd AS development

WORKDIR /app

COPY package.json package-lock.json* ./
RUN --mount=type=bind,from=release-npm-cache,source=.,target=/tmp/npm-cache-input,readonly \
    mkdir -p /root/.npm \
    && tar -xf /tmp/npm-cache-input/npm-cache.tar -C /root/.npm \
    && npm ci --offline --legacy-peer-deps --cache /root/.npm --no-audit --no-fund

COPY . .
RUN chown -R node:node /app

USER node

EXPOSE 3000

CMD ["npm", "run", "dev"]

FROM docker.1ms.run/library/node:22-alpine@sha256:e58326d0d441090181ac150dc2078d3e2cf6a0d42e809aebba3ef5880935ffdd AS builder

WORKDIR /app

COPY package.json package-lock.json* ./
RUN --mount=type=bind,from=release-npm-cache,source=.,target=/tmp/npm-cache-input,readonly \
    mkdir -p /root/.npm \
    && tar -xf /tmp/npm-cache-input/npm-cache.tar -C /root/.npm \
    && npm ci --offline --legacy-peer-deps --cache /root/.npm --no-audit --no-fund

COPY . .
ARG VITE_BILLING_ENABLED=false
ENV VITE_BILLING_ENABLED=$VITE_BILLING_ENABLED

RUN npm run build

FROM docker.1ms.run/library/node:22-alpine@sha256:e58326d0d441090181ac150dc2078d3e2cf6a0d42e809aebba3ef5880935ffdd AS production

WORKDIR /app
ENV PORT=3000
ENV HTTPS_PORT=3443

COPY --from=builder --chown=node:node /app/dist ./dist
COPY --chown=node:node server.js ./server.js

USER node

EXPOSE 3000
EXPOSE 3443

CMD ["node", "server.js"]
