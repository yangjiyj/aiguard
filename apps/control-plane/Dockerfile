FROM docker.1ms.run/library/golang:1.26.4-alpine@sha256:3ad57304ad93bbec8548a0437ad9e06a455660655d9af011d58b993f6f615648 AS builder

WORKDIR /app

COPY --from=release-go-cache /pkg/mod /go/pkg/mod
ENV GOPROXY=off GOSUMDB=off GOWORK=off

# Copy shared-go package first (as local dependency)
COPY packages/shared-go ./packages/shared-go
COPY apps/control-plane ./apps/control-plane

WORKDIR /app/apps/control-plane

RUN GOPROXY=off GOSUMDB=off go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o control-plane ./cmd/server

FROM docker.1ms.run/library/alpine:latest@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

WORKDIR /app

COPY --from=release-alpine-runtime /etc/ssl/certs /etc/ssl/certs
COPY --from=release-alpine-runtime /etc/ssl/cert.pem /etc/ssl/cert.pem
COPY --from=release-alpine-runtime /etc/ca-certificates.conf /etc/ca-certificates.conf
COPY --from=release-alpine-runtime /usr/share/zoneinfo /usr/share/zoneinfo
RUN addgroup -S app \
    && adduser -S -G app app \
    && mkdir -p /var/lib/jjdguard/retention \
    && chown -R app:app /var/lib/jjdguard

COPY --from=builder /app/apps/control-plane/control-plane .
COPY VERSION .
COPY deploy/seeds /etc/uag/seeds

USER app

EXPOSE 8081

CMD ["./control-plane"]
