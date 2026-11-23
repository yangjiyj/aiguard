#!/bin/bash
# 容器健康检查：llama-server 的 /health 在模型加载完成前返回 503，加载完成后返回 200。
exec 3<>/dev/tcp/127.0.0.1/8080 || exit 1
printf 'GET /health HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n' >&3
IFS= read -r -t 3 status <&3 || exit 1
[[ "$status" == *" 200 "* ]]
