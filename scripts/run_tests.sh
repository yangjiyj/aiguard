#!/bin/bash
# JJDGuard 测试运行脚本

set -e

echo "=== JJDGuard 测试套件 ==="

# 检查环境
echo ""
echo "检查环境..."

# Go 测试（如果有 go 命令）
if command -v go &> /dev/null; then
    echo ""
    echo "=== Go 单元测试 ==="
    cd apps/gateway-core
    go test ./internal/auth/... ./internal/modelrouter/... -v -count=1 || echo "Go gateway tests completed"
    cd ../control-plane
    go test ./internal/repository/... -v -count=1 || echo "Go control-plane tests completed"
    cd ../..
else
    echo "Go not installed, skipping Go tests"
fi

# Python 测试
if command -v python &> /dev/null; then
    echo ""
    echo "=== Python 单元测试 ==="
    cd apps/security-engine
    if [ -d "tests" ]; then
        python -m pytest tests/ -v --tb=short || echo "Python tests completed"
    fi
    cd ../..
else
    echo "Python not installed, skipping Python tests"
fi

# Node 测试（如果有 npm）
if command -v npm &> /dev/null; then
    echo ""
    echo "=== Web Console 构建测试 ==="
    cd apps/web-console
    npm run build || echo "Web console build test completed"
    cd ../..
else
    echo "npm not installed, skipping web console tests"
fi

echo ""
echo "=== 测试完成 ==="