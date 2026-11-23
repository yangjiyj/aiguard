# Tests 目录说明

## 单元测试
- Go 服务：各 `internal/*_test.go` 文件
- Python 服务：`apps/security-engine/tests/`

## 集成测试
- `tests/integration/` - 测试服务间交互

## E2E 测试
- `tests/e2e/` - 测试完整用户场景

## 运行测试

### Go 单元测试
```bash
cd apps/gateway-core
go test ./...
```

### Python 单元测试
```bash
cd apps/security-engine
pytest tests/
```

### 集成测试（需要服务运行）
```bash
cd tests
pip install -r requirements.txt
pytest integration/
```

### E2E 测试
```bash
pytest e2e/
```