# JJDGuard 顶层 Makefile
#
# 任务 13 起步：仅 identity-lab target。其它模块的便捷 target 请按需在对应目录维护，
# 或后续在此追加（保持 target 命名约定：<module>-<verb>）。

.PHONY: identity-db-test identity-lab-check identity-lab-up identity-lab-smoke identity-lab-down

# identity-lab：隔离测试环境（任务 13）。
# 完整验收必须依次执行 check/up/smoke/down；所有服务健康后才进入 smoke。

IDENTITY_LAB_DIR := deploy/identity-lab
IDENTITY_LAB_COMPOSE := $(IDENTITY_LAB_DIR)/docker-compose.identity-lab.yml
IDENTITY_LAB_SMOKE := ./scripts/identity-lab-smoke.sh
IDENTITY_LAB_CP_BIN := /tmp/jjdguard-identity-lab-control-plane
IDENTITY_LAB_GO ?= /usr/local/go/bin/go
IDENTITY_LAB_WAIT ?= ./scripts/identity-lab-wait.sh
IDENTITY_DB_TEST := ./scripts/identity-db-test.sh
export IDENTITY_LAB_ENV_FILE := $(abspath $(if $(wildcard $(IDENTITY_LAB_DIR)/.env),$(IDENTITY_LAB_DIR)/.env,$(IDENTITY_LAB_DIR)/.env.example))
IDENTITY_LAB_CHECK_ENV_FILE := $(abspath $(IDENTITY_LAB_DIR)/.env.example)
IDENTITY_LAB_COMPOSE_CMD := docker compose --project-name jjdguard-identity-lab -f $(IDENTITY_LAB_COMPOSE) --env-file $(IDENTITY_LAB_ENV_FILE)
IDENTITY_LAB_CHECK_COMPOSE_CMD := docker compose --project-name jjdguard-identity-lab -f $(IDENTITY_LAB_COMPOSE) --env-file $(IDENTITY_LAB_CHECK_ENV_FILE)

# Static config, script regressions, and --check-only gate.
identity-lab-check:
	@bash -n $(IDENTITY_LAB_SMOKE)
	@bash -n $(IDENTITY_DB_TEST)
	@bash -n ./scripts/identity-db-test-test.sh
	@./scripts/identity-db-test-test.sh
	@./scripts/identity-lab-compose-test.sh
	@./scripts/identity-lab-smoke-test.sh
	@./scripts/identity-lab-wait-test.sh
	@./scripts/identity-lab-make-cleanup-test.sh
	@python3 ./scripts/identity-lab-admin-toggle-test.py
	@python3 ./scripts/identity-lab-control-plane-api-test.py
	@python3 ./scripts/identity-lab-portal-proxy-test.py
	@$(IDENTITY_LAB_CHECK_COMPOSE_CMD) config >/dev/null
	@IDENTITY_LAB_ENV_FILE=$(IDENTITY_LAB_CHECK_ENV_FILE) $(IDENTITY_LAB_SMOKE) --check-only

identity-db-test:
	@$(IDENTITY_DB_TEST)

# Start from an empty, project-scoped lab and wait for every dependency.
identity-lab-up:
	@set -eu; cleanup() { $(IDENTITY_LAB_COMPOSE_CMD) down -v --remove-orphans; rm -f $(IDENTITY_LAB_CP_BIN); }; trap 'status=$$?; if [ $$status -ne 0 ]; then cleanup; fi' EXIT; trap 'exit 130' INT; trap 'exit 143' TERM; cleanup; cd apps/control-plane && CGO_ENABLED=0 GOFLAGS=-buildvcs=false $(IDENTITY_LAB_GO) build -o $(IDENTITY_LAB_CP_BIN) ./cmd/server; cd ../..; $(IDENTITY_LAB_COMPOSE_CMD) up -d; IDENTITY_LAB_ENV_FILE=$(IDENTITY_LAB_ENV_FILE) $(IDENTITY_LAB_WAIT); trap - EXIT INT TERM

# Run AP1-AP10 through real Portal callbacks.
identity-lab-smoke:
	@set -eu; cleanup() { $(IDENTITY_LAB_COMPOSE_CMD) down -v --remove-orphans; rm -f $(IDENTITY_LAB_CP_BIN); }; trap 'status=$$?; if [ $$status -ne 0 ]; then cleanup; fi' EXIT; trap 'exit 130' INT; trap 'exit 143' TERM; $(IDENTITY_LAB_SMOKE); trap - EXIT INT TERM

identity-lab-down:
	@$(IDENTITY_LAB_COMPOSE_CMD) down -v --remove-orphans
	@rm -f $(IDENTITY_LAB_CP_BIN)
