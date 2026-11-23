"""Backend end-to-end for custom-policy deletion against the isolated stack (stdlib only).

Driven by run.sh (needs the E2E_* environment, see e2e_lib.py). cwd = this directory.
"""
import json
import sys
import time
import uuid

sys.path.insert(0, ".")
from e2e_lib import *  # noqa: E402,F401,F403

FAILED = []


def check(label, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + label + (f"  [{detail}]" if detail and not ok else (f"  ({detail})" if detail else "")))
    if not ok:
        FAILED.append(label)
    return ok


token = admin_token()
KEY = env("API_KEY")
SUFFIX = uuid.uuid4().hex[:6]
MARK = f"E2E删除专用词{SUFFIX}"
NAME = f"E2E-自定义关键词-{SUFFIX}"


def api(method, path, body=None, tok=None):
    return req(method, CP + "/admin/v1" + path, body, token=tok or token)


def chat(text):
    return req("POST", GW + "/v1/chat/completions",
               {"model": "mock-model", "messages": [{"role": "user", "content": text}]}, token=KEY, timeout=60)


def upstream_hits():
    out = subprocess.run(["docker", "exec", PROJECT + "-upstream-1", "python", "-c",
                          "import urllib.request,json;print(json.load(urllib.request.urlopen('http://127.0.0.1:9000/hits'))['hits'])"],
                         capture_output=True, text=True)
    return int(out.stdout.strip())


def pull_status():
    s, b = api("GET", "/rules/pull-status")
    node = (b.get("nodes") or [{}])[0]
    return b.get("desired_version"), node.get("held_version"), node


def wait_engine_converged(expect_changed_from=None, timeout=120):
    def ok():
        desired, held, _ = pull_status()
        if expect_changed_from and desired == expect_changed_from:
            return None
        return (desired, held) if desired and desired == held else None
    return wait_for(ok, timeout=timeout, interval=2, what="engine to hold the desired rule pack")


def snapshot():
    s, pol = api("GET", "/security/policies")
    pols = pol["data"]
    s, rules = api("GET", "/rules")
    s, content = api("GET", "/content-security/rules")
    s, assets = api("GET", "/security/policy-assets")
    s, caps = api("GET", "/security/policies/capabilities")
    desired, held, node = pull_status()
    return {
        "policy_total": pol["total"], "policy_rows": len(pols),
        "enabled_count": pol["enabled_count"], "active_count": pol["active_count"], "configured_count": pol["configured_count"],
        "ready_count": pol["ready_count"], "pending_count": pol["pending_count"],
        "custom_rows": sum(1 for p in pols if p["origin"] == "organization_created"),
        "ids": {p["id"] for p in pols},
        "rules_total": rules["total"], "rule_ids": {r["id"] for r in rules["data"]},
        "content_rules": json.dumps(content, ensure_ascii=False),
        "asset_ids": json.dumps(assets, ensure_ascii=False),
        "assets_total": (assets["total_assets"], assets["applicable_assets"], assets["executable_assets"]),
        "caps": json.dumps(caps, ensure_ascii=False),
        "desired": desired, "held": held, "policy_runtime_count": node.get("policy_runtime_count"),
    }


print("== 切到防护阻断模式（新装默认是观察留痕，不拦截）")
st, resp = api("PUT", "/system/settings", {"security_execution_mode": "protect", "change_reason": "e2e delete verification"})
check("设置防护阻断模式", st in (200, 204), f"{st} {resp}")


def mode_ready():
    s_, b_ = api("GET", "/system/settings")
    m = (b_ or {}).get("security_execution_mode") or {}
    return m if m.get("effective_mode") == "protect" else None


mode = wait_for(mode_ready, timeout=30, what="protect mode")
print("mode:", mode)

s_, left = api("GET", "/security/policies")
for p_ in left["data"]:
    if p_["origin"] == "organization_created" and p_["name"].startswith("E2E-"):
        api("DELETE", f"/security/policies/{p_['id']}")  # leftovers of an earlier aborted run

print("== baseline（等引擎持有最新规则包、运行态计数稳定）")
wait_engine_converged()
wait_for(lambda: api("GET", "/security/policies")[1]["active_count"] > 0, timeout=120, what="runtime active_count to settle")
time.sleep(3)
base = snapshot()
print({k: v for k, v in base.items() if k not in ("ids", "rule_ids", "content_rules", "asset_ids", "caps")})
hits0 = upstream_hits()
st, body = chat("你好，今天天气怎么样")
check("基线：普通请求放行", st == 200, f"{st} {str(body)[:200]}")
check("基线：上游收到普通请求", upstream_hits() == hits0 + 1)

print("== 创建 keyword+block 自定义策略")
payload = {
    "name": NAME, "description": "e2e 删除链路验证", "scene": "data_leak", "severity": "high", "action": "block", "enabled": True,
    "matcher": {"type": "keyword", "config": {"keywords": [MARK]}}, "capability_categories": [], "binding_mode": "any",
}
st, created = api("POST", "/security/policies", payload)
check("创建自定义策略", st in (200, 201), f"{st} {str(created)[:300]}")
policy = created.get("data", created) if isinstance(created, dict) else created
pid = policy["id"]
print("policy id:", pid)
v0 = base["desired"]
wait_engine_converged(expect_changed_from=v0)
snap1 = snapshot()
check("创建后：策略总数 +1", snap1["policy_total"] == base["policy_total"] + 1, f"{base['policy_total']} -> {snap1['policy_total']}")
check("创建后：自建数 +1", snap1["custom_rows"] == base["custom_rows"] + 1)
check("创建后：启用数 +1", snap1["enabled_count"] == base["enabled_count"] + 1, f"{base['enabled_count']} -> {snap1['enabled_count']}")
check("创建后：旧规则列表出现该策略", pid in snap1["rule_ids"])
check("创建后：策略资产出现该策略，资产计数 +1", pid in snap1["asset_ids"] and snap1["assets_total"][0] == base["assets_total"][0] + 1, f"{base['assets_total']} -> {snap1['assets_total']}")
check("创建后：引擎运行策略数 +1", (snap1["policy_runtime_count"] or 0) == (base["policy_runtime_count"] or 0) + 1,
      f"{base['policy_runtime_count']} -> {snap1['policy_runtime_count']}")

print("== 删除前：请求被拦并产生告警")
for _ in range(60):  # on a fresh stack the gateway picks up the new execution mode within ~1-2 minutes
    st, body = chat(f"请帮我整理一下 {MARK} 的资料")
    if st != 200:
        break
    time.sleep(3)
check("删除前：含关键词请求被拦（403 security_blocked）", st == 403 and "security_blocked" in json.dumps(body), f"{st} {str(body)[:300]}")
check("删除前：拦截提示里带策略名", NAME in json.dumps(body, ensure_ascii=False), str(body)[:300])
hits1 = upstream_hits()  # earlier attempts may still have gone through while the mode propagated
chat(f"请帮我整理一下 {MARK} 的资料")
check("删除前：被拦请求没有到达上游", upstream_hits() == hits1)
print("block response:", st, str(body)[:300])
ev = wait_for(lambda: psql(f"SELECT id||'|'||COALESCE(action_taken,'')||'|'||COALESCE(rule_id,'') FROM security_events WHERE rule_id='{pid}' ORDER BY created_at DESC LIMIT 1"),
              timeout=60, what="security event for the policy")
check("删除前：security_events 记到该策略(rule_id 外键)", pid in ev, ev)
event_id = ev.split("|")[0]
request_id = psql(f"SELECT request_id FROM security_events WHERE id='{event_id}'")


def surfaces(name, event_id, request_id):
    """Every read path that prints a rule name next to a historical event -> does it still show `name`?"""
    out = {}
    for label, path in [
        ("审计事件列表", "/audit/events?limit=50"),
        ("拦截记录列表", "/security/block-records?limit=50"),
        ("拦截记录详情", f"/security/block-records/{event_id}"),
        ("请求审计详情", f"/audit/requests/{request_id}"),
        ("告警事件(alert-occurrences)", "/security/alert-occurrences?limit=50"),
        ("告警组", "/alert-groups?limit=50"),
        ("内容安全概览", "/audit/content/security-overview"),
    ]:
        s_, b_ = api("GET", path)
        out[label] = (s_, name in json.dumps(b_, ensure_ascii=False))
    return out


shown_before = wait_for(lambda: (lambda d: d if d["审计事件列表"][1] and d["拦截记录列表"][1] else None)(surfaces(NAME, event_id, request_id)),
                        timeout=60, what="event/block record to show the policy name")
for label, (code, shown) in shown_before.items():
    print(f"  删除前 {label}: HTTP {code}, 显示策略名={shown}")
check("删除前：审计事件列表/拦截记录列表都显示策略名", shown_before["审计事件列表"][1] and shown_before["拦截记录列表"][1])

print("== 删除")
v1 = snap1["desired"]
st, resp = api("DELETE", f"/security/policies/{pid}")
check("DELETE /security/policies/{id} → 204", st == 204, f"{st} {resp}")
audit = psql("SELECT action_type FROM audit_operations WHERE action_type='security_policy.delete' ORDER BY created_at DESC LIMIT 1")
check("审计日志有 security_policy.delete", audit == "security_policy.delete", audit)
audit_detail = psql("SELECT action_detail::text FROM audit_operations WHERE action_type='security_policy.delete' ORDER BY created_at DESC LIMIT 1")
check("审计日志详情带策略名", NAME in audit_detail, audit_detail)

wait_engine_converged(expect_changed_from=v1)
try:
    wait_for(lambda: snapshot()["active_count"] == base["active_count"], timeout=60, what="active_count to settle")
except TimeoutError as exc:
    print("note:", exc)
snap2 = snapshot()
check("删除后：规则包版本变化", snap2["desired"] != v1, f"{v1} -> {snap2['desired']}")
check("删除后：策略总数回到基线", snap2["policy_total"] == base["policy_total"], f"{base['policy_total']} -> {snap2['policy_total']}")
check("删除后：策略行数回到基线", snap2["policy_rows"] == base["policy_rows"])
check("删除后：自建数回到基线", snap2["custom_rows"] == base["custom_rows"])
check("删除后：启用数回到基线", snap2["enabled_count"] == base["enabled_count"], f"{base['enabled_count']} -> {snap2['enabled_count']}")
check("删除后：运行中数回到基线", snap2["active_count"] == base["active_count"], f"{base['active_count']} -> {snap2['active_count']}")
check("删除后：已配置/就绪数回到基线", (snap2["configured_count"], snap2["ready_count"]) == (base["configured_count"], base["ready_count"]))
check("删除后：策略列表不含它", pid not in snap2["ids"])
check("删除后：GET /rules 不含它", pid not in snap2["rule_ids"] and snap2["rules_total"] == base["rules_total"], f"{base['rules_total']} -> {snap2['rules_total']}")
check("删除后：内容安全规则列表不含它", pid not in snap2["content_rules"] and NAME not in snap2["content_rules"])
check("删除后：策略资产不含它，资产计数回到基线", pid not in snap2["asset_ids"] and NAME not in snap2["asset_ids"] and snap2["assets_total"] == base["assets_total"], f"{base['assets_total']} -> {snap2['assets_total']}")
check("删除后：检测组件引用数回到基线", snap2["caps"] == base["caps"])
check("删除后：引擎运行策略数回到基线", snap2["policy_runtime_count"] == base["policy_runtime_count"],
      f"{base['policy_runtime_count']} -> {snap2['policy_runtime_count']}")

print("== 删除后：同样请求不再被拦")
hits2 = upstream_hits()
st, body = chat(f"请帮我整理一下 {MARK} 的资料")
check("删除后：同样请求放行", st == 200, f"{st} {str(body)[:300]}")
check("删除后：上游收到该请求", upstream_hits() == hits2 + 1)

print("== 告警仍然保留并显示策略名")
shown_after = surfaces(NAME, event_id, request_id)
for label, (code, shown) in shown_after.items():
    was = shown_before[label][1]
    print(f"  删除后 {label}: HTTP {code}, 显示策略名={shown}（删除前={was}）")
    if was:
        check(f"删除后：{label}仍显示策略名", shown and code == 200, f"HTTP {code}")
row = psql(f"SELECT enabled::text||'|'||(scope_json ? 'deleted_at')::text FROM rules WHERE id='{pid}'")
check("墓碑行保留：enabled=false 且带 deleted_at", row == "false|true", row)

print("== 删除后：重复操作")
st, _ = api("DELETE", f"/security/policies/{pid}")
check("再次删除 → 404", st == 404, str(st))
st, _ = api("PATCH", f"/security/policies/{pid}", {"enabled": True})
check("修改已删除策略 → 404", st == 404, str(st))
st, _ = api("DELETE", f"/rules/{pid}")
check("旧接口删除已删除策略 → 404", st == 404, str(st))
st, _ = api("POST", f"/rules/{pid}/toggle")
check("旧接口启停已删除策略 → 404", st == 404, str(st))

print("== 同名重建")
st, created2 = api("POST", "/security/policies", payload)
check("同名策略可以重新创建", st in (200, 201), f"{st} {str(created2)[:300]}")
pid2 = (created2.get("data", created2))["id"]
check("重建的是新策略", pid2 != pid)
s, pol = api("GET", "/security/policies")
check("重建后列表里只有一条同名策略", sum(1 for p in pol["data"] if p["name"] == NAME) == 1)
wait_engine_converged(expect_changed_from=snap2["desired"])
st, body = chat(f"请帮我整理一下 {MARK} 的资料")
check("重建后：关键词请求再次被拦", st != 200, f"{st}")
st, _ = api("DELETE", f"/rules/{pid2}")
check("旧接口 DELETE /rules/{custom.*} → 204", st == 204, str(st))
s, pol = api("GET", "/security/policies")
check("旧接口删除后列表不含重建策略", all(p["id"] != pid2 for p in pol["data"]))

print("== 内置策略与不存在的 id")
builtin = next(p for p in pol["data"] if p["origin"] == "preloaded")
st, resp = api("DELETE", f"/security/policies/{builtin['id']}")
check("内置策略 DELETE → 409 policy_not_deletable", st == 409 and "policy_not_deletable" in json.dumps(resp), f"{st} {resp}")
s, pol2 = api("GET", "/security/policies")
check("内置策略仍在列表里", any(p["id"] == builtin["id"] for p in pol2["data"]))
st, _ = api("DELETE", "/security/policies/does-not-exist")
check("不存在的 id → 404", st == 404, str(st))
st, resp = api("DELETE", f"/rules/{builtin['id']}")
check("旧接口删内置策略 → 409", st == 409, f"{st} {resp}")

print("== 角色：auditor 不能删")
atok, _ = captcha_login("auditor1", "Auditor#E2e-20261109")
st, created3 = api("POST", "/security/policies", dict(payload, name=NAME + "-b"))
pid3 = (created3.get("data", created3))["id"]
st, resp = api("DELETE", f"/security/policies/{pid3}", tok=atok)
check("auditor DELETE → 403", st == 403, f"{st} {resp}")
s, pol = api("GET", "/security/policies")
check("auditor 删除被拒后策略仍在", any(p["id"] == pid3 for p in pol["data"]))
st, _ = api("DELETE", f"/security/policies/{pid3}")
check("清理：admin 删除第三条策略", st == 204)

print("== 旧接口 DELETE /rules/{id}：已产生告警的老规则不再 500")
LEGACY_NAME = f"E2E老规则-{SUFFIX}"
LEGACY_WORD = f"E2E老规则词{SUFFIX}"
st, legacy = api("POST", "/rules", {
    "rule_type": "keyword", "name": LEGACY_NAME, "severity": "high", "action": "block",
    "match_config_json": {"keywords": [LEGACY_WORD]},
})
print("legacy create:", st, str(legacy)[:300])
if check("创建老规则（无 policy_code）", st in (200, 201), f"{st} {str(legacy)[:300]}"):
    lid = (legacy.get("data", legacy))["id"]
    wait_engine_converged()
    for _ in range(40):  # real traffic: the legacy rule must reach the engine and fire
        st, body = chat(f"这是一条带有 {LEGACY_WORD} 的请求")
        if st != 200:
            break
        time.sleep(3)
    check("老规则真实拦截请求", st == 403, f"{st} {str(body)[:200]}")
    fk = wait_for(lambda: psql(f"SELECT count(*) FROM security_events WHERE rule_id='{lid}'") not in ("0", ""), timeout=30, what="legacy event")
    check("老规则已产生告警（security_events 外键引用它）", fk)
    legacy_event = psql(f"SELECT id FROM security_events WHERE rule_id='{lid}' ORDER BY created_at DESC LIMIT 1")
    legacy_req = psql(f"SELECT request_id FROM security_events WHERE id='{legacy_event}'")
    legacy_before = surfaces(LEGACY_NAME, legacy_event, legacy_req)
    st, _ = api("POST", "/content-security/exceptions", {"scope_type": "rule", "rule_ref": lid, "decision": "allow", "reason": "e2e", "expires_at": "never"})
    check("给老规则建一条永久豁免", st == 201 and psql(f"SELECT count(*) FROM content_audit_exceptions WHERE rule_id='{lid}'") == "1", str(st))
    st, resp = api("DELETE", f"/rules/{lid}")
    check("老规则 DELETE → 204（不再 500）", st == 204, f"{st} {resp}")
    check("老规则删除后：它的豁免随之消失", psql(f"SELECT count(*) FROM content_audit_exceptions WHERE rule_id='{lid}' OR rule_ref='{lid}'") == "0")
    legacy_after = surfaces(LEGACY_NAME, legacy_event, legacy_req)
    for label, (code, shown) in legacy_after.items():
        if legacy_before[label][1]:
            check(f"老规则删除后：{label}仍显示规则名", shown and code == 200, f"HTTP {code}")
    wait_engine_converged()
    st, body = chat(f"这是一条带有 {LEGACY_WORD} 的请求")
    check("老规则删除后：同样请求放行", st == 200, f"{st} {str(body)[:200]}")
    s, rules = api("GET", "/rules")
    check("老规则删除后 GET /rules 不含它", all(r["id"] != lid for r in rules["data"]))
    st, _ = api("DELETE", f"/rules/{lid}")
    check("老规则再次删除 → 404", st == 404, str(st))
    st, _ = api("PATCH", f"/rules/{lid}", {"enabled": True})
    check("老规则已删除后修改 → 404", st == 404, str(st))
    st, _ = api("POST", f"/rules/{lid}/toggle")
    check("老规则已删除后启停 → 404", st == 404, str(st))
    st, lr = api("POST", "/rules", {
        "rule_type": "keyword", "name": f"E2E老规则-无告警-{SUFFIX}", "severity": "high", "action": "block",
        "match_config_json": {"keywords": [f"E2E老规则词B{SUFFIX}"]}})
    lid2 = (lr.get("data", lr))["id"]
    st, _ = api("DELETE", f"/rules/{lid2}")
    check("没告警的老规则仍是直接删除", st == 204 and psql(f"SELECT count(*) FROM rules WHERE id='{lid2}'") == "0")

print("== 豁免随策略一起消失；按能力组合新建的策略删除后，检测组件引用数回到基线")
s, caps0 = api("GET", "/security/policies/capabilities")
cap0 = next(c for c in caps0["data"] if c["enabled"] and "audit" in c["allowed_actions"])
caps_before = json.dumps(caps0, ensure_ascii=False)
st, capol = api("POST", "/security/policies", {"name": f"E2E-组件策略-{SUFFIX}", "description": "", "scene": "data_leak", "severity": "medium", "action": "audit",
                                               "enabled": True, "capability_categories": [cap0["category"]], "binding_mode": "any"})
check("创建按能力组合的自建策略", st in (200, 201), f"{st} {str(capol)[:200]}")
capid = capol["id"]
s, caps1 = api("GET", "/security/policies/capabilities")
check("创建后：检测组件被引用数 +1", json.dumps(caps1, ensure_ascii=False) != caps_before)
v_before_exc = pull_status()[0]
st, _ = api("POST", "/content-security/exceptions", {"scope_type": "rule", "rule_ref": capid, "decision": "allow", "reason": "e2e", "expires_at": "never"})
check("给自建策略建一条永久豁免", st == 201 and psql(f"SELECT count(*) FROM content_audit_exceptions WHERE rule_id='{capid}'") == "1", str(st))
try:
    wait_engine_converged(expect_changed_from=v_before_exc)
    check("带豁免的规则包引擎照常接收（豁免有自己的 id）", True)
except TimeoutError as exc:
    check("带豁免的规则包引擎照常接收（豁免有自己的 id）", False, str(exc))
st, _ = api("DELETE", f"/security/policies/{capid}")
check("删除按能力组合的自建策略 → 204", st == 204, str(st))
check("删除后：它的豁免随之消失（库里没有）", psql(f"SELECT count(*) FROM content_audit_exceptions WHERE rule_id='{capid}' OR rule_ref='{capid}'") == "0")
s, excs = api("GET", "/content-security/exceptions")
check("删除后：豁免列表里没有它", capid not in json.dumps(excs, ensure_ascii=False))
s, caps2 = api("GET", "/security/policies/capabilities")
check("删除后：检测组件引用数回到基线", json.dumps(caps2, ensure_ascii=False) == caps_before)

print()
print("FAILED:" if FAILED else "ALL PASSED", FAILED if FAILED else "")
sys.exit(1 if FAILED else 0)
