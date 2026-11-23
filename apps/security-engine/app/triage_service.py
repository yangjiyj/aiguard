"""误报压制服务：类型感知 + Tier-1 门控的 finding triage 标注（异步路径调用）。

红线：
- 仅意图类 finding（INTENT_CLASS_TYPES）且 Tier-1 判输入良性（p<low）才调 judge_triage。
- _cannot_downgrade==true 的任何 finding + type∈{pii,secret,code_config,data_leak} 永不 triage/永不压制。
- Tier-1 不可达/None → 不压制（fail-open，不藏 finding）。
- 永不抛异常（异步旁路调用方只 log）。

P2-1 性能加固与双判定：
- 同 (rule_id, matched_location) 身份只处理一组，结果广播回同组全部 finding——
  gateway-core AnnotateTriage 回写本就按此身份 last-wins，重复按 finding 判断纯浪费。
- 每组默认做两轮独立 judge；只有两轮 verdict 一致才保留可压制结论。
  任一轮不可用或结论不一致都标为 needs_review，fail-open 不压制。
- 总预算 total_budget_seconds（从入口起算，含 Tier-1 打分耗时）用尽即停止后续 judge，
  未判的 finding 无 triage（fail-open 不压制），避免多 finding 串行 judge 撑爆网关 10s ctx。
"""
from __future__ import annotations

import logging
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from app.detectors.llm_judge import (
    judge_health_budget,
    judge_triage,  # 模块级名，便于测试 monkeypatch
)
from app.detectors.triage import build_triage_payload
from app.feature_flags import DEFAULT_TRIAGE_TOTAL_BUDGET_SECONDS

logger = logging.getLogger(__name__)

# 共享契约：仅这些类型可 triage/可压制
INTENT_CLASS_TYPES = {"prompt_injection", "content_safety", "semantic_attack"}
# 共享契约：事实暴露类永不 triage/永不压制
# data_leak 同列：其凭据/代码泄露类（code_leak_access_key/database_url/password_in_code/
# api_key_leak/token_leak/cloud_credential）是事实暴露，但 data_leak.py 产出时不带
# ，留在可压制集合会被误报压制挡出收件箱（破红线③：永不丢证）。
NEVER_TRIAGE_TYPES = {"pii", "secret", "code_config", "data_leak"}
VERIFIED_CONTENT_SOURCES = {"verified_user_input", "verified_final_output"}

TRIAGEABLE_CONTENT_SOURCES = VERIFIED_CONTENT_SOURCES | {
    "user", "model_output", "assistant", "final_output",
}
# 这些来源是系统/开发者/工具/RAG/项目框架上下文，不是用户的攻击意图。
# 即便其中出现“忽略指令”等字样，也不应被用户越狱类二次裁判压成高危告警。
FRAMEWORK_CONTENT_SOURCES = frozenset({
    "system_prompt", "developer", "developer_instruction",
    "agent_runtime_context", "tool_def", "tool_result", "assistant_history",
    "external_web", "external_webpage", "web", "rag", "rag_context",
    "retrieved_context", "project_instruction", "project_instruction_file",
    "instruction_file",
})

# 两轮独立判断是告警降噪的最低门槛；共识失败时永远不隐藏证据。
TRIAGE_JUDGE_PASSES = 2
_RISK_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}

def _eligible(finding: Dict[str, Any], content_source: Optional[str] = None) -> bool:
    prior = finding.get("triage")
    if finding.get("counts_as_security_finding") is False or (isinstance(prior, dict) and prior.get("review_mode") == "contextual_candidate"):
        return False
    if bool(finding.get("deprecated", False)):
        return False
    source = str(content_source or finding.get("content_source") or "").strip().lower()
    if source in FRAMEWORK_CONTENT_SOURCES:
        return False
    ftype = finding.get("type", "")
    if ftype in NEVER_TRIAGE_TYPES:
        return source in VERIFIED_CONTENT_SOURCES
    if source and source not in TRIAGEABLE_CONTENT_SOURCES:
        return False
    return ftype in INTENT_CLASS_TYPES


def _identity(finding: Dict[str, Any]) -> Tuple[str, str]:
    """去重身份键：与 gateway-core AnnotateTriage 回写身份一致（rule_id + matched_location）。"""
    return (
        str(finding.get("rule_id", "")),
        str(finding.get("matched_location", "input")),
    )


def _needs_review_result(reason: str) -> Dict[str, Any]:
    reason = str(reason or "两轮模型复核未形成可用结论，需人工复核")[:300]
    return {
        "verdict": "needs_review",
        "review_state": "needs_review",
        "risk_level": "medium",
        "confidence": 0.0,
        "reason": reason,
        "evidence_summary": reason,
        "suggested_action": "review",
        "report_text": reason,
    }


def _merge_judge_results(results: List[Optional[Dict[str, Any]]]) -> Optional[Dict[str, Any]]:
    """合并两轮结果；任何缺失/分歧都只能得到 needs_review。"""
    completed = [dict(result) for result in results if result is not None]
    if not completed:
        return None

    verdicts = [str(result.get("verdict", "needs_review")).strip().lower() or "needs_review" for result in completed]
    if len(completed) != TRIAGE_JUDGE_PASSES or len(set(verdicts)) != 1:
        merged = _needs_review_result(
            "两轮模型复核不可用或结论不一致，需人工复核；网关保持原始告警"
        )
        merged["judge_passes"] = len(completed)
        merged["judge_agreement"] = False
        merged["judge_verdicts"] = verdicts
        for result in completed:
            risk = str(result.get("risk_level", "")).strip().lower()
            if _RISK_RANK.get(risk, 0) > _RISK_RANK[merged["risk_level"]]:
                merged["risk_level"] = risk
        return merged

    merged = completed[0]
    merged["review_state"] = merged.get("review_state", verdicts[0])
    merged["judge_passes"] = TRIAGE_JUDGE_PASSES
    merged["judge_agreement"] = True
    merged["judge_verdicts"] = verdicts
    return merged


def apply_check_triage(
    content: str,
    findings: List[Dict[str, Any]],
    *,
    tier1_score: Callable[[str], Optional[float]],
    low_threshold: float,
    judge: Dict[str, Any],
    total_budget_seconds: float = DEFAULT_TRIAGE_TOTAL_BUDGET_SECONDS,
    clock: Callable[[], float] = time.monotonic,
    content_source: Optional[str] = None,
    stage: str = "input",
) -> List[Dict[str, Any]]:
    """对意图类 finding 在「Tier-1 判输入良性」时调 judge_triage，写 finding['triage']。

    judge = {"url","model","api_key","timeout"}（既有裁判后端连接参数）。
    total_budget_seconds：judge 总预算（秒，从本函数入口起算，含 Tier-1 打分），
    超预算停止后续 judge（fail-open，不压制）；≤0 视为不限。
    clock：仅测试注入用（仿 _CircuitBreaker），生产恒为 time.monotonic。
    返回原 list（同对象，已就地标注 triage 的填了 .triage）。
    """
    if not findings:
        return findings
    started = clock()
    eligible = [f for f in findings if _eligible(f, content_source)]
    if not eligible:
        return findings
    intent_eligible = [f for f in eligible if f.get("type", "") in INTENT_CLASS_TYPES]
    if intent_eligible:
        try:
            p = tier1_score(content or "")
        except Exception as exc:  # noqa: BLE001 fail-open
            logger.warning("Tier-1 打分异常，跳过意图类误报压制：%s", exc)
            eligible = [f for f in eligible if f not in intent_eligible]
        else:
            if p is None or p >= low_threshold:
                # Tier-1 不可达 / 输入非明显良性；verified fact 仍必须复核
                eligible = [f for f in eligible if f not in intent_eligible]
        if not eligible:
            return findings
    # 按身份分组：同 (rule_id, matched_location) 只对代表做两轮判断，
    # 结果广播回同组全部 finding（副本，避免跨 finding 共享可变 dict）。
    groups: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
    for finding in eligible:
        groups.setdefault(_identity(finding), []).append(finding)
    group_list = list(groups.values())
    for index, group in enumerate(group_list):
        if total_budget_seconds > 0 and clock() - started >= total_budget_seconds:
            logger.warning(
                "误报压制 judge 总预算 %.1fs 用尽，剩余 %d 组 finding 不再判定（fail-open，不压制）",
                total_budget_seconds, len(group_list) - index,
            )
            break
        representative = group[0]
        payload = build_triage_payload(
            content or "", representative, stage or representative.get("matched_location", "input")
        )
        options = {}
        if judge.get("judge_backend"):
            options = {
                "judge_backend": judge["judge_backend"],
                "allow_private_egress": bool(judge.get("allow_private_egress", False)),
            }
        results: List[Optional[Dict[str, Any]]] = []
        for pass_index in range(1, TRIAGE_JUDGE_PASSES + 1):
            if total_budget_seconds > 0:
                remaining = total_budget_seconds - (clock() - started)
                if remaining <= 0:
                    break
                try:
                    timeout = min(float(judge["timeout"]), remaining)
                except (TypeError, ValueError):
                    timeout = judge["timeout"]
            else:
                timeout = judge["timeout"]
            pass_payload = dict(payload)
            pass_payload["review_pass"] = pass_index
            pass_payload["instruction"] = (
                f"{payload.get('instruction', '')} 这是第 {pass_index}/{TRIAGE_JUDGE_PASSES} 轮独立复核；"
                "请重新独立判断，不要沿用任何上一轮结论。"
            )
            try:
                with judge_health_budget(float(judge["timeout"])):
                    result = judge_triage(
                        pass_payload, url=judge["url"], model=judge["model"],
                        api_key=judge["api_key"], timeout=timeout, **options,
                    )
            except Exception as exc:  # noqa: BLE001 fail-open
                logger.warning(
                    "judge_triage 第%d轮异常，该组 finding 保留待复核：%s", pass_index, exc
                )
                result = None
            results.append(dict(result) if result is not None else None)

        result = _merge_judge_results(results)
        if result is None and representative.get("type", "") in NEVER_TRIAGE_TYPES and content_source in VERIFIED_CONTENT_SOURCES:
            result = {
                "verdict": "needs_review",
                "review_state": "unavailable",
                "risk_level": "medium",
                "confidence": 0.0,
                "reason": "模型裁判不可用，需人工复核",
                "evidence_summary": "模型裁判不可用，候选仍保留",
                "suggested_action": "review",
                "report_text": "模型裁判不可用，需人工复核",
                "judge_passes": len(results),
                "judge_agreement": False,
                "judge_verdicts": [],
            }
        if result is not None:
            result.setdefault("review_state", result.get("verdict", "needs_review"))
            for finding in group:
                finding["triage"] = dict(result)
    return findings
