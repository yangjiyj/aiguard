"""Versioned deterministic revalidation of historical evidence, preserving originals.
Never infer safety from a missing excerpt or exempt a client/content source.
"""
import copy
import re
from app.detectors.data_leak import DataLeakDetector
from app.detectors.config_evidence import has_literal_sensitive_config
from app.detectors.policy_catalog import PolicyCatalogDetector
from app.detectors.policy_catalog import catalog_candidate_has_required_terms
from app.detectors.pii_checksum import validate_id_card_cn, validate_bank_card
from app.detectors.numeric_context import is_complete_pii_token, is_git_remote_reference

VERSION = "context-evidence-v3"
RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
# Protocol-derived builtin context sources (the parser's markers, never text claims).
BUILTIN_CONTEXT_SOURCES = frozenset({
    "system_prompt", "system", "developer", "developer_instruction", "developer_prompt",
    "tool_def", "agent_runtime_context", "agent_analysis_context",
})
SEMANTIC_ATTACK_TYPES = frozenset({"semantic_attack"})
RUNTIME = {"file_content_engine_unavailable", "file_content_object_unavailable",
           "file_content_request_oversized", "request_body_limit_exceeded"}
PROMPT = {"prompt_leak_internal_rules", "prompt_leak_initial_instructions"}

def invalid_reason(f):
    category = f.get("category", "")
    if category in RUNTIME:
        return "inspection_failure_is_not_content_risk"
    if f.get("rule_id") == "semantic_tier1_high_confidence":
        return "classifier_candidate_requires_context_confirmation"
    raw = f.get("raw_evidence", "") or ""
    context = f.get("evidence_context", "") or ""
    if category in {"id_card_cn", "pii_idcard", "pii_id_card"} and raw:
        if not validate_id_card_cn(raw):
            return "invalid_cn_identity_number"
    if category in {"bank_card_cn", "pii_bankcard", "pii_bank_card"} and raw:
        if not validate_bank_card(raw):
            return "invalid_bank_card_number"
    if category in {"id_card_cn", "pii_idcard", "pii_id_card", "bank_card_cn", "pii_bankcard", "pii_bank_card"} and raw and context:
        spans = [m.span() for m in re.finditer(re.escape(raw), context)]
        if spans and all(not is_complete_pii_token(context, *span) for span in spans):
            return "numeric_substring_of_identifier"
    if category in {"email", "pii_email"} and raw:
        if raw.lower() == "noreply@anthropic.com":
            return "public_service_address_is_not_personal_email"
        spans = [m.span() for m in re.finditer(re.escape(raw), context)]
        if spans and all(is_git_remote_reference(context, *span) for span in spans):
            return "git_ssh_remote_is_not_personal_email"
    if category == "illegal_organ_trade" and raw and context:
        if re.search(r'deliver', raw, re.I) and not catalog_candidate_has_required_terms(category, raw):
            return "delivery_word_is_not_organ_trade"
    if category == "injection_payload_splitting" and raw and context:
        if ('splitlines(' in raw and ('read_text(' in raw or 'read().splitlines' in raw)
                and not catalog_candidate_has_required_terms(category, raw)):
            return "source_listing_is_not_payload_splitting"
    if category in {"injection_binary_octal", "dos_resource_exhaustion_instruction"} and raw and context:
        if not catalog_candidate_has_required_terms(category, raw) and not catalog_candidate_has_required_terms(category, context):
            return "operational_reference_without_attack_payload_or_instruction"
    if category in {"dos_resource_exhaustion_instruction", "rag_fake_citation"} and raw and context:
        if re.fullmatch(r'[A-Za-z_]+', raw) and '_' in raw and not catalog_candidate_has_required_terms(category, raw):
            return "risk_category_identifier_is_not_an_instruction"
    if category in {"phone_cn", "pii_phone"} and re.fullmatch(r"1[3-9][0-9]{9}", raw):
        # Every occurrence must be inside an ASCII identifier. If even one
        # occurrence is a standalone number, preserve the event for review.
        spans = [m.span() for m in re.finditer(re.escape(raw), context)]
        if spans and all((a > 0 and re.fullmatch(r"[A-Za-z0-9_]", context[a-1])) or
                         (b < len(context) and re.fullmatch(r"[A-Za-z0-9_]", context[b])) for a,b in spans):
            return "numeric_substring_of_identifier"
    if category in {"classified_classified_cn", "classified_classified_en"} and raw and context:
        matches = list(re.finditer(re.escape(raw), context, re.I))
        detector = DataLeakDetector()
        if matches and all(not detector._has_local_classified_corroboration(context, m) for m in matches):
            return "classification_mention_without_document_evidence"
    if category in {"env_file", "config_file"} and raw and not has_literal_sensitive_config(raw):
        return "configuration_without_literal_sensitive_value"
    if category in PROMPT and raw:
        if not any(x["category"] == category for x in PolicyCatalogDetector().detect(raw, "input")):
            return "disconnected_words_are_not_prompt_disclosure"
    return ""

def out_of_scope_reason(f, inspection_scope):
    """Semantic attack verdicts on builtin context are outside the administrator's
    alert scope when inspect_builtin_context is off. Only the semantic verdict is
    withdrawn; credential/PII/catalog hits on the same source keep their own review.
    The source must be the parser's marker; free text claiming to be a system
    message never qualifies. Nothing is decided when no policy is supplied.
    """
    if not isinstance(inspection_scope, dict) or inspection_scope.get("inspect_builtin_context") is not False:
        return ""
    if str(f.get("type") or "").strip().lower() not in SEMANTIC_ATTACK_TYPES:
        return ""
    source = str(f.get("content_source") or "").strip().lower()
    if source not in BUILTIN_CONTEXT_SOURCES:
        return ""
    return "builtin_context_excluded_by_inspection_scope"


def revalidate(summary, severity, inspection_scope=None):
    revised = copy.deepcopy(summary)
    findings = revised.get("findings")
    if not isinstance(findings, list):
        return None
    changes = []
    for f in findings:
        if not isinstance(f, dict) or f.get("counts_as_security_finding") is False:
            continue
        reason = invalid_reason(f)
        status = "unconfirmed" if reason.startswith("classifier_") else "invalidated"
        if not reason:
            reason = out_of_scope_reason(f, inspection_scope)
            status = "out_of_scope"
        if not reason:
            continue
        f["evidence_revalidation"] = {"version": VERSION, "reason": reason,
            "original_counts_as_security_finding": f.get("counts_as_security_finding"),
            "status": status}
        f["counts_as_security_finding"] = False
        changes.append(reason)
    if not changes:
        return None
    active = [f for f in findings if isinstance(f, dict) and f.get("counts_as_security_finding") is not False]
    revised["findings_count"] = len(active)
    revised["evidence_revalidation"] = {"version": VERSION, "original_severity": severity, "reasons": changes}
    if isinstance(revised.get("primary_finding"), dict):
        primary = revised["primary_finding"]
        for f in findings:
            if f.get("rule_id") == primary.get("rule_id") and f.get("raw_evidence") == primary.get("raw_evidence"):
                revised["primary_finding"] = copy.deepcopy(f)
                break
    new_severity = max((f.get("severity", "low") for f in active), key=lambda v:RANK.get(v,0), default="low")
    return revised, new_severity, changes
