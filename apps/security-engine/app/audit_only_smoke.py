"""CLI smoke test for the audit-only pass-through invariant."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass
from typing import Callable, Sequence

from app.detectors.engine import SecurityEngine, engine as default_engine


@dataclass(frozen=True)
class SmokeCaseResult:
    chain: str
    action: str
    findings_count: int
    forwarded: bool
    upstream_status: int | None
    error: str = ""


@dataclass(frozen=True)
class SmokeReport:
    ok: bool
    cases: list[SmokeCaseResult]


def _loopback_upstream(_: str) -> int:
    return 204


def _run_case(
    chain: str,
    detect: Callable[[], object],
    forward: Callable[[str], int],
) -> SmokeCaseResult:
    result = detect()
    action = getattr(result, "action", "")
    findings = getattr(result, "findings", [])
    if action != "audit":
        return SmokeCaseResult(
            chain=chain,
            action=action,
            findings_count=len(findings),
            forwarded=False,
            upstream_status=None,
            error=f"expected action=audit, got {action}",
        )
    if not findings:
        return SmokeCaseResult(
            chain=chain,
            action=action,
            findings_count=0,
            forwarded=False,
            upstream_status=None,
            error="expected at least one finding",
        )
    status = forward(chain)
    return SmokeCaseResult(
        chain=chain,
        action=action,
        findings_count=len(findings),
        forwarded=200 <= status < 300,
        upstream_status=status,
        error="" if 200 <= status < 300 else f"upstream returned {status}",
    )


def run_smoke(
    engine: SecurityEngine | None = None,
    forward: Callable[[str], int] | None = None,
) -> SmokeReport:
    eng = engine or default_engine
    upstream = forward or _loopback_upstream
    cases = [
        _run_case(
            "forward",
            lambda: eng.check_input(
                "audit-only-smoke-forward",
                "api_key=ordinaryvalue123456",  # pragma: allowlist secret nosemgrep
                {"source": "gateway_forward_proxy"},
            ),
            upstream,
        ),
        _run_case(
            "reverse",
            lambda: eng.check_output(
                "audit-only-smoke-reverse",
                "身份证号码: 11010519491231002X",  # pragma: allowlist secret nosemgrep
                {"source": "gateway_reverse_proxy"},
            ),
            upstream,
        ),
    ]
    return SmokeReport(ok=all(c.forwarded and not c.error for c in cases), cases=cases)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify security-engine keeps forward/reverse chains audit-only."
    )
    parser.add_argument("--json", action="store_true", help="print JSON report")
    args = parser.parse_args(argv)

    report = run_smoke()
    if args.json:
        print(json.dumps(asdict(report), ensure_ascii=False, sort_keys=True))
    else:
        for case in report.cases:
            status = "PASS" if case.forwarded and not case.error else "FAIL"
            print(
                f"{status} {case.chain}: action={case.action} "
                f"findings={case.findings_count} forwarded={case.forwarded} "
                f"upstream_status={case.upstream_status}"
            )
            if case.error:
                print(f"  error={case.error}")
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
