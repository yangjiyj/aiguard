"""Window dilution benchmark (R1).

Reproduces the production comparison behind the 1200/200 default: take real
long bodies, embed one hardcase attack sentence at a random offset, split the
body with the engine's own window planner, and ask the production judge window
by window. A pair counts as hit when any window returns ``malicious``.

The unmodified body is judged with the same settings to measure false positives,
so a window widening must move both columns, not just the judge-call column.

Usage (from a source checkout; ``bench/`` is not packaged into the engine image)::

    cd apps/security-engine
    python3 bench/window_dilution.py \
        --corpus /tmp/bodies.jsonl --attack /tmp/attacks.txt \
        --window 1200 --overlap 200 --count 100 --seed 2026

``--url`` / ``--model`` / ``--key`` default to ``SECURITY_LLM_JUDGE_URL``,
``SECURITY_LLM_JUDGE_MODEL`` and ``SECURITY_LLM_JUDGE_API_KEY`` (the legacy
``JUDGE_KEY`` still works), so on an engine host that already talks to the judge
the only arguments needed are the corpus and the attack list. The production
judge listens on port 8100; nothing here holds a real credential.

``--corpus`` is JSONL with one object per line carrying a ``text`` field (any
``content``/``body`` field is accepted too). ``--attack`` is one attack sentence
per line, 40-80 characters, matching the hardcase shape used in the measurement.

Instead of exporting a corpus by hand, ``--from-db`` reads it through ``psql``
(read-only, one statement) from ``content_log_bodies``::

    python3 bench/window_dilution.py --from-db "$DATABASE_URL" --attack /tmp/attacks.txt

That path needs ``psql`` on PATH (the engine image ships no PostgreSQL client);
without it, export JSONL and use ``--corpus``.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import shutil
import statistics
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.detectors.llm_judge import _build_semantic_payload  # noqa: E402
from app.detectors.semantic import plan_windows  # noqa: E402

DEFAULT_TIMEOUT = 20.0


def _read_bodies(path: Path, minimum: int) -> list:
    bodies = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            text = record.get("text") or record.get("content") or record.get("body") or ""
            if isinstance(text, str) and len(text) >= minimum:
                bodies.append(text)
    return bodies


def _bodies_from_db(dsn: str, minimum: int, limit: int) -> list:
    """Read-only export of long customer bodies, one statement, no Python driver.

    The engine image carries no PostgreSQL client library, so this shells out to
    ``psql``. Rows come back as one JSON object per line, which is exactly the
    ``--corpus`` format, so both input paths share the same reader.
    """
    if not shutil.which("psql"):
        raise SystemExit(
            "--from-db needs psql on PATH; export JSONL from content_log_bodies and use --corpus")
    sql = (
        "SELECT json_build_object('text', content)::text FROM content_log_bodies "
        "WHERE customer_text AND char_length(content) >= %d "
        "ORDER BY created_at DESC LIMIT %d" % (minimum, limit)
    )
    completed = subprocess.run(
        ["psql", dsn, "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-c", sql],
        check=True, capture_output=True, text=True,
    )
    bodies = []
    for line in completed.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        text = record.get("text") or ""
        if isinstance(text, str) and len(text) >= minimum:
            bodies.append(text)
    return bodies


def _read_attacks(path: Path) -> list:
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _judge(url: str, key: str, model: str, content: str, timeout: float) -> tuple:
    payload = _build_semantic_payload(content, model, json_schema=True)
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "Authorization": "Bearer " + key},
        method="POST",
    )
    started = time.monotonic()
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = json.loads(response.read().decode("utf-8"))
    latency = (time.monotonic() - started) * 1000.0
    raw = body["choices"][0]["message"]["content"]
    try:
        verdict = json.loads(raw).get("verdict", "")
    except json.JSONDecodeError:
        verdict = ""
    usage = body.get("usage") or {}
    return verdict, latency, int(usage.get("prompt_tokens") or 0)


def _scan(url: str, key: str, model: str, text: str, window: int, overlap: int,
          max_windows: int, timeout: float) -> tuple:
    windows = plan_windows(len(text), window, overlap, max_windows)
    calls = 0
    tokens = 0
    latencies = []
    for start, end in windows:
        calls += 1
        try:
            verdict, latency, prompt_tokens = _judge(url, key, model, text[start:end], timeout)
        except (urllib.error.URLError, TimeoutError, KeyError, ValueError) as exc:
            print("judge call failed: %s: %s" % (type(exc).__name__, exc), file=sys.stderr)
            continue
        latencies.append(latency)
        tokens = max(tokens, prompt_tokens)
        if verdict == "malicious":
            return True, calls, tokens, latencies
    return False, calls, tokens, latencies


def main() -> int:
    parser = argparse.ArgumentParser(description="semantic window dilution benchmark")
    parser.add_argument("--url", default=os.getenv("SECURITY_LLM_JUDGE_URL", "").strip(),
                        help="judge chat completions URL (default: $SECURITY_LLM_JUDGE_URL)")
    parser.add_argument("--key", default=(os.getenv("SECURITY_LLM_JUDGE_API_KEY", "").strip()
                                          or os.getenv("JUDGE_KEY", "").strip()),
                        help="judge bearer token (default: $SECURITY_LLM_JUDGE_API_KEY, "
                             "then $JUDGE_KEY)")
    parser.add_argument("--model", default=os.getenv("SECURITY_LLM_JUDGE_MODEL", "bundled-judge"),
                        help="judge model name (default: $SECURITY_LLM_JUDGE_MODEL)")
    parser.add_argument("--corpus", default="", help="JSONL with a text field per line")
    parser.add_argument("--from-db", dest="from_db", nargs="?", const="-", default="",
                        metavar="DSN",
                        help="read bodies from content_log_bodies through psql; bare "
                             "--from-db uses $DATABASE_URL")
    parser.add_argument("--attack", required=True, help="one attack sentence per line")
    parser.add_argument("--window", type=int, default=1200)
    parser.add_argument("--overlap", type=int, default=200)
    parser.add_argument("--max-windows", type=int, default=32)
    parser.add_argument("--count", type=int, default=100)
    parser.add_argument("--min-chars", type=int, default=4000)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--out", default="", help="write the per-pair JSONL here")
    args = parser.parse_args()

    if not args.url:
        parser.error("--url (or SECURITY_LLM_JUDGE_URL) is required")
    if not args.key:
        parser.error("--key (or SECURITY_LLM_JUDGE_API_KEY / JUDGE_KEY) is required")
    if bool(args.corpus) == bool(args.from_db):
        parser.error("pass exactly one of --corpus or --from-db")
    if args.from_db == "-":
        args.from_db = os.getenv("DATABASE_URL", "").strip()
        if not args.from_db:
            parser.error("--from-db without a DSN needs $DATABASE_URL")

    if args.from_db:
        bodies = _bodies_from_db(args.from_db, args.min_chars, args.count)
    else:
        bodies = _read_bodies(Path(args.corpus), args.min_chars)
    attacks = _read_attacks(Path(args.attack))
    if not bodies or not attacks:
        print("no usable bodies (>= %d chars) or no attacks" % args.min_chars, file=sys.stderr)
        return 2

    rng = random.Random(args.seed)
    sample = rng.sample(bodies, min(args.count, len(bodies)))
    hits = 0
    false_positives = 0
    judge_calls = 0
    all_latencies = []
    peak_tokens = 0
    records = []
    for index, body in enumerate(sample):
        attack = rng.choice(attacks)
        offset = rng.randrange(0, max(1, len(body) - len(attack)))
        poisoned = body[:offset] + attack + body[offset:]

        hit, calls, tokens, latencies = _scan(
            args.url, args.key, args.model, poisoned, args.window, args.overlap,
            args.max_windows, args.timeout)
        control_hit, control_calls, control_tokens, control_latencies = _scan(
            args.url, args.key, args.model, body, args.window, args.overlap,
            args.max_windows, args.timeout)
        hits += int(hit)
        false_positives += int(control_hit)
        judge_calls += calls + control_calls
        all_latencies.extend(latencies)
        all_latencies.extend(control_latencies)
        peak_tokens = max(peak_tokens, tokens, control_tokens)
        records.append({
            "index": index, "chars": len(body), "attack_chars": len(attack),
            "attack_offset": offset, "hit": hit, "control_flagged": control_hit,
            "judge_calls": calls + control_calls,
        })
        print("[%d/%d] chars=%d hit=%s control=%s calls=%d"
              % (index + 1, len(sample), len(body), hit, control_hit, calls + control_calls),
              file=sys.stderr)

    summary = {
        "window": args.window, "overlap": args.overlap, "pairs": len(sample),
        "attack_hits": hits, "control_flagged": false_positives,
        "hit_rate": round(hits / len(sample), 4),
        "false_positive_rate": round(false_positives / len(sample), 4),
        "judge_calls": judge_calls,
        "judge_calls_per_pair": round(judge_calls / len(sample), 2),
        "peak_prompt_tokens": peak_tokens,
        "p50_ms": round(statistics.median(all_latencies), 1) if all_latencies else 0.0,
        "p95_ms": round(sorted(all_latencies)[int(len(all_latencies) * 0.95) - 1], 1)
        if all_latencies else 0.0,
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            for record in records:
                handle.write(json.dumps(record, ensure_ascii=False) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
