"""Tier-1 分类器客户端：httpx 调 sidecar /classify，超时/失败/非200 → None（fail-open）。

红线：
- classify() 永不抛异常（被 semantic.detect 调用，detect 必须永不冒泡）。
- 不可达/超时/解析失败一律返回 None → security-engine 跳过语义（fail-open，不回退 3B 打全量）。
- 复用 llm_judge 的熔断器范式：连续失败达阈值即在冷却窗内短路。
"""
from __future__ import annotations

import json
import logging
import math
import os
import time
import threading
from dataclasses import dataclass
import urllib.error
import urllib.parse
import urllib.request
from typing import Callable, Optional, Tuple

from app.header_compat import INTERNAL_TOKEN_HEADER
from app.bounded_work import positive_number, check_work_budget, effective_deadline, WorkUnavailable
from app.coordination import breaker_state
from app.detectors.http_budget import read_response_body

logger = logging.getLogger(__name__)

_ALLOWED_URL_SCHEMES = {"http", "https"}
BUNDLED_TIER1_URL = "http://tier1-classifier:8000/classify"
MAX_TIER1_RESPONSE_BYTES = 64 * 1024
_BREAKER_THRESHOLD = 5
_BREAKER_COOLDOWN = 30.0


def _tier1_endpoint_allowlist() -> tuple:
    """Operator-controlled endpoint allowlist. Defaults to the bundled sidecar.

    Multi-replica / GPU deployments may need an explicit additional hostname
    (for example a tier1 instance on the judge GPU host). Nothing is inferred
    from request data: hosts, ports and schemes come only from the deployment
    environment, and redirects are never followed.
    """
    raw_hosts = os.getenv("SECURITY_TIER1_ALLOWED_HOSTS", "tier1-classifier")
    hosts = {h.strip().lower().rstrip(".") for h in raw_hosts.split(",") if h.strip()}
    raw_ports = os.getenv("SECURITY_TIER1_ALLOWED_PORTS", "8000")
    ports = set()
    for chunk in raw_ports.split(","):
        try:
            ports.add(int(chunk.strip()))
        except ValueError:
            continue
    schemes = {s.strip().lower() for s in os.getenv(
        "SECURITY_TIER1_ALLOWED_SCHEMES", "http").split(",") if s.strip()}
    schemes &= _ALLOWED_URL_SCHEMES
    path = os.getenv("SECURITY_TIER1_ALLOWED_PATH", "/classify").strip() or "/classify"
    return hosts or {"tier1-classifier"}, ports or {8000}, schemes or {"http"}, path


class _CircuitBreaker:
    """连续失败达阈值即在冷却窗内短路（fail-open），成功即复位。仿 llm_judge._CircuitBreaker。"""

    def __init__(self, threshold: int, cooldown: float, clock: Callable[[], float] = time.monotonic):
        self.threshold = max(1, threshold)
        self.cooldown = cooldown
        self.clock = clock
        self.fails = 0
        self.open_until = 0.0

    def allow(self) -> bool:
        if self.fails >= self.threshold and self.clock() < self.open_until:
            return False
        return True

    def record_success(self) -> None:
        self.fails = 0
        self.open_until = 0.0

    def record_failure(self) -> None:
        self.fails += 1
        if self.fails >= self.threshold:
            self.open_until = self.clock() + self.cooldown


@dataclass(frozen=True)
class Tier1Failure:
    reason: str
    retryable: bool = False
    http_status: int = 0

# Local queueing uses the caller's remaining budget; the socket/inference
# budget starts after admission. Defaults match the bundled single scorer.
_admission: dict = {}
_admission_lock = threading.Lock()

def _admission_for(url):
    with _admission_lock:
        if url not in _admission:
            limit = positive_number("SECURITY_TIER1_MAX_INFLIGHT", 1, integer=True)
            _admission[url] = threading.BoundedSemaphore(limit)
        return _admission[url]

_breakers: dict = {}


def _breaker_for(url: str) -> _CircuitBreaker:
    cb = _breakers.get(url)
    if cb is None:
        cb = _CircuitBreaker(_BREAKER_THRESHOLD, _BREAKER_COOLDOWN)
        _breakers[url] = cb
    return cb


def _reset_breakers() -> None:
    _breakers.clear()
    with _admission_lock:
        _admission.clear()


def _validated_url(url: str) -> Optional[str]:
    """Return a canonical, allowlisted URL or None (SSRF guard).

    The allowlist is deployment configuration, never request input. userinfo,
    query, fragment, redirects and non-allowlisted host/port/scheme/path are all
    rejected, so widening the list cannot turn the client into a general fetcher.
    """
    try:
        parsed = urllib.parse.urlparse(str(url).strip())
        port = parsed.port
    except ValueError:
        return None
    hosts, ports, schemes, path = _tier1_endpoint_allowlist()
    host = (parsed.hostname or "").lower().rstrip(".")
    if (
        parsed.scheme.lower() not in schemes
        or host not in hosts
        or (port or (443 if parsed.scheme.lower() == "https" else 80)) not in ports
        or parsed.path != path
        or parsed.query
        or parsed.fragment
        or parsed.username
        or parsed.password
        or "[" in host or "%" in host
    ):
        return None
    netloc = host
    if port is not None:
        netloc = "%s:%d" % (host, port)
    return urllib.parse.urlunparse((parsed.scheme.lower(), netloc, path, "", "", ""))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _http_post(url: str, body: bytes, token: str, timeout: float) -> Optional[str | Tier1Failure]:
    """POST 到 sidecar，返回响应体文本；任何失败/非200 → None。"""
    deadline = time.monotonic() + timeout
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", INTERNAL_TOKEN_HEADER: token,
                 "X-JJDGuard-Inference-Budget-Ms": str(max(1, int(
                     max(0.001, timeout - min(0.05, timeout * 0.1)) * 1000)))},
    )
    try:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            _NoRedirect(),
        )
        # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected -- exact bundled URL only
        with opener.open(req, timeout=timeout) as resp:
            if resp.status != 200:
                return None
            raw = read_response_body(resp, MAX_TIER1_RESPONSE_BYTES, deadline)
            if len(raw) > MAX_TIER1_RESPONSE_BYTES:
                return None
            return raw.decode("utf-8", "ignore")
    except urllib.error.HTTPError as exc:
        code = ""
        try:
            body = read_response_body(exc, 4096, deadline)
            value = json.loads(body)
            error = value.get("error") if isinstance(value, dict) else None
            code = error.get("code", "") if isinstance(error, dict) else ""
        except (ValueError, TypeError, OSError, TimeoutError):
            pass
        finally:
            exc.close()
        reasons = {
            "inference_capacity_overflow": "tier1_capacity_overflow",
            "inference_queue_timeout": "tier1_queue_timeout",
            "inference_timeout": "tier1_inference_timeout",
        }
        if exc.code == 503 and code in reasons:
            return Tier1Failure(reasons[code], retryable=True, http_status=503)
        return Tier1Failure("tier1_http_error", http_status=exc.code)
    except (urllib.error.URLError, OSError, TimeoutError, ValueError) as exc:
        logger.warning("Tier-1 transport failed: %s", type(exc).__name__)
        return None


def _clamp(value: float) -> float:
    if value < 0.0:
        return 0.0
    if value > 1.0:
        return 1.0
    return value


class Tier1Client:
    """Tier-1 攻击概率初筛客户端。classify 返回 (score, label) 或 None（fail-open）。"""

    def __init__(self, *, url: str, token: str, timeout: float) -> None:
        self._url = url
        self._token = token
        self._timeout = timeout

    def classify(self, text: Optional[str], *, timeout: Optional[float] = None) -> Optional[Tuple[float, str]]:
        result = self.classify_detailed(text, timeout=timeout)
        return result if isinstance(result, tuple) else None

    def classify_detailed(self, text: Optional[str], *, timeout: Optional[float] = None):
        if not text or len(text) > 4096:
            return Tier1Failure("tier1_input_unavailable")
        caller_budget = self._timeout if timeout is None else timeout
        if (not math.isfinite(caller_budget) or caller_budget <= 0
                or not math.isfinite(self._timeout) or self._timeout <= 0):
            return Tier1Failure("tier1_client_queue_timeout", retryable=True)
        safe_url = _validated_url(self._url)
        if safe_url is None:
            return Tier1Failure("tier1_invalid_endpoint")
        requested_deadline = time.monotonic() + caller_budget
        deadline = effective_deadline(requested_deadline)
        gate = _admission_for(safe_url)
        contended = not gate.acquire(blocking=False)
        if contended:
            while True:
                try:
                    check_work_budget(deadline)
                except WorkUnavailable as exc:
                    reason = "tier1_client_cancelled" if exc.reason in {"cancelled", "canceled"} else "tier1_client_queue_timeout"
                    return Tier1Failure(reason, retryable=True)
                remaining = deadline-time.monotonic()
                if remaining <= 0:
                    return Tier1Failure("tier1_client_queue_timeout", retryable=True)
                if gate.acquire(timeout=min(0.05, remaining)):
                    break
        try:
            try:
                check_work_budget(deadline)
            except WorkUnavailable as exc:
                reason = "tier1_client_cancelled" if exc.reason in {"cancelled", "canceled"} else "tier1_client_queue_timeout"
                return Tier1Failure(reason, retryable=True)
            remaining = deadline-time.monotonic()
            if remaining <= 0:
                return Tier1Failure("tier1_client_queue_timeout", retryable=True)
            caller_shortened = ((timeout is not None and timeout < self._timeout)
                                or (contended and remaining < self._timeout)
                                or (deadline < requested_deadline and remaining < self._timeout))
            return self._classify_admitted(text, safe_url, min(self._timeout, remaining),
                                           caller_shortened=caller_shortened)
        finally:
            gate.release()

    def _classify_admitted(self, text, safe_url, operation_timeout, *, caller_shortened=False):
        breaker = _breaker_for(safe_url)
        shared_breaker = breaker_state()
        if not breaker.allow() or shared_breaker.is_open(safe_url):
            return Tier1Failure("tier1_breaker_open")
        started = time.monotonic()

        def record_upstream_failure():
            shortened_and_expired = (
                caller_shortened
                and time.monotonic()-started >= operation_timeout
            )
            if not shortened_and_expired:
                breaker.record_failure()
                if not breaker.allow():
                    shared_breaker.publish_open(safe_url, _BREAKER_COOLDOWN)

        try:
            body = json.dumps({"text": text}, ensure_ascii=False).encode("utf-8")
            raw = _http_post(safe_url, body, self._token, operation_timeout)
            if isinstance(raw, Tier1Failure):
                # Capacity/deadline exhaustion is incomplete detection, not a
                # broken model. No hidden retry and no 30-second health blackout.
                if not raw.retryable:
                    record_upstream_failure()
                return raw
            if raw is None:
                record_upstream_failure()
                return Tier1Failure("tier1_unavailable")
            obj = json.loads(raw)
            if obj.get("coverage_complete") is not True:
                raise ValueError("incomplete token coverage")
            score = float(obj["score"])
            if not math.isfinite(score):
                raise ValueError("non-finite tier1 score")
            label = str(obj.get("label", ""))
        except (ValueError, TypeError, KeyError):
            record_upstream_failure()
            return Tier1Failure("tier1_invalid_response")
        except Exception:
            record_upstream_failure()
            return Tier1Failure("tier1_unavailable")
        breaker.record_success()
        shared_breaker.clear(safe_url)
        return (_clamp(score), label)
