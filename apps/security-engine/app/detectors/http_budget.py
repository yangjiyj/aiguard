"""Bound model response bodies by bytes and wall time, including slow trickles."""
from __future__ import annotations
import time
from app.bounded_work import check_work_budget, effective_deadline, WorkUnavailable


def read_response_body(response, limit: int, deadline: float) -> bytes:
    deadline = effective_deadline(deadline)
    def check():
        try:
            check_work_budget(deadline)
        except WorkUnavailable as exc:
            raise TimeoutError("model response canceled or expired") from exc
    check()
    read1 = getattr(response, "read1", None) if callable(getattr(type(response), "read1", None)) else None
    if not callable(read1):
        # In-memory test/adapter responses do not expose a socket or read1.
        data = response.read(limit + 1)
        check()
        if time.monotonic() >= deadline:
            raise TimeoutError("model response budget exhausted")
        check()
        return data
    data = bytearray()
    while len(data) <= limit:
        check()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("model response budget exhausted")
        # urllib's timeout alone is an idle timeout; refresh it against the
        # same deadline for each read instead of restarting a full budget.
        raw = getattr(getattr(response, "fp", None), "raw", None)
        sock = getattr(raw, "_sock", None)
        if sock is not None:
            sock.settimeout(remaining)
        chunk = read1(min(65536, limit + 1 - len(data)))
        if not chunk:
            break
        data.extend(chunk)
    if time.monotonic() >= deadline:
        raise TimeoutError("model response budget exhausted")
    check()
    return bytes(data)
