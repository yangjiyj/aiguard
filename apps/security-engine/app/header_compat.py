"""Scalar security-header compatibility parser over raw ASGI headers."""

from __future__ import annotations

from collections.abc import Iterable

INTERNAL_TOKEN_HEADER = "X-JJDGuard-Internal-Token"
INTERNAL_TOKEN_HEADER_BYTES = b"x-jjdguard-internal-token"
LEGACY_INTERNAL_TOKEN_HEADER_BYTES = b"x-newapi-internal-token"


def resolve_raw_headers(
    raw_headers: Iterable[tuple[bytes, bytes]],
    new_name: bytes = INTERNAL_TOKEN_HEADER_BYTES,
    legacy_name: bytes = LEGACY_INTERNAL_TOKEN_HEADER_BYTES,
) -> tuple[str, bool]:
    """Return (unique_value, conflict); errors and conflicts never include values."""
    new_lower = new_name.lower()
    legacy_lower = legacy_name.lower()
    values: list[bytes] = []
    for raw_name, raw_value in raw_headers:
        name = raw_name.lower()
        if name != new_lower and name != legacy_lower:
            continue
        value = raw_value.strip(b" \t")
        if not value:
            continue
        if b"," in value:
            return "", True
        values.append(value)
    if not values:
        return "", False
    first = values[0]
    if any(value != first for value in values[1:]):
        return "", True
    return first.decode("latin-1"), False
