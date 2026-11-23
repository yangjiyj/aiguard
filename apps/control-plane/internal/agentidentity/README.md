# agentidentity

This package validates claim-only `identity-events.v1` envelopes before a trusted ingestion layer uses them.

## Contract pin

The accepted source is platform repository commit `eaf985aa94385b0174138a38690b2e91e122d97a`:

- `contracts/identity-events.v1.schema.json` SHA-256: `c0e8ad21b278c35148b7fffc42c460d675be71909c93a4de3d76762df017b45e`
- `contracts/identity-events.v1.examples.json` SHA-256: `d994c4d5d497ec5cf504b95305ec82efe67173bac1397e0fa8b7d67446c12064`
- `contracts/test_identity_events_v1.py` SHA-256: `0d12c73f273af477cad03718c09ac64c77a2e1b86625d04a0b18bd268f393f7a`

The synthetic examples were copied directly from that pinned commit to `testdata/identity-events.v1.examples.json`. The validator implements the ten event variants, allowed reference-kind relationships, optional fields, UUID forms, RFC3339 timestamps, enums, and Unicode code-point lengths in the schema. It rejects unknown fields, duplicate JSON object keys, malformed UTF-8, and trailing JSON values.

## API and trust boundary

Call `ParseEnvelope` for raw request bytes. It returns producer claims and typed native references with event-role names. `Producer` and `SubjectClaim` are untrusted claims; this package never resolves them to canonical tenant, user, service-account, or Agent identities.

Each `Event.Raw` is a deterministic `encoding/json` re-encoding with sorted object keys. The raw JSON value preserves event ID casing and timestamp text. This is intended for replay comparison and is not a claim of RFC 8785/JCS canonicalization.

## Additional parser limits

The schema has no body-size or nesting-depth limit. This package rejects bodies over 1 MiB and JSON with more than 16 nested containers to bound request memory and recursion. It also rejects U+0000 in JSON strings because the downstream PostgreSQL JSONB/text storage cannot represent it. Escaped UTF-16 surrogate code units must form valid high/low pairs; unmatched escapes are rejected because Go's JSON decoder replaces them with U+FFFD, which could collapse distinct claimed identifiers. Literal U+FFFD and valid escaped pairs remain accepted. This enforces Unicode scalar values in decoded strings. Timestamps accept RFC3339's uppercase or lowercase `T`/`Z` forms, then check exact digit widths and time/offset ranges before Go parsing. These are parser/storage safety limits beyond the schema.
