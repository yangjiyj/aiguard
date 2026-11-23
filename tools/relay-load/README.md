# Relay Data Plane Load Asset

This directory is an independent k6 asset for gateway-only measurements. It
does not claim to measure provider performance: the upstream must be an
explicit mock or a real provider selected by the test environment.

The scenario exercises:

- Chat to Responses compatibility;
- native Responses SSE;
- native Messages SSE;
- 500 sustained SSE virtual users by default.

Run from a controlled test environment:

    BASE_URL=http://gateway:8080 API_KEY=test-key DURATION=60s k6 run tools/relay-load/k6.js

Record the k6 summary together with gateway metrics endpoint output, database
query counters, peak RSS, TTFT P50/P95/P99, total duration, error rate and
cancel/backpressure counters. k6 response waiting time is only a first-byte
proxy; use packet-level or client instrumentation for authoritative TTFT.

Do not point this asset at a customer environment. Do not include customer
tokens, endpoints, prompts or response bodies in result files.
