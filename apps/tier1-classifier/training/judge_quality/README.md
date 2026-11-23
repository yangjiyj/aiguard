# Semantic judge correctness workbench

Experimental development tools. No candidate here is accepted for production.
Running gateway configuration and production model artifacts are unchanged.

## What the workbench fixes

- Inclusive threshold selection handles direction, ties and float32 representation.
- Request-level metrics keep window and request denominators separate.
- report_run.py binds expected IDs/labels and input hashes to results. Missing
  predictions count as incomplete; missing benign outputs produce an FPR interval
  of possibilities, not evidence for zero false positives.
- Confidence intervals assume the sampled population; synthetic or correlated
  template rows cannot establish customer error rates.
- windows.py uses bounded overlapping windows. Complete coverage is not a safe verdict.
- views.py retains original text and decoding offsets, has explicit expansion
  limits and contiguous Unicode decoding. Production semantic_evidence.py currently
  has the same SHA-256; changes must update and verify both implementations.
- corpus.py preserves source/task context, quarantines annotation conflicts and
  uses full shingle sets for duplicate comparisons.
- artifact.py verifies local integrity only, not license, independent review or
  the identity of a model actually loaded by a remote service.
- attention_model.py is experimental. Its inherited family head is not validated
  with the new pooling and must not be used as a subtype classifier.

## Test and report inside the designated home VM

Run python -m pytest -q from this directory.
Run python report_run.py --help for complete-population summaries.
Use a fixed calibration threshold, never a holdout-derived oracle threshold.
Store model, input contract, evaluator and input/output file hashes in each run.
A development point gate is not independent acceptance.

## Current evidence

Four encoder continuations were rejected. C1/C2/C3/C4 calibration attack recall:
150/174, 115/174, 118/174, 129/174 (each at 1/174 benign false positives).
These are development/calibration results, not a fair end-to-end customer comparison.
C4 quarantines 1855 task-change examples with questionable attack annotations.

Official/reference generative models improve some focused regressions. The
Qwen3-14B inline profile passed the 25 developer normalization cases, but failed
long-document attacks. Local-scope prompting and evidence-first diagnostics did
not repair the demonstrated long-document failure. These are viewed development
sets and cannot be promoted back to blind acceptance.

The reserved runtime alias jjdguard-context-judge-v1 is opt-in experimental code.
It is NOT configured, released or accepted. It requires Tier-1 shortcuts disabled,
a compatible dual-output model, >=8192 context, no automatic context shifting,
and completion-aware responses. The conservative UTF-8 byte budget rejects
oversized requests explicitly. A backend/contract change requires new validation.
No activation or production-timeout increase is included in this change.
