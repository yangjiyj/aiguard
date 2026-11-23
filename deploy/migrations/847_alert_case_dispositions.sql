-- Triage cases are dispositions over recorded findings, not replacement evidence.
ALTER TABLE audit_dispositions DROP CONSTRAINT IF EXISTS audit_dispositions_subject_type_check;
ALTER TABLE audit_dispositions ADD CONSTRAINT audit_dispositions_subject_type_check
 CHECK (subject_type IN ('request','session','security_event','tool_call','alert_case'));
ALTER TABLE audit_dispositions ADD COLUMN IF NOT EXISTS case_seen_through TIMESTAMPTZ;
