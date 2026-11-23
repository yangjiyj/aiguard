-- 154_request_logs_customer_content_shape.sql
-- Store the customer-visible request/response shape beside the existing
-- customer-content flag so overview reads never rescan message bodies.

ALTER TABLE request_logs
    ADD COLUMN IF NOT EXISTS has_customer_request_body BOOLEAN,
    ADD COLUMN IF NOT EXISTS has_customer_response_body BOOLEAN;

-- Historical computation is deliberately absent. Migration 834 registers the
-- bounded background task after the supporting indexes and framework exist.
