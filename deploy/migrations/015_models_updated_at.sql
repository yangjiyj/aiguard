-- +goose Up
-- +goose StatementBegin

-- Add updated_at column to models table if it doesn't exist
-- This fixes the issue where UpdatePricing/UpdateStatus/UpdateCapabilities
-- tried to set updated_at but the column didn't exist

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'models' AND column_name = 'updated_at'
    ) THEN
        ALTER TABLE models ADD COLUMN updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW();
        UPDATE models SET updated_at = created_at WHERE updated_at IS NULL;
    END IF;
END $$;

-- +goose StatementEnd
