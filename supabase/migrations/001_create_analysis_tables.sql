CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS analysis_requests (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  source TEXT NOT NULL DEFAULT 'web',
  content_preview TEXT NOT NULL,
  risk_level TEXT NOT NULL DEFAULT 'low' CHECK (risk_level IN ('low', 'medium', 'high')),
  total_entities INTEGER NOT NULL DEFAULT 0 CHECK (total_entities >= 0),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS detected_entities (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  analysis_request_id UUID NOT NULL REFERENCES analysis_requests(id) ON DELETE CASCADE,
  category TEXT NOT NULL,
  label TEXT NOT NULL,
  confidence NUMERIC(4,3) NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
  severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high')),
  replacement TEXT NOT NULL,
  start_index INTEGER NOT NULL CHECK (start_index >= 0),
  end_index INTEGER NOT NULL CHECK (end_index >= start_index),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  analysis_request_id UUID REFERENCES analysis_requests(id) ON DELETE SET NULL,
  action TEXT NOT NULL,
  details JSONB NOT NULL DEFAULT '{}'::JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_analysis_requests_created_at ON analysis_requests(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_detected_entities_request ON detected_entities(analysis_request_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_request ON audit_logs(analysis_request_id);
