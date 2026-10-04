CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_audits_correlation ON audits(correlation_id);
INSERT INTO schema_migrations(version) VALUES ('002_security_indexes') ON CONFLICT DO NOTHING;
