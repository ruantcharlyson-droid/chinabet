-- Migration baseline for v14.
CREATE TABLE IF NOT EXISTS schema_migrations(
  version VARCHAR(32) PRIMARY KEY,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
INSERT INTO schema_migrations(version) VALUES ('001_initial') ON CONFLICT DO NOTHING;
