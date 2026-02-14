BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS developers (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email text UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS projects (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  developer_id uuid NOT NULL REFERENCES developers(id) ON DELETE CASCADE,
  name text NOT NULL,
  tier text NOT NULL DEFAULT 'free' CHECK (tier IN ('free', 'pro')),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS api_keys (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  label text NOT NULL DEFAULT 'default',
  key_id text NOT NULL UNIQUE,
  secret_hash text NOT NULL,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz
);

CREATE TABLE IF NOT EXISTS usage_counters (
  project_id uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  window_start timestamptz NOT NULL,
  endpoint text NOT NULL,
  count integer NOT NULL DEFAULT 0,
  PRIMARY KEY (project_id, window_start, endpoint)
);

CREATE TABLE IF NOT EXISTS resolver_objects (
  object_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  schema_id text NOT NULL,
  radius_m double precision NOT NULL,
  payload jsonb NOT NULL,
  payload_hash text NOT NULL,
  creator_public_key text NOT NULL,
  creator_signature text NOT NULL,
  presence jsonb NOT NULL,
  cell_id text NOT NULL,
  lat double precision NOT NULL,
  lng double precision NOT NULL,
  parent_object_id uuid REFERENCES resolver_objects(object_id) ON DELETE SET NULL,
  supersedes_object_id uuid REFERENCES resolver_objects(object_id) ON DELETE SET NULL,
  project_id uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_resolver_objects_cell ON resolver_objects(cell_id);
CREATE INDEX IF NOT EXISTS idx_resolver_objects_project ON resolver_objects(project_id);

CREATE TABLE IF NOT EXISTS schema_migrations (
  version text PRIMARY KEY,
  applied_at timestamptz NOT NULL DEFAULT now()
);

COMMIT;
