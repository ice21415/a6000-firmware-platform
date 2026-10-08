/* Data-aware migration. Column backfills and evidence/reference merging live
   in fwplatform.migration_v3 so the process can be resumed safely and retain
   a complete archive of superseded evidence rows. */
CREATE TABLE IF NOT EXISTS source_identity (
  id INTEGER PRIMARY KEY,
  identity_key TEXT NOT NULL UNIQUE,
  source_path TEXT,
  source_sha256 TEXT,
  kind TEXT,
  first_seen_at TEXT NOT NULL,
  metadata_json TEXT
);

CREATE TABLE IF NOT EXISTS binary_identity (
  id INTEGER PRIMARY KEY,
  identity_key TEXT NOT NULL UNIQUE,
  sha256 TEXT NOT NULL,
  size INTEGER NOT NULL,
  format TEXT NOT NULL,
  arch TEXT,
  endian TEXT,
  first_seen_at TEXT NOT NULL,
  metadata_json TEXT
);

CREATE TABLE IF NOT EXISTS evidence_archive (
  old_id INTEGER PRIMARY KEY,
  canonical_id INTEGER NOT NULL,
  source_path TEXT NOT NULL,
  source_sha256 TEXT,
  kind TEXT,
  locator TEXT,
  excerpt TEXT,
  old_status TEXT,
  confidence_id INTEGER,
  created_at TEXT,
  metadata_json TEXT,
  merged_at TEXT NOT NULL,
  merge_reason TEXT NOT NULL
);
