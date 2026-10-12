/* Phase 3.1 function body ranges, evidence adapters, and provenance fields. */

CREATE TABLE IF NOT EXISTS function_body_range (
  id INTEGER PRIMARY KEY,
  function_id INTEGER NOT NULL REFERENCES function(id),
  binary_id INTEGER REFERENCES binary(id),
  start_vma TEXT NOT NULL,
  end_vma TEXT NOT NULL,
  address_space TEXT,
  status TEXT NOT NULL DEFAULT 'UNKNOWN',
  confidence_id INTEGER REFERENCES confidence(id),
  source_evidence_id INTEGER REFERENCES evidence(id),
  analysis_run_id INTEGER REFERENCES analysis_run(id),
  identity_key TEXT NOT NULL UNIQUE,
  metadata_json TEXT
);

CREATE TABLE IF NOT EXISTS evidence_adapter_run (
  id INTEGER PRIMARY KEY,
  run_key TEXT NOT NULL UNIQUE,
  adapter TEXT NOT NULL,
  adapter_version TEXT NOT NULL,
  root_path TEXT NOT NULL,
  input_file_count INTEGER NOT NULL DEFAULT 0,
  observation_count INTEGER NOT NULL DEFAULT 0,
  relation_count INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL,
  started_at TEXT NOT NULL,
  completed_at TEXT,
  error_text TEXT,
  metadata_json TEXT
);

CREATE TABLE IF NOT EXISTS research_observation (
  id INTEGER PRIMARY KEY,
  source_evidence_id INTEGER NOT NULL REFERENCES evidence(id),
  source_sha256 TEXT NOT NULL,
  source_path TEXT NOT NULL,
  binary_id INTEGER REFERENCES binary(id),
  binary_sha256 TEXT,
  function_id INTEGER REFERENCES function(id),
  function_name TEXT,
  address TEXT,
  address_space TEXT,
  observation_type TEXT NOT NULL,
  locator TEXT NOT NULL,
  value_json TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'UNKNOWN',
  confidence_id INTEGER REFERENCES confidence(id),
  derived_relation TEXT,
  analyzer_version TEXT NOT NULL,
  adapter_run_id INTEGER REFERENCES evidence_adapter_run(id),
  identity_key TEXT NOT NULL UNIQUE
);

CREATE INDEX IF NOT EXISTS idx_function_body_range_function ON function_body_range(function_id,start_vma);
CREATE INDEX IF NOT EXISTS idx_research_observation_type ON research_observation(observation_type,status);
CREATE INDEX IF NOT EXISTS idx_research_observation_binary ON research_observation(binary_sha256,address);
