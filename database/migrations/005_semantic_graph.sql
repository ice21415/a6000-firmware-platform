/* Phase 3 semantic graph, protocol evidence, and SDK specification layer. */

CREATE TABLE IF NOT EXISTS cfg_edge (
  id INTEGER PRIMARY KEY,
  binary_id INTEGER NOT NULL REFERENCES binary(id),
  function_id INTEGER REFERENCES function(id),
  from_block_id INTEGER REFERENCES basic_block(id),
  to_block_id INTEGER REFERENCES basic_block(id),
  from_address TEXT NOT NULL,
  to_address TEXT NOT NULL,
  address_space TEXT,
  edge_kind TEXT NOT NULL DEFAULT 'control_flow',
  status TEXT NOT NULL DEFAULT 'VERIFIED_STATIC',
  confidence_id INTEGER REFERENCES confidence(id),
  source_evidence_id INTEGER REFERENCES evidence(id),
  analysis_run_id INTEGER REFERENCES analysis_run(id),
  identity_key TEXT NOT NULL UNIQUE,
  metadata_json TEXT
);

CREATE TABLE IF NOT EXISTS semantic_graph_run (
  id INTEGER PRIMARY KEY,
  run_key TEXT NOT NULL UNIQUE,
  analyzer TEXT NOT NULL,
  analyzer_version TEXT NOT NULL,
  status TEXT NOT NULL,
  started_at TEXT NOT NULL,
  completed_at TEXT,
  node_count INTEGER NOT NULL DEFAULT 0,
  edge_count INTEGER NOT NULL DEFAULT 0,
  error_text TEXT,
  metadata_json TEXT
);

CREATE TABLE IF NOT EXISTS semantic_node (
  id INTEGER PRIMARY KEY,
  node_type TEXT NOT NULL,
  identity_key TEXT NOT NULL UNIQUE,
  entity_table TEXT,
  entity_id INTEGER,
  label TEXT,
  namespace TEXT,
  binary_id INTEGER REFERENCES binary(id),
  address TEXT,
  address_space TEXT,
  status TEXT NOT NULL DEFAULT 'UNKNOWN',
  confidence_id INTEGER REFERENCES confidence(id),
  source_evidence_id INTEGER REFERENCES evidence(id),
  analyzer_version TEXT,
  metadata_json TEXT
);

CREATE TABLE IF NOT EXISTS semantic_edge (
  id INTEGER PRIMARY KEY,
  identity_key TEXT NOT NULL UNIQUE,
  source_node_id INTEGER NOT NULL REFERENCES semantic_node(id),
  target_node_id INTEGER REFERENCES semantic_node(id),
  relation_type TEXT NOT NULL,
  source_binary_id INTEGER REFERENCES binary(id),
  target_binary_id INTEGER REFERENCES binary(id),
  address_space TEXT,
  source_address TEXT,
  target_address TEXT,
  evidence_id INTEGER REFERENCES evidence(id),
  status TEXT NOT NULL DEFAULT 'UNKNOWN',
  confidence_id INTEGER REFERENCES confidence(id),
  analyzer_version TEXT,
  metadata_json TEXT
);

CREATE TABLE IF NOT EXISTS osal_message (
  id INTEGER PRIMARY KEY,
  queue_id INTEGER NOT NULL REFERENCES message_queue(id),
  message_id INTEGER REFERENCES message_id(id),
  direction TEXT,
  semantics TEXT,
  payload_layout TEXT,
  reply_message_id INTEGER REFERENCES message_id(id),
  timeout_ms REAL,
  producer_function_id INTEGER REFERENCES function(id),
  consumer_function_id INTEGER REFERENCES function(id),
  callback_function_id INTEGER REFERENCES function(id),
  status TEXT NOT NULL DEFAULT 'CANDIDATE',
  source_evidence_id INTEGER REFERENCES evidence(id),
  analyzer_version TEXT,
  identity_key TEXT NOT NULL UNIQUE,
  metadata_json TEXT
);

CREATE TABLE IF NOT EXISTS message_flow (
  id INTEGER PRIMARY KEY,
  osal_message_id INTEGER NOT NULL REFERENCES osal_message(id),
  role TEXT NOT NULL,
  module_id INTEGER REFERENCES module(id),
  function_id INTEGER REFERENCES function(id),
  status TEXT NOT NULL DEFAULT 'CANDIDATE',
  source_evidence_id INTEGER REFERENCES evidence(id),
  identity_key TEXT NOT NULL UNIQUE,
  metadata_json TEXT
);

CREATE TABLE IF NOT EXISTS sdk_interface (
  id INTEGER PRIMARY KEY,
  identity_key TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  domain TEXT,
  module_id INTEGER REFERENCES module(id),
  binary_id INTEGER REFERENCES binary(id),
  function_id INTEGER REFERENCES function(id),
  address TEXT,
  abi TEXT,
  calling_convention TEXT,
  parameter_layout TEXT,
  return_semantics TEXT,
  preconditions TEXT,
  thread_context TEXT,
  state_requirements TEXT,
  side_effects TEXT,
  event_dependencies TEXT,
  firmware_version TEXT,
  evidence_references TEXT,
  verification_status TEXT NOT NULL DEFAULT 'UNKNOWN',
  runtime_safety TEXT NOT NULL DEFAULT 'DESCRIPTIVE_ONLY',
  mock_status TEXT,
  source_evidence_id INTEGER REFERENCES evidence(id),
  analyzer_version TEXT,
  metadata_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_semantic_node_type ON semantic_node(node_type);
CREATE INDEX IF NOT EXISTS idx_semantic_node_entity ON semantic_node(entity_table,entity_id);
CREATE INDEX IF NOT EXISTS idx_semantic_edge_relation ON semantic_edge(relation_type,status);
CREATE INDEX IF NOT EXISTS idx_semantic_edge_source ON semantic_edge(source_node_id);
CREATE INDEX IF NOT EXISTS idx_semantic_edge_target ON semantic_edge(target_node_id);
CREATE INDEX IF NOT EXISTS idx_cfg_edge_function ON cfg_edge(function_id,from_address);
CREATE INDEX IF NOT EXISTS idx_osal_message_queue ON osal_message(queue_id,message_id);
CREATE INDEX IF NOT EXISTS idx_message_flow_role ON message_flow(role,module_id,function_id);
CREATE INDEX IF NOT EXISTS idx_sdk_interface_name ON sdk_interface(name,verification_status);
