PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS schema_migration (
  version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL, tool_version TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS confidence (
  id INTEGER PRIMARY KEY, code TEXT NOT NULL UNIQUE, description TEXT NOT NULL,
  ordinal INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS firmware_image (
  id INTEGER PRIMARY KEY, path TEXT NOT NULL UNIQUE, sha256 TEXT, size INTEGER,
  format TEXT, version TEXT, source_kind TEXT, parent_id INTEGER REFERENCES firmware_image(id),
  status TEXT NOT NULL DEFAULT 'UNKNOWN', metadata_json TEXT
);
CREATE TABLE IF NOT EXISTS partition (
  id INTEGER PRIMARY KEY, image_id INTEGER REFERENCES firmware_image(id), name TEXT NOT NULL,
  path TEXT, sha256 TEXT, format TEXT, offset INTEGER, size INTEGER,
  status TEXT NOT NULL DEFAULT 'UNKNOWN', metadata_json TEXT, UNIQUE(image_id,name,path)
);
CREATE TABLE IF NOT EXISTS binary (
  id INTEGER PRIMARY KEY, path TEXT NOT NULL UNIQUE, sha256 TEXT NOT NULL, size INTEGER NOT NULL,
  format TEXT NOT NULL, arch TEXT, endian TEXT, elf_class INTEGER, elf_machine TEXT,
  entry_vma TEXT, image_base TEXT, runtime_va TEXT, physical_offset TEXT, wbi_offset TEXT,
  image_id INTEGER REFERENCES firmware_image(id), partition_id INTEGER REFERENCES partition(id),
  source_path TEXT, source_sha256 TEXT, unpack_method TEXT,
  analysis_status TEXT NOT NULL DEFAULT 'UNQUEUED', metadata_json TEXT
);
CREATE TABLE IF NOT EXISTS section (
  id INTEGER PRIMARY KEY, binary_id INTEGER NOT NULL REFERENCES binary(id), name TEXT,
  vma TEXT, file_offset TEXT, size INTEGER, flags TEXT, type TEXT, metadata_json TEXT,
  UNIQUE(binary_id,name,file_offset)
);
CREATE TABLE IF NOT EXISTS segment (
  id INTEGER PRIMARY KEY, binary_id INTEGER NOT NULL REFERENCES binary(id), type TEXT,
  vma TEXT, paddr TEXT, file_offset TEXT, file_size INTEGER, mem_size INTEGER, flags TEXT,
  metadata_json TEXT, UNIQUE(binary_id,file_offset,vma)
);
CREATE TABLE IF NOT EXISTS module (
  id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, binary_id INTEGER REFERENCES binary(id),
  description TEXT, domain TEXT, status TEXT NOT NULL DEFAULT 'UNKNOWN', confidence_id INTEGER REFERENCES confidence(id),
  source_evidence_id INTEGER
);
CREATE TABLE IF NOT EXISTS function (
  id INTEGER PRIMARY KEY, binary_id INTEGER REFERENCES binary(id), module_id INTEGER REFERENCES module(id),
  name TEXT, address TEXT, size INTEGER, calling_convention TEXT, thumb_mode INTEGER,
  vma TEXT, runtime_va TEXT, physical_offset TEXT, wbi_offset TEXT,
  status TEXT NOT NULL DEFAULT 'UNKNOWN', confidence_id INTEGER REFERENCES confidence(id),
  source_evidence_id INTEGER, generated_name INTEGER NOT NULL DEFAULT 0,
  UNIQUE(binary_id,address,name)
);
CREATE TABLE IF NOT EXISTS symbol (
  id INTEGER PRIMARY KEY, binary_id INTEGER REFERENCES binary(id), name TEXT, address TEXT,
  size INTEGER, type TEXT, binding TEXT, section TEXT, status TEXT NOT NULL DEFAULT 'UNKNOWN',
  UNIQUE(binary_id,name,address)
);
CREATE TABLE IF NOT EXISTS basic_block (
  id INTEGER PRIMARY KEY, function_id INTEGER REFERENCES function(id), start_vma TEXT, end_vma TEXT,
  size INTEGER, status TEXT NOT NULL DEFAULT 'UNKNOWN', UNIQUE(function_id,start_vma)
);
CREATE TABLE IF NOT EXISTS instruction (
  id INTEGER PRIMARY KEY, function_id INTEGER REFERENCES function(id), address TEXT,
  mnemonic TEXT, operands TEXT, bytes_hex TEXT, mode TEXT, source_text TEXT,
  UNIQUE(function_id,address)
);
CREATE TABLE IF NOT EXISTS callsite (
  id INTEGER PRIMARY KEY, caller_id INTEGER REFERENCES function(id), callee_id INTEGER REFERENCES function(id),
  address TEXT, target TEXT, kind TEXT, status TEXT NOT NULL DEFAULT 'CANDIDATE',
  source_evidence_id INTEGER, UNIQUE(caller_id,address,target)
);
CREATE TABLE IF NOT EXISTS cross_reference (
  id INTEGER PRIMARY KEY, from_binary_id INTEGER REFERENCES binary(id), from_address TEXT,
  to_binary_id INTEGER REFERENCES binary(id), to_address TEXT, kind TEXT, status TEXT NOT NULL DEFAULT 'UNKNOWN',
  source_evidence_id INTEGER, UNIQUE(from_binary_id,from_address,to_binary_id,to_address,kind)
);
CREATE TABLE IF NOT EXISTS import_export (
  id INTEGER PRIMARY KEY, binary_id INTEGER REFERENCES binary(id), name TEXT, direction TEXT,
  address TEXT, library TEXT, status TEXT NOT NULL DEFAULT 'UNKNOWN', source_evidence_id INTEGER,
  UNIQUE(binary_id,name,direction,address)
);
CREATE TABLE IF NOT EXISTS relocation (
  id INTEGER PRIMARY KEY, binary_id INTEGER REFERENCES binary(id), offset TEXT, type TEXT,
  symbol TEXT, addend TEXT, status TEXT NOT NULL DEFAULT 'UNKNOWN', UNIQUE(binary_id,offset,type,symbol)
);
CREATE TABLE IF NOT EXISTS vtable (
  id INTEGER PRIMARY KEY, binary_id INTEGER REFERENCES binary(id), class_name TEXT, address TEXT,
  slot INTEGER, slot_address TEXT, target_address TEXT, symbol TEXT, imported INTEGER,
  status TEXT NOT NULL DEFAULT 'CANDIDATE', confidence_id INTEGER REFERENCES confidence(id), source_evidence_id INTEGER,
  UNIQUE(binary_id,class_name,slot_address)
);
CREATE TABLE IF NOT EXISTS data_structure (
  id INTEGER PRIMARY KEY, binary_id INTEGER REFERENCES binary(id), name TEXT, base_address TEXT,
  field_offset TEXT, field_name TEXT, field_type TEXT, width INTEGER, status TEXT NOT NULL DEFAULT 'CANDIDATE',
  source_evidence_id INTEGER, UNIQUE(binary_id,name,field_offset)
);
CREATE TABLE IF NOT EXISTS module_dependency (
  id INTEGER PRIMARY KEY, from_module_id INTEGER REFERENCES module(id), to_module_id INTEGER REFERENCES module(id),
  kind TEXT, status TEXT NOT NULL DEFAULT 'CANDIDATE', source_evidence_id INTEGER,
  UNIQUE(from_module_id,to_module_id,kind)
);
CREATE TABLE IF NOT EXISTS lifecycle_callback (
  id INTEGER PRIMARY KEY, module_id INTEGER REFERENCES module(id), name TEXT NOT NULL,
  function_id INTEGER REFERENCES function(id), phase TEXT, status TEXT NOT NULL DEFAULT 'CANDIDATE',
  source_evidence_id INTEGER, UNIQUE(module_id,name,function_id)
);
CREATE TABLE IF NOT EXISTS message_queue (
  id INTEGER PRIMARY KEY, module_id INTEGER REFERENCES module(id), name TEXT, address TEXT,
  direction TEXT, status TEXT NOT NULL DEFAULT 'CANDIDATE', source_evidence_id INTEGER,
  UNIQUE(module_id,name,address)
);
CREATE TABLE IF NOT EXISTS message_id (
  id INTEGER PRIMARY KEY, namespace TEXT, value TEXT, name TEXT, description TEXT,
  status TEXT NOT NULL DEFAULT 'UNKNOWN', source_evidence_id INTEGER, UNIQUE(namespace,value,name)
);
CREATE TABLE IF NOT EXISTS event_id (
  id INTEGER PRIMARY KEY, namespace TEXT, value TEXT, name TEXT, description TEXT,
  status TEXT NOT NULL DEFAULT 'UNKNOWN', source_evidence_id INTEGER, UNIQUE(namespace,value,name)
);
CREATE TABLE IF NOT EXISTS event_producer (
  id INTEGER PRIMARY KEY, event_id INTEGER REFERENCES event_id(id), module_id INTEGER REFERENCES module(id),
  function_id INTEGER REFERENCES function(id), status TEXT NOT NULL DEFAULT 'CANDIDATE', source_evidence_id INTEGER,
  UNIQUE(event_id,module_id,function_id)
);
CREATE TABLE IF NOT EXISTS event_consumer (
  id INTEGER PRIMARY KEY, event_id INTEGER REFERENCES event_id(id), module_id INTEGER REFERENCES module(id),
  function_id INTEGER REFERENCES function(id), status TEXT NOT NULL DEFAULT 'CANDIDATE', source_evidence_id INTEGER,
  UNIQUE(event_id,module_id,function_id)
);
CREATE TABLE IF NOT EXISTS state_machine (
  id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, module_id INTEGER REFERENCES module(id),
  description TEXT, status TEXT NOT NULL DEFAULT 'INFERRED', source_evidence_id INTEGER
);
CREATE TABLE IF NOT EXISTS state (
  id INTEGER PRIMARY KEY, machine_id INTEGER REFERENCES state_machine(id), value TEXT, name TEXT,
  description TEXT, status TEXT NOT NULL DEFAULT 'CANDIDATE', source_evidence_id INTEGER, UNIQUE(machine_id,value,name)
);
CREATE TABLE IF NOT EXISTS state_transition (
  id INTEGER PRIMARY KEY, machine_id INTEGER REFERENCES state_machine(id), from_state_id INTEGER REFERENCES state(id),
  event_id INTEGER REFERENCES event_id(id), to_state_id INTEGER REFERENCES state(id), action TEXT,
  status TEXT NOT NULL DEFAULT 'CANDIDATE', source_evidence_id INTEGER, UNIQUE(machine_id,from_state_id,event_id,to_state_id,action)
);
CREATE TABLE IF NOT EXISTS driver_interface (
  id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, device TEXT, module_id INTEGER REFERENCES module(id),
  description TEXT, status TEXT NOT NULL DEFAULT 'UNKNOWN', source_evidence_id INTEGER
);
CREATE TABLE IF NOT EXISTS ioctl (
  id INTEGER PRIMARY KEY, interface_id INTEGER REFERENCES driver_interface(id), request_id TEXT,
  name TEXT, caller_function_id INTEGER REFERENCES function(id), parameter_type TEXT, target_device TEXT,
  status TEXT NOT NULL DEFAULT 'CANDIDATE', source_evidence_id INTEGER, UNIQUE(interface_id,request_id,name)
);
CREATE TABLE IF NOT EXISTS jni_bridge (
  id INTEGER PRIMARY KEY, class_name TEXT, method_name TEXT, signature TEXT, native_entry TEXT,
  module_id INTEGER REFERENCES module(id), status TEXT NOT NULL DEFAULT 'CANDIDATE', source_evidence_id INTEGER,
  UNIQUE(class_name,method_name,signature,native_entry)
);
CREATE TABLE IF NOT EXISTS java_method (
  id INTEGER PRIMARY KEY, class_name TEXT, method_name TEXT, signature TEXT, dex_path TEXT,
  status TEXT NOT NULL DEFAULT 'UNKNOWN', source_evidence_id INTEGER, UNIQUE(class_name,method_name,signature,dex_path)
);
CREATE TABLE IF NOT EXISTS configuration_key (
  id INTEGER PRIMARY KEY, key TEXT NOT NULL, value TEXT, source_path TEXT, status TEXT NOT NULL DEFAULT 'UNKNOWN',
  source_evidence_id INTEGER, UNIQUE(key,value,source_path)
);
CREATE TABLE IF NOT EXISTS resource (
  id INTEGER PRIMARY KEY, binary_id INTEGER REFERENCES binary(id), path TEXT, resource_type TEXT,
  description TEXT, status TEXT NOT NULL DEFAULT 'UNKNOWN', source_evidence_id INTEGER, UNIQUE(binary_id,path)
);
CREATE TABLE IF NOT EXISTS evidence (
  id INTEGER PRIMARY KEY, source_path TEXT NOT NULL, source_sha256 TEXT, kind TEXT, locator TEXT,
  excerpt TEXT, status TEXT NOT NULL DEFAULT 'UNKNOWN', confidence_id INTEGER REFERENCES confidence(id),
  created_at TEXT NOT NULL, metadata_json TEXT, UNIQUE(source_path,locator,kind,excerpt)
);
CREATE TABLE IF NOT EXISTS hypothesis (
  id INTEGER PRIMARY KEY, subject_type TEXT, subject_id INTEGER, statement TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'CANDIDATE', confidence_id INTEGER REFERENCES confidence(id), source_evidence_id INTEGER,
  UNIQUE(subject_type,subject_id,statement)
);
CREATE TABLE IF NOT EXISTS verification (
  id INTEGER PRIMARY KEY, hypothesis_id INTEGER REFERENCES hypothesis(id), method TEXT, result TEXT,
  status TEXT NOT NULL DEFAULT 'UNKNOWN', source_evidence_id INTEGER, verified_at TEXT
);
CREATE TABLE IF NOT EXISTS runtime_observation (
  id INTEGER PRIMARY KEY, trace_path TEXT, timestamp TEXT, component TEXT, event TEXT, value TEXT,
  duration_ms REAL, status TEXT NOT NULL DEFAULT 'VERIFIED_RUNTIME', source_evidence_id INTEGER
);
CREATE TABLE IF NOT EXISTS analysis_run (
  id INTEGER PRIMARY KEY, binary_id INTEGER REFERENCES binary(id), analyzer TEXT NOT NULL, analyzer_version TEXT,
  input_sha256 TEXT, started_at TEXT NOT NULL, completed_at TEXT, status TEXT NOT NULL, checkpoint TEXT,
  error_text TEXT, metadata_json TEXT, UNIQUE(binary_id,analyzer,analyzer_version,input_sha256)
);
CREATE TABLE IF NOT EXISTS unresolved_edge (
  id INTEGER PRIMARY KEY, from_type TEXT, from_id INTEGER, to_type TEXT, to_id INTEGER, relation TEXT,
  reason TEXT, status TEXT NOT NULL DEFAULT 'UNKNOWN', source_evidence_id INTEGER, UNIQUE(from_type,from_id,to_type,to_id,relation)
);

CREATE INDEX IF NOT EXISTS idx_binary_format ON binary(format);
CREATE INDEX IF NOT EXISTS idx_function_name ON function(name);
CREATE INDEX IF NOT EXISTS idx_function_address ON function(address);
CREATE INDEX IF NOT EXISTS idx_evidence_status ON evidence(status);
CREATE INDEX IF NOT EXISTS idx_hypothesis_status ON hypothesis(status);
CREATE INDEX IF NOT EXISTS idx_event_value ON event_id(value);
CREATE INDEX IF NOT EXISTS idx_module_domain ON module(domain);
