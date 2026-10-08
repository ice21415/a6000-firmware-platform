# DATA_INTEGRITY_REPORT

Generated: 2026-10-08T06:25:57.524816+00:00

- SQLite schema version: `4`
- `PRAGMA quick_check`: `ok`
- Foreign-key violations: `0`
- Duplicate evidence keys: `0`
- Evidence rows: `7006`; archived merged rows: `37825`

## Table counts

| Table | Rows |
|---|---:|
| `analysis_run` | 39257 |
| `basic_block` | 353 |
| `binary` | 37838 |
| `binary_identity` | 27268 |
| `callsite` | 400 |
| `confidence` | 6 |
| `configuration_key` | 0 |
| `cross_reference` | 1497 |
| `data_structure` | 143 |
| `domain_catalog` | 14 |
| `driver_interface` | 0 |
| `event_consumer` | 0 |
| `event_id` | 8 |
| `event_producer` | 0 |
| `evidence` | 7006 |
| `evidence_archive` | 37825 |
| `firmware_image` | 6646 |
| `function` | 135313 |
| `hypothesis` | 4 |
| `import_export` | 215105 |
| `instruction` | 2363 |
| `ioctl` | 0 |
| `java_method` | 0 |
| `jni_bridge` | 0 |
| `lifecycle_callback` | 846 |
| `message_id` | 0 |
| `message_queue` | 0 |
| `module` | 813 |
| `module_dependency` | 2084 |
| `partition` | 27196 |
| `relocation` | 615090 |
| `resource` | 12834 |
| `runtime_observation` | 0 |
| `schema_migration` | 4 |
| `section` | 17336 |
| `segment` | 3248 |
| `source_identity` | 6964 |
| `state` | 7 |
| `state_machine` | 1 |
| `state_transition` | 17 |
| `symbol` | 258675 |
| `unresolved_edge` | 0 |
| `verification` | 0 |
| `vtable` | 560 |

Identity keys with NULL/empty values:

```json
{
  "evidence": 0,
  "binary_identity": 0,
  "source_identity": 0
}
```