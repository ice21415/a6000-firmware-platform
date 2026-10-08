# Firmware Modding Framework (offline mock)

The first version is deliberately an offline registry. A module declares its
firmware SHA-256, dependencies and conflicts; activation is transactional and
diagnostics are queryable. It does not write NAND, WBI, boot settings or camera
memory. Real adapters can be added only after a verified SDK contract and an
independent recovery procedure exist.

