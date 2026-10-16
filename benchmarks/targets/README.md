# AuditForge benchmark targets

These are representative, non-executed source and catalog fixtures derived from
the public references listed in `docs/BENCHMARK_MATRIX.md`. They are intentionally
small enough for deterministic CI and are not copies of upstream servers. The
benchmark loads `catalog.json` and parses `server.py`; it never starts these
targets on the host.
