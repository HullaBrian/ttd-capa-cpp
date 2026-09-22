# Documentation

Reference for the current code:

- **[ARGUMENT-DECODING.md](ARGUMENT-DECODING.md)** - how API metadata drives argument decoding:
  the win32json and phnt indexes, what lands in the report, and how x86 traces differ.
- **[CODE-SCAN.md](CODE-SCAN.md)** - how `--scan-code` reconstructs runtime code and static-scans
  it, the memory budgets, and positioning code capabilities at their real execution moments.
- **[EMBEDDING.md](EMBEDDING.md)** - the C ABI for running ttd-capa's three analysis passes
  in-process from another program. This is the contract.

Historical design records, kept because they explain *why* the current code is shaped the way
it is. They describe work that is already done, so read them as background rather than as
plans:

- **[CAPA-CPP-INTEGRATION.md](CAPA-CPP-INTEGRATION.md)** - the plan to move rule matching off
  Python capa and onto capa-cpp, including the static "code scan" path. Completed; ttd-capa
  has no Python-capa dependency today.
- **[TIMELINE-CODE-CAPS-DESIGN.md](TIMELINE-CODE-CAPS-DESIGN.md)** - how static (code-scan)
  capabilities came to be positioned at their real execution moments rather than at the point
  their region was reconstructed. Completed through M4; see the milestone list at the end for
  what was and wasn't wired up.
- **[WIN32JSON-TTD-INTEGRATION-NOTES.md](WIN32JSON-TTD-INTEGRATION-NOTES.md)** - a read of
  Microsoft's Win32 metadata, and what it can and cannot tell an extractor about a function's
  parameters. The basis for the metadata-driven argument decoding.
