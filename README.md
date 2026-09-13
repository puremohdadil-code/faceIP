# SentinelMesh

SentinelMesh is an authorized, defensive network inventory and change-analysis tool for small labs, homes, and internal environments. It builds a privacy-aware inventory of visible devices, records changes, scores operational risk, and produces analyst-friendly reports.

## Safety boundary

This project is intentionally limited to networks you own or are explicitly authorized to assess. It does not capture passwords, packet payloads, private messages, browser history, or credentials. Active checks are opt-in, rate-limited, and restricted to an explicit target list.

## What is included

- Local interface and neighbor-table inventory.
- Device identity normalization with stable pseudonyms.
- Change ledger for first-seen, last-seen, and state transitions.
- Explainable risk scoring for stale, unknown, or unexpectedly changed devices.
- Command-line inventory, reporting, event review, and JSON export.
- A Python orchestrator plus optional C, C++, Rust, Java, Ruby, Lua, and ASM processing modules.
- Export-ready event format and privacy controls.

## Native pipeline

Python is only the orchestrator and storage boundary. The native pipeline is
`C neighbor -> C++ identity -> Java scheduler -> Lua policy -> ASM checksum ->
Rust risk -> Ruby report`. Each stage communicates over bounded stdin/stdout
records and the snapshot records whether a stage was active or unavailable.
Run `modules/build.ps1` to build the toolchains installed on your machine.

## Quick start

Set `PYTHONPATH` to the API package and run an inventory:

```powershell
$env:PYTHONPATH="d:\o_o_IP\apps\api"
C:/Python314/python.exe -m sentinelmesh_api --root d:\o_o_IP inventory
C:/Python314/python.exe -m sentinelmesh_api --root d:\o_o_IP report
C:/Python314/python.exe -m sentinelmesh_api --root d:\o_o_IP events --limit 20
C:/Python314/python.exe -m sentinelmesh_api --root d:\o_o_IP export .\snapshot.json
C:/Python314/python.exe -m sentinelmesh_api --root d:\o_o_IP csv .\inventory.csv
C:/Python314/python.exe -m sentinelmesh_api --root d:\o_o_IP baseline save .\baseline.json
C:/Python314/python.exe -m sentinelmesh_api --root d:\o_o_IP baseline compare .\baseline.json
```

Reports include network grouping, source counts, hostname coverage, inventory quality, and baseline differences that ignore expected timestamp updates.

## Repository map

- `apps/api`: Python command-line tool and domain logic.
- `modules`: native processing components with one responsibility each.
- `contracts`: newline-delimited JSON contract shared by modules.
- `fixtures`: deterministic inputs for repeatable checks.
- `tests`: focused unit tests.
- `docs`: architecture, threat model, and contribution guide.

## Roadmap

The project is intentionally built in vertical slices. Future modules can add vendor enrichment from user-supplied data, passive flow summaries, signed exports, SQLite storage, role-based access, and a replayable lab dataset without changing the public contract.

## License

MIT. See `LICENSE`.
