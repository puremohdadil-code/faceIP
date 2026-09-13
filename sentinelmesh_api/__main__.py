from __future__ import annotations

import argparse
from pathlib import Path

from .service import SentinelService
from .analysis import compare_snapshots
from .baseline import load, save
from .report import render_csv, render_diff, render_report


def main() -> None:
    parser = argparse.ArgumentParser(description="SentinelMesh authorized network inventory and change analyzer")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("inventory", help="collect and print the current authorized network inventory")
    subparsers.add_parser("report", help="collect inventory and print an analyst report")
    events_parser = subparsers.add_parser("events", help="print recent inventory events")
    events_parser.add_argument("--limit", type=int, default=25)
    export_parser = subparsers.add_parser("export", help="write a machine-readable snapshot")
    export_parser.add_argument("path", type=Path)
    csv_parser = subparsers.add_parser("csv", help="write the inventory as CSV")
    csv_parser.add_argument("path", type=Path)
    baseline_parser = subparsers.add_parser("baseline", help="save or compare an inventory baseline")
    baseline_subparsers = baseline_parser.add_subparsers(dest="baseline_command", required=True)
    save_parser = baseline_subparsers.add_parser("save")
    save_parser.add_argument("path", type=Path)
    compare_parser = baseline_subparsers.add_parser("compare")
    compare_parser.add_argument("path", type=Path)
    args = parser.parse_args()
    data_dir = args.root / ".sentinelmesh"
    service = SentinelService(data_dir)
    if args.command in {"inventory", "report", "export", "csv", "baseline"}:
        service.refresh()
    if args.command == "inventory":
        print(service.snapshot()["devices"])
    elif args.command == "report":
        print(render_report(service.snapshot()))
    elif args.command == "events":
        for event in service.store.events(args.limit):
            print(f"{event.created_at} [{event.severity}] {event.event_type}: {event.message}")
    elif args.command == "export":
        args.path.parent.mkdir(parents=True, exist_ok=True)
        args.path.write_text(render_report(service.snapshot(), json_output=True), encoding="utf-8")
        print(f"Snapshot written to {args.path}")
    elif args.command == "csv":
        args.path.parent.mkdir(parents=True, exist_ok=True)
        args.path.write_text(render_csv(service.snapshot()), encoding="utf-8", newline="")
        print(f"CSV written to {args.path}")
    elif args.command == "baseline":
        current = service.snapshot()
        if args.baseline_command == "save":
            save(args.path, current)
            print(f"Baseline saved to {args.path}")
        else:
            print(render_diff(compare_snapshots(load(args.path), current)))


if __name__ == "__main__":
    main()
