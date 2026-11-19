# SPDX-License-Identifier: Apache-2.0
"""Command-line entry point: `targetzero <command>`."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from datetime import date
from pathlib import Path

from targetzero import __version__
from targetzero.common.config import ConfigError, load_config
from targetzero.common.output import read_csv
from targetzero.common.resources import example_config_dir, templates_dir
from targetzero.common.schema import SCHEMAS, validate, validate_summary
from targetzero.scorecard import scorecard

# Register file name -> schema, for `targetzero validate` without --schema.
CSV_SCHEMAS = {
    "manual_admins": "admins",
    "inventory": "inventory",
    "findings": "findings",
    "exceptions": "exceptions",
    "alert_tests": "alert_tests",
}


def _date(value: str) -> date:
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"not a date (YYYY-MM-DD): {value}") from exc


def cmd_init(args: argparse.Namespace) -> int:
    target = Path(args.dir).resolve()
    registers = target / "registers"
    registers.mkdir(parents=True, exist_ok=True)
    examples = example_config_dir()
    copies = [
        (examples / "targetzero.example.yaml", target / "targetzero.yaml"),
        (examples / "privileged_roles.yaml", target / "privileged_roles.yaml"),
        (examples / "approved_exposure.example.csv", registers / "approved_exposure.csv"),
    ]
    copies += [(t, registers / t.name) for t in sorted(templates_dir().glob("*.csv"))]
    copies.append((templates_dir() / "recovery_page.md", registers / "recovery" / "_template.md"))
    for source, destination in copies:
        if destination.exists():
            print(f"kept     {destination}")
            continue
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        print(f"created  {destination}")
    print("\nNext: edit targetzero.yaml, then run the inventory scripts for your platforms.")
    return 0


def cmd_scorecard(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    card = scorecard.build(config, args.date)
    paths = scorecard.write(config, card)
    print(scorecard.render_text(card))
    print("\nWritten:\n  " + "\n  ".join(str(p) for p in paths))
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    failed = False
    for name in args.files:
        path = Path(name)
        if path.name.endswith(".summary.json"):
            problems = validate_summary(json.loads(path.read_text(encoding="utf-8")))
        else:
            schema = args.schema or CSV_SCHEMAS.get(path.stem)
            if not schema:
                print(f"{path}: cannot tell which schema to use; pass --schema", file=sys.stderr)
                failed = True
                continue
            problems = [
                f"row {n}: {p}"
                for n, row in enumerate(read_csv(path), start=2)
                for p in validate(row, schema)
            ]
        failed = failed or bool(problems)
        print(f"{path}: {'OK' if not problems else f'{len(problems)} problem(s)'}")
        for problem in problems:
            print(f"  {problem}")
    return 1 if failed else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="targetzero", description=__doc__)
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init", help="create targetzero.yaml and empty registers")
    p.add_argument("dir", nargs="?", default=".", help="folder to set up (default: current)")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("scorecard", help="build the scorecard from today's summaries")
    p.add_argument("--config", help="path to targetzero.yaml")
    p.add_argument("--date", type=_date, default=date.today(), help="run date (default: today)")
    p.set_defaults(func=cmd_scorecard)

    p = sub.add_parser("validate", help="check summaries or register CSVs against the schemas")
    p.add_argument("files", nargs="+")
    p.add_argument("--schema", choices=[s for s in SCHEMAS if s not in ("summary", "config")])
    p.set_defaults(func=cmd_validate)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
