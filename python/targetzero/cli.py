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


def _print_paths(paths: list[Path]) -> int:
    for path in paths:
        print(f"written  {path}")
    for path in paths:
        if path.name.endswith(".summary.json"):
            data = json.loads(path.read_text(encoding="utf-8"))
            state = "" if data["complete"] else "  (incomplete)"
            print(f"Zero {data['zero']} {data['source']}/{data['name']}: {data['count']}{state}")
            for note in data.get("notes", []):
                print(f"  note: {note}")
    return 0


def cmd_registers(args: argparse.Namespace) -> int:
    from targetzero.registers import findings, inventory, manual_admins

    config = load_config(args.config)
    runners = {
        "manual-admins": manual_admins.run,
        "inventory": inventory.count,
        "findings": findings.count,
    }
    return _print_paths(runners[args.register](config, args.date))


def cmd_external(args: argparse.Namespace) -> int:
    from targetzero.external import dangling, discover, enrich, kev, scan, waf

    config = load_config(args.config)
    if args.check == "scan":
        if not args.authorised:
            print(
                "error: confirm with --authorised that you own or may scan every address in "
                "scope.ip_ranges. Run it from outside your own network.",
                file=sys.stderr,
            )
            return 2
        paths = scan.run(
            config,
            args.date,
            use_nmap=not args.no_nmap,
            use_internetdb=args.internetdb,
            max_hosts=args.max_hosts,
            timeout=args.timeout,
        )
    elif args.check == "discover":
        zones = []
        for spec in args.zone_file:
            file, _, origin = spec.partition(":")
            zones.append((Path(file), origin or None))
        paths = discover.run(config, args.date, use_crtsh=not args.no_crtsh, zone_files=zones)
    elif args.check == "waf":
        paths = waf.run(config, args.date, test_origins=args.authorised)
    elif args.check == "enrich":
        paths = enrich.run(config, args.date)
    elif args.check == "dangling-dns":
        paths = dangling.run(config, args.date)
    else:
        paths = kev.run(config, args.date, use_nvd=not args.no_nvd, recent_days=args.recent_days)
    return _print_paths(paths)


def _confirm(question: str) -> bool:
    try:
        return input(f"{question} Type yes to continue: ").strip().lower() == "yes"
    except EOFError:
        return False


def _print_results(results: list[dict[str, str]], paths: list[Path]) -> int:
    for r in results:
        print(
            f"{r['status']:<8} {r.get('plan_id', ''):<6} {r['account']:<40} {r['action']:<20} "
            f"{r['detail']}"
        )
    print("\nLog:\n  " + "\n  ".join(str(p) for p in paths))
    return 1 if any(r["status"] == "failed" for r in results) else 0


def cmd_gws(args: argparse.Namespace) -> int:
    from targetzero.gws import admins, changes, client, domains

    config = load_config(args.config)
    if args.check == "apply":
        if args.apply and not args.yes and not _confirm(f"Apply the actions in {args.plan}?"):
            print("Nothing changed.")
            return 1
        gws = client.connect(
            config, scopes=client.WRITE_SCOPES if args.apply else client.READ_SCOPES
        )
        results, paths = changes.apply_plan(
            config, gws, Path(args.plan), args.date, apply=args.apply
        )
        return _print_results(results, paths)
    gws = client.connect(config)
    if args.check == "admins":
        return _print_paths(admins.run(config, args.date, gws, days=args.days))
    return _print_paths(domains.run(config, args.date, gws))


def cmd_vendors(args: argparse.Namespace) -> int:
    from targetzero.vendors import cisco_asa, common, fortigate, panos, redfish, vsphere

    config = load_config(args.config)
    break_glass = set(config.break_glass(args.vendor))
    offline = {"fortigate": fortigate.collect, "panos": panos.collect, "asa": cisco_asa.collect}
    if args.vendor in offline:
        devices = [offline[args.vendor](Path(f), break_glass) for f in args.files]
    elif args.vendor == "redfish":
        context = redfish.ssl_context(args.ca_bundle, args.insecure)
        user, password = redfish.credentials()
        devices = [
            redfish.collect(redfish.Redfish(h, user, password, context), h, break_glass)
            for h in args.host
        ]
    else:
        from pyVim.connect import Disconnect

        context = redfish.ssl_context(args.ca_bundle, args.insecure)
        devices = []
        for host in args.host:
            instance = vsphere.connect(host, context)
            try:
                devices.append(
                    vsphere.collect(
                        instance.RetrieveContent(), host, break_glass, mfa_via_idp=args.mfa_via_idp
                    )
                )
            finally:
                Disconnect(instance)
    return _print_paths(
        common.write_outputs(
            config,
            args.date,
            args.vendor,
            devices,
            tool=f"targetzero vendors {args.vendor}",
        )
    )


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

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config", help="path to targetzero.yaml")
    common.add_argument(
        "--date", type=_date, default=date.today(), help="run date (default: today)"
    )

    p = sub.add_parser("registers", help="count the hand-maintained registers")
    p.add_argument("register", choices=["manual-admins", "inventory", "findings"])
    p.add_argument("--config", help="path to targetzero.yaml")
    p.add_argument("--date", type=_date, default=date.today(), help="run date (default: today)")
    p.set_defaults(func=cmd_registers)

    ext = sub.add_parser("external", help="checks from outside: scan, discover, kev")
    ext_sub = ext.add_subparsers(dest="check", required=True)
    p = ext_sub.add_parser("scan", parents=[common], help="open ports vs approved list (Zero 4)")
    p.add_argument(
        "--authorised",
        action="store_true",
        help="confirm you own or may scan every address in scope",
    )
    p.add_argument("--no-nmap", action="store_true", help="use the built-in scanner")
    p.add_argument(
        "--internetdb", action="store_true", help="also ask Shodan InternetDB (free, no key)"
    )
    p.add_argument("--max-hosts", type=int, default=1024)
    p.add_argument("--timeout", type=float, default=1.5, help="seconds per port (built-in)")
    p = ext_sub.add_parser(
        "discover", parents=[common], help="find names and addresses, update the inventory (Zero 5)"
    )
    p.add_argument("--no-crtsh", action="store_true", help="skip certificate transparency")
    p.add_argument(
        "--zone-file",
        action="append",
        default=[],
        metavar="FILE[:ORIGIN]",
        help="DNS zone file export; repeat for more zones",
    )
    p = ext_sub.add_parser(
        "kev", parents=[common], help="match CISA KEV against the inventory (Zero 6)"
    )
    p.add_argument("--no-nvd", action="store_true", help="skip NVD version checks")
    p.add_argument(
        "--recent-days",
        type=int,
        default=30,
        help="without a version, report KEV entries this recent (default 30)",
    )
    p = ext_sub.add_parser(
        "waf", parents=[common], help="web names behind a WAF/CDN, origins closed (Zero 4)"
    )
    p.add_argument(
        "--authorised",
        action="store_true",
        help="also test origins in registers/origins.csv (must be in scope)",
    )
    ext_sub.add_parser(
        "enrich", parents=[common], help="suggest product, version and support status (Zero 5)"
    )
    ext_sub.add_parser(
        "dangling-dns",
        parents=[common],
        help="DNS records pointing to unclaimed resources (Zero 5)",
    )
    ext.set_defaults(func=cmd_external)

    g = sub.add_parser("gws", help="Google Workspace checks")
    g_sub = g.add_subparsers(dest="check", required=True)
    p = g_sub.add_parser("admins", parents=[common], help="admins and MFA (Zero 1, 2)")
    p.add_argument("--days", type=int, default=30, help="sign-in history to read (default 30)")
    g_sub.add_parser("domains", parents=[common], help="domains, for discovery (Zero 5)")
    p = g_sub.add_parser(
        "apply", parents=[common], help="apply a reviewed role plan (dry run unless --apply)"
    )
    p.add_argument("plan", help="1_gws_role-plan.csv with the action column filled in")
    p.add_argument("--apply", action="store_true", help="make the changes")
    p.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    g.set_defaults(func=cmd_gws)

    v = sub.add_parser("vendors", help="firewall and VPN collectors (offline config files)")
    v_sub = v.add_subparsers(dest="vendor", required=True)
    for name, label in (
        ("fortigate", "FortiGate .conf backups"),
        ("panos", "PAN-OS running-config.xml files"),
        ("asa", "Cisco ASA running-config text files"),
    ):
        p = v_sub.add_parser(name, parents=[common], help=label)
        p.add_argument("files", nargs="+", help="all devices of this vendor, in one run")
    for name, label in (
        ("redfish", "iDRAC, iLO and other Redfish management cards (live, read-only)"),
        ("vsphere", "vCenter or ESXi (live, read-only; needs targetzero[vsphere])"),
    ):
        p = v_sub.add_parser(name, parents=[common], help=label)
        p.add_argument("--host", action="append", required=True, help="repeat for more hosts")
        p.add_argument("--ca-bundle", help="CA file for self-signed management certificates")
        p.add_argument("--insecure", action="store_true", help="do not verify certificates")
        if name == "vsphere":
            p.add_argument(
                "--mfa-via-idp",
                action="store_true",
                help="your identity source enforces MFA for these admins",
            )
    v.set_defaults(func=cmd_vendors)

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
