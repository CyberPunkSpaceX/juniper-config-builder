"""Command line: build a config from a saved project file.

    exbuilder build project.json              # set commands to stdout
    exbuilder build project.json -f hierarchy -o switch.conf
    exbuilder models                          # list the known models
"""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__, models
from .generator import build


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="exbuilder", description="Juniper EX config builder")
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build", help="build a config from a project JSON file")
    b.add_argument("project")
    b.add_argument("-f", "--format", choices=("set", "hierarchy"), default="set")
    b.add_argument("-o", "--output", help="write here instead of stdout")
    b.add_argument("--force", action="store_true", help="write the config even when there are errors")
    sub.add_parser("models", help="list switch models")
    sub.add_parser("serve", help="run the web GUI (development server)").add_argument("--port", type=int, default=8080)
    sub.add_parser("jobs", help="run the background jobs (nightly backups); one copy next to the web service")
    args = ap.parse_args(argv)

    if args.cmd == "models":
        for m in models.catalog():
            print(f"{m['name']:<14} mgmt {m['mgmt']:<4} {'PoE ' if m['poe'] else '    '}{len(m['ports'])} ports  {m['notes']}")
        return 0
    if args.cmd == "jobs":
        from .jobs import main as jobs_main
        return jobs_main()
    if args.cmd == "serve":
        from .web import create_app
        create_app().run(host="127.0.0.1", port=args.port)
        return 0

    with open(args.project, encoding="utf-8") as fh:
        project = json.load(fh)
    res = build(project)
    for m in res.errors:
        print(f"ERROR   {m['section']}: {m['message']}", file=sys.stderr)
    for m in res.warnings:
        print(f"warning {m['section']}: {m['message']}", file=sys.stderr)
    if res.errors and not args.force:
        print("Not writing the config because of the errors above (use --force to write it anyway).", file=sys.stderr)
        return 1
    text = res.set_text if args.format == "set" else res.hier_text
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
