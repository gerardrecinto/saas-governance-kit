import argparse
import json
import sys
from pathlib import Path

from .mapping import build_report, to_markdown


def _load(path: str | None):
    return json.loads(Path(path).read_text()) if path else None


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Map audit outputs to SOC 2 Trust Services Criteria (evidence support only)"
    )
    p.add_argument("--github", help="Report JSON from github-audit")
    p.add_argument("--slack-audit", help="Summary JSON from slack-audit-logs")
    p.add_argument("--scim-store", help="SCIM server JSON store file")
    p.add_argument("--access-log", help="JSON list of /access-request decisions")
    p.add_argument("--auth-events", help="JSON lines of SAML/OIDC validation events")
    p.add_argument("--format", choices=["md", "json"], default="md")
    p.add_argument("--out", help="Write to this file instead of stdout")
    args = p.parse_args(argv)
    events = None
    if args.auth_events:
        events = [
            json.loads(x) for x in Path(args.auth_events).read_text().splitlines() if x.strip()
        ]
    report = build_report(
        _load(args.github),
        _load(args.slack_audit),
        _load(args.scim_store),
        _load(args.access_log),
        events,
    )
    text = to_markdown(report) if args.format == "md" else json.dumps(report, indent=2) + "\n"
    if args.out:
        Path(args.out).write_text(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
