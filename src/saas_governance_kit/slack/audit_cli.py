import argparse
import json
import os
import sys

from .audit_logs import AuditLogClient, summarize


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Export and summarize Slack Enterprise Grid audit logs")
    p.add_argument("--oldest", type=int, help="Unix timestamp lower bound")
    p.add_argument("--latest", type=int, help="Unix timestamp upper bound")
    p.add_argument("--action")
    p.add_argument("--out", help="Write summary JSON here instead of stdout")
    p.add_argument("--entries-out", help="Also write raw entries JSON here")
    args = p.parse_args(argv)
    token = os.environ.get("SLACK_AUDIT_TOKEN")
    if not token:
        print("Set SLACK_AUDIT_TOKEN (org-level token with auditlogs:read)", file=sys.stderr)
        return 2
    entries = list(AuditLogClient(token).iter_entries(args.oldest, args.latest, action=args.action))
    if args.entries_out:
        with open(args.entries_out, "w") as f:
            json.dump(entries, f, indent=2)
    out = json.dumps(summarize(entries), indent=2)
    if args.out:
        with open(args.out, "w") as f:
            f.write(out)
    else:
        print(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
