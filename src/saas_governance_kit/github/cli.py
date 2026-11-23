import argparse
import json
import os
import sys

import httpx

from .audit import audit_org
from .client import GitHubClient, GitHubError
from .fixture_transport import fixture_transport


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Audit a GitHub organization (read-only)")
    p.add_argument("--org", required=True)
    p.add_argument("--base-url", default="https://api.github.com", help="GHES: https://host/api/v3")
    p.add_argument("--out", help="Write report JSON here (default stdout)")
    p.add_argument("--audit-log-out", help="Write exported audit log entries JSON here")
    p.add_argument("--audit-phrase", help="Audit log search phrase, e.g. action:org.update_member")
    p.add_argument(
        "--offline-fixtures", help="Use a routes.json instead of the network (demo/test)"
    )
    args = p.parse_args(argv)

    if args.offline_fixtures:
        token, http = "offline", httpx.Client(transport=fixture_transport(args.offline_fixtures))
    else:
        token, http = os.environ.get("GITHUB_TOKEN", ""), None
        if not token:
            print("Set GITHUB_TOKEN (read-only: read:org, repo metadata)", file=sys.stderr)
            return 2
    try:
        report, entries = audit_org(
            GitHubClient(token, args.base_url, http), args.org, args.audit_phrase
        )
    except GitHubError as e:
        print(f"GitHub API error: {e}", file=sys.stderr)
        return 1
    if args.audit_log_out:
        with open(args.audit_log_out, "w") as f:
            json.dump(entries, f, indent=2)
    text = json.dumps(report, indent=2)
    if args.out:
        with open(args.out, "w") as f:
            f.write(text + "\n")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
