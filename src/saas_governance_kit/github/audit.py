"""Audit a GitHub organization through the REST API and emit a findings report."""

from datetime import UTC, datetime

from .client import GitHubClient, GitHubError


def check_sso(gh: GitHubClient, org: str) -> dict:
    """SAML SSO state. REST exposes credential authorizations only when SAML SSO is enabled.

    SSO *enforcement* is not readable through REST (it needs GraphQL), so this reports what is
    observable: whether the endpoint exists and how many PAT/SSH credentials are SSO-authorized.
    """
    r = gh.get(f"/orgs/{org}/credential-authorizations", allow=(403, 404))
    if r.status_code != 200:
        return {"status": "unavailable", "http_status": r.status_code, "authorizations": []}
    auths = list(gh.paginate(f"/orgs/{org}/credential-authorizations"))
    return {
        "status": "enabled",
        "authorizations": [
            {
                "login": a.get("login"),
                "credential_type": a.get("credential_type"),
                "credential_authorized_at": a.get("credential_authorized_at"),
                "credential_accessed_at": a.get("credential_accessed_at"),
            }
            for a in auths
        ],
    }


def check_two_factor(gh: GitHubClient, org: str) -> dict:
    members = list(gh.paginate(f"/orgs/{org}/members", {"filter": "2fa_disabled"}))
    return {"members_without_2fa": sorted(m["login"] for m in members)}


def _default_branch_protection(gh: GitHubClient, org: str, repo: dict) -> dict:
    name, branch = repo["name"], repo.get("default_branch", "main")
    r = gh.get(f"/repos/{org}/{name}/branches/{branch}/protection", allow=(403, 404))
    if r.status_code == 200:
        p = r.json()
        reviews = p.get("required_pull_request_reviews") or {}
        return {
            "repo": name,
            "branch": branch,
            "protected": True,
            "source": "branch_protection",
            "required_reviews": reviews.get("required_approving_review_count", 0),
            "enforce_admins": (p.get("enforce_admins") or {}).get("enabled", False),
            "required_status_checks": bool(p.get("required_status_checks")),
            "allow_force_pushes": (p.get("allow_force_pushes") or {}).get("enabled", False),
        }
    rules = gh.get(f"/repos/{org}/{name}/rules/branches/{branch}", allow=(403, 404))
    if rules.status_code == 200 and rules.json():
        types = {x.get("type") for x in rules.json()}
        return {
            "repo": name,
            "branch": branch,
            "protected": True,
            "source": "ruleset",
            "required_reviews": 1 if "pull_request" in types else 0,
            "enforce_admins": None,
            "required_status_checks": "required_status_checks" in types,
            "allow_force_pushes": "non_fast_forward" not in types,
        }
    return {"repo": name, "branch": branch, "protected": False, "source": None}


def check_branch_protection(gh: GitHubClient, org: str) -> dict:
    repos = [r for r in gh.paginate(f"/orgs/{org}/repos", {"type": "all"}) if not r.get("archived")]
    return {"repos": [_default_branch_protection(gh, org, r) for r in repos]}


def check_outside_collaborators(gh: GitHubClient, org: str) -> dict:
    cols = list(gh.paginate(f"/orgs/{org}/outside_collaborators"))
    return {"outside_collaborators": sorted(c["login"] for c in cols)}


def export_audit_log(gh: GitHubClient, org: str, phrase: str | None = None, limit: int = 1000):
    params = {"phrase": phrase} if phrase else None
    r = gh.get(f"/orgs/{org}/audit-log", {"per_page": 100, **(params or {})}, allow=(403, 404))
    if r.status_code != 200:
        return {"status": "unavailable", "http_status": r.status_code}, []
    entries = list(gh.paginate(f"/orgs/{org}/audit-log", params))[:limit]
    return {"status": "exported", "entries": len(entries)}, entries


def _finding(fid: str, severity: str, title: str, items: list) -> dict:
    return {"id": fid, "severity": severity, "title": title, "items": items}


def build_findings(report: dict) -> list[dict]:
    out = []
    sso = report["sso"]
    if sso["status"] != "enabled":
        out.append(_finding("GH-SSO-001", "high", "SAML SSO not detected for the organization", []))
    two = report["two_factor"]["members_without_2fa"]
    if two:
        out.append(_finding("GH-2FA-001", "high", "Members without two-factor authentication", two))
    repos = report["branch_protection"]["repos"]
    unprot = [r["repo"] for r in repos if not r["protected"]]
    if unprot:
        out.append(_finding("GH-BP-001", "high", "Default branch has no protection", unprot))
    weak = [
        r["repo"]
        for r in repos
        if r["protected"] and (r["required_reviews"] < 1 or r["allow_force_pushes"])
    ]
    if weak:
        out.append(
            _finding(
                "GH-BP-002", "medium", "Protected branch lacks review or allows force push", weak
            )
        )
    oc = report["outside_collaborators"]["outside_collaborators"]
    if oc:
        out.append(_finding("GH-OC-001", "medium", "Outside collaborators have access", oc))
    if report["audit_log"]["status"] != "exported":
        out.append(_finding("GH-AL-001", "low", "Audit log not available to this token", []))
    return out


def audit_org(gh: GitHubClient, org: str, audit_phrase: str | None = None, audit_limit: int = 1000):
    """Returns (report, audit_log_entries)."""
    report: dict = {
        "org": org,
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": "github-rest",
    }
    report["sso"] = check_sso(gh, org)
    report["two_factor"] = check_two_factor(gh, org)
    report["branch_protection"] = check_branch_protection(gh, org)
    report["outside_collaborators"] = check_outside_collaborators(gh, org)
    report["audit_log"], entries = export_audit_log(gh, org, audit_phrase, audit_limit)
    report["findings"] = build_findings(report)
    return report, entries


__all__ = ["GitHubError", "audit_org", "build_findings"]
