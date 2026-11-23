"""Map collected findings to AICPA Trust Services Criteria (2017 TSC) as EVIDENCE SUPPORT only."""

from collections import Counter
from datetime import UTC, datetime

DISCLAIMER = (
    "Evidence support only. This output is not a SOC 2 report, attestation, certification or "
    "compliance claim. It summarizes machine-collected data from the supplied inputs; control "
    "design, operating effectiveness and sampling remain the auditor's determination."
)

CRITERIA = {
    "CC6.1": "Logical access security software, infrastructure and architectures",
    "CC6.2": "User registration and authorization; removal of access when no longer needed",
    "CC6.3": "Role-based access and least privilege",
    "CC7.2": "Monitoring of system components for anomalies and security events",
    "CC8.1": "Change management authorization and approval",
}


def ev(source: str, check: str, status: str, detail: str, items: list | None = None) -> dict:
    return {
        "source": source,
        "check": check,
        "status": status,
        "detail": detail,
        "items": items or [],
    }


def _rollup(evidence: list[dict]) -> str:
    if not evidence or all(e["status"] == "no_data" for e in evidence):
        return "no_data"
    return (
        "exceptions_noted"
        if any(e["status"] == "exception" for e in evidence)
        else "no_exceptions_noted"
    )


def build_report(
    github: dict | None = None,
    slack_audit: dict | None = None,
    scim_store: dict | None = None,
    access_log: list[dict] | None = None,
    auth_events: list[dict] | None = None,
) -> dict:
    c: dict[str, list[dict]] = {k: [] for k in CRITERIA}
    gh = github
    # CC6.1 logical access
    if gh:
        sso = gh["sso"]["status"]
        c["CC6.1"].append(
            ev("github", "SAML SSO detected", "ok" if sso == "enabled" else "exception",
               f"Credential-authorization endpoint status: {sso}. Enforcement is not readable via REST.")
        )  # fmt: skip
        no2fa = gh["two_factor"]["members_without_2fa"]
        c["CC6.1"].append(
            ev("github", "Members without 2FA", "exception" if no2fa else "ok",
               f"{len(no2fa)} member(s) without two-factor authentication", no2fa)
        )  # fmt: skip
    else:
        c["CC6.1"].append(ev("github", "SSO and 2FA", "no_data", "No GitHub audit report supplied"))
    if auth_events:
        n = Counter((e["protocol"], e["result"]) for e in auth_events)
        codes = Counter(e["code"] for e in auth_events if e["result"] == "rejected")
        c["CC6.1"].append(
            ev("auth-events", "SAML/OIDC validation outcomes", "info",
               "; ".join(f"{p} {r}: {v}" for (p, r), v in sorted(n.items())),
               [f"{k}: {v}" for k, v in sorted(codes.items())])
        )  # fmt: skip

    # CC6.2 registration, authorization, deprovisioning
    if scim_store:
        users = list(scim_store.get("Users", {}).values())
        inactive = [u for u in users if not u.get("active", True)]
        member_ids = {
            m.get("value")
            for g in scim_store.get("Groups", {}).values()
            for m in g.get("members", [])
        }
        lingering = sorted(u["userName"] for u in inactive if u["id"] in member_ids)
        c["CC6.2"].append(
            ev("scim", "Deprovisioned users removed from groups",
               "exception" if lingering else "ok",
               f"{len(users)} user(s), {len(inactive)} deactivated; "
               f"{len(lingering)} deactivated user(s) still in a group", lingering)
        )  # fmt: skip
    else:
        c["CC6.2"].append(ev("scim", "Deprovisioning state", "no_data", "No SCIM store supplied"))
    if access_log is not None:
        by = Counter(d["decision"] for d in access_log)
        errors = [
            f"{d['requester']} -> {d['group']}: {d['detail']}"
            for d in access_log
            if d["decision"] == "error"
        ]
        c["CC6.2"].append(
            ev("slack-access-requests", "Access requests approved by a named approver",
               "exception" if errors else "ok",
               "Decisions: " + (", ".join(f"{k}={v}" for k, v in sorted(by.items())) or "none"), errors)
        )  # fmt: skip
    # CC6.3 least privilege
    if gh:
        oc = gh["outside_collaborators"]["outside_collaborators"]
        c["CC6.3"].append(
            ev("github", "Outside collaborators", "exception" if oc else "ok",
               f"{len(oc)} outside collaborator(s) with org access", oc)
        )  # fmt: skip
    else:
        c["CC6.3"].append(
            ev("github", "Outside collaborators", "no_data", "No GitHub audit report supplied")
        )
    if slack_audit:
        priv = slack_audit.get("privileged_events", [])
        c["CC6.3"].append(
            ev("slack", "Privileged role and app changes", "info",
               f"{len(priv)} privileged event(s) for review",
               [f'{p["action"]} by {p["actor"]} on {p["entity"]}' for p in priv])
        )  # fmt: skip

    # CC7.2 monitoring
    if slack_audit:
        c["CC7.2"].append(
            ev("slack", "Audit log collected", "ok" if slack_audit["total_entries"] else "exception",
               f'{slack_audit["total_entries"]} entries; {slack_audit["failed_logins"]} failed login(s)')
        )  # fmt: skip
    else:
        c["CC7.2"].append(
            ev("slack", "Audit log collected", "no_data", "No Slack audit summary supplied")
        )
    if gh:
        al = gh["audit_log"]
        c["CC7.2"].append(
            ev("github", "Audit log exported", "ok" if al["status"] == "exported" else "exception",
               f'Audit log status: {al["status"]}' + (f', {al["entries"]} entries' if "entries" in al else ""))
        )  # fmt: skip
    else:
        c["CC7.2"].append(
            ev("github", "Audit log exported", "no_data", "No GitHub audit report supplied")
        )

    # CC8.1 change management
    if gh:
        repos = gh["branch_protection"]["repos"]
        unprot = [r["repo"] for r in repos if not r["protected"]]
        weak = [
            r["repo"]
            for r in repos
            if r["protected"] and (r["required_reviews"] < 1 or r["allow_force_pushes"])
        ]
        c["CC8.1"].append(
            ev("github", "Default branch protected", "exception" if unprot else "ok",
               f"{len(repos) - len(unprot)} of {len(repos)} repo(s) protect the default branch", unprot)
        )  # fmt: skip
        c["CC8.1"].append(
            ev("github", "Reviews required and force push blocked", "exception" if weak else "ok",
               f"{len(weak)} protected repo(s) lack a required review or allow force push", weak)
        )  # fmt: skip
    else:
        c["CC8.1"].append(
            ev("github", "Branch protection", "no_data", "No GitHub audit report supplied")
        )

    return {
        "disclaimer": DISCLAIMER,
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "criteria": [
            {"id": k, "title": CRITERIA[k], "result": _rollup(v), "evidence": v}
            for k, v in c.items()
        ],
    }


def to_markdown(report: dict) -> str:
    lines = ["# SOC 2 evidence support report", "", f"> {report['disclaimer']}", "",
             f"Generated: {report['generated_at']}", "",
             "| Criterion | Result |", "| --- | --- |"]  # fmt: skip
    for c in report["criteria"]:
        lines.append(f"| {c['id']} | {c['result']} |")
    for c in report["criteria"]:
        lines += ["", f"## {c['id']}: {c['title']}", ""]
        for e in c["evidence"]:
            lines.append(f"- [{e['status']}] **{e['check']}** ({e['source']}): {e['detail']}")
            lines += [f"  - {i}" for i in e["items"]]
    return "\n".join(lines) + "\n"
