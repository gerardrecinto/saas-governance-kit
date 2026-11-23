import json
from pathlib import Path

import httpx
import pytest

from saas_governance_kit.github.audit import audit_org
from saas_governance_kit.github.cli import main
from saas_governance_kit.github.client import GitHubClient, GitHubError
from saas_governance_kit.github.fixture_transport import fixture_transport

ROUTES = Path(__file__).parent / "fixtures" / "github" / "acme_routes.json"


def gh(transport=None, **kw):
    return GitHubClient(
        "tok", http=httpx.Client(transport=transport or fixture_transport(ROUTES)), **kw
    )


def test_full_audit_against_fixtures():
    report, entries = audit_org(gh(), "acme")
    assert report["sso"]["status"] == "enabled"
    assert report["two_factor"]["members_without_2fa"] == ["bob", "dave"]
    repos = {r["repo"]: r for r in report["branch_protection"]["repos"]}
    assert set(repos) == {"api", "web", "infra"}  # archived repo skipped
    assert repos["api"]["protected"] and repos["api"]["required_reviews"] == 2
    assert repos["web"]["protected"] is False
    assert repos["infra"]["source"] == "ruleset" and repos["infra"]["protected"]
    assert report["outside_collaborators"]["outside_collaborators"] == ["contractor-1"]
    assert report["audit_log"] == {"status": "exported", "entries": 2}
    assert len(entries) == 2
    ids = {f["id"]: f for f in report["findings"]}
    assert set(ids) == {"GH-2FA-001", "GH-BP-001", "GH-OC-001"}
    assert ids["GH-BP-001"]["items"] == ["web"]


def test_sso_and_audit_log_unavailable_produce_findings(tmp_path):
    routes = {
        "/orgs/solo/members?filter=2fa_disabled": [],
        "/orgs/solo/repos": [],
        "/orgs/solo/outside_collaborators": [],
    }
    f = tmp_path / "r.json"
    f.write_text(json.dumps(routes))
    report, entries = audit_org(gh(fixture_transport(f)), "solo")
    assert {x["id"] for x in report["findings"]} == {"GH-SSO-001", "GH-AL-001"}
    assert entries == []


def test_pagination_via_link_header():
    def handler(req):
        if req.url.params.get("page") == "2":
            return httpx.Response(200, json=[{"login": "c"}])
        return httpx.Response(
            200,
            json=[{"login": "a"}, {"login": "b"}],
            headers={"link": '<https://api.github.com/orgs/x/members?page=2>; rel="next"'},
        )

    client = gh(httpx.MockTransport(handler))
    assert [m["login"] for m in client.paginate("/orgs/x/members")] == ["a", "b", "c"]


def test_rate_limit_backoff():
    n, sleeps = [], []

    def handler(req):
        n.append(1)
        if len(n) == 1:
            return httpx.Response(403, headers={"retry-after": "5"})
        if len(n) == 2:
            return httpx.Response(
                403, headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": "0"}
            )
        return httpx.Response(200, json=[])

    client = gh(httpx.MockTransport(handler), sleep=sleeps.append)
    assert list(client.paginate("/x")) == []
    assert sleeps[0] == 5.0 and len(sleeps) == 2


def test_plain_403_is_not_retried_and_errors():
    client = gh(httpx.MockTransport(lambda r: httpx.Response(403, json={"message": "Forbidden"})))
    with pytest.raises(GitHubError) as e:
        client.get("/orgs/x/members")
    assert e.value.status == 403


def test_cli_offline(tmp_path, capsys):
    out, al = tmp_path / "report.json", tmp_path / "al.json"
    rc = main(
        [
            "--org",
            "acme",
            "--offline-fixtures",
            str(ROUTES),
            "--out",
            str(out),
            "--audit-log-out",
            str(al),
        ]
    )
    assert rc == 0
    assert json.loads(out.read_text())["org"] == "acme"
    assert len(json.loads(al.read_text())) == 2


def test_cli_requires_token(monkeypatch, capsys):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    assert main(["--org", "acme"]) == 2
