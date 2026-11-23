import json
from pathlib import Path

import httpx

from saas_governance_kit.github.audit import audit_org
from saas_governance_kit.github.client import GitHubClient
from saas_governance_kit.github.fixture_transport import fixture_transport
from saas_governance_kit.slack.audit_logs import summarize
from saas_governance_kit.soc2.cli import main
from saas_governance_kit.soc2.events import auth_event
from saas_governance_kit.soc2.mapping import DISCLAIMER, build_report, to_markdown

FX = Path(__file__).parent / "fixtures"


def gh_report():
    c = GitHubClient(
        "t", http=httpx.Client(transport=fixture_transport(FX / "github" / "acme_routes.json"))
    )
    return audit_org(c, "acme")[0]


def slack_summary():
    entries = []
    for n in (1, 2):
        entries += json.loads((FX / f"slack_audit_page{n}.json").read_text())["entries"]
    return summarize(entries)


def by_id(report):
    return {c["id"]: c for c in report["criteria"]}


def scim_store(lingering):
    users = {"u1": {"id": "u1", "userName": "gone@x.com", "active": False}}
    members = [{"value": "u1"}] if lingering else []
    return {
        "Users": users,
        "Groups": {"g1": {"id": "g1", "displayName": "eng", "members": members}},
    }


def test_mapping_all_inputs():
    events = [auth_event("saml"), auth_event("saml", type("E", (), {"code": "replay"})())]
    r = build_report(
        gh_report(), slack_summary(), scim_store(True),
        [{"decision": "approved", "requester": "U1", "group": "g", "detail": ""}], events,
    )  # fmt: skip
    c = by_id(r)
    assert set(c) == {"CC6.1", "CC6.2", "CC6.3", "CC7.2", "CC8.1"}
    assert c["CC6.1"]["result"] == "exceptions_noted"  # bob and dave lack 2FA
    assert c["CC6.2"]["result"] == "exceptions_noted"  # deactivated user still in group
    assert c["CC6.3"]["result"] == "exceptions_noted"  # outside collaborator
    assert c["CC7.2"]["result"] == "no_exceptions_noted"
    assert c["CC8.1"]["result"] == "exceptions_noted"  # web unprotected
    assert r["disclaimer"] == DISCLAIMER


def test_clean_scim_and_no_data():
    r = build_report(scim_store=scim_store(False))
    c = by_id(r)
    assert c["CC6.2"]["result"] == "no_exceptions_noted"
    assert c["CC8.1"]["result"] == "no_data"


def test_markdown_labels_not_a_certification():
    md = to_markdown(build_report(gh_report()))
    assert "not a SOC 2 report" in md and "CC8.1" in md
    assert "certified" not in md.lower().replace(
        "not a soc 2 report, attestation, certification", ""
    )


def test_cli_end_to_end(tmp_path):
    gh_file, sl_file = tmp_path / "gh.json", tmp_path / "sl.json"
    gh_file.write_text(json.dumps(gh_report()))
    sl_file.write_text(json.dumps(slack_summary()))
    out = tmp_path / "r.json"
    assert (
        main(
            [
                "--github",
                str(gh_file),
                "--slack-audit",
                str(sl_file),
                "--format",
                "json",
                "--out",
                str(out),
            ]
        )
        == 0
    )
    assert json.loads(out.read_text())["criteria"][0]["id"] == "CC6.1"
