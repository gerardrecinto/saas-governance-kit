import json
from pathlib import Path

import httpx
import pytest

from saas_governance_kit.slack.audit_logs import AuditLogClient, AuditLogError, summarize
from saas_governance_kit.slack.signing import sign, verify_slack_signature

FX = Path(__file__).parent / "fixtures"
P1 = json.loads((FX / "slack_audit_page1.json").read_text())
P2 = json.loads((FX / "slack_audit_page2.json").read_text())


def client_for(handler, sleeps=None, **kw):
    http = httpx.Client(transport=httpx.MockTransport(handler))
    return AuditLogClient(
        "xoxp-test",
        http=http,
        sleep=(sleeps.append if sleeps is not None else lambda s: None),
        **kw,
    )


def test_cursor_pagination_and_params():
    seen = []

    def handler(req):
        seen.append(dict(req.url.params))
        assert req.headers["authorization"] == "Bearer xoxp-test"
        return httpx.Response(200, json=P2 if req.url.params.get("cursor") else P1)

    entries = list(client_for(handler).iter_entries(oldest=100, action="user_login"))
    assert [e["id"][-1] for e in entries] == ["1", "2", "3", "4", "5"]
    assert seen[0]["oldest"] == "100" and seen[0]["action"] == "user_login"
    assert seen[1]["cursor"] == "cursor-page-2"


def test_retry_after_on_429():
    calls = []

    def handler(req):
        calls.append(1)
        if len(calls) < 3:
            return httpx.Response(429, headers={"Retry-After": "7"})
        return httpx.Response(200, json=P2)

    sleeps = []
    assert len(list(client_for(handler, sleeps).iter_entries())) == 2
    assert sleeps == [7.0, 7.0]


def test_retry_after_is_capped_and_bounded():
    sleeps = []
    c = client_for(
        lambda r: httpx.Response(429, headers={"Retry-After": "99999"}),
        sleeps,
        max_retries=2,
        max_retry_after=30,
    )
    with pytest.raises(AuditLogError, match="out of retries"):
        list(c.iter_entries())
    assert sleeps == [30.0, 30.0]


def test_http_error_and_slack_error():
    with pytest.raises(AuditLogError, match="HTTP 403"):
        list(client_for(lambda r: httpx.Response(403, text="forbidden")).iter_entries())
    bad = httpx.Response(200, json={"ok": False, "error": "invalid_auth"})
    with pytest.raises(AuditLogError, match="invalid_auth"):
        list(client_for(lambda r: bad).iter_entries())


def test_repeated_cursor_stops():
    loop = {"entries": [], "response_metadata": {"next_cursor": "same"}}
    n = []

    def handler(req):
        n.append(1)
        return httpx.Response(200, json=loop)

    list(client_for(handler).iter_entries())
    assert len(n) == 2


def test_summarize_fixture():
    s = summarize(P1["entries"] + P2["entries"])
    assert s["total_entries"] == 5
    assert s["failed_logins"] == 2
    assert [p["action"] for p in s["privileged_events"]] == [
        "role_change_to_admin",
        "app_installed",
    ]
    assert s["privileged_events"][0]["entity"] == "carol@example.com"
    assert s["privileged_events"][1]["entity"] == "Deploy Bot"


def test_signing_secret_verification():
    body, ts, secret = b"token=x&command=%2Faccess-request", "1700000000", "s3cret"
    sig = sign(secret, ts, body)
    assert verify_slack_signature(secret, ts, body, sig, now=1700000010)
    assert not verify_slack_signature("other", ts, body, sig, now=1700000010)
    assert not verify_slack_signature(secret, ts, body + b"x", sig, now=1700000010)
    assert not verify_slack_signature(secret, ts, body, sig, now=1700000400)  # replay window
    assert not verify_slack_signature(secret, "abc", body, sig, now=1700000010)
    assert not verify_slack_signature(secret, ts, body, "", now=1700000010)
