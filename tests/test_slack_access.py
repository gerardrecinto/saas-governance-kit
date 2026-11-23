import json
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

import httpx
import pytest
from slack_bolt.request import BoltRequest

from saas_governance_kit.slack.access_request import (
    APPROVE_ID,
    DENY_ID,
    AccessConfig,
    handle_command,
    handle_decision,
    parse_command_text,
)
from saas_governance_kit.slack.bolt_app import build_app
from saas_governance_kit.slack.scim_client import ScimClient, ScimClientError
from saas_governance_kit.slack.signing import sign


class FakeSlack:
    def __init__(self, email="req@example.com"):
        self.calls = []
        self.email = email

    def chat_postMessage(self, **kw):
        self.calls.append(("post", kw))

    def chat_update(self, **kw):
        self.calls.append(("update", kw))

    def chat_postEphemeral(self, **kw):
        self.calls.append(("ephemeral", kw))

    def users_info(self, user):
        return {"user": {"profile": {"email": self.email}}}


class FakeScim:
    def __init__(self, user=None, group=None, fail=False):
        self.user = {"id": "uid1"} if user is None else user or None
        self.group = {"id": "gid1"} if group is None else group or None
        self.fail = fail
        self.added = []

    def find_user_by_email(self, email):
        return self.user

    def find_group(self, name):
        return self.group

    def add_member(self, gid, uid):
        if self.fail:
            raise ScimClientError("boom")
        self.added.append((gid, uid))


@pytest.fixture
def cfg():
    return AccessConfig("C-APPROVE", {"UAPPR"}, {"github-admins", "prod-read"})


def click(action_id, clicker="UAPPR", requester="UREQ", group="prod-read"):
    value = json.dumps({"requester": requester, "group": group, "reason": "oncall"})
    return {
        "user": {"id": clicker},
        "channel": {"id": "C-APPROVE"},
        "message": {"ts": "1.1"},
        "actions": [{"action_id": action_id, "value": value}],
    }


def test_parse_command_text():
    assert parse_command_text("prod-read need it for incident") == (
        "prod-read",
        "need it for incident",
    )
    assert parse_command_text("") == ("", "")
    assert parse_command_text("only") == ("only", "")


def test_command_posts_approval_buttons(cfg):
    slack = FakeSlack()
    reply = handle_command({"user_id": "UREQ", "text": "prod-read incident 42"}, slack, cfg)
    assert "sent to approvers" in reply
    kind, kw = slack.calls[0]
    assert kind == "post" and kw["channel"] == "C-APPROVE"
    ids = [b["action_id"] for b in kw["blocks"][1]["elements"]]
    assert ids == [APPROVE_ID, DENY_ID]


def test_command_rejects_unknown_group_and_missing_reason(cfg):
    slack = FakeSlack()
    assert "not requestable" in handle_command({"user_id": "U", "text": "root why"}, slack, cfg)
    assert "reason" in handle_command({"user_id": "U", "text": "prod-read"}, slack, cfg)
    assert "Usage" in handle_command({"user_id": "U", "text": ""}, slack, cfg)
    assert slack.calls == []


def test_approve_adds_group_member(cfg):
    slack, scim = FakeSlack(), FakeScim()
    assert handle_decision(click(APPROVE_ID), slack, scim, cfg) == "approved"
    assert scim.added == [("gid1", "uid1")]
    assert cfg.audit[-1]["decision"] == "approved"
    assert slack.calls[-1][0] == "update"


def test_deny_does_not_touch_scim(cfg):
    slack, scim = FakeSlack(), FakeScim()
    assert handle_decision(click(DENY_ID), slack, scim, cfg) == "denied"
    assert scim.added == []


def test_non_approver_and_self_approval_blocked(cfg):
    slack, scim = FakeSlack(), FakeScim()
    assert (
        handle_decision(click(APPROVE_ID, clicker="USTRANGER"), slack, scim, cfg) == "not_approver"
    )
    cfg.approver_ids.add("UREQ")
    assert handle_decision(click(APPROVE_ID, clicker="UREQ"), slack, scim, cfg) == "self_approval"
    assert scim.added == []


def test_group_revalidated_at_approval_time(cfg):
    slack, scim = FakeSlack(), FakeScim()
    assert handle_decision(click(APPROVE_ID, group="root"), slack, scim, cfg) == "group_not_allowed"
    assert scim.added == []


def test_missing_scim_user_and_scim_failure(cfg):
    slack = FakeSlack()
    assert handle_decision(click(APPROVE_ID), slack, FakeScim(user=False), cfg) == "not_found"
    assert handle_decision(click(APPROVE_ID), slack, FakeScim(fail=True), cfg) == "error"
    assert [a["decision"] for a in cfg.audit] == ["error", "error"]


def test_scim_client_over_mock_transport():
    seen = []

    def handler(req):
        seen.append((req.method, req.url.path, dict(req.url.params), req.content))
        assert req.headers["authorization"] == "Bearer tok"
        if req.method == "GET" and req.url.path.endswith("/Users"):
            return httpx.Response(200, json={"Resources": [{"id": "u1"}]})
        if req.method == "GET":
            return httpx.Response(200, json={"Resources": [{"id": "g1"}]})
        return httpx.Response(200, json={"id": "g1"})

    c = ScimClient(
        "https://scim.test/scim/v2/", "tok", httpx.Client(transport=httpx.MockTransport(handler))
    )
    assert c.find_user_by_email('a"@x.com')["id"] == "u1"
    assert c.find_group("g")["id"] == "g1"
    c.add_member("g1", "u1")
    assert seen[0][2]["filter"] == 'userName eq "a@x.com"'
    body = json.loads(seen[2][3])
    assert body["Operations"][0] == {"op": "add", "path": "members", "value": [{"value": "u1"}]}
    bad = ScimClient(
        "https://scim.test",
        "tok",
        httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(409, text="dup"))),
    )
    with pytest.raises(ScimClientError, match="409"):
        bad.add_member("g", "u")


# --- Bolt integration against a local fake Slack Web API (no real tokens) ---


class _FakeSlackApi(BaseHTTPRequestHandler):
    calls: list = []

    def do_POST(self):
        length = int(self.headers.get("content-length", 0))
        raw = self.rfile.read(length).decode()
        _FakeSlackApi.calls.append((self.path, dict(urllib.parse.parse_qsl(raw)) or raw))
        if self.path.endswith("auth.test"):
            out = {
                "ok": True,
                "user_id": "UBOT",
                "bot_id": "B1",
                "team_id": "T1",
                "user": "bot",
                "url": "https://x.slack.com/",
            }
        else:
            out = {"ok": True}
        data = json.dumps(out).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


@pytest.fixture
def fake_api():
    _FakeSlackApi.calls = []
    srv = HTTPServer(("127.0.0.1", 0), _FakeSlackApi)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}/"
    srv.shutdown()


def signed_request(secret, body, ts=None, bad=False):
    ts = ts or str(int(time.time()))
    sig = sign(secret, ts, body.encode())
    if bad:
        sig = sig[:-1] + ("0" if sig[-1] != "0" else "1")
    return BoltRequest(
        body=body,
        headers={
            "x-slack-signature": [sig],
            "x-slack-request-timestamp": [ts],
            "content-type": ["application/x-www-form-urlencoded"],
        },
    )


def test_bolt_command_requires_valid_signature_and_posts_approval(fake_api, cfg):
    from slack_sdk import WebClient

    secret = "signing-secret"
    app = build_app(
        "xoxb-fake",
        secret,
        FakeScim(),
        cfg,
        client=WebClient(token="xoxb-fake", base_url=fake_api),
        token_verification_enabled=False,
        process_before_response=True,
    )
    body = urllib.parse.urlencode(
        {"command": "/access-request", "text": "prod-read incident", "user_id": "UREQ",
         "team_id": "T1", "channel_id": "C1", "response_url": f"{fake_api}response"}
    )  # fmt: skip
    assert app.dispatch(signed_request(secret, body, bad=True)).status == 401
    assert app.dispatch(signed_request(secret, body, ts="1")).status == 401
    resp = app.dispatch(signed_request(secret, body))
    assert resp.status == 200
    paths = [p for p, _ in _FakeSlackApi.calls]
    assert any(p.endswith("chat.postMessage") for p in paths)
