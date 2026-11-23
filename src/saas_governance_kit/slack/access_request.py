"""/access-request slash command with approve and deny buttons that add the requester to a SCIM group.

Handler logic takes plain dependencies (a Slack web client, a SCIM client, a config), so it can be
unit tested with fakes. `bolt_app.py` wires it into slack-bolt.
"""

import json
from dataclasses import dataclass, field

from .scim_client import ScimClient, ScimClientError

APPROVE_ID = "access_request_approve"
DENY_ID = "access_request_deny"


@dataclass
class AccessConfig:
    approver_channel: str
    approver_ids: set[str]
    allowed_groups: set[str]
    audit: list[dict] = field(default_factory=list)  # in-memory decision log


def parse_command_text(text: str) -> tuple[str, str]:
    parts = (text or "").strip().split(None, 1)
    if not parts:
        return "", ""
    return parts[0], parts[1] if len(parts) > 1 else ""


def handle_command(body: dict, client, config: AccessConfig) -> str:
    """Returns the ephemeral reply for the requester and posts the approval request."""
    group, reason = parse_command_text(body.get("text", ""))
    if not group:
        return "Usage: /access-request <group> <reason>"
    if group not in config.allowed_groups:
        allowed = ", ".join(sorted(config.allowed_groups)) or "none configured"
        return f"Group `{group}` is not requestable. Requestable groups: {allowed}"
    if not reason:
        return "Please include a reason: /access-request <group> <reason>"
    requester = body["user_id"]
    payload = json.dumps({"requester": requester, "group": group, "reason": reason[:500]})
    client.chat_postMessage(
        channel=config.approver_channel,
        text=f"<@{requester}> requests access to {group}",
        blocks=[
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"<@{requester}> requests access to *{group}*\nReason: {reason[:500]}",
                },
            },
            {
                "type": "actions",
                "block_id": "access_request_actions",
                "elements": [
                    {
                        "type": "button",
                        "action_id": APPROVE_ID,
                        "style": "primary",
                        "text": {"type": "plain_text", "text": "Approve"},
                        "value": payload,
                    },
                    {
                        "type": "button",
                        "action_id": DENY_ID,
                        "style": "danger",
                        "text": {"type": "plain_text", "text": "Deny"},
                        "value": payload,
                    },
                ],
            },
        ],
    )
    return f"Request for `{group}` sent to approvers."


def _finish(client, body: dict, text: str) -> None:
    client.chat_update(
        channel=body["channel"]["id"],
        ts=body["message"]["ts"],
        text=text,
        blocks=[{"type": "section", "text": {"type": "mrkdwn", "text": text}}],
    )


def _log(config: AccessConfig, decision: str, req: dict, approver: str, detail: str = "") -> None:
    config.audit.append({"decision": decision, "approver": approver, "detail": detail, **req})


def handle_decision(body: dict, client, scim: ScimClient, config: AccessConfig) -> str:
    """Handle an Approve or Deny click. Returns a short status string (also used by tests)."""
    action = body["actions"][0]
    clicker = body["user"]["id"]
    req = json.loads(action["value"])
    requester, group = req["requester"], req["group"]

    if clicker not in config.approver_ids:
        client.chat_postEphemeral(
            channel=body["channel"]["id"], user=clicker, text="You are not an approver."
        )
        return "not_approver"
    if clicker == requester:
        client.chat_postEphemeral(
            channel=body["channel"]["id"], user=clicker, text="You cannot approve your own request."
        )
        return "self_approval"

    if action["action_id"] == DENY_ID:
        _log(config, "denied", req, clicker)
        _finish(client, body, f":no_entry: <@{clicker}> denied <@{requester}> access to *{group}*")
        return "denied"

    if group not in config.allowed_groups:
        _finish(client, body, f"Group `{group}` is no longer requestable.")
        return "group_not_allowed"
    try:
        email = client.users_info(user=requester)["user"]["profile"]["email"]
        user = scim.find_user_by_email(email)
        grp = scim.find_group(group)
        if user is None or grp is None:
            missing = "user" if user is None else "group"
            _log(config, "error", req, clicker, f"SCIM {missing} not found")
            _finish(client, body, f"Could not find the SCIM {missing} for this request.")
            return "not_found"
        scim.add_member(grp["id"], user["id"])
    except (ScimClientError, KeyError) as e:
        _log(config, "error", req, clicker, str(e))
        _finish(client, body, f"Approval failed: {e}")
        return "error"
    _log(config, "approved", req, clicker)
    _finish(client, body, f":white_check_mark: <@{clicker}> approved <@{requester}> for *{group}*")
    return "approved"
