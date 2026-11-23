import os

from slack_bolt import App

from .access_request import APPROVE_ID, DENY_ID, AccessConfig, handle_command, handle_decision
from .scim_client import ScimClient


def build_app(
    token: str, signing_secret: str, scim: ScimClient, config: AccessConfig, **app_kwargs
) -> App:
    """Bolt verifies the Slack signing secret on every incoming request."""
    app = App(token=token, signing_secret=signing_secret, **app_kwargs)

    @app.command("/access-request")
    def access_request(ack, body, client, respond):
        ack()
        respond(text=handle_command(body, client, config), response_type="ephemeral")

    @app.action(APPROVE_ID)
    @app.action(DENY_ID)
    def decide(ack, body, client):
        ack()
        handle_decision(body, client, scim, config)

    return app


def main() -> None:
    config = AccessConfig(
        approver_channel=os.environ["APPROVER_CHANNEL_ID"],
        approver_ids=set(os.environ["APPROVER_USER_IDS"].split(",")),
        allowed_groups=set(os.environ["ALLOWED_GROUPS"].split(",")),
    )
    scim = ScimClient(os.environ["SCIM_BASE_URL"], os.environ["SCIM_BEARER_TOKEN"])
    app = build_app(os.environ["SLACK_BOT_TOKEN"], os.environ["SLACK_SIGNING_SECRET"], scim, config)
    app.start(port=int(os.environ.get("PORT", "3000")))


if __name__ == "__main__":
    main()
