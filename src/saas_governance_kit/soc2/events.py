"""Tiny helper so SAML and OIDC validation outcomes can be logged as evidence."""

import json
from datetime import UTC, datetime


def auth_event(protocol: str, error: Exception | None = None, subject: str | None = None) -> dict:
    return {
        "ts": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "protocol": protocol,
        "result": "rejected" if error else "accepted",
        "code": getattr(error, "code", None) if error else None,
        "subject": subject,
    }


def append_event(path: str, event: dict) -> None:
    with open(path, "a") as f:
        f.write(json.dumps(event) + "\n")
