"""Slack request signature verification (https://api.slack.com/authentication/verifying-requests-from-slack)."""

import hashlib
import hmac
import time


def verify_slack_signature(
    signing_secret: str,
    timestamp: str,
    body: bytes,
    signature: str,
    now: float | None = None,
    tolerance_seconds: int = 300,
) -> bool:
    now = time.time() if now is None else now
    try:
        if abs(now - int(timestamp)) > tolerance_seconds:
            return False
    except (TypeError, ValueError):
        return False
    base = b"v0:" + timestamp.encode() + b":" + body
    expected = "v0=" + hmac.new(signing_secret.encode(), base, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature or "")


def sign(signing_secret: str, timestamp: str, body: bytes) -> str:
    base = b"v0:" + timestamp.encode() + b":" + body
    return "v0=" + hmac.new(signing_secret.encode(), base, hashlib.sha256).hexdigest()
