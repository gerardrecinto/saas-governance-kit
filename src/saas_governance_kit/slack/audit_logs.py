"""Slack Enterprise Grid Audit Logs API client (https://api.slack.com/admins/audit-logs).

Needs an org-level user token with the auditlogs:read scope. Uses cursor pagination and honors
Retry-After on HTTP 429.
"""

import time
from collections import Counter
from collections.abc import Callable, Iterator

import httpx

BASE_URL = "https://api.slack.com/audit/v1/logs"
PRIVILEGED_ACTIONS = {
    "role_change_to_admin",
    "role_change_to_owner",
    "app_installed",
    "app_scopes_expanded",
    "user_deactivated",
    "user_created",
}


class AuditLogError(Exception):
    pass


class AuditLogClient:
    def __init__(
        self,
        token: str,
        http: httpx.Client | None = None,
        base_url: str = BASE_URL,
        sleep: Callable[[float], None] = time.sleep,
        max_retries: int = 5,
        max_retry_after: float = 120.0,
    ):
        self.http = http or httpx.Client(timeout=30)
        self.headers = {"Authorization": f"Bearer {token}"}
        self.base_url = base_url
        self.sleep = sleep
        self.max_retries = max_retries
        self.max_retry_after = max_retry_after

    def _get(self, params: dict) -> dict:
        for attempt in range(self.max_retries + 1):
            r = self.http.get(self.base_url, headers=self.headers, params=params)
            if r.status_code == 429:
                if attempt == self.max_retries:
                    raise AuditLogError("Rate limited and out of retries")
                try:
                    wait = float(r.headers.get("Retry-After", "1"))
                except ValueError:
                    wait = 1.0
                self.sleep(min(max(wait, 0), self.max_retry_after))
                continue
            if r.status_code >= 500 and attempt < self.max_retries:
                self.sleep(min(2**attempt, 30))
                continue
            if r.status_code != 200:
                raise AuditLogError(f"HTTP {r.status_code}: {r.text[:200]}")
            data = r.json()
            if data.get("ok") is False:
                raise AuditLogError(f"Slack error: {data.get('error')}")
            return data
        raise AuditLogError("unreachable")

    def iter_entries(
        self,
        oldest: int | None = None,
        latest: int | None = None,
        action: str | None = None,
        actor: str | None = None,
        entity: str | None = None,
        limit: int = 1000,
    ) -> Iterator[dict]:
        params: dict = {"limit": limit}
        for k, v in (
            ("oldest", oldest),
            ("latest", latest),
            ("action", action),
            ("actor", actor),
            ("entity", entity),
        ):
            if v is not None:
                params[k] = v
        seen_cursors: set[str] = set()
        while True:
            data = self._get(params)
            yield from data.get("entries", [])
            cursor = (data.get("response_metadata") or {}).get("next_cursor")
            if not cursor or cursor in seen_cursors:
                return
            seen_cursors.add(cursor)
            params["cursor"] = cursor


def summarize(entries: list[dict]) -> dict:
    actions = Counter(e.get("action", "unknown") for e in entries)
    privileged = [
        {
            "action": e["action"],
            "actor": (e.get("actor", {}).get("user") or {}).get("email"),
            "entity": (e.get("entity", {}).get("user") or {}).get("email")
            or (e.get("entity", {}).get("app") or {}).get("name"),
            "date_create": e.get("date_create"),
        }
        for e in entries
        if e.get("action") in PRIVILEGED_ACTIONS
    ]
    return {
        "total_entries": len(entries),
        "action_counts": dict(sorted(actions.items())),
        "failed_logins": actions.get("user_login_failed", 0),
        "privileged_events": privileged,
    }
