"""Minimal SCIM 2.0 client used by the access-request flow."""

import httpx

PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"


class ScimClientError(Exception):
    pass


class ScimClient:
    def __init__(self, base_url: str, token: str, http: httpx.Client | None = None):
        self.base = base_url.rstrip("/")
        self.http = http or httpx.Client(timeout=15)
        self.headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/scim+json"}

    def _request(self, method: str, path: str, **kw) -> dict:
        r = self.http.request(method, f"{self.base}{path}", headers=self.headers, **kw)
        if r.status_code >= 400:
            raise ScimClientError(f"{method} {path} -> {r.status_code}: {r.text[:200]}")
        return r.json() if r.content else {}

    def find_user_by_email(self, email: str) -> dict | None:
        safe = email.replace('"', "")
        res = self._request("GET", "/Users", params={"filter": f'userName eq "{safe}"'})
        items = res.get("Resources", [])
        return items[0] if items else None

    def find_group(self, display_name: str) -> dict | None:
        safe = display_name.replace('"', "")
        res = self._request("GET", "/Groups", params={"filter": f'displayName eq "{safe}"'})
        items = res.get("Resources", [])
        return items[0] if items else None

    def add_member(self, group_id: str, user_id: str) -> dict:
        body = {
            "schemas": [PATCH_SCHEMA],
            "Operations": [{"op": "add", "path": "members", "value": [{"value": user_id}]}],
        }
        return self._request("PATCH", f"/Groups/{group_id}", json=body)
