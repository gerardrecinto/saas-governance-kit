import re
import time
from collections.abc import Callable, Iterator

import httpx

API = "https://api.github.com"


class GitHubError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(f"HTTP {status}: {message}")
        self.status = status


class GitHubClient:
    """Read-only REST client with Link-header pagination and rate-limit backoff."""

    def __init__(
        self,
        token: str,
        base_url: str = API,
        http: httpx.Client | None = None,
        sleep: Callable[[float], None] = time.sleep,
        max_retries: int = 3,
        max_wait: float = 120.0,
    ):
        self.base = base_url.rstrip("/")
        self.http = http or httpx.Client(timeout=30)
        self.sleep = sleep
        self.max_retries = max_retries
        self.max_wait = max_wait
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def _wait_for(self, r: httpx.Response) -> float | None:
        if r.status_code not in (403, 429):
            return None
        if "retry-after" in r.headers:
            return float(r.headers["retry-after"])
        if r.headers.get("x-ratelimit-remaining") == "0":
            reset = float(r.headers.get("x-ratelimit-reset", "0"))
            return max(reset - time.time(), 1)
        return None

    def request(self, path_or_url: str, params: dict | None = None) -> httpx.Response:
        url = path_or_url if path_or_url.startswith("http") else f"{self.base}{path_or_url}"
        for attempt in range(self.max_retries + 1):
            r = self.http.get(url, headers=self.headers, params=params)
            wait = self._wait_for(r)
            if wait is not None and attempt < self.max_retries:
                self.sleep(min(wait, self.max_wait))
                continue
            return r
        raise GitHubError(0, "unreachable")

    def get(
        self, path: str, params: dict | None = None, allow: tuple[int, ...] = ()
    ) -> httpx.Response:
        r = self.request(path, params)
        if r.status_code >= 400 and r.status_code not in allow:
            raise GitHubError(r.status_code, r.text[:200])
        return r

    def paginate(
        self, path: str, params: dict | None = None, key: str | None = None
    ) -> Iterator[dict]:
        url: str | None = path
        p = {"per_page": 100, **(params or {})}
        while url:
            r = self.get(url, p)
            data = r.json()
            yield from (data[key] if key else data)
            m = re.search(r'<([^>]+)>;\s*rel="next"', r.headers.get("link", ""))
            url, p = (m.group(1) if m else None), None
