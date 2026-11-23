"""Serve GitHub REST responses from a routes.json file. Used by tests and the offline demo mode."""

import json
from pathlib import Path

import httpx


def fixture_transport(routes_file: str | Path) -> httpx.MockTransport:
    routes: dict = json.loads(Path(routes_file).read_text())

    def handler(request: httpx.Request) -> httpx.Response:
        key = request.url.path
        flt = request.url.params.get("filter")
        keyed = f"{key}?filter={flt}" if flt else key
        value = routes.get(keyed)
        if value is None:
            return httpx.Response(404, json={"message": "Not Found"})
        if isinstance(value, dict) and "__status" in value:
            return httpx.Response(value["__status"], json={"message": value.get("message", "")})
        return httpx.Response(200, json=value)

    return httpx.MockTransport(handler)
