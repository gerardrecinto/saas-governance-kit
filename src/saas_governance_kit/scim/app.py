import hmac
from typing import Any

from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response

from .errors import ScimError
from .filters import compile_filter
from .patch import apply_operations
from .schemas import (
    GROUP_SCHEMA,
    LIST_SCHEMA,
    PATCH_SCHEMA,
    RESOURCE_TYPES,
    SCHEMAS,
    SERVICE_PROVIDER_CONFIG,
    USER_SCHEMA,
)
from .store import ScimStore

MEDIA = "application/scim+json"
MAX_COUNT = 200
IMMUTABLE = ("id", "meta")


def _resp(body: Any, status: int = 200) -> JSONResponse:
    return JSONResponse(body, status_code=status, media_type=MEDIA)


def create_app(store: ScimStore, token: str, base_path: str = "/scim/v2") -> FastAPI:
    if not token:
        raise ValueError("A non-empty bearer token is required")
    app = FastAPI(title="SCIM 2.0 server", docs_url=None, redoc_url=None, openapi_url=None)
    expected = token.encode()

    async def require_auth(request: Request) -> None:
        header = request.headers.get("authorization", "")
        scheme, _, supplied = header.partition(" ")
        ok = scheme.lower() == "bearer" and hmac.compare_digest(supplied.strip().encode(), expected)
        if not ok:
            raise ScimError(401, "Invalid or missing bearer token")

    @app.exception_handler(ScimError)
    async def scim_error_handler(_r: Request, exc: ScimError):
        headers = {"WWW-Authenticate": "Bearer"} if exc.status == 401 else None
        return JSONResponse(exc.body(), status_code=exc.status, media_type=MEDIA, headers=headers)

    @app.exception_handler(RequestValidationError)
    async def validation_handler(_r: Request, exc: RequestValidationError):
        return _resp(ScimError(400, "Invalid request", "invalidValue").body(), 400)

    async def body_json(request: Request) -> dict:
        try:
            data = await request.json()
        except ValueError:
            raise ScimError(400, "Body is not valid JSON", "invalidSyntax") from None
        if not isinstance(data, dict):
            raise ScimError(400, "Body must be a JSON object", "invalidSyntax")
        return data

    def with_location(kind: str, doc: dict, request: Request) -> dict:
        doc["meta"]["location"] = (
            f"{str(request.base_url).rstrip('/')}{base_path}/{kind}/{doc['id']}"
        )
        return doc

    def validate(kind: str, data: dict) -> dict:
        schema = USER_SCHEMA if kind == "Users" else GROUP_SCHEMA
        if schema not in data.get("schemas", []):
            raise ScimError(400, f"schemas must include {schema}", "invalidSyntax")
        key = "userName" if kind == "Users" else "displayName"
        if not isinstance(data.get(key), str) or not data[key].strip():
            raise ScimError(400, f"{key} is required", "invalidValue")
        for field in IMMUTABLE:
            data.pop(field, None)
        if kind == "Groups":
            check_members(data.get("members", []))
        return data

    def check_members(members: list[dict]) -> None:
        for m in members:
            try:
                store.get("Users", m.get("value", ""))
            except ScimError:
                raise ScimError(
                    400, f"Member {m.get('value')} is not a known user", "invalidValue"
                ) from None

    def register(kind: str) -> None:
        prefix = f"{base_path}/{kind}"

        @app.post(prefix, status_code=201, dependencies=[Depends(require_auth)])
        async def create(request: Request):
            doc = store.create(kind, validate(kind, await body_json(request)))
            return _resp(with_location(kind, doc, request), 201)

        @app.get(prefix, dependencies=[Depends(require_auth)])
        async def list_(request: Request):
            q = request.query_params
            try:
                start = max(int(q.get("startIndex", 1)), 1)
                count = min(max(int(q.get("count", 100)), 0), MAX_COUNT)
            except ValueError:
                raise ScimError(
                    400, "startIndex and count must be integers", "invalidValue"
                ) from None
            pred = compile_filter(q.get("filter"))
            matched = [d for d in store.all(kind) if pred(d)]
            page = matched[start - 1 : start - 1 + count]
            return _resp(
                {
                    "schemas": [LIST_SCHEMA],
                    "totalResults": len(matched),
                    "startIndex": start,
                    "itemsPerPage": len(page),
                    "Resources": [with_location(kind, d, request) for d in page],
                }
            )

        @app.get(prefix + "/{rid}", dependencies=[Depends(require_auth)])
        async def read(rid: str, request: Request):
            return _resp(with_location(kind, store.get(kind, rid), request))

        @app.put(prefix + "/{rid}", dependencies=[Depends(require_auth)])
        async def replace(rid: str, request: Request):
            doc = store.replace(kind, rid, validate(kind, await body_json(request)))
            return _resp(with_location(kind, doc, request))

        @app.patch(prefix + "/{rid}", dependencies=[Depends(require_auth)])
        async def patch(rid: str, request: Request):
            data = await body_json(request)
            if PATCH_SCHEMA not in data.get("schemas", []):
                raise ScimError(400, f"schemas must include {PATCH_SCHEMA}", "invalidSyntax")
            ops = data.get("Operations")
            if not isinstance(ops, list) or not ops:
                raise ScimError(400, "Operations must be a non-empty list", "invalidSyntax")
            current = store.get(kind, rid)
            updated = apply_operations(current, ops)
            for field in IMMUTABLE:
                updated[field] = current[field]
            if kind == "Groups":
                check_members(updated.get("members", []))
            return _resp(with_location(kind, store.save_patched(kind, rid, updated), request))

        @app.delete(prefix + "/{rid}", status_code=204, dependencies=[Depends(require_auth)])
        async def delete(rid: str):
            store.delete(kind, rid)
            return Response(status_code=204)

    register("Users")
    register("Groups")

    @app.get(f"{base_path}/ServiceProviderConfig", dependencies=[Depends(require_auth)])
    async def spc():
        return _resp(SERVICE_PROVIDER_CONFIG)

    @app.get(f"{base_path}/Schemas", dependencies=[Depends(require_auth)])
    async def schemas():
        return _resp({"schemas": [LIST_SCHEMA], "totalResults": len(SCHEMAS), "Resources": SCHEMAS})

    @app.get(f"{base_path}/ResourceTypes", dependencies=[Depends(require_auth)])
    async def resource_types():
        return _resp(
            {
                "schemas": [LIST_SCHEMA],
                "totalResults": len(RESOURCE_TYPES),
                "Resources": RESOURCE_TYPES,
            }
        )

    return app
