"""RFC 7644 3.5.2 PATCH: add, replace, remove with attribute, sub-attribute and value-filter paths."""

import copy
import re
from typing import Any

from .errors import ScimError
from .filters import compile_filter

_PATH = re.compile(r"^(?P<attr>[\w:.$-]+?)(?:\[(?P<flt>[^\]]+)\])?(?:\.(?P<sub>\w+))?$")


def _key(doc: dict, name: str) -> str:
    for k in doc:
        if k.lower() == name.lower():
            return k
    return name


def _parse(path: str):
    # Schema-qualified paths like urn:...:User:active keep the final segment as the attribute.
    m = _PATH.match(path)
    if not m:
        raise ScimError(400, f"Invalid path: {path}", "invalidPath")
    attr = m["attr"]
    if attr.startswith("urn:") and ":" in attr:
        attr = attr.rsplit(":", 1)[1]
    return attr, m["flt"], m["sub"]


def _merge_value(doc: dict, attr: str, value: Any, op: str) -> None:
    key = _key(doc, attr)
    existing = doc.get(key)
    if isinstance(value, list):
        if op == "replace" or existing is None:
            doc[key] = copy.deepcopy(value)
        else:
            have = {repr(sorted(x.items())) if isinstance(x, dict) else repr(x) for x in existing}
            for item in value:
                tag = repr(sorted(item.items())) if isinstance(item, dict) else repr(item)
                if tag not in have:
                    existing.append(copy.deepcopy(item))
    elif isinstance(value, dict) and isinstance(existing, dict) and op == "add":
        existing.update(value)
    else:
        doc[key] = copy.deepcopy(value)


def _set_dotted(doc: dict, dotted: str, value: Any) -> None:
    parts = dotted.split(".")
    cur = doc
    for p in parts[:-1]:
        cur = cur.setdefault(_key(cur, p), {})
    cur[_key(cur, parts[-1])] = value


def apply_operations(doc: dict, operations: list[dict]) -> dict:
    doc = copy.deepcopy(doc)
    for raw in operations:
        op = str(raw.get("op", "")).lower()
        if op not in ("add", "replace", "remove"):
            raise ScimError(400, f"Unsupported op: {raw.get('op')}", "invalidSyntax")
        path = raw.get("path")
        value = raw.get("value")
        if not path:
            if op == "remove":
                raise ScimError(400, "remove requires a path", "noTarget")
            if not isinstance(value, dict):
                raise ScimError(400, "Pathless operation needs an object value", "invalidValue")
            for k, v in value.items():
                if "." in k and not k.startswith("urn:"):
                    _set_dotted(doc, k, v)
                else:
                    _merge_value(doc, k.rsplit(":", 1)[-1] if k.startswith("urn:") else k, v, op)
            continue
        attr, flt, sub = _parse(path)
        key = _key(doc, attr)
        if flt:
            items = doc.get(key)
            if not isinstance(items, list):
                raise ScimError(400, f"No target at {path}", "noTarget")
            pred = compile_filter(flt)
            matched = [i for i in items if pred(i)]
            if op == "remove":
                if sub:
                    for i in matched:
                        i.pop(_key(i, sub), None)
                else:
                    doc[key] = [i for i in items if not pred(i)]
            else:
                if not matched:
                    raise ScimError(400, f"No target at {path}", "noTarget")
                for i in matched:
                    if sub:
                        i[_key(i, sub)] = copy.deepcopy(value)
                    elif isinstance(value, dict):
                        i.update(value)
            continue
        if sub:
            parent = doc.get(key)
            if op == "remove":
                if isinstance(parent, dict):
                    parent.pop(_key(parent, sub), None)
                elif isinstance(parent, list):
                    for i in parent:
                        i.pop(_key(i, sub), None)
            elif isinstance(parent, list):
                for i in parent:
                    i[_key(i, sub)] = copy.deepcopy(value)
            else:
                _set_dotted(doc, f"{attr}.{sub}", copy.deepcopy(value))
            continue
        if op == "remove":
            if key == "members" and isinstance(value, list):
                gone = {m.get("value") for m in value}
                doc[key] = [m for m in doc.get(key, []) if m.get("value") not in gone]
            else:
                doc.pop(key, None)
        else:
            _merge_value(doc, attr, value, op)
    return doc
