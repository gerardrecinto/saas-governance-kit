"""Small SCIM filter engine: eq, ne, co, sw, pr joined with 'and' (RFC 7644 3.4.2.2 subset)."""

import re
from typing import Any

from .errors import ScimError

_CLAUSE = re.compile(
    r'^\s*(?P<attr>[\w.:$-]+)\s+(?P<op>eq|ne|co|sw|pr)(?:\s+(?P<val>"(?:[^"\\]|\\.)*"|true|false|null|-?\d+(?:\.\d+)?))?\s*$',
    re.IGNORECASE,
)


def _split_and(expr: str) -> list[str]:
    parts, buf, in_q, esc = [], [], False, False
    tokens = expr
    i = 0
    while i < len(tokens):
        ch = tokens[i]
        if in_q:
            buf.append(ch)
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_q = False
        elif ch == '"':
            in_q = True
            buf.append(ch)
        elif tokens[i : i + 5].lower() == " and " and not in_q:
            parts.append("".join(buf))
            buf = []
            i += 5
            continue
        else:
            buf.append(ch)
        i += 1
    parts.append("".join(buf))
    return parts


def _literal(raw: str) -> Any:
    low = raw.lower()
    if low == "true":
        return True
    if low == "false":
        return False
    if low == "null":
        return None
    if raw.startswith('"'):
        return raw[1:-1].replace('\\"', '"').replace("\\\\", "\\")
    return float(raw) if "." in raw else int(raw)


def resolve(resource: Any, path: str) -> list[Any]:
    """Return all values at a dotted path, flattening multi-valued attributes."""
    current = [resource]
    for part in path.split("."):
        nxt: list[Any] = []
        for item in current:
            if isinstance(item, list):
                for sub in item:
                    if isinstance(sub, dict):
                        found = _get_ci(sub, part)
                        if found is not None:
                            nxt.extend(found if isinstance(found, list) else [found])
            elif isinstance(item, dict):
                found = _get_ci(item, part)
                if found is not None:
                    nxt.extend(found if isinstance(found, list) else [found])
        current = nxt
    return current


def _get_ci(d: dict, key: str) -> Any:
    if key in d:
        return d[key]
    lk = key.lower()
    for k, v in d.items():
        if k.lower() == lk:
            return v
    return None


def _match(values: list[Any], op: str, expected: Any) -> bool:
    if op == "pr":
        return any(v not in (None, "", []) for v in values)
    if not values:
        return op == "ne"
    if op == "eq":
        return any(_eq(v, expected) for v in values)
    if op == "ne":
        return not any(_eq(v, expected) for v in values)
    text = str(expected).lower()
    if op == "co":
        return any(text in str(v).lower() for v in values)
    if op == "sw":
        return any(str(v).lower().startswith(text) for v in values)
    return False


def _eq(actual: Any, expected: Any) -> bool:
    if isinstance(actual, str) and isinstance(expected, str):
        return actual.lower() == expected.lower()
    return actual == expected


def compile_filter(expr: str | None):
    """Return a predicate for the filter expression; None means match everything."""
    if not expr or not expr.strip():
        return lambda _r: True
    clauses = []
    for chunk in _split_and(expr):
        m = _CLAUSE.match(chunk)
        if not m:
            raise ScimError(400, f"Unsupported or invalid filter: {chunk.strip()}", "invalidFilter")
        op = m["op"].lower()
        if op != "pr" and m["val"] is None:
            raise ScimError(400, f"Filter operator {op} needs a value", "invalidFilter")
        val = _literal(m["val"]) if m["val"] is not None else None
        clauses.append((m["attr"], op, val))

    def predicate(resource: dict) -> bool:
        return all(_match(resolve(resource, a), op, v) for a, op, v in clauses)

    return predicate
