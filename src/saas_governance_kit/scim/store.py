import copy
import json
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path

from .errors import ScimError

KINDS = ("Users", "Groups")


def now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class ScimStore:
    """In-memory store with optional JSON file persistence."""

    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else None
        self._lock = threading.RLock()
        self._data: dict[str, dict[str, dict]] = {k: {} for k in KINDS}
        if self.path and self.path.exists():
            loaded = json.loads(self.path.read_text())
            for kind in KINDS:
                self._data[kind] = loaded.get(kind, {})

    def _save(self) -> None:
        if self.path:
            tmp = self.path.with_suffix(self.path.suffix + ".tmp")
            tmp.write_text(json.dumps(self._data, indent=2, sort_keys=True))
            tmp.replace(self.path)

    def _check_unique(self, kind: str, resource: dict, exclude_id: str | None = None) -> None:
        key = "userName" if kind == "Users" else "displayName"
        value = str(resource.get(key, "")).lower()
        for rid, other in self._data[kind].items():
            if rid != exclude_id and str(other.get(key, "")).lower() == value:
                raise ScimError(409, f"{key} '{resource.get(key)}' already exists", "uniqueness")

    def create(self, kind: str, resource: dict) -> dict:
        with self._lock:
            self._check_unique(kind, resource)
            rid = uuid.uuid4().hex
            stamp = now_iso()
            doc = copy.deepcopy(resource)
            doc["id"] = rid
            if kind == "Users":
                doc.setdefault("active", True)
            doc["meta"] = {
                "resourceType": kind[:-1],
                "created": stamp,
                "lastModified": stamp,
            }
            self._data[kind][rid] = doc
            self._save()
            return copy.deepcopy(doc)

    def get(self, kind: str, rid: str) -> dict:
        with self._lock:
            if rid not in self._data[kind]:
                raise ScimError(404, f"{kind[:-1]} {rid} not found")
            return copy.deepcopy(self._data[kind][rid])

    def replace(self, kind: str, rid: str, resource: dict) -> dict:
        with self._lock:
            old = self.get(kind, rid)
            self._check_unique(kind, resource, exclude_id=rid)
            doc = copy.deepcopy(resource)
            doc["id"] = rid
            if kind == "Users":
                doc.setdefault("active", True)
            doc["meta"] = {**old["meta"], "lastModified": now_iso()}
            self._data[kind][rid] = doc
            self._save()
            return copy.deepcopy(doc)

    def save_patched(self, kind: str, rid: str, doc: dict) -> dict:
        with self._lock:
            self._check_unique(kind, doc, exclude_id=rid)
            doc["meta"]["lastModified"] = now_iso()
            self._data[kind][rid] = doc
            self._save()
            return copy.deepcopy(doc)

    def delete(self, kind: str, rid: str) -> None:
        with self._lock:
            self.get(kind, rid)
            del self._data[kind][rid]
            if kind == "Users":
                for group in self._data["Groups"].values():
                    group["members"] = [
                        m for m in group.get("members", []) if m.get("value") != rid
                    ]
            self._save()

    def all(self, kind: str) -> list[dict]:
        with self._lock:
            return [copy.deepcopy(v) for v in self._data[kind].values()]
