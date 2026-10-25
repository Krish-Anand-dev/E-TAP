"""
db.fake_mongo -- an in-memory stand-in for a pymongo Database/Collection.

This exists so that db.repository / correlation.engine can be run and
tested *today*, without a MongoDB server, by setting USE_FAKE_DB=1. It
implements only the operations those two modules actually use:

    Collection.insert_one(doc)
    Collection.find_one(filter)
    Collection.find(filter)          -> FakeCursor (.sort().limit())
    Collection.update_one(filter, update, upsert=False)
    Collection.find_one_and_update(filter, update, upsert=False,
                                    return_document=AFTER)
    Collection.count_documents(filter)
    Collection.distinct(field)
    Collection.create_index(...)     -> no-op

Query operators supported: exact match, $in, $gte, $lte.
Update operators supported: $set, $inc, $addToSet (with or without
$each), $pull.
Dotted field paths (e.g. "ioc_analysis.domains") are supported for both
querying and distinct(), including reaching into arrays (Mongo's usual
multikey behavior).

This is intentionally NOT a general pymongo replacement. It is not
persistent (everything lives in a process-local dict), does not enforce
unique indexes, and is not concurrency-safe. Once a real MongoDB
instance is available, just don't set USE_FAKE_DB and this module is
never imported.
"""

from __future__ import annotations

import itertools
from typing import Any, Optional


class ReturnDocument:
    BEFORE = "before"
    AFTER = "after"


def _get_path(doc: dict, path: str) -> Any:
    """Fetch a (possibly dotted) field path from a document. Returns a
    list of matches when the path passes through an array (mirroring
    Mongo's multikey field semantics), or a single value/None otherwise."""
    parts = path.split(".")
    current: Any = doc

    for i, part in enumerate(parts):
        if isinstance(current, list):
            remaining = ".".join(parts[i:])
            results = []
            for item in current:
                if isinstance(item, dict):
                    val = _get_path(item, remaining)
                    if isinstance(val, list):
                        results.extend(val)
                    elif val is not None:
                        results.append(val)
            return results
        if isinstance(current, dict):
            current = current.get(part)
        else:
            return None

    return current


def _set_path(doc: dict, path: str, value: Any) -> None:
    parts = path.split(".")
    current = doc
    for part in parts[:-1]:
        current = current.setdefault(part, {})
    current[parts[-1]] = value


def _matches(doc: dict, filt: dict) -> bool:
    for key, condition in (filt or {}).items():
        value = _get_path(doc, key)

        if isinstance(condition, dict) and any(
            op.startswith("$") for op in condition.keys()
        ):
            for op, operand in condition.items():
                if op == "$in":
                    candidates = value if isinstance(value, list) else [value]
                    if not any(v in operand for v in candidates):
                        return False
                elif op == "$gte":
                    if value is None or value < operand:
                        return False
                elif op == "$lte":
                    if value is None or value > operand:
                        return False
                elif op == "$ne":
                    if value == operand:
                        return False
                else:
                    raise NotImplementedError(f"FakeDatabase: unsupported operator {op}")
        else:
            candidates = value if isinstance(value, list) else [value]
            if condition not in candidates and value != condition:
                return False

    return True


def _apply_update(doc: dict, update: dict) -> None:
    for op, changes in update.items():
        if op == "$set":
            for path, value in changes.items():
                _set_path(doc, path, value)
        elif op == "$inc":
            for path, amount in changes.items():
                current = _get_path(doc, path) or 0
                _set_path(doc, path, current + amount)
        elif op == "$addToSet":
            for path, spec in changes.items():
                parts = path.split(".")
                container = doc
                for part in parts[:-1]:
                    container = container.setdefault(part, {})
                existing = container.setdefault(parts[-1], [])
                if isinstance(spec, dict) and "$each" in spec:
                    new_values = spec["$each"]
                else:
                    new_values = [spec]
                for v in new_values:
                    if v not in existing:
                        existing.append(v)
        elif op == "$pull":
            for path, value in changes.items():
                parts = path.split(".")
                container = doc
                for part in parts[:-1]:
                    container = container.get(part, {})
                existing = container.get(parts[-1], [])
                if isinstance(existing, list):
                    container[parts[-1]] = [v for v in existing if v != value]
        elif op == "$push":
            for path, spec in changes.items():
                parts = path.split(".")
                container = doc
                for part in parts[:-1]:
                    container = container.setdefault(part, {})
                existing = container.setdefault(parts[-1], [])
                if isinstance(spec, dict) and "$each" in spec:
                    existing.extend(spec["$each"])
                else:
                    existing.append(spec)
        else:
            raise NotImplementedError(f"FakeDatabase: unsupported update operator {op}")


class _FakeObjectId:
    """A minimal stand-in for bson.ObjectId -- just needs to be unique
    and str()-able; nothing in this codebase inspects it further."""

    _counter = itertools.count(1)

    def __init__(self) -> None:
        self._value = f"{next(_FakeObjectId._counter):024x}"

    def __str__(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return f"FakeObjectId('{self._value}')"

    def __eq__(self, other) -> bool:
        return str(self) == str(other)

    def __hash__(self) -> int:
        return hash(self._value)


class FakeCursor:
    def __init__(self, docs: list[dict]) -> None:
        self._docs = docs

    def sort(self, field: str, direction: int = 1) -> "FakeCursor":
        self._docs = sorted(
            self._docs,
            key=lambda d: (_get_path(d, field) is None, _get_path(d, field)),
            reverse=(direction == -1),
        )
        return self

    def limit(self, n: int) -> "FakeCursor":
        self._docs = self._docs[:n]
        return self

    def __iter__(self):
        return iter(self._docs)

    def __list__(self):
        return list(self._docs)


class FakeCollection:
    def __init__(self, name: str) -> None:
        self.name = name
        self._docs: dict[str, dict] = {}

    # -- writes -----------------------------------------------------
    def insert_one(self, doc: dict):
        doc = dict(doc)
        if "_id" not in doc:
            doc["_id"] = _FakeObjectId()
        self._docs[str(doc["_id"])] = doc

        class _Result:
            inserted_id = doc["_id"]

        return _Result()

    def update_one(self, filt: dict, update: dict, upsert: bool = False):
        for doc in self._docs.values():
            if _matches(doc, filt):
                _apply_update(doc, update)
                return
        if upsert:
            new_doc: dict = {}
            for key, value in filt.items():
                if not key.startswith("$"):
                    new_doc[key] = value
            _apply_update(new_doc, update)
            self.insert_one(new_doc)

    def find_one_and_update(
        self,
        filt: dict,
        update: dict,
        upsert: bool = False,
        return_document: str = ReturnDocument.BEFORE,
    ) -> Optional[dict]:
        for doc in self._docs.values():
            if _matches(doc, filt):
                before = dict(doc)
                _apply_update(doc, update)
                return dict(doc) if return_document == ReturnDocument.AFTER else before

        if upsert:
            new_doc: dict = {}
            for key, value in filt.items():
                if not key.startswith("$"):
                    new_doc[key] = value
            _apply_update(new_doc, update)
            result = self.insert_one(new_doc)
            new_doc["_id"] = result.inserted_id
            return new_doc if return_document == ReturnDocument.AFTER else None

        return None

    def delete_many(self, filt):
        from types import SimpleNamespace
        keys = [key for key, doc in self._docs.items() if _matches(doc, filt)]
        for key in keys:
            del self._docs[key]
        return SimpleNamespace(deleted_count=len(keys))

    # -- reads --------------------------------------------------------
    @staticmethod
    def _project(doc: dict, projection: Optional[dict]) -> dict:
        """Apply the common PyMongo inclusion/exclusion projection forms."""
        if not projection:
            return dict(doc)
        included = [k for k, enabled in projection.items() if enabled and k != "_id"]
        excluded = [k for k, enabled in projection.items() if not enabled]
        if included:
            result = {k: _get_path(doc, k) for k in included if _get_path(doc, k) is not None}
            if projection.get("_id", 1) and "_id" in doc:
                result["_id"] = doc["_id"]
            return result
        result = dict(doc)
        for key in excluded:
            result.pop(key, None)
        return result

    def find_one(self, filt: Optional[dict] = None, projection: Optional[dict] = None) -> Optional[dict]:
        for doc in self._docs.values():
            if _matches(doc, filt or {}):
                return self._project(doc, projection)
        return None

    def find(self, filt: Optional[dict] = None, projection: Optional[dict] = None) -> FakeCursor:
        matches = [self._project(doc, projection) for doc in self._docs.values() if _matches(doc, filt or {})]
        return FakeCursor(matches)

    def count_documents(self, filt: Optional[dict] = None) -> int:
        return sum(1 for doc in self._docs.values() if _matches(doc, filt or {}))

    def distinct(self, field: str) -> list:
        values: list = []
        seen = set()
        for doc in self._docs.values():
            result = _get_path(doc, field)
            candidates = result if isinstance(result, list) else [result]
            for v in candidates:
                if v is None or v in seen:
                    continue
                seen.add(v)
                values.append(v)
        return values

    # -- setup no-ops --------------------------------------------------
    def create_index(self, *args, **kwargs) -> None:
        return None


class FakeDatabase:
    def __init__(self) -> None:
        self.name = 'etap-memory'
        self._collections: dict[str, FakeCollection] = {}

    def __getitem__(self, name: str) -> FakeCollection:
        if name not in self._collections:
            self._collections[name] = FakeCollection(name)
        return self._collections[name]
