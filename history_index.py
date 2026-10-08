"""Incremental index of Burp Proxy history: one compact entry per record, no bodies.

Burp keeps Proxy history append-only, and a history_id is a record's offset in it. So after the first build,
a refresh reads only the records added since the last one.

Refresh starts with the last indexed record. If it is still there and unchanged, the history only grew. If it is
gone or different, the history was cleared or replaced, and the index starts over.

The first build of a large history takes many small pages, so a refresh stops after a time budget. The next
refresh continues from the last indexed record.

The index keeps the newest max_records records. A longer history loses its oldest records from the index, never its
newest ones: new traffic is always visible, and complete=True means the index reached the end of Burp's history.

The index can be saved to a file, so a restart does not rebuild it. A saved index is never trusted blindly: the
first refresh after a load checks its last record against Burp, exactly as in a running session.
"""

import asyncio
import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Awaitable, Callable

import httpmsg
from httpmsg import MsgError
from redact import mask_query

log = logging.getLogger(__name__)
STATE_VERSION = 1

# (offset, count) -> parsed records, as returned by get_proxy_http_history
PageFetch = Callable[[int, int], Awaitable[list[dict]]]


@dataclass(frozen=True)
class Entry:
    history_id: int
    host: str
    method: str
    path: str
    status: str | None
    fingerprint: str  # identifies the record, so a changed or replaced record is noticed


def fingerprint(item: dict) -> str:
    """Hash of the start of the request. Burp truncates long fields, but the start stays the same."""
    return hashlib.sha256((item.get("request") or "")[:256].encode("utf-8", "replace")).hexdigest()[:24]


def _entry(history_id: int, item: dict) -> Entry:
    req = item.get("request") or ""
    try:
        method, path = httpmsg.split_request(req)
    except MsgError:  # a malformed record stays in the index but can never match a search
        method, path = "", ""
    # secrets in the query are masked here, so neither the file nor a search result ever holds them
    return Entry(history_id, httpmsg.host_from_request(req) or "", method, mask_query(path),
                 httpmsg.status_of(item.get("response") or ""), fingerprint(item))


async def _count_records(fetch: PageFetch) -> int:
    """How many records Burp holds. Doubles a probe until it passes the end, then bisects: about 2*log2(n) reads of
    one record each, never a full scan."""
    async def has(n: int) -> bool:  # True if there are at least n records
        return bool(await fetch(n - 1, 1))

    if not await has(1):
        return 0
    low, high = 1, 2  # has(low) is True; has(high) may be False
    while await has(high):
        low, high = high, high * 2
    while high - low > 1:
        mid = (low + high) // 2
        if await has(mid):
            low = mid
        else:
            high = mid
    return low


class HistoryIndex:
    def __init__(self, max_records: int, page: int = 10, on_reset: Callable[[], None] | None = None,
                 store: Path | None = None):
        self.max_records = max_records  # the index keeps this many of the newest records
        self.page = page
        self.entries: list[Entry] = []
        self.complete = False  # True when the last refresh reached the end of Burp's history
        self.checked_at = 0.0  # monotonic time of the last refresh that completed
        self._on_reset = on_reset  # the caller drops anything it cached by history_id, which is now stale
        self._store = store  # file where the index is kept between runs; None keeps it in memory only
        self._dirty = False  # True when the entries differ from the saved file
        self._lock = asyncio.Lock()

    def reset(self) -> None:
        self.entries.clear()
        self.complete = False
        self._dirty = True
        if self._on_reset is not None:
            self._on_reset()

    async def refresh(self, fetch: PageFetch, time_budget_s: float = 20.0, max_age_s: float = 0.0) -> None:
        """Indexes the records that are new since the last call. Stops early once time_budget_s is spent.

        If the index was complete less than max_age_s seconds ago, nothing is read from Burp at all.
        """
        async with self._lock:
            started = time.monotonic()
            if self.complete and started - self.checked_at < max_age_s:
                return
            try:
                await self._read_new(fetch, started, time_budget_s)
            finally:  # progress is kept even if Burp failed halfway: the entries stay in order
                self._save_if_dirty()

    async def _read_new(self, fetch: PageFetch, started: float, time_budget_s: float) -> None:
        self.complete = False
        next_id = None  # None: the window of newest records has to be located first
        if self.entries:
            last = self.entries[-1]
            # the page starts at the last indexed record, so one call both checks it and reads the new ones
            page = await fetch(last.history_id, self.page)
            if page and fingerprint(page[0]) == last.fingerprint:
                next_id = self._add(last.history_id + 1, page[1:])
            else:
                self.reset()  # cleared, replaced or shorter: index again from the newest records
        if next_id is None:
            next_id = max(0, await _count_records(fetch) - self.max_records)
        while True:
            if time.monotonic() - started >= time_budget_s:  # >= so that a zero budget always stops
                self._trim()
                return  # partial: the next refresh continues from the last indexed record
            page = await fetch(next_id, self.page)
            if not page:
                break  # end of history
            next_id = self._add(next_id, page)
        self._trim()
        self.complete = True
        self.checked_at = time.monotonic()

    def _add(self, first_id: int, records: list[dict]) -> int:
        """Indexes records whose history_ids start at first_id. Returns the next history_id to read."""
        for i, item in enumerate(records):
            self.entries.append(_entry(first_id + i, item))
            self._dirty = True
        return first_id + len(records)

    def _trim(self) -> None:
        """Drops the oldest records once the index holds more than max_records."""
        excess = len(self.entries) - self.max_records
        if excess > 0:
            del self.entries[:excess]
            self._dirty = True

    def find(self, predicate: Callable[[Entry], bool], limit: int) -> tuple[list[Entry], int]:
        """The first `limit` matching entries in history order, and how many entries were examined."""
        found, examined = [], 0
        for entry in self.entries:
            examined += 1
            if predicate(entry):
                found.append(entry)
                if len(found) >= limit:
                    break
        return found, examined

    def load(self) -> bool:
        """Starts from the index saved by an earlier run. Returns False and stays empty if there is no usable file.

        The loaded entries are not verified yet, so complete stays False: the next refresh checks them against Burp.
        """
        if self._store is None or not self._store.is_file():
            return False
        try:
            data = json.loads(self._store.read_text(encoding="utf-8"))
            if data.get("version") != STATE_VERSION:
                raise ValueError("unknown state version")
            # paths are masked again on load: a file written by an older version may hold raw secrets
            entries = [Entry(int(hid), str(host), str(method), mask_query(str(path)),
                             None if status is None else str(status), str(fp))
                       for hid, host, method, path, status, fp in data["entries"]]
        except (OSError, ValueError, TypeError, KeyError, AttributeError) as ex:
            log.warning("history index file ignored: %s", ex)
            return False
        if entries and any(e.history_id != entries[0].history_id + i for i, e in enumerate(entries)):
            log.warning("history index file ignored: record ids are not consecutive")
            return False
        self.entries = entries[max(0, len(entries) - self.max_records):]  # keep the newest records
        self.complete = False
        self._dirty = False
        return True

    def _save_if_dirty(self) -> None:
        """Writes the index to its file, readable only by the owner. A failed write is logged, never raised:
        a search must not fail because the file cannot be written."""
        if self._store is None or not self._dirty:
            return
        data = {"version": STATE_VERSION,
                "entries": [[e.history_id, e.host, e.method, e.path, e.status, e.fingerprint] for e in self.entries]}
        tmp = self._store.with_name(self._store.name + ".tmp")
        try:
            self._store.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(data, fh)
            os.replace(tmp, self._store)  # the file is either the old version or the new one, never half-written
        except OSError as ex:
            log.warning("history index not saved: %s", ex)
            return
        self._dirty = False
