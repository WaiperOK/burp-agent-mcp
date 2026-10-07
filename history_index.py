"""Incremental index of Burp Proxy history: one compact entry per record, no bodies.

Burp keeps Proxy history append-only, and a history_id is a record's offset in it. So after the first build,
a refresh reads only the records added since the last one.

Refresh starts with the last indexed record. If it is still there and unchanged, the history only grew. If it is
gone or different, the history was cleared or replaced, and the index starts over.

The first build of a large history takes many small pages, so a refresh stops after a time budget. The next
refresh continues from the last indexed record.
"""

import asyncio
import hashlib
import time
from dataclasses import dataclass
from typing import Awaitable, Callable

import httpmsg
from httpmsg import MsgError

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
    return Entry(history_id, httpmsg.host_from_request(req) or "", method, path,
                 httpmsg.status_of(item.get("response") or ""), fingerprint(item))


class HistoryIndex:
    def __init__(self, max_records: int, page: int = 10, on_reset: Callable[[], None] | None = None):
        self.max_records = max_records  # the index covers history_ids below this value
        self.page = page
        self.entries: list[Entry] = []
        self.complete = False  # True when the last refresh reached the end of history or max_records
        self.checked_at = 0.0  # monotonic time of the last refresh that completed
        self._on_reset = on_reset  # the caller drops anything it cached by history_id, which is now stale
        self._lock = asyncio.Lock()

    def reset(self) -> None:
        self.entries.clear()
        self.complete = False
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
            self.complete = False
            offset = 0
            if self.entries:
                last = self.entries[-1]
                # the page starts at the last indexed record, so one call both checks it and reads the new ones
                page = await fetch(last.history_id, self.page)
                if page and fingerprint(page[0]) == last.fingerprint:
                    offset = self._add(last.history_id + 1, page[1:])
                else:
                    self.reset()  # cleared, replaced or shorter: index again from the start
            while offset < self.max_records:
                if time.monotonic() - started > time_budget_s:
                    return  # partial: the next refresh continues from the last indexed record
                page = await fetch(offset, self.page)
                if not page:
                    break  # end of history
                offset = self._add(offset, page)
            self.complete = True
            self.checked_at = time.monotonic()

    def _add(self, first_id: int, records: list[dict]) -> int:
        """Indexes records whose history_ids start at first_id. Returns the next history_id to read."""
        for i, item in enumerate(records):
            history_id = first_id + i
            if history_id >= self.max_records:
                return history_id
            self.entries.append(_entry(history_id, item))
        return first_id + len(records)

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
