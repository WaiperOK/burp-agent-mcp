"""Tests for the incremental Proxy history index, against a fake Burp history. Run: python tests/test_history_index.py"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from history_index import HistoryIndex  # noqa: E402


def record(i: int, method: str = "GET", host: str = "app.test") -> dict:
    return {"request": f"{method} /api/item/{i} HTTP/1.1\r\nHost: {host}\r\n\r\n",
            "response": "HTTP/1.1 200 OK\r\n\r\nbody"}


class FakeHistory:
    """Stands in for get_proxy_http_history: pages by offset and records every call."""

    def __init__(self, items):
        self.items = list(items)
        self.calls = []

    async def fetch(self, offset, count):
        self.calls.append((offset, count))
        return self.items[offset:offset + count]


class BuildTests(unittest.IsolatedAsyncioTestCase):
    async def test_first_build_indexes_every_record(self):
        burp = FakeHistory(record(i) for i in range(25))
        index = HistoryIndex(max_records=500, page=10)
        await index.refresh(burp.fetch)
        self.assertTrue(index.complete)
        self.assertEqual([e.history_id for e in index.entries], list(range(25)))
        self.assertEqual(index.entries[3].path, "/api/item/3")
        self.assertEqual(index.entries[3].host, "app.test")
        self.assertEqual(index.entries[3].status, "200")

    async def test_refresh_reads_only_records_added_since_last_time(self):
        burp = FakeHistory(record(i) for i in range(25))
        index = HistoryIndex(max_records=500, page=10)
        await index.refresh(burp.fetch)
        burp.items.extend(record(i) for i in range(25, 28))
        burp.calls.clear()
        await index.refresh(burp.fetch)
        self.assertEqual(len(index.entries), 28)
        self.assertTrue(index.complete)
        # the first call starts at the last indexed record (24); nothing older is read again
        self.assertEqual(burp.calls[0][0], 24)
        self.assertTrue(all(offset >= 24 for offset, _ in burp.calls))

    async def test_no_new_records_costs_two_calls(self):
        burp = FakeHistory(record(i) for i in range(5))
        index = HistoryIndex(max_records=500, page=10)
        await index.refresh(burp.fetch)
        burp.calls.clear()
        await index.refresh(burp.fetch)
        self.assertEqual(len(burp.calls), 2)  # the last record as a check, then an empty page
        self.assertEqual(len(index.entries), 5)

    async def test_max_age_skips_burp_while_the_index_is_fresh(self):
        burp = FakeHistory(record(i) for i in range(5))
        index = HistoryIndex(max_records=500, page=10)
        await index.refresh(burp.fetch)
        burp.items.append(record(5))
        burp.calls.clear()
        await index.refresh(burp.fetch, max_age_s=60)
        self.assertEqual(burp.calls, [])  # no call at all
        self.assertEqual(len(index.entries), 5)
        await index.refresh(burp.fetch)  # max_age_s=0 checks Burp again
        self.assertEqual(len(index.entries), 6)

    async def test_max_records_caps_the_index(self):
        burp = FakeHistory(record(i) for i in range(25))
        index = HistoryIndex(max_records=12, page=10)
        await index.refresh(burp.fetch)
        self.assertEqual(len(index.entries), 12)
        self.assertEqual(index.entries[-1].history_id, 11)
        self.assertTrue(index.complete)


class ChangeTests(unittest.IsolatedAsyncioTestCase):
    async def test_cleared_history_is_indexed_again(self):
        burp = FakeHistory(record(i) for i in range(25))
        index = HistoryIndex(max_records=500, page=10)
        await index.refresh(burp.fetch)
        burp.items = [record(i, host="other.test") for i in range(4)]  # cleared and refilled, shorter
        await index.refresh(burp.fetch)
        self.assertEqual(len(index.entries), 4)
        self.assertEqual({e.host for e in index.entries}, {"other.test"})

    async def test_reset_tells_the_owner_so_cached_records_are_dropped(self):
        resets = []
        burp = FakeHistory(record(i) for i in range(5))
        index = HistoryIndex(max_records=500, page=10, on_reset=lambda: resets.append(1))
        await index.refresh(burp.fetch)
        burp.items = [record(9)]  # shorter than before: the old tail is gone
        await index.refresh(burp.fetch)
        self.assertEqual(len(resets), 1)
        self.assertEqual([e.path for e in index.entries], ["/api/item/9"])

    async def test_replaced_last_record_triggers_rebuild(self):
        burp = FakeHistory(record(i) for i in range(10))
        index = HistoryIndex(max_records=500, page=10)
        await index.refresh(burp.fetch)
        burp.items[-1] = record(99, method="POST")  # same length, different last record
        await index.refresh(burp.fetch)
        self.assertEqual(len(index.entries), 10)
        self.assertEqual(index.entries[-1].method, "POST")

    async def test_empty_history_gives_empty_index(self):
        index = HistoryIndex(max_records=500, page=10)
        await index.refresh(FakeHistory([]).fetch)
        self.assertEqual(index.entries, [])
        self.assertTrue(index.complete)


class TimeBudgetTests(unittest.IsolatedAsyncioTestCase):
    async def test_zero_budget_stops_early_and_next_refresh_resumes(self):
        burp = FakeHistory(record(i) for i in range(25))
        index = HistoryIndex(max_records=500, page=10)
        await index.refresh(burp.fetch, time_budget_s=0)
        self.assertFalse(index.complete)
        self.assertEqual(index.entries, [])
        await index.refresh(burp.fetch)
        self.assertTrue(index.complete)
        self.assertEqual(len(index.entries), 25)


class FindTests(unittest.IsolatedAsyncioTestCase):
    async def test_find_returns_first_matches_in_history_order(self):
        items = [record(i, method="POST" if i % 3 == 0 else "GET") for i in range(12)]
        index = HistoryIndex(max_records=500, page=10)
        await index.refresh(FakeHistory(items).fetch)
        found, examined = index.find(lambda e: e.method == "POST", limit=2)
        self.assertEqual([e.history_id for e in found], [0, 3])
        self.assertEqual(examined, 4)  # stopped right after the second match

    async def test_malformed_record_is_kept_but_never_matches(self):
        items = [{"request": "garbage", "response": ""}, record(1)]
        index = HistoryIndex(max_records=500, page=10)
        await index.refresh(FakeHistory(items).fetch)
        self.assertEqual(len(index.entries), 2)
        found, _ = index.find(lambda e: e.host == "app.test", limit=10)
        self.assertEqual([e.history_id for e in found], [1])


if __name__ == "__main__":
    unittest.main()
