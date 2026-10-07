"""Append-only аудит-лог в JSONL с хеш-цепочкой (sha256).

Каждая запись содержит хеш предыдущей, поэтому удаление или правка
записи в середине файла обнаруживается командой `python audit.py verify`.
"""

import hashlib
import json
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

GENESIS = "0" * 64


def _digest(obj: dict) -> str:
    body = json.dumps(obj, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self, path: str, engagement_id: str):
        self.path = Path(path).expanduser()
        self.engagement_id = engagement_id
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._prev = self._last_hash()
        if not self.path.exists():
            self.path.touch(mode=0o600)

    def _last_hash(self) -> str:
        if not self.path.exists():
            return GENESIS
        last = None
        with self.path.open(encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    last = line
        return json.loads(last)["hash"] if last else GENESIS

    def record(self, tool: str, decision: str, args: dict, summary=None, error=None) -> None:
        """decision: 'allow' | 'deny' | 'error'."""
        with self._lock:
            entry = {
                "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "engagement_id": self.engagement_id,
                "tool": tool,
                "decision": decision,
                "args": args,
                "summary": summary,
                "error": error,
                "prev": self._prev,
            }
            entry["hash"] = _digest(entry)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
            self._prev = entry["hash"]


def verify(path: str) -> tuple[bool, str]:
    """Проверяет целостность цепочки. Возвращает (ok, сообщение)."""
    prev = GENESIS
    count = 0
    with Path(path).expanduser().open(encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            if not line.strip():
                continue
            obj = json.loads(line)
            stored = obj.pop("hash", None)
            if obj.get("prev") != prev:
                return False, f"line {lineno}: broken chain (prev mismatch)"
            if _digest(obj) != stored:
                return False, f"line {lineno}: record was modified"
            prev = stored
            count += 1
    return True, f"ok, {count} records"


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "verify":
        ok, msg = verify(sys.argv[2])
        print(msg)
        sys.exit(0 if ok else 1)
    print("usage: python audit.py verify <audit.jsonl>")
    sys.exit(2)
