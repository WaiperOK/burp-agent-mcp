"""Policy: scope (hosts and URLs), environment, mode and limits. Fail-closed: if the config is invalid, the server does not start."""

import hashlib
import json
import re
import threading
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

MODES = ("read_only", "active")
# Active actions are allowed only in test environments. The policy owner sets this.
ENVIRONMENTS = ("test", "stage", "staging", "lab")
_HOST_RE = re.compile(r"^[a-z0-9.-]{1,253}$")
_DEFAULT_PORT = {"http": 80, "https": 443}


class PolicyError(Exception):
    pass


class RateLimitError(PolicyError):
    """Rate limit: the caller may wait for the window and retry (unlike other refusals)."""


def _norm_path(path: str) -> str | None:
    """Path without dot segments or encoded dots. None means the path is suspicious (directory traversal)."""
    if "%2e" in path.lower() or "%2f" in path.lower() or "%5c" in path.lower():
        return None
    segments = []
    for seg in path.split("/"):
        if seg in ("..", "."):
            return None  # do not normalise silently: such a path is refused entirely
        segments.append(seg)
    return "/".join(segments) or "/"


def _prefix_matches(path: str, prefix: str) -> bool:
    if prefix in ("", "/"):
        return True
    if prefix.endswith("/"):
        return path.startswith(prefix) or path == prefix.rstrip("/")
    return path == prefix or path.startswith(prefix + "/")


@dataclass(frozen=True)
class Policy:
    engagement_id: str
    mode: str
    authorized_hosts: tuple
    allowed_methods: tuple
    max_requests_per_minute: int
    max_active_requests_total: int
    audit_log: str
    universal_output_dir: str
    upstream_sse_url: str
    max_response_chars: int = 20000
    # Environment: active actions are allowed only for test/stage/staging/lab.
    environment: str = ""
    # Scope by URL: https://host/prefix. Empty means the whole host from authorized_hosts.
    scope_urls: tuple = ()
    # Empty allowed_paths means replays (replay_variant, intruder, repeater) are refused entirely.
    allowed_paths: tuple = ()
    # OpenAPI specification files used by openapi_coverage and scan (matched by basename).
    openapi_files: tuple = ()
    # File where the Burp extension writes passive findings (JSON lines).
    findings_file: str = "~/burp_agent_findings/findings.jsonl"
    # Burp proxy for the browser; None means the browser connects directly (local tests only).
    browser_proxy: str | None = "http://127.0.0.1:8080"
    browser_profile_dir: str = "~/burp_agent_browser_profile"
    # Intruder: hard ceilings per run, protection against overloading the target.
    intruder_max_requests: int = 50
    intruder_min_delay_ms: int = 300
    # URL scanner: request ceiling per run, pause, overall time limit.
    scan_max_requests: int = 150
    scan_min_delay_ms: int = 300
    scan_max_seconds: int = 1800
    # Directory with payload files (file name only, no paths). Empty means the inline list only.
    payload_dir: str = "~/burp_agent_payloads"
    screenshots_dir: str = "~/burp_agent_findings/screenshots"
    # Do not load images, fonts and media in the guarded browser: faster, less noise.
    block_heavy_resources: bool = True
    # How many of the most recent history records one tool scans.
    max_history_records: int = 500
    policy_sha256: str = ""

    @classmethod
    def load(cls, path: str) -> "Policy":
        p = Path(path).expanduser()
        if not p.is_file():
            raise PolicyError(f"policy file not found: {p}")
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except json.JSONDecodeError as ex:
            raise PolicyError(f"policy file is not valid JSON: {ex}") from ex

        mode = data.get("mode", "read_only")
        if mode not in MODES:
            raise PolicyError(f"mode must be one of {MODES}, got {mode!r}")

        hosts = tuple(h.strip().lower() for h in data.get("authorized_hosts", []))
        if not hosts:
            raise PolicyError("authorized_hosts is empty: nothing is in scope")
        for h in hosts:
            base = h[2:] if h.startswith("*.") else h
            if not _HOST_RE.match(base):
                raise PolicyError(f"invalid host pattern: {h!r}")

        engagement = str(data.get("engagement_id", "")).strip()
        if not engagement:
            raise PolicyError("engagement_id is required (goes into the audit log)")

        environment = str(data.get("environment", "")).strip().lower()
        if environment and environment not in ENVIRONMENTS:
            raise PolicyError(f"environment must be one of {ENVIRONMENTS}, got {environment!r}")

        scope_urls = tuple(str(u).strip() for u in data.get("scope_urls", []))
        for u in scope_urls:
            parts = urlsplit(u)
            if parts.scheme not in ("http", "https") or not parts.hostname:
                raise PolicyError(f"scope_url must be http(s)://host[/prefix]: {u!r}")
            if not any(_host_match(parts.hostname.lower(), h) for h in hosts):
                raise PolicyError(f"scope_url host is not in authorized_hosts: {u!r}")
            if _norm_path(parts.path or "/") is None:
                raise PolicyError(f"scope_url path contains dot segments: {u!r}")

        return cls(
            engagement_id=engagement,
            mode=mode,
            authorized_hosts=hosts,
            allowed_methods=tuple(m.upper() for m in data.get("allowed_methods", ["GET", "HEAD", "OPTIONS"])),
            max_requests_per_minute=int(data.get("max_requests_per_minute", 30)),
            max_active_requests_total=int(data.get("max_active_requests_total", 500)),
            audit_log=str(data.get("audit_log", "~/burp_agent_audit/audit.jsonl")),
            universal_output_dir=str(data.get("universal_output_dir", "~/burp_universal_output")),
            upstream_sse_url=str(data.get("upstream_sse_url", "http://127.0.0.1:9876/")),
            max_response_chars=int(data.get("max_response_chars", 20000)),
            environment=environment,
            scope_urls=scope_urls,
            allowed_paths=tuple(str(p) for p in data.get("allowed_paths", [])),
            openapi_files=tuple(str(Path(p).expanduser()) for p in data.get("openapi_files", [])),
            findings_file=str(data.get("findings_file", "~/burp_agent_findings/findings.jsonl")),
            browser_proxy=data.get("browser_proxy", "http://127.0.0.1:8080") or None,
            browser_profile_dir=str(data.get("browser_profile_dir", "~/burp_agent_browser_profile")),
            intruder_max_requests=int(data.get("intruder_max_requests", 50)),
            intruder_min_delay_ms=int(data.get("intruder_min_delay_ms", 300)),
            scan_max_requests=int(data.get("scan_max_requests", 150)),
            scan_min_delay_ms=int(data.get("scan_min_delay_ms", 300)),
            scan_max_seconds=int(data.get("scan_max_seconds", 1800)),
            payload_dir=str(data.get("payload_dir", "~/burp_agent_payloads")),
            screenshots_dir=str(data.get("screenshots_dir", "~/burp_agent_findings/screenshots")),
            block_heavy_resources=bool(data.get("block_heavy_resources", True)),
            max_history_records=int(data.get("max_history_records", 500)),
            policy_sha256=hashlib.sha256(p.read_bytes()).hexdigest(),
        )

    @property
    def environment_ok(self) -> bool:
        return self.environment in ENVIRONMENTS

    def path_allowed(self, path: str) -> bool:
        """Path is allowed only if it starts with one of the allowed_paths prefixes and has no directory traversal."""
        if not path.startswith("/") or any(c in path for c in "\r\n \t"):
            return False
        if _norm_path(path.split("?", 1)[0]) is None:
            return False
        return any(path.startswith(prefix) for prefix in self.allowed_paths)

    def host_in_scope(self, host: str) -> bool:
        h = host.strip().lower().rstrip(".")
        if not _HOST_RE.match(h):
            return False
        return any(_host_match(h, pattern) for pattern in self.authorized_hosts)

    def url_in_scope(self, url: str) -> bool:
        """URL is in scope: the host is authorized and, if scope_urls are set, the URL matches one of the prefixes."""
        try:
            parts = urlsplit(url)
        except ValueError:
            return False
        if parts.scheme not in ("http", "https") or not parts.hostname:
            return False
        host = parts.hostname.lower()
        if not self.host_in_scope(host):
            return False
        if not self.scope_urls:
            return True
        path = parts.path or "/"
        if _norm_path(path) is None:
            return False
        try:
            port = parts.port or _DEFAULT_PORT[parts.scheme]
        except ValueError:
            return False
        for entry in self.scope_urls:
            e = urlsplit(entry)
            if e.scheme != parts.scheme or (e.hostname or "").lower() != host:
                continue
            if (e.port or _DEFAULT_PORT[e.scheme]) != port:
                continue
            if _prefix_matches(path, e.path or "/"):
                return True
        return False


def _host_match(host: str, pattern: str) -> bool:
    if pattern.startswith("*."):
        return host.endswith(pattern[1:])
    return host == pattern


class Gate:
    """Decides whether an action may run. The checks run in code, not in the model prompt."""

    def __init__(self, policy: Policy, clock=time.monotonic):
        self.policy = policy
        self._clock = clock
        self._stamps: deque = deque()
        self._active_total = 0
        self._lock = threading.Lock()

    def check_active(self, host: str, method: str) -> None:
        p = self.policy
        if p.mode != "active":
            raise PolicyError("active actions are disabled (mode=read_only)")
        if not p.host_in_scope(host):
            raise PolicyError(f"host is not in authorized scope: {host}")
        if method.upper() not in p.allowed_methods:
            raise PolicyError(f"method {method} is not allowed by policy")
        with self._lock:
            if self._active_total >= p.max_active_requests_total:
                raise PolicyError("max_active_requests_total reached for this session")
            now = self._clock()
            while self._stamps and now - self._stamps[0] > 60:
                self._stamps.popleft()
            if len(self._stamps) >= p.max_requests_per_minute:
                raise RateLimitError("rate limit: max_requests_per_minute reached")
            self._stamps.append(now)
            self._active_total += 1
