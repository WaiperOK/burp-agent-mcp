"""URL scanner: several checks per endpoint; all requests go through Burp and the gateway gate.

Only idempotent methods (GET, HEAD, OPTIONS): the scanner never writes to the target.
Checks:
  baseline   - the original request; anonymous access to the endpoint without authorization (candidate)
  auth       - the same request without Cookie/Authorization: 200 with a body means authorization is not enforced (candidate)
  ids        - neighbouring numeric ids (N-1, N+1): 200 means objects can be enumerated (candidate for IDOR, verify by hand)
  malformed  - a quote instead of a numeric id: 5xx means an unhandled error (candidate)
  reflect    - a unique marker in a query parameter: reflected in the response means reflected input (candidate)

Every finding is a candidate for manual review, not a confirmed vulnerability. Response bodies are not returned.
"""

import asyncio
import secrets
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpmsg
from httpmsg import MsgError

CHECKS = ("auth", "ids", "malformed", "reflect")
SAFE_METHODS = ("GET", "HEAD", "OPTIONS")
PUSHBACK = (429, 503)
MAX_ERRORS = 5
_AUTH = ("cookie", "authorization")
SEVERITY_HINT = {
    "anonymous_200_candidate": "medium",
    "auth_not_enforced_candidate": "high",
    "neighbor_object_exists": "info",
    "server_error_on_malformed_input": "low",
    "reflected_input_candidate": "low",
}


@dataclass
class Endpoint:
    method: str
    host: str
    port: int
    use_https: bool
    path: str  # path with query
    raw: str  # original raw request
    has_auth: bool
    source: str  # history | openapi

    @property
    def key(self) -> tuple:
        return (self.method, self.host, self.port, httpmsg.normalize_path(self.path))

    @property
    def origin(self) -> str:
        scheme = "https" if self.use_https else "http"
        default = 443 if self.use_https else 80
        return f"{scheme}://{self.host}" + ("" if self.port == default else f":{self.port}")


@dataclass
class Probe:
    check: str
    endpoint: Endpoint
    raw: str
    marker: str = ""
    note: str = ""


def endpoint_from_raw(raw: str, source: str) -> Endpoint:
    """Endpoint from a history record. Port and scheme are not stored in history: taken from Host, default https/443."""
    method, path = httpmsg.split_request(raw)
    if method not in SAFE_METHODS:
        raise MsgError(f"scanner sends only {SAFE_METHODS}, got {method}")
    host_line = next((l for l in raw.replace("\r\n", "\n").split("\n")[1:] if l.lower().startswith("host:")), "")
    host_value = host_line.partition(":")[2].strip().lower()
    host, _, port_text = host_value.partition(":")
    use_https = port_text != "80"
    port = int(port_text) if port_text.isdigit() else (443 if use_https else 80)
    has_auth = any(line.partition(":")[0].strip().lower() in _AUTH for line in raw.replace("\r\n", "\n").split("\n")[1:] if line.strip())
    return Endpoint(method=method, host=host, port=port, use_https=use_https, path=path, raw=raw,
                    has_auth=has_auth, source=source)


def endpoint_from_url(url: str, method: str = "GET") -> Endpoint:
    raw, host, port, use_https = httpmsg.build_from_url(url, method)
    method, path = httpmsg.split_request(raw)
    return Endpoint(method=method, host=host, port=port, use_https=use_https, path=path, raw=raw,
                    has_auth=False, source="openapi")


def _numeric_segment(path: str) -> tuple[int, int] | None:
    """Index and value of the first numeric path segment (0-based index, no query)."""
    segments = path.split("?", 1)[0].split("/")[1:]
    for i, seg in enumerate(segments):
        if seg.isdigit():
            return i, int(seg)
    return None


def _strip_auth(raw: str) -> str:
    method, path = httpmsg.split_request(raw)
    return httpmsg.build_request(raw, method, path, remove_headers=["Cookie", "Authorization"])


def _with_query(raw: str, marker: str) -> str:
    method, path = httpmsg.split_request(raw)
    base, _, query = path.partition("?")
    new_path = base + "?" + (query + "&" if query else "") + f"zq={marker}"
    return httpmsg.build_request(raw, method, new_path)


def _bundle(ep: Endpoint, checks: tuple) -> list[Probe]:
    """All probes of one endpoint: the baseline and its checks."""
    out = [Probe("baseline", ep, ep.raw)]
    if "auth" in checks and ep.has_auth:
        out.append(Probe("auth", ep, _strip_auth(ep.raw), note="without Cookie/Authorization"))
    seg = _numeric_segment(ep.path)
    if "ids" in checks and seg is not None:
        idx, n = seg
        for delta in (-1, 1):
            if n + delta >= 0:
                out.append(Probe("ids", ep, httpmsg.apply_position(ep.raw, f"path:{idx}", str(n + delta)),
                                 note=f"id {n}->{n + delta}"))
    if "malformed" in checks and seg is not None:
        out.append(Probe("malformed", ep, httpmsg.apply_position(ep.raw, f"path:{seg[0]}", "'"),
                         note="quote instead of id"))
    if "reflect" in checks:
        marker = "zq" + secrets.token_hex(4)
        out.append(Probe("reflect", ep, _with_query(ep.raw, marker), marker=marker))
    return out


def build_probes(endpoints: list[Endpoint], checks: tuple, max_requests: int) -> list[Probe]:
    """Budget cuts by whole endpoints: an endpoint is either fully checked or not part of the run at all.

    If even the first endpoint does not fit, it is truncated by probes (the baseline stays first).
    """
    unknown = set(checks) - set(CHECKS)
    if unknown:
        raise MsgError(f"unknown checks: {sorted(unknown)}; allowed: {CHECKS}")
    chosen: list[Probe] = []
    for ep in endpoints:
        bundle = _bundle(ep, checks)
        if len(chosen) + len(bundle) > max_requests:
            if not chosen:
                chosen = bundle[:max_requests]
            break
        chosen.extend(bundle)
    return chosen


def _status(resp: str) -> str | None:
    return httpmsg.status_of(resp)


def _body(resp: str) -> str:
    return resp.replace("\r\n", "\n").partition("\n\n")[2]


def _finding(kind: str, probe: Probe, status: str | None, length: int, base: dict | None) -> dict:
    method, path = httpmsg.split_request(probe.raw)
    return {
        "candidate": kind,
        "hint": SEVERITY_HINT[kind],
        "check": probe.check,
        "method": method,
        "url": probe.endpoint.origin + path,
        "status": status,
        "baseline_status": base["status"] if base else None,
        "length": length,
        "note": probe.note,
    }


def judge(probe: Probe, status: str | None, length: int, text: str, base: dict | None) -> dict | None:
    """Decides whether there is a candidate. base is the baseline result for the same endpoint."""
    ep = probe.endpoint
    if probe.check == "baseline":
        if not ep.has_auth and status == "200" and length > 0:
            return _finding("anonymous_200_candidate", probe, status, length, None)
        return None
    if probe.check == "auth":
        if status == "200" and length > 0 and base and base["status"] == "200":
            return _finding("auth_not_enforced_candidate", probe, status, length, base)
        return None
    if probe.check == "ids":
        if status == "200" and length > 0 and base and base["status"] == "200":
            return _finding("neighbor_object_exists", probe, status, length, base)
        return None
    if probe.check == "malformed":
        if status and int(status) >= 500:
            return _finding("server_error_on_malformed_input", probe, status, length, base)
        return None
    if probe.check == "reflect" and probe.marker and probe.marker in text:
        return _finding("reflected_input_candidate", probe, status, length, base)
    return None


async def run(probes: list[Probe], send, gate_wait, audit, *, min_delay_s: float, max_seconds: float,
              should_stop, result: dict, on_finding=None) -> dict:
    """Sequential run. send(probe) -> response; gate_wait(endpoint) waits for the gate window or raises.

    result is a dict that is updated during the run (the job status is visible while it runs).
    on_finding(finding), if given, is called as soon as a candidate is found, so nothing is lost on a crash.
    """
    result.update({"findings": [], "sent": 0, "errors": 0, "stopped": None, "baseline": {}})
    started = time.monotonic()
    consecutive_errors = 0
    for probe in probes:
        if should_stop():
            result["stopped"] = "stopped by operator"
            break
        if time.monotonic() - started > max_seconds:
            result["stopped"] = "time limit reached"
            break
        try:
            await gate_wait(probe.endpoint)
        except Exception as ex:  # mode, scope and the total limit: stop the whole run
            result["stopped"] = f"gate: {str(ex)[:200]}"
            break
        t0 = time.perf_counter()
        try:
            resp = await send(probe)
        except Exception as ex:
            result["errors"] += 1
            consecutive_errors += 1
            audit({"check": probe.check, "error": str(ex)[:200]})
            if consecutive_errors >= MAX_ERRORS:
                result["stopped"] = "too many consecutive errors"
                break
            await asyncio.sleep(min_delay_s)
            continue
        consecutive_errors = 0
        result["sent"] += 1
        ms = round((time.perf_counter() - t0) * 1000)
        status = _status(resp)
        text = _body(resp)
        length = len(text)
        audit({"check": probe.check, "url_path": httpmsg.split_request(probe.raw)[1].split("?")[0][:200],
               "status": status, "ms": ms})
        if status and int(status) in PUSHBACK:
            result["stopped"] = f"server pushback {status}: stopped to avoid load on the target"
            break
        if probe.check == "baseline":
            result["baseline"][probe.endpoint.key] = {"status": status, "length": length}
        base = result["baseline"].get(probe.endpoint.key)
        finding = judge(probe, status, length, text, base)
        if finding:
            result["findings"].append(finding)
            if on_finding is not None:
                on_finding(finding)
        await asyncio.sleep(min_delay_s)
    return result

