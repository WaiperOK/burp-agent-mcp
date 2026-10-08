"""URL scanner: several checks per endpoint; all requests go through Burp and the gateway gate.

By default only idempotent methods (GET, HEAD, OPTIONS) are probed. POST endpoints are probed only when the
run asks for the "post" check and the policy allows POST (the caller passes the allowed methods in).
Checks:
  baseline      - the original request; anonymous access to the endpoint without authorization (candidate)
  auth          - the same request without Cookie/Authorization: 200 with a body means authorization is not enforced
  ids           - neighbouring numeric ids (N-1, N+1): 200 means objects can be enumerated (candidate for IDOR)
  malformed     - a quote instead of a numeric id: 5xx means an unhandled error (candidate)
  reflect       - a unique marker in a query parameter: reflected in the response means reflected input (candidate)
  params        - each query parameter (not credential-like): a quote gives SQL errors or 5xx; a condition that is
                  always true gives a much longer response than the baseline (candidate for SQL injection)
  post          - each string field of a JSON POST body (not credential-like): a quote gives SQL errors or 5xx;
                  a marker that comes back in the response means reflected input (candidate)

Login, registration, password and token endpoints are never probed by the "post" check, and a body that carries
a password or token field is never sent. Every finding is a candidate for manual review, not a confirmed
vulnerability. Response bodies are not returned.
"""

import asyncio
import json
import re
import secrets
import time
from dataclasses import dataclass, replace
from urllib.parse import unquote_plus, urlsplit

import httpmsg
from httpmsg import MsgError
from intruder import AUTH_RE
from redact import mask_query, redact_text

CHECKS = ("auth", "ids", "malformed", "reflect", "params", "post")
SAFE_METHODS = ("GET", "HEAD", "OPTIONS")
PUSHBACK = (429, 503)
# If the signed-in requests are refused (401) almost every time, the saved session has expired: stop, do not
# run the rest of the checks, and say so. Checked after at least SESSION_MIN_SAMPLE signed-in baselines.
SESSION_MIN_SAMPLE = 3
SESSION_REFUSED_SHARE = 0.8
# When a sign-in is configured, an expired session is renewed at most this many times per run.
SCAN_MAX_RELOGINS = 2
# Candidates from these checks are sent once more to see whether they reproduce.
REPRODUCE_CHECKS = ("auth", "ids", "malformed", "reflect", "params_quote", "params_bool")
# A POST probe changes data on the target, so its candidates are never sent a second time automatically.
NO_REPEAT_CHECKS = ("post_quote", "post_reflect")
MAX_ERRORS = 5
_AUTH = ("cookie", "authorization")
# Parameter and field names that carry secrets: never probed, and a body with such a field is never sent.
CREDENTIAL_NAME_RE = re.compile(r"pass|pwd|secret|token|otp|mfa|card|iban|passport|cvv|key|session|auth|pin", re.I)
# Database error texts (SQLite, MySQL, PostgreSQL, Oracle, Sequelize) that show an unescaped quote reached SQL.
SQL_ERROR_RE = re.compile(
    r"SQLITE_|SQLSTATE|syntax error|unterminated|SequelizeDatabaseError|ORA-\d{5}|"
    r"You have an error in your SQL|mysql_|pg_query|Unclosed quotation", re.I)
STATIC_FILE_RE = re.compile(r"\.(js|mjs|css|png|jpe?g|gif|svg|ico|webp|woff2?|ttf|eot|map|mp3|mp4)$", re.I)
# A boolean condition that is always true returns at least this many times the baseline size (plus a margin).
BOOL_GROWTH = 1.5
BOOL_MARGIN = 200
FALLBACK_PARAM_VALUE = "test"  # used for a query parameter when no non-empty value was seen anywhere in the run
SEVERITY_HINT = {
    "anonymous_200_candidate": "medium",
    "auth_not_enforced_candidate": "high",
    "neighbor_object_exists": "info",
    "server_error_on_malformed_input": "low",
    "reflected_input_candidate": "low",
    "sql_error_candidate": "high",
    "sql_boolean_candidate": "high",
    "other_owner_object_candidate": "high",
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


def endpoint_from_raw(raw: str, source: str, methods: tuple = SAFE_METHODS) -> Endpoint:
    """Endpoint from a history record. Port and scheme are not stored in history: taken from Host, default https/443."""
    method, path = httpmsg.split_request(raw)
    if method not in methods:
        raise MsgError(f"scanner sends only {methods}, got {method}")
    host_line = next((l for l in raw.replace("\r\n", "\n").split("\n")[1:] if l.lower().startswith("host:")), "")
    host_value = host_line.partition(":")[2].strip().lower()
    host, _, port_text = host_value.partition(":")
    use_https = port_text != "80"
    port = int(port_text) if port_text.isdigit() else (443 if use_https else 80)
    has_auth = any(line.partition(":")[0].strip().lower() in _AUTH for line in raw.replace("\r\n", "\n").split("\n")[1:] if line.strip())
    return Endpoint(method=method, host=host, port=port, use_https=use_https, path=path, raw=raw,
                    has_auth=has_auth, source=source)


def endpoint_in_scope(raw: str, source: str, in_scope, methods: tuple = SAFE_METHODS) -> Endpoint | None:
    """Endpoint from a history record that the scope allows, or None.

    History does not say whether a connection was HTTP or HTTPS. If the Host header names a port, both schemes
    are tried, and the one that the scope allows is used. Without a port, the HTTPS default is the only guess.
    """
    ep = endpoint_from_raw(raw, source, methods)
    host_value = next((l for l in raw.replace("\r\n", "\n").split("\n")[1:] if l.lower().startswith("host:")), "")
    candidates = [ep]
    if ":" in host_value.partition(":")[2]:  # an explicit port is in the Host header
        candidates.append(replace(ep, use_https=not ep.use_https))
    for cand in candidates:
        if in_scope(cand.origin + cand.path.split("?", 1)[0]):
            return cand
    return None


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


def _query_pairs(path: str) -> list[tuple[str, str]]:
    """Decoded (name, value) pairs of the query string, in order."""
    query = path.partition("?")[2]
    pairs = []
    for piece in query.split("&") if query else []:
        name, _, value = piece.partition("=")
        if name:
            pairs.append((unquote_plus(name), unquote_plus(value)))
    return pairs


def _is_login_like(path: str) -> bool:
    return bool(AUTH_RE.search(path.split("?", 1)[0]))


def _has_data(text: str) -> bool:
    """True if the answer carries something: an empty JSON object or list, null or nothing does not count."""
    stripped = text.strip()
    if not stripped:
        return False
    try:
        value = json.loads(stripped)
    except ValueError:
        return True  # not JSON: any text is treated as content
    def content(v) -> bool:
        if isinstance(v, dict):
            return any(content(x) for x in v.values())
        if isinstance(v, list):
            return any(content(x) for x in v)
        return v is not None and v != ""
    return content(value)


def _with_bearer(raw: str, token: str) -> str:
    """The same request with its Authorization header replaced by a fresh bearer token.

    A request without an Authorization header is returned unchanged: the anonymous probe must stay anonymous.
    """
    head = raw.replace("\r\n", "\n").partition("\n\n")[0]
    if not any(line.partition(":")[0].strip().lower() == "authorization" for line in head.split("\n")[1:]):
        return raw
    method, path = httpmsg.split_request(raw)
    return httpmsg.build_request(raw, method, path, set_headers={"Authorization": f"Bearer {token}"})


def _is_static(path: str) -> bool:
    """Public static files (scripts, styles, images, fonts, UI translations). Without a session they are normal."""
    plain = path.split("?", 1)[0]
    return bool(STATIC_FILE_RE.search(plain)) or (plain.startswith("/assets/") and plain.endswith(".json"))


def _has_credentials(obj) -> bool:
    """True if a JSON value holds a credential-like key or a JWT anywhere inside it."""
    if isinstance(obj, dict):
        return any(CREDENTIAL_NAME_RE.search(str(k)) or _has_credentials(v) for k, v in obj.items())
    if isinstance(obj, list):
        return any(_has_credentials(v) for v in obj)
    return isinstance(obj, str) and bool(re.match(r"eyJ[A-Za-z0-9_-]{5,}\.", obj))


def _known_param_values(endpoints: list[Endpoint]) -> dict:
    """First non-empty value seen for each query parameter name, over all endpoints of the run."""
    known: dict[str, str] = {}
    for ep in endpoints:
        for name, value in _query_pairs(ep.path):
            if value and name not in known:
                known[name] = value
    return known


def _param_probes(ep: Endpoint, known: dict) -> list[Probe]:
    """A quote and an always-true condition in each query parameter. Credential-like names are skipped.

    An empty value makes a weak probe: a quote after nothing is not a quote inside a word. So the value seen
    elsewhere in the run for the same name is used, and FALLBACK_PARAM_VALUE when there is none.
    """
    out, seen = [], set()
    for name, value in _query_pairs(ep.path):
        if name in seen or CREDENTIAL_NAME_RE.search(name):
            continue
        seen.add(name)
        value = value or known.get(name) or FALLBACK_PARAM_VALUE
        try:
            out.append(Probe("params_quote", ep, httpmsg.apply_position(ep.raw, f"query:{name}", value + "'"),
                             note=f"quote in parameter {name}"))
            out.append(Probe("params_bool", ep, httpmsg.apply_position(ep.raw, f"query:{name}", value + "' OR 1=1--"),
                             note=f"always-true condition in parameter {name}"))
        except MsgError:  # the parameter name is encoded in a way the position helper does not match: skip it
            continue
    return out


MAX_POST_FIELDS = 20  # per endpoint: a large body would otherwise take the whole budget
EVIDENCE_CHARS = 200  # a finding carries at most this much of the answer, after masking
OWNER_KEYS = ("UserId", "userId", "user_id", "owner", "ownerId", "owner_id")


def _request_content_type(raw: str) -> str:
    head = raw.replace("\r\n", "\n").partition("\n\n")[0]
    return httpmsg.header_of(head, "content-type").lower()


def _json_leaves(obj, path: str = "", depth: int = 0) -> list[tuple[str, str]]:
    """(dot path, value) of every string inside a JSON value. A list index counts as a name."""
    if depth > 8:
        return []
    if isinstance(obj, str):
        return [(path, obj)] if path else []
    if isinstance(obj, dict):
        items = [(str(k), v) for k, v in obj.items() if "." not in str(k)]  # a dot would be read as a path
    elif isinstance(obj, list):
        items = [(str(i), v) for i, v in enumerate(obj)]
    else:
        return []
    out = []
    for name, value in items:
        out.extend(_json_leaves(value, f"{path}.{name}" if path else name, depth + 1))
    return out


def _form_fields(body: str) -> list[tuple[str, str]]:
    """(name, value) pairs of an application/x-www-form-urlencoded body, decoded."""
    fields = []
    for piece in body.split("&") if body else []:
        name, _, value = piece.partition("=")
        if name:
            fields.append((unquote_plus(name), unquote_plus(value)))
    return fields


def _post_probes(ep: Endpoint) -> list[Probe]:
    """A quote and a marker in each text field of a POST body: JSON (nested fields too) or a form.

    Login-like paths get nothing. A body with a credential-like name or a token anywhere in it is never sent again:
    the recorded secrets must not go back to the target. At most MAX_POST_FIELDS fields are probed per endpoint.
    """
    if _is_login_like(ep.path):
        return []
    body = ep.raw.replace("\r\n", "\n").partition("\n\n")[2]
    if "x-www-form-urlencoded" in _request_content_type(ep.raw):
        fields = _form_fields(body)
        if any(CREDENTIAL_NAME_RE.search(name) or _has_credentials(value) for name, value in fields):
            return []
        targets = [(f"form:{name}", name, value) for name, value in fields]
    else:
        try:
            data = json.loads(body)
        except ValueError:
            return []  # neither a form nor JSON: nothing to probe
        if _has_credentials(data):
            return []
        targets = [(f"json:{path}", path, value) for path, value in _json_leaves(data)]
    out = []
    for spec, name, value in targets[:MAX_POST_FIELDS]:
        try:
            out.append(Probe("post_quote", ep, httpmsg.apply_position(ep.raw, spec, value + "'"),
                             note=f"quote in field {name}"))
            marker = "zq" + secrets.token_hex(4)
            out.append(Probe("post_reflect", ep, httpmsg.apply_position(ep.raw, spec, marker),
                             marker=marker, note=f"marker in field {name}"))
        except MsgError:
            continue
    return out

def _bundle(ep: Endpoint, checks: tuple, known: dict | None = None) -> list[Probe]:
    """All probes of one endpoint. A POST endpoint gets only the POST checks: its recorded request is not re-sent."""
    if ep.method == "POST":
        return _post_probes(ep) if "post" in checks else []
    known = known or {}
    out = [Probe("baseline", ep, ep.raw)]
    if "auth" in checks and ep.has_auth and not _is_static(ep.path):
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
    if "params" in checks:
        out.extend(_param_probes(ep, known))
    return out


def build_probes(endpoints: list[Endpoint], checks: tuple, max_requests: int) -> list[Probe]:
    """Budget cuts by whole endpoints: an endpoint is either fully checked or not part of the run at all.

    If even the first endpoint does not fit, it is truncated by probes (the baseline stays first).
    """
    unknown = set(checks) - set(CHECKS)
    if unknown:
        raise MsgError(f"unknown checks: {sorted(unknown)}; allowed: {CHECKS}")
    chosen: list[Probe] = []
    known = _known_param_values(endpoints)
    for ep in endpoints:
        bundle = _bundle(ep, checks, known)
        if len(chosen) + len(bundle) > max_requests:
            if not chosen:
                chosen = bundle[:max_requests]
            break
        chosen.extend(bundle)
    return chosen


def _status(resp: str) -> str | None:
    return httpmsg.status_of(resp)


def _body(resp: str) -> str:
    return httpmsg.unwrap_response(resp).replace("\r\n", "\n").partition("\n\n")[2]


def _content_type(resp: str) -> str:
    return httpmsg.parse_reply(resp)["headers"].get("content-type", "")


def _evidence(text: str, pattern: re.Pattern | None = None) -> str:
    """A short piece of the answer, around the match when there is one, with secrets masked."""
    at = 0
    if pattern is not None:
        m = pattern.search(text)
        if m:
            at = max(0, m.start() - 80)
    return mask_query(redact_text(text[at:at + EVIDENCE_CHARS]))[:EVIDENCE_CHARS]


def _owner(text: str) -> str | None:
    """The owner id of the object in a JSON answer, if the answer names one (for example data.UserId)."""
    try:
        data = json.loads(text.strip())
    except ValueError:
        return None

    def walk(value, depth: int = 0) -> str | None:
        if depth > 4:
            return None
        if isinstance(value, dict):
            for key in OWNER_KEYS:
                if isinstance(value.get(key), (int, str)) and not isinstance(value.get(key), bool):
                    return str(value[key])
            children = list(value.values())
        elif isinstance(value, list):
            children = value[:5]
        else:
            return None
        for child in children:
            found = walk(child, depth + 1)
            if found is not None:
                return found
        return None

    return walk(data)


USER_DATA_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+")
USER_KEY_RE = re.compile(r'"(username|user_name|email|login)"\s*:', re.I)


def _is_json_answer(text: str, content_type: str) -> bool:
    """True for a JSON answer: by its Content-Type, or by a body that parses as JSON (some APIs send text/plain)."""
    if "json" in content_type.lower():
        return True
    try:
        json.loads(text)
    except ValueError:
        return False
    return text.strip()[:1] in ("{", "[")


def _user_specific(text: str) -> bool:
    """True if an answer names a person or an account: an owner id, an e-mail address or a user name."""
    return _owner(text) is not None or bool(USER_DATA_RE.search(text)) or bool(USER_KEY_RE.search(text))


def _finding(kind: str, probe: Probe, status: str | None, length: int, base: dict | None,
             evidence: str = "", hint: str | None = None) -> dict:
    method, path = httpmsg.split_request(probe.raw)
    return {
        "candidate": kind,
        "hint": hint or SEVERITY_HINT[kind],
        "check": probe.check,
        "method": method,
        "url": mask_query(probe.endpoint.origin + path),  # findings are stored and shown: no secrets in the URL
        "status": status,
        "baseline_status": base["status"] if base else None,
        "length": length,
        "note": probe.note,
        "evidence": evidence,
    }

SEVERITY_RANK = {"info": 1, "low": 2, "medium": 3, "high": 4}


def group_findings(findings: list[dict]) -> list[dict]:
    """One row per kind, method and path, with the number of hits and how many were repeated and confirmed.

    The same problem on one path (a quote in each parameter of an endpoint, say) becomes one row, not many.
    """
    rows: dict[tuple, dict] = {}
    for f in findings:
        path = f["url"].split("?", 1)[0]
        method = f.get("method", "")
        row = rows.setdefault((f["candidate"], method, path), {
            "candidate": f["candidate"], "method": method, "path": path, "example_url": f["url"],
            "hint": "info", "count": 0, "statuses": set(), "notes": [], "repeated": 0,
            "confirmed": 0, "example_evidence": ""})
        row["count"] += 1
        if SEVERITY_RANK.get(f.get("hint", ""), 0) > SEVERITY_RANK.get(row["hint"], 0):  # the group has the worst hint
            row["hint"] = f["hint"]
        if not row["example_evidence"]:
            row["example_evidence"] = f.get("evidence", "")
        if f.get("status"):
            row["statuses"].add(f["status"])
        if f.get("note") and f["note"] not in row["notes"] and len(row["notes"]) < 5:
            row["notes"].append(f["note"])
        if f.get("reproduced") is not None:
            row["repeated"] += 1
            row["confirmed"] += 1 if f["reproduced"] else 0
    out = [{**row, "statuses": sorted(row["statuses"])} for row in rows.values()]
    return sorted(out, key=lambda r: (-r["count"], r["candidate"], r["path"]))


def judge(probe: Probe, status: str | None, length: int, text: str, base: dict | None,
          content_type: str = "") -> dict | None:
    """Decides whether there is a candidate. base is the baseline result for the same endpoint.

    content_type is the response's Content-Type. An anonymous page that is HTML or an image is normal and is not
    reported: only an anonymous JSON answer counts as a possible missing check.
    """
    ep = probe.endpoint

    def found(kind: str, pattern: re.Pattern | None = None, hint: str | None = None) -> dict:
        return _finding(kind, probe, status, length, base, _evidence(text, pattern), hint)

    if probe.check == "baseline":
        is_json = "json" in content_type.lower()
        if not ep.has_auth and status == "200" and is_json and _has_data(text) and not _is_static(ep.path):
            # medium when it names a person or looks administrative; a public list is low
            sensitive = re.search(r"admin|config|secret|internal|debug|setting", ep.path, re.I)
            return found("anonymous_200_candidate", hint="medium" if (sensitive or _user_specific(text)) else "low")
        return None
    if probe.check == "auth":
        # A public HTML or text page opens without a sign-in, so it counts only as JSON data or as a named person.
        if status == "200" and base and base["status"] == "200" and _has_data(text) \
                and (_is_json_answer(text, content_type) or _user_specific(text)):
            # high when the answer is someone's data; an answer with no person in it is only a low lead
            return found("auth_not_enforced_candidate", hint="high" if _user_specific(text) else "low")
        return None
    if probe.check == "ids":
        if status == "200" and _has_data(text) and base and base["status"] == "200":
            new_owner, old_owner = _owner(text), base.get("owner")
            if new_owner and old_owner and new_owner != old_owner:  # someone else's object
                return found("other_owner_object_candidate")
            return found("neighbor_object_exists")
        return None
    if probe.check == "malformed":
        if status and int(status) >= 500:
            return found("server_error_on_malformed_input")
        return None
    if probe.check in ("params_quote", "post_quote"):
        if SQL_ERROR_RE.search(text):
            return found("sql_error_candidate", SQL_ERROR_RE)
        if status and int(status) >= 500:
            return found("server_error_on_malformed_input")
        return None
    if probe.check == "params_bool":
        # an error on the always-true payload means the input reached SQL and broke the query
        if SQL_ERROR_RE.search(text) or (status and int(status) >= 500):
            return found("sql_error_candidate", SQL_ERROR_RE)
        if status == "200" and base and base["status"] == "200" \
                and length > base["length"] * BOOL_GROWTH + BOOL_MARGIN:
            return found("sql_boolean_candidate")
        return None
    if probe.check == "reflect" and probe.marker and probe.marker in text:
        return found("reflected_input_candidate", re.compile(re.escape(probe.marker)))
    if probe.check == "post_reflect":
        # a 5xx on a harmless value in a field is a server error worth a look, even without a quote
        if status and int(status) >= 500:
            return found("server_error_on_malformed_input")
        if probe.marker and probe.marker in text:
            return found("reflected_input_candidate", re.compile(re.escape(probe.marker)))
    return None

async def _reproduce(finding: dict, probe: Probe, base: dict | None, send, gate_wait, audit, result: dict,
                     min_delay_s: float, spare_requests: int | None = None) -> None:
    """Sends the same probe once more. A candidate that does not reproduce is kept, but marked.

    spare_requests is the budget not needed by the probes still to come; None means no cap.
    """
    if spare_requests is not None and spare_requests < 1:
        finding["reproduced"] = None
        finding["reproduce_error"] = "skipped: request budget is reserved for the remaining probes"
        return
    try:
        await gate_wait(probe.endpoint)
        again = await send(probe)
    except Exception as ex:  # budget, scope or a transport error: the candidate stays, unverified
        finding["reproduced"] = None
        finding["reproduce_error"] = str(ex)[:120]
        return
    result["sent"] += 1
    status = _status(again)
    text = _body(again)
    finding["reproduced"] = judge(probe, status, len(text), text, base, _content_type(again)) is not None
    finding["second_status"] = status
    audit({"check": probe.check, "reproduce": True, "status": status})
    await asyncio.sleep(min_delay_s)


async def run(probes: list[Probe], send, gate_wait, audit, *, min_delay_s: float, max_seconds: float,
              should_stop, result: dict, on_finding=None, max_requests: int | None = None,
              relogin=None) -> dict:
    """Sequential run. send(probe) -> response; gate_wait(endpoint) waits for the gate window or raises.

    result is a dict that is updated during the run (the job status is visible while it runs).
    on_finding(finding), if given, is called as soon as a candidate is found, so nothing is lost on a crash.
    max_requests caps probes plus repeats; repeats never take budget from probes that are still to come.
    """
    result.update({"findings": [], "sent": 0, "errors": 0, "stopped": None, "baseline": {},
                   "session": {"signed_in": 0, "refused": 0}, "relogins": 0})
    started = time.monotonic()
    consecutive_errors = 0
    for index, probe in enumerate(probes):
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
        if probe.check == "baseline" and probe.endpoint.has_auth:
            session = result["session"]
            session["signed_in"] += 1
            if status == "401":
                session["refused"] += 1
            if session["signed_in"] >= SESSION_MIN_SAMPLE and \
                    session["refused"] >= SESSION_REFUSED_SHARE * session["signed_in"]:
                if relogin is None:
                    result["stopped"] = ("session looks expired: signed-in requests get 401. "
                                         "Sign in again with browser_guard.py login, then scan again")
                    break
                token = None
                if result["relogins"] < SCAN_MAX_RELOGINS:
                    result["relogins"] += 1
                    try:
                        token = await relogin()
                    except Exception:  # a failed sign-in ends the run below, with the reason
                        token = None
                    audit({"relogin": result["relogins"], "signed_in_again": bool(token)})
                if not token:
                    result["stopped"] = ("session looks expired and signing in again did not work. "
                                         "Check the local test account and the login page, then scan again")
                    break
                for later in probes[index + 1:]:  # the rest of the run uses the fresh token
                    if later.check != "auth":
                        later.raw = _with_bearer(later.raw, token)
                session.update(signed_in=0, refused=0)
        if probe.check == "baseline":
            result["baseline"][probe.endpoint.key] = {"status": status, "length": length, "owner": _owner(text)}
        base = result["baseline"].get(probe.endpoint.key)
        finding = judge(probe, status, length, text, base, _content_type(resp))
        if finding:
            if probe.check in REPRODUCE_CHECKS:
                # result["sent"] already counts this probe; reserve one slot per probe still unsent
                spare = None if max_requests is None else max_requests - result["sent"] - (len(probes) - index - 1)
                await _reproduce(finding, probe, base, send, gate_wait, audit, result, min_delay_s, spare)
            elif probe.check in NO_REPEAT_CHECKS:
                finding["reproduced"] = None
                finding["reproduce_error"] = "not repeated: a POST request changes data on the target"
            result["findings"].append(finding)
            if on_finding is not None:
                on_finding(finding)
        await asyncio.sleep(min_delay_s)
    return result

