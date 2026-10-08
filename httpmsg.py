"""Pure functions for HTTP/1.1 messages and Burp history records. No network and no state.

This module parses upstream responses (including partial records), builds requests and substitutes values
into a position (for Intruder). Anything that breaks on input raises MsgError.
"""

import json
import re
from urllib.parse import quote, unquote_plus, urlsplit

POSITION_KINDS = ("query", "header", "json", "path", "form")
HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9-]{1,64}$")
_NUM_RE = re.compile(r"^\d+$")
_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]{16,}$")
_STATUS_RE = re.compile(r"HTTP/[\d.]+\s+(\d{3})")

PARTIAL_START = '{"request":"'
PARTIAL_SPLIT = '","response":"'
_TRUNC_RE = re.compile(r'\s*\.{0,3}\s*\(truncated\)\s*$')
PROTECTED_HEADERS = ("host", "content-length", "transfer-encoding")


class MsgError(ValueError):
    """Error while parsing or building an HTTP message. The text goes to the model, so it contains no secrets."""


def host_from_request(raw: str) -> str | None:
    for line in raw.replace("\r\n", "\n").split("\n")[1:]:
        if not line.strip():
            break
        name, _, value = line.partition(":")
        if name.strip().lower() == "host":
            return value.strip().split(":")[0].lower()
    return None


def split_request(raw: str) -> tuple[str, str]:
    first = raw.replace("\r\n", "\n").split("\n", 1)[0].split()
    if len(first) < 2:
        raise MsgError("malformed request line")
    return first[0].upper(), first[1]


def normalize_path(path: str) -> str:
    """Path template without the query: numeric, UUID and hex segments are replaced with {id}."""
    segs = []
    for s in path.split("?", 1)[0].split("/"):
        if _NUM_RE.match(s) or _UUID_RE.match(s) or _HEX_RE.match(s):
            segs.append("{id}")
        else:
            segs.append(s)
    return "/".join(segs) or "/"


def unwrap_response(raw: str) -> str:
    """The HTTP response inside a Burp send reply.

    Burp wraps a sent request and its reply as HttpRequestResponse{httpRequest=..., httpResponse=...}. Only the
    response part is wanted: the request part can be long, and the status line would fall outside the first bytes.
    """
    if not raw.startswith("HttpRequestResponse{"):
        return raw
    marker = ", httpResponse="
    at = raw.find(marker)
    if at == -1:
        return raw
    text = raw[at + len(marker):]
    annotations = text.find(", messageAnnotations=")  # Burp may add this field after the response
    if annotations != -1:
        return text[:annotations]
    return text[:-1] if text.endswith("}") else text  # otherwise the wrapper ends with one closing brace


def status_of(response: str) -> str | None:
    m = _STATUS_RE.search(unwrap_response(response)[:200])
    return m.group(1) if m else None


def header_of(head: str, name: str) -> str:
    """Header value from the header block (the first line is the status or request line)."""
    for line in head.split("\n")[1:]:
        k, _, v = line.partition(":")
        if k.strip().lower() == name:
            return v.strip()
    return ""


def parse_reply(raw: str) -> dict:
    """A Burp send reply split into fields: status, reason, headers (lower-case names) and body.

    The reply is unwrapped first. The body is everything after the header block, as text.
    """
    text = unwrap_response(raw).replace("\r\n", "\n")
    head, _, body = text.partition("\n\n")
    lines = head.split("\n")
    m = re.match(r"HTTP/[\d.]+\s+(\d{3})\s*(.*)$", lines[0]) if lines else None
    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, sep, value = line.partition(":")
        if sep and name.strip():
            headers.setdefault(name.strip().lower(), value.strip())
    return {"status": m.group(1) if m else None, "reason": m.group(2).strip() if m else "",
            "headers": headers, "body": body}


def json_fragment(fragment: str) -> str:
    """Decodes a truncated JSON string fragment; an unfinished escape at the end is dropped."""
    fragment = _TRUNC_RE.sub("", fragment)
    for cut in range(6):
        candidate = fragment[: len(fragment) - cut] if cut else fragment
        try:
            return json.loads('"' + candidate + '"')
        except json.JSONDecodeError:
            continue
    return fragment


def parse_partial(line: str) -> dict | None:
    """Partial record: upstream truncates each field to about 5000 characters."""
    if not line.startswith(PARTIAL_START):
        return None
    req_raw, sep, resp_raw = line[len(PARTIAL_START):].partition(PARTIAL_SPLIT)
    if sep:  # the request is complete, the response is truncated
        return {"request": json_fragment(req_raw), "response": json_fragment(resp_raw),
                "request_truncated": False, "response_truncated": True}
    # the request itself is truncated: it cannot be replayed
    return {"request": json_fragment(req_raw), "response": "",
            "request_truncated": True, "response_truncated": True}


def parse_history(raw: str) -> list[dict]:
    """Parses a get_proxy_http_history response: a JSON list, records line by line, or partial records."""
    text = raw.strip()
    # Burp replies with the text "Reached end of items" when the history is exhausted.
    if not text or text.startswith("Reached end of items"):
        return []
    try:
        whole = json.loads(text)
        if isinstance(whole, list):
            return whole
    except json.JSONDecodeError:
        pass  # not a single JSON document: parse line by line

    items = []
    for line in text.split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            partial = parse_partial(line)
            if partial is None:
                raise MsgError(f"unexpected upstream format, sample: {line[:200]!r}") from None
            items.append(partial)
            continue
        if not isinstance(obj, dict):
            raise MsgError("unexpected upstream format (expected record objects)")
        items.append(obj)
    return items


def json_records(raw: str) -> tuple[list[dict], bool]:
    """JSON object records from a Burp response: one JSON list, one object, or records line by line.

    Returns (records, whether the output was truncated). Unrecognised lines are skipped instead of failing the parse.
    """
    text = raw.strip()
    truncated = text.endswith("(truncated)")
    if truncated:
        text = text[: -len("(truncated)")].rstrip()
    if not text or text.startswith("Reached end of items"):
        return [], truncated
    try:
        whole = json.loads(text)
        if isinstance(whole, list):
            return [x for x in whole if isinstance(x, dict)], truncated
        if isinstance(whole, dict):
            return [whole], truncated
    except json.JSONDecodeError:
        pass
    records = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue  # a truncated last line or stray text
        if isinstance(obj, dict):
            records.append(obj)
    return records, truncated


def build_request(orig: str, method: str, path: str, set_headers: dict | None = None,
                  remove_headers: list | None = None, body: str | None = None) -> str:
    """Builds an HTTP/1.1 request from a history record with changes. Host is kept, Content-Length is recalculated."""
    text = orig.replace("\r\n", "\n")
    head, _, orig_body = text.partition("\n\n")
    first = head.split("\n", 1)[0].split()
    version = first[2] if len(first) >= 3 else "HTTP/1.1"

    set_headers = set_headers or {}
    remove_headers = remove_headers or []
    for name, value in set_headers.items():
        if not HEADER_NAME_RE.match(name):
            raise MsgError(f"invalid header name: {name!r}")
        if name.lower() in PROTECTED_HEADERS:
            raise MsgError(f"header {name} cannot be set manually")
        if "\r" in value or "\n" in value:
            raise MsgError(f"invalid header value for {name}")
    if any(h.lower() == "host" for h in remove_headers):
        raise MsgError("Host cannot be removed")

    drop = {h.lower() for h in remove_headers} | {"content-length", "transfer-encoding"}
    replaced = {n.lower() for n in set_headers}
    headers = []
    for line in head.split("\n")[1:]:
        if not line.strip():
            continue
        name, _, value = line.partition(":")
        key = name.strip().lower()
        if key not in drop and key not in replaced:
            headers.append([name.strip(), value.strip()])
    headers += [[n, v] for n, v in set_headers.items()]

    new_body = orig_body if body is None else body
    if new_body:
        headers.append(["Content-Length", str(len(new_body.encode("utf-8")))])
    lines = [f"{method} {path} {version}"] + [f"{n}: {v}" for n, v in headers]
    return "\r\n".join(lines) + "\r\n\r\n" + new_body


def parse_position(spec: str) -> tuple[str, str]:
    kind, sep, name = spec.partition(":")
    if kind not in POSITION_KINDS or not sep or not name:
        raise MsgError("position must be query:<name> | header:<name> | json:<dot.path> | path:<index> | form:<name>")
    return kind, name


def apply_position(orig: str, spec: str, payload: str) -> str:
    """Substitutes a payload into a position of the original request and returns the new raw request."""
    kind, name = parse_position(spec)
    method, path = split_request(orig)
    base, _, query = path.partition("?")

    if kind == "query":
        pieces = query.split("&") if query else []
        found = False
        new_pieces = []
        for piece in pieces:
            key, _, _ = piece.partition("=")
            if key == name:
                found = True
                new_pieces.append(f"{name}={quote(payload, safe='')}")
            else:
                new_pieces.append(piece)  # other parameters are kept byte for byte
        if not found:
            raise MsgError(f"query parameter not found: {name}")
        return build_request(orig, method, base + "?" + "&".join(new_pieces))

    if kind == "path":
        parts = base.split("/")
        try:
            index = int(name) + 1  # parts[0] == "" (leading slash)
        except ValueError:
            raise MsgError("path position index must be an integer") from None
        if not (1 <= index < len(parts)):
            raise MsgError(f"path segment index out of range: {name}")
        parts[index] = quote(payload, safe="")
        new_path = "/".join(parts) + (("?" + query) if query else "")
        return build_request(orig, method, new_path)

    if kind == "header":
        text = orig.replace("\r\n", "\n")
        head = text.partition("\n\n")[0]
        present = any(line.partition(":")[0].strip().lower() == name.lower() for line in head.split("\n")[1:])
        if not present:
            raise MsgError(f"header not found: {name}")
        return build_request(orig, method, path, set_headers={name: payload})

    if kind == "form":  # a field of an application/x-www-form-urlencoded body: the other fields stay byte for byte
        body = orig.replace("\r\n", "\n").partition("\n\n")[2]
        found = False
        new_pieces = []
        for piece in body.split("&") if body else []:
            key, _, _ = piece.partition("=")
            if unquote_plus(key) == name:
                found = True
                new_pieces.append(f"{key}={quote(payload, safe='')}")
            else:
                new_pieces.append(piece)
        if not found:
            raise MsgError(f"form field not found: {name}")
        return build_request(orig, method, path, body="&".join(new_pieces))

    # json: body fields that already exist in the object (no new keys are created)
    body = orig.replace("\r\n", "\n").partition("\n\n")[2]
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        raise MsgError("body is not JSON") from None
    cur = data
    keys = name.split(".")
    for key in keys[:-1]:
        cur = _step(cur, key)
    last = keys[-1]
    if isinstance(cur, dict) and last in cur:
        cur[last] = payload
    elif isinstance(cur, list) and last.isdigit() and int(last) < len(cur):
        cur[int(last)] = payload
    else:
        raise MsgError(f"json field not found: {name}")
    return build_request(orig, method, path, body=json.dumps(data, ensure_ascii=False))


def _step(cur, key: str):
    if isinstance(cur, dict) and key in cur:
        return cur[key]
    if isinstance(cur, list) and key.isdigit() and int(key) < len(cur):
        return cur[int(key)]
    raise MsgError(f"json field not found: {key}")


def build_from_url(url: str, method: str = "GET", headers: dict | None = None,
                   body: str | None = None) -> tuple[str, str, int, bool]:
    """Builds a request from a full URL. Returns (raw request, host, port, use_https).

    Host and port come from the URL; Content-Length is computed here. The Host, Content-Length
    and Transfer-Encoding headers cannot be set manually: the builder handles them.
    """
    try:
        parts = urlsplit(url)
        port_value = parts.port
    except ValueError as ex:
        raise MsgError(f"bad url: {ex}") from None
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise MsgError("url must be http(s)://host/path")
    use_https = parts.scheme == "https"
    default = 443 if use_https else 80
    port = port_value or default
    host = parts.hostname.lower()
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    if any(c in path for c in " \r\n\t"):
        raise MsgError("url path contains spaces or control characters: percent-encode them")
    host_header = host if port == default else f"{host}:{port}"
    lines = [f"{method.upper()} {path} HTTP/1.1", f"Host: {host_header}", "User-Agent: burp-agent"]
    for name, value in (headers or {}).items():
        if not HEADER_NAME_RE.match(name):
            raise MsgError(f"invalid header name: {name!r}")
        if name.lower() in PROTECTED_HEADERS:
            raise MsgError(f"header {name} cannot be set manually")
        if "\r" in value or "\n" in value:
            raise MsgError(f"invalid header value for {name}")
        lines.append(f"{name}: {value}")
    body_text = body or ""
    if body_text:
        lines.append(f"Content-Length: {len(body_text.encode('utf-8'))}")
    raw = "\r\n".join(lines) + "\r\n\r\n" + body_text
    return raw, host, port, use_https
