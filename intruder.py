"""Intruder: последовательная подстановка payload в одну позицию запроса.

Намеренно без параллельности и с жёсткими потолками: это проверка гипотез (например, IDOR по id),
а не нагрузка на стенд. Останавливается при 429/503, серии ошибок, отказе гарда, превышении
времени и на первом payload, который нельзя подставить. Перебор аутентификации запрещён:
цели с login/token/otp/password и заголовки Authorization/Cookie отклоняются до первого запроса.
"""

import asyncio
import hashlib
import re
import time

from httpmsg import MsgError, apply_position, parse_position, split_request, status_of

AUTH_RE = re.compile(
    r"login|log-in|signin|sign-in|auth|passw|pwd|otp|mfa|2fa|token|reset|regist|oauth|session|logout|captcha",
    re.I,
)
STOP_STATUSES = (429, 503)
MAX_PAYLOADS = 100
MAX_PAYLOAD_LEN = 200
MAX_SECONDS = 300
MAX_ERRORS = 5
FORBIDDEN_HEADERS = ("authorization", "cookie", "proxy-authorization")


def check_target(raw_base: str, position: str, payloads: list[str]) -> None:
    """Отказ до первого запроса: аутентификация, учётные данные, размер payload-списка."""
    kind, name = parse_position(position)
    if kind == "header" and name.lower() in FORBIDDEN_HEADERS:
        raise MsgError("intruder cannot target auth headers")
    _, path = split_request(raw_base)
    if AUTH_RE.search(path) or AUTH_RE.search(name):
        raise MsgError("auth-related target: intruder is not allowed here")
    if not payloads:
        raise MsgError("no payloads")
    if len(payloads) > MAX_PAYLOADS:
        raise MsgError(f"too many payloads: max {MAX_PAYLOADS}")
    for p in payloads:
        if len(p) > MAX_PAYLOAD_LEN or "\n" in p or "\r" in p:
            raise MsgError("payload is too long or multiline")


def is_truncated(response: str) -> bool:
    """Burp дописывает «(truncated)», когда обрезал вывод: длина такого ответа не сравнима."""
    return response.rstrip().endswith("(truncated)")


def body_length(response: str) -> int:
    _, sep, body = response.replace("\r\n", "\n").partition("\n\n")
    return len(body) if sep else 0


async def run(raw_base: str, position: str, payloads: list[str], send, gate, audit, *,
              max_requests: int, min_delay_s: float, baseline: bool = True) -> dict:
    """send(raw_request) -> сырой ответ (awaitable). gate() бросает исключение, если нельзя слать.

    audit(entry) получает запись на каждый отправленный запрос (без значений payload, только sha256).
    """
    started = time.monotonic()
    result: dict = {"rows": [], "stopped": None, "baseline": None, "errors": 0}

    if baseline:
        gate()
        resp = await send(raw_base)
        result["baseline"] = {"status": status_of(resp), "length": body_length(resp),
                              "truncated": is_truncated(resp)}
        audit({"kind": "baseline", "status": status_of(resp)})
        await asyncio.sleep(min_delay_s)

    base_status = result["baseline"]["status"] if result["baseline"] else None
    base_len = None
    if result["baseline"] and not result["baseline"]["truncated"]:
        base_len = result["baseline"]["length"]

    consecutive_errors = 0
    for i, payload in enumerate(payloads):
        if len(result["rows"]) >= max_requests:
            result["stopped"] = "request limit reached"
            break
        if time.monotonic() - started > MAX_SECONDS:
            result["stopped"] = "time limit reached"
            break
        try:
            raw = apply_position(raw_base, position, payload)
        except MsgError as ex:
            result["stopped"] = f"payload cannot be applied: {ex}"
            break
        try:
            gate()
        except Exception as ex:  # гард, лимит частоты, режим — останавливаем запуск целиком
            result["stopped"] = f"gate: {str(ex)[:200]}"
            break

        t0 = time.perf_counter()
        try:
            resp = await send(raw)
        except Exception as ex:
            result["errors"] += 1
            consecutive_errors += 1
            result["rows"].append({"i": i, "payload": payload[:MAX_PAYLOAD_LEN], "error": str(ex)[:200]})
            audit({"kind": "payload", "i": i, "payload_sha256": _sha(payload), "error": str(ex)[:200]})
            if consecutive_errors >= MAX_ERRORS:
                result["stopped"] = "too many consecutive errors"
                break
            await asyncio.sleep(min_delay_s)
            continue
        consecutive_errors = 0
        ms = round((time.perf_counter() - t0) * 1000)
        status = status_of(resp)
        truncated = is_truncated(resp)
        length = None if truncated else body_length(resp)
        result["rows"].append({"i": i, "payload": payload[:MAX_PAYLOAD_LEN], "status": status,
                               "length": length, "ms": ms, "truncated": truncated})
        audit({"kind": "payload", "i": i, "payload_sha256": _sha(payload), "status": status, "ms": ms})

        if status and int(status) in STOP_STATUSES:
            result["stopped"] = f"server pushback {status}: stopped to avoid load on the target"
            break
        await asyncio.sleep(min_delay_s)

    result["interesting"] = [
        r for r in result["rows"]
        if "status" in r and (r["status"] != base_status or _length_changed(r.get("length"), base_len))
    ]
    return result


def _length_changed(length: int | None, base: int | None) -> bool:
    if base is None or length is None:
        return False
    return abs(length - base) > max(5, base * 0.05)


def _sha(payload: str) -> str:
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
