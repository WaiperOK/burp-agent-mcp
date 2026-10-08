"""Burp replies in the shape they came back in when the gateway ran against a live OWASP Juice Shop.

Regression fixtures: each one broke something before. A long Cookie hid the status line, an annotations tail leaked
into the body, and a SQL error on a quoted search was missed. The fixtures are shortened copies of real replies.
Run: python tests/test_burp_replies.py
"""

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import httpmsg  # noqa: E402
import scanner  # noqa: E402

HOST = "127.0.0.1:3000"

SQL_ERROR_500 = (
    "HttpRequestResponse{httpRequest=GET /rest/products/search?q=test%27 HTTP/1.1\r\n"
    f"Host: {HOST}\r\nCookie: language=en; token=eyJhbGciOiJIUzI1NiJ9.eyJzdGF0dXMiOiJzdWNjZXNzIn0.sig; continueCode=abc\r\n"
    "User-Agent: Mozilla/5.0 (Macintosh)\r\nAccept: */*\r\n\r\n, "
    "httpResponse=HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/html; charset=utf-8\r\n"
    "X-Recruiting: /#/jobs\r\n\r\n<html><pre>Error: SQLITE_ERROR: near \"'%'\": syntax error</pre></html>, "
    "messageAnnotations=Annotations{comment='', highlightColor=NONE}}"
)

WHOAMI_200 = (
    "HttpRequestResponse{httpRequest=GET /rest/user/whoami?fields=email HTTP/1.1\r\nHost: " + HOST + "\r\n\r\n, "
    "httpResponse=HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\n"
    "Set-Cookie: token=eyJhbGciOiJIUzI1NiJ9.e30.sig; Path=/\r\n\r\n"
    '{"user":{"email":"tester@example.test"}}, '
    "messageAnnotations=Annotations{comment='', highlightColor=NONE}}"
)

UNAUTHORIZED_401 = (
    "HttpRequestResponse{httpRequest=GET /api/BasketItems/ HTTP/1.1\r\nHost: " + HOST + "\r\n"
    "Cookie: " + "language=en; x=" + "y" * 300 + "\r\n\r\n, "
    "httpResponse=HTTP/1.1 401 Unauthorized\r\nContent-Type: text/plain\r\n\r\nUnauthorized, "
    "messageAnnotations=Annotations{comment='', highlightColor=NONE}}"
)


def request_part(reply: str) -> str:
    """The raw request inside a wrapped reply, as the scanner gets it from history."""
    return reply.split("httpRequest=", 1)[1].split(", httpResponse=", 1)[0]


class LiveRepliesTests(unittest.TestCase):
    def test_sql_error_reply_has_its_status_and_a_clean_body(self):
        self.assertEqual(httpmsg.status_of(SQL_ERROR_500), "500")
        body = httpmsg.parse_reply(SQL_ERROR_500)["body"]
        self.assertIn("SQLITE_ERROR", body)
        self.assertNotIn("messageAnnotations", body)  # Burp's tail is not part of the body
        self.assertNotIn("eyJ", body)  # the token was in the request part, not in the answer

    def test_sql_error_on_a_quoted_search_is_a_candidate(self):
        ep = scanner.endpoint_from_raw(request_part(SQL_ERROR_500), "history")
        probe = next(p for p in scanner.build_probes([ep], ("params",), 50) if p.check == "params_quote")
        body = httpmsg.parse_reply(SQL_ERROR_500)["body"]
        out = scanner.judge(probe, httpmsg.status_of(SQL_ERROR_500), len(body), body, None, "text/html")
        self.assertEqual(out["candidate"], "sql_error_candidate")
        self.assertNotIn("eyJ", out["evidence"])

    def test_json_answer_parses_once_the_tail_is_gone(self):
        body = httpmsg.parse_reply(WHOAMI_200)["body"]
        self.assertEqual(json.loads(body)["user"]["email"], "tester@example.test")
        self.assertEqual(httpmsg.parse_reply(WHOAMI_200)["headers"]["content-type"], "application/json; charset=utf-8")

    def test_status_is_found_behind_a_very_long_cookie(self):
        self.assertEqual(httpmsg.status_of(UNAUTHORIZED_401), "401")
        self.assertEqual(httpmsg.parse_reply(UNAUTHORIZED_401)["body"], "Unauthorized")


if __name__ == "__main__":
    unittest.main()
