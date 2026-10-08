"""Tests for the pure HTTP functions: history parsing, request building, position substitution for Intruder.

Run: python tests/test_httpmsg.py
"""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from httpmsg import MsgError, apply_position, build_request, json_records, parse_history, parse_position  # noqa: E402
import httpmsg  # noqa: E402

HOST = "ehealth.test.local"
GET_QUERY = (f"GET /api/visits?patient=101&lang=uk&sort= HTTP/1.1\r\nHost: {HOST}\r\n"
             f"User-Agent: t\r\nX-Role: patient\r\n\r\n")
POST_JSON = (f"POST /api/visits HTTP/1.1\r\nHost: {HOST}\r\nContent-Type: application/json\r\n"
             f"Content-Length: 22\r\n\r\n" + json.dumps({"patient": {"id": 101}, "note": "x"}, ensure_ascii=False))


class ApplyPositionTests(unittest.TestCase):
    def test_query_replaces_only_target_and_keeps_others_raw(self):
        out = apply_position(GET_QUERY, "query:patient", "102")
        self.assertTrue(out.startswith("GET /api/visits?patient=102&lang=uk&sort= HTTP/1.1\r\n"))
        self.assertIn(f"Host: {HOST}", out)

    def test_query_payload_is_encoded(self):
        out = apply_position(GET_QUERY, "query:patient", "1 OR 1=1&x")
        self.assertIn("patient=1%20OR%201%3D1%26x", out.split("\r\n")[0])

    def test_query_missing_param_fails(self):
        with self.assertRaises(MsgError):
            apply_position(GET_QUERY, "query:absent", "1")

    def test_path_segment(self):
        # 0-based segment indices after the leading slash: /api/visits -> api(0), visits(1)
        out = apply_position(GET_QUERY, "path:1", "7")
        self.assertTrue(out.startswith("GET /api/7?patient=101&lang=uk&sort= HTTP/1.1"))

    def test_path_index_out_of_range(self):
        with self.assertRaises(MsgError):
            apply_position(GET_QUERY, "path:9", "1")

    def test_header_replaced_and_content_length_untouched_for_get(self):
        out = apply_position(GET_QUERY, "header:X-Role", "admin")
        self.assertIn("X-Role: admin", out)
        self.assertNotIn("Content-Length", out)

    def test_header_missing_fails(self):
        with self.assertRaises(MsgError):
            apply_position(GET_QUERY, "header:X-Absent", "1")

    def test_json_field_nested_and_length_recomputed(self):
        out = apply_position(POST_JSON, "json:patient.id", "102")
        body = out.partition("\r\n\r\n")[2]
        self.assertEqual(json.loads(body)["patient"]["id"], "102")
        self.assertIn(f"Content-Length: {len(body.encode())}", out)

    def test_json_unknown_field_refused_no_new_keys(self):
        with self.assertRaises(MsgError):
            apply_position(POST_JSON, "json:patient.role", "admin")

    def test_json_body_not_json(self):
        raw = f"POST /x HTTP/1.1\r\nHost: {HOST}\r\n\r\nplain text"
        with self.assertRaises(MsgError):
            apply_position(raw, "json:a", "1")

    def test_bad_position_spec(self):
        for spec in ("cookie:sid", "query", "query:", "json"):
            with self.assertRaises(MsgError):
                parse_position(spec)


class BuildRequestTests(unittest.TestCase):
    def test_host_cannot_be_set_or_removed(self):
        with self.assertRaises(MsgError):
            build_request(GET_QUERY, "GET", "/api/x", set_headers={"Host": "evil.example"})
        with self.assertRaises(MsgError):
            build_request(GET_QUERY, "GET", "/api/x", remove_headers=["Host"])

    def test_header_injection_refused(self):
        with self.assertRaises(MsgError):
            build_request(GET_QUERY, "GET", "/api/x", set_headers={"X-A": "1\r\nX-B: 2"})

    def test_bad_header_name_refused(self):
        with self.assertRaises(MsgError):
            build_request(GET_QUERY, "GET", "/api/x", set_headers={"X A": "1"})


class ParseHistoryTests(unittest.TestCase):
    def test_json_list(self):
        self.assertEqual(len(parse_history(json.dumps([{"request": "GET / HTTP/1.1"}]))), 1)

    def test_records_per_line_with_blank_lines(self):
        rec = json.dumps({"request": "GET / HTTP/1.1\r\nHost: a\r\n\r\n", "response": "HTTP/1.1 200 OK\r\n\r\nok"})
        items = parse_history(rec + "\n\n" + rec)
        self.assertEqual(len(items), 2)
        self.assertNotIn("response_truncated", items[0])

    def test_response_truncated_per_field(self):
        raw = ('{"request":"GET /a HTTP/1.1\\r\\nHost: h\\r\\n\\r\\n","response":"HTTP/1.1 200 OK\\r\\n\\r\\nabc'
               '.. (truncated)')
        items = parse_history(raw)
        self.assertTrue(items[0]["response_truncated"])
        self.assertFalse(items[0]["request_truncated"])
        self.assertTrue(items[0]["response"].startswith("HTTP/1.1 200 OK"))

    def test_request_truncated_flagged(self):
        self.assertTrue(parse_history('{"request":"GET /very-long.. (truncated)')[0]["request_truncated"])

    def test_end_marker_and_garbage(self):
        self.assertEqual(parse_history("Reached end of items"), [])
        with self.assertRaises(MsgError):
            parse_history("garbage\nmore garbage")


class JsonRecordsTests(unittest.TestCase):
    def test_lines_with_truncated_tail(self):
        recs, cut = json_records('{"name":"A"}\n{"name":"B"}\n{"name":"C", (truncated)')
        self.assertEqual([r["name"] for r in recs], ["A", "B"])
        self.assertTrue(cut)

    def test_json_list_and_single_object(self):
        self.assertEqual(json_records('[{"name":"X"},{"name":"Y"}]'), ([{"name": "X"}, {"name": "Y"}], False))
        self.assertEqual(json_records('{"name":"Z"}'), ([{"name": "Z"}], False))

    def test_end_marker_and_noise(self):
        self.assertEqual(json_records("Reached end of items"), ([], False))
        recs, _ = json_records('garbage\n{"name":"ok"}\nmore garbage')
        self.assertEqual(recs, [{"name": "ok"}])


class BurpReplyTests(unittest.TestCase):
    """Burp wraps a sent request and its reply. The status must be found even when the request part is long."""

    WRAPPED = "HttpRequestResponse{httpRequest=GET /rest/x?q=apple HTTP/1.1\r\nHost: 127.0.0.1:3000\r\nCookie: a=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\r\n\r\n, httpResponse=HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/html\r\n\r\nSQLITE_ERROR: syntax error}"

    def test_unwrap_returns_the_response_part_only(self):
        out = httpmsg.unwrap_response(self.WRAPPED)
        self.assertTrue(out.startswith("HTTP/1.1 500"))
        self.assertTrue(out.endswith("syntax error"))  # the closing brace of the wrapper is removed

    def test_status_is_found_after_a_long_request(self):
        self.assertEqual(httpmsg.status_of(self.WRAPPED), "500")

    def test_plain_responses_are_unchanged(self):
        plain = "HTTP/1.1 200 OK\r\n\r\n{}"
        self.assertEqual(httpmsg.unwrap_response(plain), plain)
        self.assertEqual(httpmsg.status_of(plain), "200")


class ParseReplyTests(unittest.TestCase):
    def test_wrapped_reply_is_split_into_fields(self):
        raw = ("HttpRequestResponse{httpRequest=GET / HTTP/1.1\r\nHost: a\r\n\r\n, "
               "httpResponse=HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\n"
               "Set-Cookie: s=1\r\n\r\n{\"e\": 1}}")
        out = httpmsg.parse_reply(raw)
        self.assertEqual(out["status"], "404")
        self.assertEqual(out["reason"], "Not Found")
        self.assertEqual(out["headers"]["content-type"], "application/json")
        self.assertEqual(out["headers"]["set-cookie"], "s=1")
        self.assertEqual(out["body"], '{"e": 1}')


if __name__ == "__main__":
    unittest.main()
