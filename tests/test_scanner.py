"""Scanner rule tests: which probes are built and what counts as a candidate. Run: python tests/test_scanner.py"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import asyncio  # noqa: E402

import scanner  # noqa: E402
from httpmsg import MsgError  # noqa: E402

HOST = "ehealth.test.local"
GET_WITH_COOKIE = f"GET /api/patients/101 HTTP/1.1\r\nHost: {HOST}\r\nCookie: sid=s\r\n\r\n"
POST = f"POST /api/visits HTTP/1.1\r\nHost: {HOST}\r\nContent-Length: 2\r\n\r\n{{}}"


class PlanTests(unittest.TestCase):
    def test_only_safe_methods_are_scanned(self):
        with self.assertRaises(MsgError):
            scanner.endpoint_from_raw(POST, "history")

    def test_auth_probe_only_for_authenticated_endpoints(self):
        ep = scanner.endpoint_from_raw(GET_WITH_COOKIE, "history")
        anon = scanner.endpoint_from_raw(f"GET /api/public HTTP/1.1\r\nHost: {HOST}\r\n\r\n", "history")
        probes = scanner.build_probes([ep, anon], ("auth",), 50)
        auth = [p for p in probes if p.check == "auth"]
        self.assertEqual(len(auth), 1)
        self.assertNotIn("Cookie", auth[0].raw)

    def test_budget_cuts_probes_but_keeps_baselines_first(self):
        ep = scanner.endpoint_from_raw(GET_WITH_COOKIE, "history")
        probes = scanner.build_probes([ep], ("auth", "ids", "malformed", "reflect"), 2)
        self.assertEqual([p.check for p in probes], ["baseline", "auth"])

    def test_budget_covers_whole_endpoints_not_only_baselines(self):
        # distinct path templates: one representative per template, so the paths must differ
        eps = [scanner.endpoint_from_raw(f"GET /api/{name}/{i} HTTP/1.1\r\nHost: {HOST}\r\n\r\n", "history")
               for name, i in (('a', 1), ('b', 2), ('c', 3))]
        checks = ("ids", "malformed", "reflect")
        one = scanner.build_probes(eps, checks, 7)  # one endpoint = 5 probes; the second one does not fit whole
        self.assertEqual(len({p.endpoint.key for p in one}), 1)
        self.assertEqual({p.check for p in one}, {"baseline", "ids", "malformed", "reflect"})
        two = scanner.build_probes(eps, checks, 10)
        self.assertEqual(len({p.endpoint.key for p in two}), 2)
        for key in {p.endpoint.key for p in two}:
            self.assertIn("malformed", [p.check for p in two if p.endpoint.key == key])

    def test_ids_probe_uses_neighbors_and_skips_negative(self):
        zero = scanner.endpoint_from_raw(f"GET /api/patients/0 HTTP/1.1\r\nHost: {HOST}\r\n\r\n", "history")
        probes = scanner.build_probes([zero], ("ids",), 50)
        self.assertEqual([p.note for p in probes if p.check == "ids"], ["id 0->1"])

    def test_reflect_marker_is_unique_per_probe(self):
        ep = scanner.endpoint_from_raw(GET_WITH_COOKIE, "history")
        a = [p.marker for p in scanner.build_probes([ep], ("reflect",), 9) if p.check == "reflect"]
        b = [p.marker for p in scanner.build_probes([ep], ("reflect",), 9) if p.check == "reflect"]
        self.assertNotEqual(a, b)

    def test_unknown_check_rejected(self):
        ep = scanner.endpoint_from_raw(GET_WITH_COOKIE, "history")
        with self.assertRaises(MsgError):
            scanner.build_probes([ep], ("dos",), 5)


class JudgeTests(unittest.TestCase):
    def setUp(self):
        self.ep = scanner.endpoint_from_raw(GET_WITH_COOKIE, "history")
        self.base = {"status": "200", "length": 40}

    def _probe(self, check, raw=None, marker=""):
        return scanner.Probe(check, self.ep, raw or GET_WITH_COOKIE, marker=marker)

    def test_auth_not_enforced(self):
        f = scanner.judge(self._probe("auth"), "200", 30, "body", self.base)
        self.assertEqual(f["candidate"], "auth_not_enforced_candidate")

    def test_auth_enforced_gives_nothing(self):
        self.assertIsNone(scanner.judge(self._probe("auth"), "401", 0, "", self.base))

    def test_server_error_on_malformed(self):
        f = scanner.judge(self._probe("malformed"), "500", 9, "x", self.base)
        self.assertEqual(f["candidate"], "server_error_on_malformed_input")

    def test_reflection_needs_marker_in_body(self):
        probe = self._probe("reflect", marker="zqabc")
        self.assertEqual(scanner.judge(probe, "200", 20, "value zqabc", self.base)["candidate"],
                         "reflected_input_candidate")
        self.assertIsNone(scanner.judge(probe, "200", 20, "nothing here", self.base))

    def test_baseline_anonymous_only_for_endpoints_without_auth(self):
        anon_ep = scanner.endpoint_from_raw(f"GET /api/public HTTP/1.1\r\nHost: {HOST}\r\n\r\n", "history")
        f = scanner.judge(scanner.Probe("baseline", anon_ep, anon_ep.raw), "200", 50, "x", None,
                         "application/json")
        self.assertEqual(f["candidate"], "anonymous_200_candidate")
        self.assertIsNone(scanner.judge(self._probe("baseline"), "200", 50, "x", None))


class OnFindingTests(unittest.IsolatedAsyncioTestCase):
    async def test_callback_fires_for_each_candidate(self):
        ep = scanner.endpoint_from_raw(f"GET /api/patients/101 HTTP/1.1\r\nHost: {HOST}\r\nCookie: s=1\r\n\r\n", "history")
        probes = scanner.build_probes([ep], ("auth",), 10)

        async def send(probe):  # the auth probe succeeds: authorization is not enforced
            return "HTTP/1.1 200 OK\r\n\r\nbody"

        async def gate_wait(endpoint):
            return None

        seen, result = [], {}
        out = await scanner.run(probes, send, gate_wait, lambda e: None, min_delay_s=0, max_seconds=30,
                                should_stop=lambda: False, result=result, on_finding=seen.append)
        self.assertEqual(len(seen), len(out["findings"]))
        self.assertEqual([f["candidate"] for f in seen], ["auth_not_enforced_candidate"])


class ReproduceTests(unittest.IsolatedAsyncioTestCase):
    def _run(self, responses, max_requests=None):
        ep = scanner.endpoint_from_raw(f"GET /api/patients/101 HTTP/1.1\r\nHost: {HOST}\r\nCookie: s=1\r\n\r\n", "history")
        probes = scanner.build_probes([ep], ("auth",), 10)
        queue = list(responses)

        async def send(probe):  # pops scripted responses in order
            return queue.pop(0)

        async def gate_wait(endpoint):
            return None

        return scanner.run(probes, send, gate_wait, lambda e: None, min_delay_s=0, max_seconds=30,
                           should_stop=lambda: False, result={}, on_finding=lambda f: None,
                           max_requests=max_requests)

    async def test_candidate_that_reproduces_is_marked(self):
        ok = "HTTP/1.1 200 OK\r\n\r\nbody"
        out = await self._run([ok, ok, ok])  # baseline, auth probe, then the repeat of the candidate
        self.assertTrue(out["findings"][0]["reproduced"])

    async def test_flaky_candidate_is_kept_but_marked(self):
        ok = "HTTP/1.1 200 OK\r\n\r\nbody"
        denied = "HTTP/1.1 403 Forbidden\r\n\r\nno"
        out = await self._run([ok, ok, denied])  # the repeat is refused: the candidate is not confirmed
        self.assertEqual(len(out["findings"]), 1)
        self.assertFalse(out["findings"][0]["reproduced"])

    async def test_repeat_never_exceeds_the_scan_limit(self):
        ok = "HTTP/1.1 200 OK\r\n\r\nbody"
        # the limit is spent by the baseline and the auth probe, so the repeat must be skipped, not sent
        out = await self._run([ok, ok], max_requests=2)
        self.assertEqual(out["sent"], 2)
        self.assertIsNone(out["findings"][0]["reproduced"])
        self.assertIn("reserved", out["findings"][0]["reproduce_error"])


class SchemeTests(unittest.TestCase):
    """History does not store the scheme: the scope decides it when the Host header names a port."""

    def _raw(self, host_header: str) -> str:
        return f"GET /api/Products HTTP/1.1\r\nHost: {host_header}\r\n\r\n"

    def test_plain_http_port_is_found_when_the_scope_says_http(self):
        allowed = {"http://127.0.0.1:3000/api/Products"}
        ep = scanner.endpoint_in_scope(self._raw("127.0.0.1:3000"), "history", lambda u: u in allowed)
        self.assertIsNotNone(ep)
        self.assertFalse(ep.use_https)
        self.assertEqual(ep.origin, "http://127.0.0.1:3000")

    def test_https_is_kept_when_the_scope_allows_it(self):
        allowed = {"https://app.test:8443/api/Products"}
        ep = scanner.endpoint_in_scope(self._raw("app.test:8443"), "history", lambda u: u in allowed)
        self.assertTrue(ep.use_https)

    def test_outside_the_scope_under_either_scheme_gives_none(self):
        self.assertIsNone(scanner.endpoint_in_scope(self._raw("127.0.0.1:3000"), "history", lambda u: False))

    def test_without_a_port_the_https_default_is_the_only_guess(self):
        seen = []
        def in_scope(url):
            seen.append(url)
            return False
        scanner.endpoint_in_scope(self._raw(HOST), "history", in_scope)
        self.assertEqual(seen, [f"https://{HOST}/api/Products"])  # no http:// candidate is tried


class ActiveChecksTests(unittest.TestCase):
    """The params and post checks: which probes are built, and which responses count as candidates."""

    def _get(self, path: str):
        return scanner.endpoint_from_raw(f"GET {path} HTTP/1.1\r\nHost: {HOST}\r\n\r\n", "history")

    def _post(self, path: str, body: str):
        raw = f"POST {path} HTTP/1.1\r\nHost: {HOST}\r\nContent-Type: application/json\r\n\r\n{body}"
        return scanner.endpoint_from_raw(raw, "history", scanner.SAFE_METHODS + ("POST",))

    def test_post_is_refused_unless_the_methods_allow_it(self):
        raw = f"POST /api/x HTTP/1.1\r\nHost: {HOST}\r\n\r\n{{}}"
        with self.assertRaises(MsgError):
            scanner.endpoint_from_raw(raw, "history")
        self.assertEqual(scanner.endpoint_from_raw(raw, "history", scanner.SAFE_METHODS + ("POST",)).method, "POST")

    def test_query_parameters_get_a_quote_and_an_always_true_probe(self):
        probes = scanner.build_probes([self._get("/api/items?q=apple&page=2")], ("params",), 50)
        probes = [p for p in probes if p.check != "baseline"]  # the baseline request is always sent first
        self.assertEqual([p.check for p in probes], ["params_quote", "params_bool", "params_quote", "params_bool"])
        first = probes[0].raw.split("\r\n")[0]
        self.assertIn("q=apple%27", first)  # the quote is percent-encoded and the other parameter is kept
        self.assertIn("page=2", first)
        self.assertIn("OR%201%3D1--", probes[1].raw.split("\r\n")[0])

    def test_credential_parameters_are_kept_unchanged(self):
        probes = [p for p in scanner.build_probes([self._get("/api/items?token=abc&q=apple")], ("params",), 50)
                  if p.check != "baseline"]
        self.assertTrue(probes)
        for p in probes:
            self.assertIn("token=abc", p.raw.split("\r\n")[0])  # never varied, so the secret is not probed

    def test_json_string_fields_get_a_quote_and_a_marker(self):
        probes = scanner.build_probes([self._post("/api/feedback", '{"comment": "hi", "rating": 3}')], ("post",), 50)
        self.assertEqual([p.check for p in probes], ["post_quote", "post_reflect"])  # the number is not probed
        self.assertIn("hi'", probes[0].raw.split("\r\n\r\n", 1)[1])
        self.assertIn(probes[1].marker, probes[1].raw)

    def test_post_endpoints_are_ignored_unless_the_post_check_is_asked(self):
        ep = self._post("/api/feedback", '{"comment": "hi"}')
        self.assertEqual(scanner.build_probes([ep], ("params", "reflect"), 50), [])

    def test_login_like_post_gets_no_probes(self):
        self.assertEqual(scanner.build_probes([self._post("/rest/user/login", '{"comment": "hi"}')], ("post",), 50), [])

    def test_body_with_a_password_or_a_token_is_never_sent_again(self):
        with_password = self._post("/api/feedback", '{"comment": "hi", "user": {"password": "x"}}')
        with_jwt = self._post("/api/feedback", '{"data": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig"}')
        self.assertEqual(scanner.build_probes([with_password, with_jwt], ("post",), 50), [])

    def test_sql_error_text_is_a_candidate(self):
        probe = next(p for p in scanner.build_probes([self._get("/api/items?q=apple")], ("params",), 50)
                     if p.check == "params_quote")
        out = scanner.judge(probe, "500", 40, 'SQLITE_ERROR: near "\'": syntax error', None)
        self.assertEqual(out["candidate"], "sql_error_candidate")

    def test_always_true_condition_with_a_much_longer_body_is_a_candidate(self):
        probes = scanner.build_probes([self._get("/api/items?q=apple")], ("params",), 50)
        bool_probe = next(p for p in probes if p.check == "params_bool")
        base = {"status": "200", "length": 500}
        self.assertEqual(scanner.judge(bool_probe, "200", 4000, "x" * 4000, base)["candidate"], "sql_boolean_candidate")
        self.assertIsNone(scanner.judge(bool_probe, "200", 520, "x" * 520, base))  # same size: no candidate

    def test_error_on_the_always_true_payload_is_a_sql_error_candidate(self):
        probes = scanner.build_probes([self._get("/api/items?q=apple")], ("params",), 50)
        bool_probe = next(p for p in probes if p.check == "params_bool")
        out = scanner.judge(bool_probe, "500", 40, 'Error: SQLITE_ERROR: incomplete input', {"status": "200", "length": 500})
        self.assertEqual(out["candidate"], "sql_error_candidate")

    def test_static_files_are_not_checked_for_authorization(self):
        raw = f"GET /assets/public/images/apple.png HTTP/1.1\r\nHost: {HOST}\r\nCookie: s=1\r\n\r\n"
        ep = scanner.endpoint_from_raw(raw, "history")
        self.assertNotIn("auth", [p.check for p in scanner.build_probes([ep], ("auth",), 50)])
        self.assertIsNone(scanner.judge(scanner.Probe("baseline", ep, raw), "200", 300, "x" * 300, None))

    def test_api_endpoints_are_still_checked_for_authorization(self):
        raw = f"GET /api/Users/1 HTTP/1.1\r\nHost: {HOST}\r\nCookie: s=1\r\n\r\n"
        ep = scanner.endpoint_from_raw(raw, "history")
        self.assertIn("auth", [p.check for p in scanner.build_probes([ep], ("auth",), 50)])

    def test_marker_returned_in_a_post_field_is_reflected_input(self):
        probes = scanner.build_probes([self._post("/api/feedback", '{"comment": "hi"}')], ("post",), 50)
        reflect = next(p for p in probes if p.check == "post_reflect")
        out = scanner.judge(reflect, "201", 30, f"saved: {reflect.marker}", None)
        self.assertEqual(out["candidate"], "reflected_input_candidate")


class BurpReplyScanTests(unittest.TestCase):
    """The scanner reads status and body from a Burp reply, so its candidates depend on the response part."""

    WRAPPED = "HttpRequestResponse{httpRequest=GET /rest/x?q=apple HTTP/1.1\r\nHost: 127.0.0.1:3000\r\nCookie: a=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\r\n\r\n, httpResponse=HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/html\r\n\r\nSQLITE_ERROR: syntax error}"

    def test_status_and_body_come_from_the_response_part(self):
        self.assertEqual(scanner._status(self.WRAPPED), "500")
        self.assertIn("SQLITE_ERROR", scanner._body(self.WRAPPED))

    def test_sql_error_in_a_wrapped_reply_is_a_candidate(self):
        ep = scanner.endpoint_from_raw(f"GET /api/items?q=apple HTTP/1.1\r\nHost: {HOST}\r\n\r\n", "history")
        probe = next(p for p in scanner.build_probes([ep], ("params",), 50) if p.check == "params_quote")
        out = scanner.judge(probe, scanner._status(self.WRAPPED), 40, scanner._body(self.WRAPPED), None)
        self.assertEqual(out["candidate"], "sql_error_candidate")


class EmptyValueAndNoiseTests(unittest.TestCase):
    def _get(self, path: str):
        return scanner.endpoint_from_raw(f"GET {path} HTTP/1.1\r\nHost: {HOST}\r\n\r\n", "history")

    def test_empty_parameter_takes_the_value_seen_elsewhere_in_the_run(self):
        probes = scanner.build_probes([self._get("/rest/products/search?q="), self._get("/rest/products/search?q=apple")],
                                      ("params",), 50)
        quote = next(p for p in probes if p.check == "params_quote" and "q=" in p.raw.split("\r\n")[0])
        self.assertIn("q=apple%27", quote.raw.split("\r\n")[0])

    def test_empty_parameter_falls_back_when_nothing_is_known(self):
        probes = scanner.build_probes([self._get("/rest/products/search?q=")], ("params",), 50)
        quote = next(p for p in probes if p.check == "params_quote")
        self.assertIn(f"q={scanner.FALLBACK_PARAM_VALUE}%27", quote.raw.split("\r\n")[0])

    def test_anonymous_page_is_reported_only_when_it_is_json(self):
        anon = self._get("/rest/languages")
        probe = scanner.Probe("baseline", anon, anon.raw)
        self.assertIsNotNone(scanner.judge(probe, "200", 50, "x", None, "application/json; charset=utf-8"))
        self.assertIsNone(scanner.judge(probe, "200", 50, "<html></html>", None, "text/html"))


class GroupAndRepeatTests(unittest.TestCase):
    def _finding(self, url: str, reproduced, note: str = "quote in parameter q") -> dict:
        return {"candidate": "sql_error_candidate", "method": "GET", "url": url, "status": "500",
                "note": note, "reproduced": reproduced}

    def test_same_problem_on_one_path_is_one_row(self):
        rows = scanner.group_findings([
            self._finding("https://h/api/x?a=1", True, "quote in parameter a"),
            self._finding("https://h/api/x?b=1", None, "quote in parameter b"),
            self._finding("https://h/api/x?c=1", False, "quote in parameter c"),
        ])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["count"], 3)
        self.assertEqual(rows[0]["repeated"], 2)  # the one with None was not repeated
        self.assertEqual(rows[0]["confirmed"], 1)
        self.assertEqual(rows[0]["path"], "https://h/api/x")
        self.assertEqual(rows[0]["statuses"], ["500"])
        self.assertEqual(len(rows[0]["notes"]), 3)

    def test_different_paths_stay_separate(self):
        rows = scanner.group_findings([self._finding("https://h/api/x?a=1", True),
                                       self._finding("https://h/api/y?a=1", True)])
        self.assertEqual(sorted(r["path"] for r in rows), ["https://h/api/x", "https://h/api/y"])


class FormAndNestedBodyTests(unittest.TestCase):
    """POST bodies: form fields, JSON fields at any depth, and the per-endpoint field cap."""

    def _json_post(self, body: str):
        raw = f"POST /api/feedback HTTP/1.1\r\nHost: {HOST}\r\nContent-Type: application/json\r\n\r\n{body}"
        return scanner.endpoint_from_raw(raw, "history", scanner.SAFE_METHODS + ("POST",))

    def _form_post(self, body: str):
        raw = (f"POST /api/feedback HTTP/1.1\r\nHost: {HOST}\r\n"
               f"Content-Type: application/x-www-form-urlencoded\r\n\r\n{body}")
        return scanner.endpoint_from_raw(raw, "history", scanner.SAFE_METHODS + ("POST",))

    def test_form_fields_get_a_quote_and_a_marker_each(self):
        probes = scanner.build_probes([self._form_post("comment=hi&rating=3")], ("post",), 50)
        self.assertEqual([p.check for p in probes], ["post_quote", "post_reflect", "post_quote", "post_reflect"])
        self.assertIn("comment=hi%27&rating=3", probes[0].raw.split("\r\n\r\n", 1)[1])

    def test_form_with_a_credential_field_is_never_sent_again(self):
        self.assertEqual(scanner.build_probes([self._form_post("comment=hi&password=x")], ("post",), 50), [])

    def test_nested_json_fields_are_probed_at_their_own_path(self):
        body = '{"comment": "hi", "user": {"nickname": "bob", "tags": ["a", 5]}}'
        probes = scanner.build_probes([self._json_post(body)], ("post",), 50)
        self.assertEqual(len(probes), 6)  # comment, user.nickname, user.tags.0 (a number is not probed)
        nick = next(p for p in probes if p.note == "quote in field user.nickname")
        self.assertIn('"nickname": "bob\'"', nick.raw.split("\r\n\r\n", 1)[1])

    def test_probes_per_endpoint_are_capped(self):
        body = "{" + ", ".join(f'"f{i}": "v{i}"' for i in range(30)) + "}"
        probes = scanner.build_probes([self._json_post(body)], ("post",), 500)
        self.assertEqual(len(probes), 2 * scanner.MAX_POST_FIELDS)


class SessionCheckTests(unittest.IsolatedAsyncioTestCase):
    """An expired login makes every signed-in request fail with 401. The run must stop and say why."""

    def _endpoints(self, n: int) -> list:
        return [scanner.endpoint_from_raw(f"GET /api/item/{i} HTTP/1.1\r\nHost: {HOST}\r\nCookie: s=1\r\n\r\n",
                                          "history") for i in range(n)]

    async def _run(self, status: str) -> dict:
        probes = scanner.build_probes(self._endpoints(10), ("auth",), 100)

        async def send(probe):
            return f"HTTP/1.1 {status} X\r\n\r\nbody"

        async def gate_wait(endpoint):
            return None

        return await scanner.run(probes, send, gate_wait, lambda e: None, min_delay_s=0, max_seconds=30,
                                 should_stop=lambda: False, result={})

    async def test_expired_session_stops_the_run_with_a_reason(self):
        out = await self._run("401")
        self.assertTrue(out["stopped"].startswith("session looks expired"), out["stopped"])
        self.assertEqual(out["session"]["refused"], scanner.SESSION_MIN_SAMPLE)
        self.assertLess(out["sent"], 10)  # stopped early, not after every probe

    async def test_working_session_is_not_stopped(self):
        out = await self._run("200")
        self.assertIsNone(out["stopped"])
        self.assertEqual(out["session"], {"signed_in": 10, "refused": 0})


class EmptyAnswerTests(unittest.TestCase):
    """An empty answer is not a leak: {} or {"user":{}} without a session must not become a candidate."""

    def test_has_data_ignores_empty_json(self):
        self.assertFalse(scanner._has_data('{"user":{}}'))
        self.assertFalse(scanner._has_data("[]"))
        self.assertFalse(scanner._has_data("null"))
        self.assertFalse(scanner._has_data(""))
        self.assertTrue(scanner._has_data('{"status":"success","data":[{"id":1}]}'))
        self.assertTrue(scanner._has_data("plain text answer"))

    def test_auth_and_neighbour_candidates_need_data_in_the_answer(self):
        ep = scanner.endpoint_from_raw(f"GET /rest/user/whoami HTTP/1.1\r\nHost: {HOST}\r\nCookie: s=1\r\n\r\n",
                                       "history")
        probe = scanner.Probe("auth", ep, ep.raw)
        base = {"status": "200", "length": 50}
        self.assertIsNone(scanner.judge(probe, "200", 11, '{"user":{}}', base))
        self.assertEqual(scanner.judge(probe, "200", 20, '{"user":{"id":1}}', base)["candidate"],
                         "auth_not_enforced_candidate")


class FindingDetailTests(unittest.TestCase):
    """Evidence in findings, owner comparison for object access, and 5xx on POST probes."""

    def _ep(self, path: str, method: str = "GET"):
        return scanner.endpoint_from_raw(f"{method} {path} HTTP/1.1\r\nHost: {HOST}\r\nCookie: s=1\r\n\r\n", "history")

    def test_evidence_is_short_and_masked(self):
        ep = self._ep("/api/x")
        probe = scanner.Probe("auth", ep, ep.raw)
        text = '{"user": {"id": 1}, "note": "token=supersecret12 ' + "x" * 400 + '"}'
        out = scanner.judge(probe, "200", len(text), text, {"status": "200", "length": 9})
        self.assertLessEqual(len(out["evidence"]), scanner.EVIDENCE_CHARS)
        self.assertNotIn("supersecret12", out["evidence"])

    def test_other_owner_object_is_high_severity(self):
        ep = self._ep("/rest/basket/1")
        probe = scanner.build_probes([ep], ("ids",), 50)
        probe = next(p for p in probe if p.check == "ids")
        base = {"status": "200", "length": 40, "owner": "1"}
        out = scanner.judge(probe, "200", 60, '{"status":"success","data":{"UserId":2,"Products":[]}}', base)
        self.assertEqual(out["candidate"], "other_owner_object_candidate")
        self.assertEqual(out["hint"], "high")

    def test_same_owner_stays_a_low_neighbour_finding(self):
        ep = self._ep("/rest/basket/1")
        probe = next(p for p in scanner.build_probes([ep], ("ids",), 50) if p.check == "ids")
        base = {"status": "200", "length": 40, "owner": "1"}
        out = scanner.judge(probe, "200", 60, '{"data":{"UserId":1}}', base)
        self.assertEqual(out["candidate"], "neighbor_object_exists")

    def test_owner_is_found_inside_nested_data(self):
        self.assertEqual(scanner._owner('{"status":"success","data":{"UserId":7}}'), "7")
        self.assertIsNone(scanner._owner('{"user":{}}'))

    def test_server_error_on_a_harmless_post_value_is_a_candidate(self):
        ep = scanner.endpoint_from_raw(
            f"POST /api/BasketItems HTTP/1.1\r\nHost: {HOST}\r\nContent-Type: application/json\r\n\r\n"
            '{"BasketId": "1"}', "history", scanner.SAFE_METHODS + ("POST",))
        probe = next(p for p in scanner.build_probes([ep], ("post",), 50) if p.check == "post_reflect")
        out = scanner.judge(probe, "500", 30, "Internal Server Error", None)
        self.assertEqual(out["candidate"], "server_error_on_malformed_input")


class SeverityCalibrationTests(unittest.TestCase):
    def _ep(self, path: str, auth: bool = False):
        cookie = "Cookie: s=1\\r\\n" if auth else ""
        return scanner.endpoint_from_raw(f"GET {path} HTTP/1.1\\r\\nHost: {HOST}\\r\\n{cookie}\\r\\n", "history")

    def test_signed_in_answer_about_a_person_is_high(self):
        ep = self._ep("/rest/user/whoami", auth=True)
        out = scanner.judge(scanner.Probe("auth", ep, ep.raw), "200", 40, '{"user":{"email":"a@b.test"}}',
                            {"status": "200", "length": 9})
        self.assertEqual((out["candidate"], out["hint"]), ("auth_not_enforced_candidate", "high"))

    def test_answer_with_no_person_is_only_a_low_lead(self):
        ep = self._ep("/rest/continue-code", auth=True)
        out = scanner.judge(scanner.Probe("auth", ep, ep.raw), "200", 80, '{"continueCode":"abc123xyz"}',
                            {"status": "200", "length": 9})
        self.assertEqual(out["hint"], "low")

    def test_anonymous_admin_config_is_medium_and_public_list_is_low(self):
        admin = self._ep("/rest/admin/application-configuration")
        public = self._ep("/rest/languages")
        text = '{"status":"success","data":[{"key":"en"}]}'
        self.assertEqual(scanner.judge(scanner.Probe("baseline", admin, admin.raw), "200", 50, text, None,
                                       "application/json")["hint"], "medium")
        self.assertEqual(scanner.judge(scanner.Probe("baseline", public, public.raw), "200", 50, text, None,
                                       "application/json")["hint"], "low")

    def test_group_takes_the_worst_hint_of_its_findings(self):
        rows = scanner.group_findings([
            {"candidate": "auth_not_enforced_candidate", "method": "GET", "url": "https://h/x", "hint": "low"},
            {"candidate": "auth_not_enforced_candidate", "method": "GET", "url": "https://h/x?a=1", "hint": "high"},
        ])
        self.assertEqual(rows[0]["hint"], "high")


class ReloginTests(unittest.IsolatedAsyncioTestCase):
    """An expired session is renewed in the run: the rest of the probes carry the new bearer token."""

    def _endpoints(self, n: int) -> list:
        return [scanner.endpoint_from_raw(
            f"GET /api/item/{i} HTTP/1.1\r\nHost: {HOST}\r\nAuthorization: Bearer OLD\r\n\r\n", "history")
            for i in range(n)]

    async def _run(self, status_for, relogin, n: int = 10) -> tuple[dict, list]:
        probes = scanner.build_probes(self._endpoints(n), ("auth",), 200)
        sent = []

        async def send(probe):
            sent.append(probe.raw)
            return status_for(probe.raw)

        async def gate_wait(endpoint):
            return None

        out = await scanner.run(probes, send, gate_wait, lambda e: None, min_delay_s=0, max_seconds=30,
                                should_stop=lambda: False, result={}, relogin=relogin)
        return out, sent

    async def test_renewed_session_is_used_for_the_rest_of_the_run(self):
        async def relogin():
            return "NEW"

        def status_for(raw):
            if "Bearer NEW" in raw:
                return 'HTTP/1.1 200 OK\r\n\r\n{"data": 1}'
            return "HTTP/1.1 401 X\r\n\r\nno"

        out, sent = await self._run(status_for, relogin)
        self.assertEqual(out["relogins"], 1)
        self.assertIsNone(out["stopped"])
        self.assertTrue(any("Bearer NEW" in raw for raw in sent))
        for raw in sent:  # the anonymous probes never carry a token
            if "Authorization" not in raw:
                self.assertNotIn("Bearer", raw)

    async def test_renewals_are_limited_per_run(self):
        async def relogin():
            return "NEW"

        out, _ = await self._run(lambda raw: "HTTP/1.1 401 X\r\n\r\nno", relogin)
        self.assertEqual(out["relogins"], scanner.SCAN_MAX_RELOGINS)
        self.assertTrue(out["stopped"].startswith("session looks expired"))

    async def test_failed_sign_in_stops_with_a_reason(self):
        async def relogin():
            return None

        out, _ = await self._run(lambda raw: "HTTP/1.1 401 X\r\n\r\nno", relogin)
        self.assertIn("did not work", out["stopped"])


if __name__ == "__main__":
    unittest.main()
