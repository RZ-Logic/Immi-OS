"""Tests for scripts/make_pull.py.

No network: every test injects a fake transport. The fake token and every
secret-shaped value are assembled at runtime so this file holds no literal
the pre-commit hook would block. All fixtures are synthetic and minimal.
"""

import contextlib
import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
import urllib.parse
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import make_pull  # noqa: E402
from make_pull import Response  # noqa: E402

TOKEN = "-".join(["0a1b2c3d", "4e5f", "6a7b", "8c9d", "0e1f2a3b4c5d"]) + "x"
ALNUM = "A1b2C3d4E5f6G7h8J9k0L1m2N3p4Q5r6"
FIXED_NOW = datetime(2026, 10, 28, 12, 0, 0, tzinfo=timezone.utc)


def synthetic_blueprint(name, extra_module=None):
    """Minimal export-shaped blueprint. Key order deliberately not sorted."""
    flow = [{
        "id": 1,
        "module": "gateway:CustomWebHook",
        "version": 1,
        "parameters": {"hook": 1},
        "mapper": {},
        "metadata": {"designer": {"x": 0, "y": 0}},
    }]
    if extra_module:
        flow.append(extra_module)
    return {
        "name": name,
        "flow": flow,
        "metadata": {"version": 1, "scenario": {"maxErrors": 3, "autoCommit": True}},
    }


def secret_http_module():
    return {
        "id": 2,
        "module": "http:ActionSendData",
        "version": 3,
        "mapper": {
            "url": "https://example.invalid/hook",
            "method": "post",
            "headers": [{"name": "Authorization", "value": "Bearer " + "lit" + ALNUM}],
        },
        "metadata": {},
    }


class FakeMake:
    """Fake transport that serves a scripted Make API and records every call."""

    def __init__(self, scenarios, blueprints=None, drafts=None, hooks=None):
        self.scenarios = scenarios                  # list of list-entry dicts
        self.hooks = hooks                          # None: the token lacks hooks:read (403), else a list of raw hook dicts
        self.blueprints = blueprints or {}          # id -> blueprint dict
        self.drafts = drafts or {}                  # id -> draft blueprint or int status
        self.calls = []                             # (method, url, headers, timeout)
        self.queued = {}                            # path -> list of Response to serve first

    def queue(self, path, *responses):
        self.queued.setdefault(path, []).extend(responses)

    def __call__(self, method, url, headers, timeout):
        self.calls.append((method, url, dict(headers), timeout))
        parts = urllib.parse.urlsplit(url)
        assert parts.scheme == "https"
        path = parts.path[len("/api/v2"):]
        q = dict(urllib.parse.parse_qsl(parts.query))
        if self.queued.get(path):
            item = self.queued[path].pop(0)
            if isinstance(item, Exception):
                raise item
            return item
        if path == "/hooks":
            if self.hooks is None:
                return Response(403, {}, b'{"code":"SC403","message":"Access denied"}')
            off = int(q.get("pg[offset]", 0))
            lim = int(q.get("pg[limit]", 50))
            return self._json({"hooks": self.hooks[off:off + lim]})
        if path == "/scenarios":
            off = int(q["pg[offset]"])
            lim = int(q["pg[limit]"])
            page = sorted(self.scenarios, key=lambda s: s["id"])[off:off + lim]
            return self._json({"scenarios": page, "pg": {"limit": lim, "offset": off}})
        if path.startswith("/scenarios/") and path.endswith("/blueprint"):
            sid = int(path.split("/")[2])
            bp = self.blueprints[sid]
            if q.get("draft") == "true" and sid in self.drafts:
                d = self.drafts[sid]
                if isinstance(d, int):
                    return Response(d, {}, b'{"message":"not found","code":"IM005"}')
                bp = d
            return self._json({"code": "OK", "response": {
                "blueprint": bp,
                "scheduling": {"type": "indefinitely", "interval": 900},
                "idSequence": 3,
                "created": "2026-01-01T00:00:00.000Z",
                "last_edit": "2026-10-01T00:00:00.000Z",
                "version": 7,
            }})
        return Response(404, {}, b"{}")

    @staticmethod
    def _json(obj):
        return Response(200, {"content-type": "application/json"}, json.dumps(obj).encode("utf-8"))

    def paths(self):
        return [urllib.parse.urlsplit(c[1]).path for c in self.calls]

    def queries(self):
        return [dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(c[1]).query)) for c in self.calls]


def entry(sid, name, active=True):
    return {"id": sid, "name": name, "isActive": active, "isPaused": False,
            "scheduling": {"type": "indefinitely", "interval": 900},
            "lastEdit": "2026-10-01T00:00:00.000Z"}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="make_pull_test_")
        self.out = os.path.join(self.tmp, "blueprints")
        os.makedirs(self.out)
        self.env = os.path.join(self.tmp, ".env")
        self.write_env(TOKEN, "us2", "123")
        self.sleeps = []

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write_env(self, token, zone, team):
        lines = ["# synthetic", ""]
        if token is not None:
            lines.append("MAKE_API_TOKEN=" + token)
        if zone is not None:
            lines.append("MAKE_ZONE=" + zone)
        if team is not None:
            lines.append("MAKE_TEAM_ID=" + team)
        with open(self.env, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")

    def run_main(self, fake, *extra):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = make_pull.main(["--env", self.env, "--out", self.out, *extra],
                                  transport=fake, sleep=self.sleeps.append,
                                  environ={}, now=lambda: FIXED_NOW)
        output = out.getvalue() + err.getvalue()
        self.assertNotIn(TOKEN, output)
        for name in os.listdir(self.out) if os.path.isdir(self.out) else []:
            with open(os.path.join(self.out, name), encoding="utf-8") as fh:
                self.assertNotIn(TOKEN, fh.read())
        return code, output

    def snapshot(self):
        out = {}
        for n in os.listdir(self.out):
            with open(os.path.join(self.out, n), "rb") as fh:
                out[n] = fh.read()
        return out

    def manifest(self):
        with open(os.path.join(self.out, "manifest.json"), encoding="utf-8") as fh:
            return json.load(fh)

    def simple_fake(self, n=2):
        scen = [entry(i, f"Scenario {i}") for i in range(1, n + 1)]
        bps = {i: synthetic_blueprint(f"Scenario {i}") for i in range(1, n + 1)}
        return FakeMake(scen, bps)


class TestConfig(Base):
    def test_parse_env_ignores_comments_blanks_and_strips_quotes(self):
        parsed = make_pull.parse_env('# c\n\nA=1\n  B = "two words" \nC=\'x\'\nnoequals\n=v\n')
        self.assertEqual(parsed, {"A": "1", "B": "two words", "C": "x"})

    def test_missing_token_exits_2_without_echoing_values(self):
        self.write_env(None, "us2", "98765")
        code, output = self.run_main(self.simple_fake())
        self.assertEqual(code, 2)
        self.assertIn("MAKE_API_TOKEN", output)
        self.assertNotIn("98765", output)
        self.assertFalse(os.path.exists(os.path.join(self.out, "manifest.json")))

    def test_empty_token_exits_2(self):
        self.write_env("", "us2", "123")
        code, _ = self.run_main(self.simple_fake())
        self.assertEqual(code, 2)

    def test_missing_env_file_exits_2(self):
        os.remove(self.env)
        code, output = self.run_main(self.simple_fake())
        self.assertEqual(code, 2)
        self.assertIn("not found", output)

    def test_bad_zone_exits_2_without_echo(self):
        self.write_env(TOKEN, "zz9weird", "123")
        code, output = self.run_main(self.simple_fake())
        self.assertEqual(code, 2)
        self.assertNotIn("zz9weird", output)

    def test_non_numeric_team_exits_2(self):
        self.write_env(TOKEN, "eu1", "12a")
        code, _ = self.run_main(self.simple_fake())
        self.assertEqual(code, 2)

    def test_no_request_made_on_config_error(self):
        self.write_env(None, "us2", "123")
        fake = self.simple_fake()
        self.run_main(fake)
        self.assertEqual(fake.calls, [])

    def test_environment_overrides_file(self):
        cfg = make_pull.load_config(self.env, {"MAKE_ZONE": "eu2"})
        self.assertEqual(cfg.zone, "eu2")
        self.assertNotIn(TOKEN, repr(cfg))


class TestRequests(Base):
    def test_auth_header_get_only_zone_and_timeout(self):
        fake = self.simple_fake()
        code, _ = self.run_main(fake)
        self.assertEqual(code, 0)
        self.assertTrue(fake.calls)
        for method, url, headers, timeout in fake.calls:
            self.assertEqual(method, "GET")
            self.assertTrue(url.startswith("https://us2.make.com/api/v2/"))
            self.assertEqual(headers["Authorization"], "Token " + TOKEN)
            self.assertGreater(timeout, 0)

    def test_live_blueprint_uses_draft_false_and_draft_check_uses_true(self):
        fake = self.simple_fake(1)
        self.run_main(fake)
        bp_queries = [q for p, q in zip(fake.paths(), fake.queries()) if p.endswith("/blueprint")]
        self.assertEqual([q["draft"] for q in bp_queries], ["false", "true"])

    def test_skip_draft_check_only_fetches_live(self):
        fake = self.simple_fake(2)
        code, _ = self.run_main(fake, "--skip-draft-check")
        self.assertEqual(code, 0)
        bp_queries = [q for p, q in zip(fake.paths(), fake.queries()) if p.endswith("/blueprint")]
        self.assertEqual([q["draft"] for q in bp_queries], ["false", "false"])
        self.assertTrue(all(s["draft_differs"] is None for s in self.manifest()["scenarios"]))

    def test_list_params(self):
        fake = self.simple_fake(1)
        self.run_main(fake)
        q = fake.queries()[0]
        self.assertEqual(q["teamId"], "123")
        self.assertEqual(q["pg[offset]"], "0")
        self.assertEqual(q["pg[limit]"], str(make_pull.PAGE_LIMIT))
        self.assertEqual(q["pg[sortBy]"], "id")

    def test_pagination_walks_offsets(self):
        n = 2 * make_pull.PAGE_LIMIT + 5
        scen = [entry(i, f"S{i}") for i in range(1, n + 1)]
        fake = FakeMake(scen, {i: synthetic_blueprint(f"S{i}") for i in range(1, n + 1)})
        cfg = make_pull.load_config(self.env, {})
        client = make_pull.MakeClient(cfg, transport=fake, sleep=self.sleeps.append)
        got = make_pull.list_scenarios(client, "123")
        self.assertEqual([s["id"] for s in got], list(range(1, n + 1)))
        offsets = [q["pg[offset]"] for q in fake.queries()]
        # Paging stops on an empty page, never on a short one.
        self.assertEqual(offsets, ["0", "100", "200", "205"])

    def test_server_page_cap_does_not_truncate_listing(self):
        # Review finding make-api-F2(b): a server that caps pg[limit] below
        # the requested value must not end the listing after one page.
        n = 15
        ids = range(1, n + 1)
        bps = {i: synthetic_blueprint(f"S{i}") for i in ids}
        self.run_main(FakeMake([entry(i, f"S{i}") for i in ids], bps))

        class Capped(FakeMake):
            def __call__(self, method, url, headers, timeout):
                url = url.replace("pg%5Blimit%5D=" + str(make_pull.PAGE_LIMIT), "pg%5Blimit%5D=10")
                return super().__call__(method, url, headers, timeout)

        fake = Capped([entry(i, f"S{i}") for i in ids], bps)
        code, output = self.run_main(fake)
        self.assertEqual(code, 0, output)
        self.assertEqual(len([f for f in os.listdir(self.out) if f != "manifest.json"]), n)
        self.assertNotIn("Removed", output)
        self.assertEqual(self.manifest()["scenario_count"], n)

    def test_pagination_exact_multiple_stops_on_empty_page(self):
        n = make_pull.PAGE_LIMIT
        fake = FakeMake([entry(i, f"S{i}") for i in range(1, n + 1)], {})
        cfg = make_pull.load_config(self.env, {})
        client = make_pull.MakeClient(cfg, transport=fake, sleep=self.sleeps.append)
        got = make_pull.list_scenarios(client, "123")
        self.assertEqual(len(got), n)
        self.assertEqual([q["pg[offset]"] for q in fake.queries()], ["0", "100"])

    def test_pagination_ignored_by_server_is_an_error(self):
        n = make_pull.PAGE_LIMIT
        page = {"scenarios": [entry(i, f"S{i}") for i in range(1, n + 1)]}
        fake = FakeMake([], {})
        fake.queue("/scenarios", FakeMake._json(page), FakeMake._json(page))
        code, output = self.run_main(fake)
        self.assertEqual(code, 3)
        self.assertIn("returned twice", output)


class TestBackoff(Base):
    def test_429_honours_retry_after(self):
        fake = self.simple_fake(1)
        fake.queue("/scenarios", Response(429, {"retry-after": "7"}, b""))
        code, _ = self.run_main(fake)
        self.assertEqual(code, 0)
        self.assertEqual(self.sleeps, [7.0])

    def test_429_without_retry_after_waits_out_the_rate_window(self):
        # Make limits per organization per minute and sends no Retry-After,
        # so each bare 429 waits a full window (review finding make-api-F4).
        fake = self.simple_fake(1)
        fake.queue("/scenarios", *[Response(429, {}, b"") for _ in range(3)])
        code, _ = self.run_main(fake)
        self.assertEqual(code, 0)
        self.assertEqual(self.sleeps, [make_pull.RATE_WINDOW_S] * 3)

    def test_429_retry_budget_outlasts_a_rate_window(self):
        slept = []
        cfg = make_pull.load_config(self.env, {})
        client = make_pull.MakeClient(cfg, transport=lambda *a: Response(429, {}, b""), sleep=slept.append)
        with self.assertRaises(make_pull.PullError):
            client.get_json("/scenarios", [])
        self.assertGreaterEqual(sum(slept), 90.0)

    def test_5xx_without_retry_after_still_backs_off_exponentially(self):
        fake = self.simple_fake(1)
        fake.queue("/scenarios", *[Response(503, {}, b"") for _ in range(3)])
        code, _ = self.run_main(fake)
        self.assertEqual(code, 0)
        self.assertEqual(self.sleeps, [1.0, 2.0, 4.0])

    def test_retry_after_is_capped(self):
        fake = self.simple_fake(1)
        fake.queue("/scenarios", Response(429, {"retry-after": "100000"}, b""))
        self.run_main(fake)
        self.assertEqual(self.sleeps, [make_pull.MAX_WAIT_S])

    def test_retry_after_http_date(self):
        secs = make_pull.retry_after_seconds("Wed, 28 Oct 2026 12:00:30 GMT", now=FIXED_NOW.timestamp())
        self.assertAlmostEqual(secs, 30.0)
        self.assertIsNone(make_pull.retry_after_seconds("soon"))

    def test_429_retries_are_bounded_and_nothing_written(self):
        fake = self.simple_fake(1)
        fake.queue("/scenarios", *[Response(429, {}, b"") for _ in range(make_pull.MAX_RETRIES + 1)])
        code, output = self.run_main(fake)
        self.assertEqual(code, 3)
        self.assertIn("HTTP 429", output)
        self.assertEqual(len(self.sleeps), make_pull.MAX_RETRIES)
        self.assertEqual(os.listdir(self.out), [])

    def test_5xx_retried(self):
        fake = self.simple_fake(1)
        fake.queue("/scenarios/1/blueprint", Response(503, {}, b""))
        code, _ = self.run_main(fake)
        self.assertEqual(code, 0)
        self.assertEqual(self.sleeps, [1.0])

    def test_network_error_retried_then_fails(self):
        fake = self.simple_fake(1)
        errs = [make_pull.TransientError("TimeoutError") for _ in range(make_pull.MAX_RETRIES + 1)]
        fake.queue("/scenarios", *errs)
        code, output = self.run_main(fake)
        self.assertEqual(code, 3)
        self.assertIn("network error", output)


class TestFailures(Base):
    def test_401_fails_without_echoing_token(self):
        fake = self.simple_fake(1)
        body = json.dumps({"code": "IM005", "message": "Invalid token " + TOKEN}).encode()
        fake.queue("/scenarios", Response(401, {}, body))
        code, output = self.run_main(fake)
        self.assertEqual(code, 3)
        self.assertIn("HTTP 401", output)
        self.assertIn("IM005", output)
        self.assertNotIn("Invalid token", output)

    def test_partial_token_in_error_never_printed(self):
        # Review finding security-SEC-10: a masked or partial token echoed
        # in an error message must not reach stderr.
        for status in (401, 403, 400):
            with self.subTest(status=status):
                fake = self.simple_fake(1)
                body = json.dumps({"code": "IM005", "message": "bad token " + TOKEN[:8] + "..."}).encode()
                fake.queue("/scenarios", Response(status, {}, body))
                code, output = self.run_main(fake)
                self.assertEqual(code, 3)
                for i in range(len(TOKEN) - make_pull.REDACT_MIN_FRAGMENT + 1):
                    self.assertNotIn(TOKEN[i:i + make_pull.REDACT_MIN_FRAGMENT], output)

    def test_redact_removes_fragments(self):
        text = "a " + TOKEN + " b " + TOKEN[3:12] + " c " + TOKEN[-7:]
        out = make_pull.redact(text, TOKEN)
        for i in range(len(TOKEN) - make_pull.REDACT_MIN_FRAGMENT + 1):
            self.assertNotIn(TOKEN[i:i + make_pull.REDACT_MIN_FRAGMENT], out)
        self.assertTrue(out.startswith("a <redacted> b "))

    def test_failure_mid_pull_writes_nothing(self):
        fake = self.simple_fake(3)
        stale = os.path.join(self.out, "old__999.json")
        with open(stale, "w", encoding="utf-8") as fh:
            fh.write("{}\n")
        fake.queue("/scenarios/3/blueprint", Response(400, {}, b"{}"))
        code, _ = self.run_main(fake)
        self.assertEqual(code, 3)
        self.assertEqual(os.listdir(self.out), ["old__999.json"])

    def test_malformed_blueprint_payload_fails(self):
        fake = self.simple_fake(1)
        fake.queue("/scenarios/1/blueprint", FakeMake._json({"response": {"blueprint": "nope"}}))
        code, _ = self.run_main(fake)
        self.assertEqual(code, 3)

    def test_draft_404_gives_null_not_failure(self):
        fake = self.simple_fake(1)
        fake.drafts[1] = 404
        code, output = self.run_main(fake)
        self.assertEqual(code, 0)
        self.assertIsNone(self.manifest()["scenarios"][0]["draft_differs"])
        self.assertIn("Draft state unknown", output)

    def test_draft_null_blueprint_means_no_separate_draft(self):
        # Make returns blueprint: null for draft=true when there are no unpublished edits
        # (measured on the live API 2026-10-28).
        fake = self.simple_fake(1)
        fake.drafts[1] = None
        code, _ = self.run_main(fake)
        self.assertEqual(code, 0)
        self.assertIs(self.manifest()["scenarios"][0]["draft_differs"], False)

    def test_live_null_blueprint_still_fails(self):
        fake = self.simple_fake(1)
        fake.queue("/scenarios/1/blueprint", FakeMake._json({"response": {"blueprint": None}}))
        code, _ = self.run_main(fake)
        self.assertEqual(code, 3)

    def test_designer_samples_never_written(self):
        # Make's editor sample data can hold client records (hard rule 5).
        fake = self.simple_fake(1)
        bp = fake.blueprints[1]
        bp.setdefault("metadata", {})["designer"] = {"orphans": [], "samples": {"1": [{"email": "a" + "@" + "b.co"}]}}
        code, _ = self.run_main(fake)
        self.assertEqual(code, 0)
        written = json.loads(self.snapshot()[[n for n in self.snapshot() if n != "manifest.json"][0]])
        self.assertNotIn("samples", written["metadata"]["designer"])
        self.assertIn("orphans", written["metadata"]["designer"])

    def test_draft_other_error_fails(self):
        fake = self.simple_fake(1)
        fake.drafts[1] = 400
        code, _ = self.run_main(fake)
        self.assertEqual(code, 3)

    def test_default_transport_rejects_non_get(self):
        with self.assertRaises(ValueError):
            make_pull.urllib_transport("POST", "https://example.invalid", {}, 1)

    def test_redirects_not_followed(self):
        handler = make_pull._NoRedirect()
        self.assertIsNone(handler.redirect_request(None, None, 302, "Found", {}, "https://other.invalid"))


class TestWithheld(Base):
    def make_secret_fake(self):
        scen = [entry(1, "Clean one"), entry(2, "Leaky one")]
        bps = {1: synthetic_blueprint("Clean one"),
               2: synthetic_blueprint("Leaky one", secret_http_module())}
        return FakeMake(scen, bps)

    def test_secret_blueprint_withheld_others_written(self):
        fake = self.make_secret_fake()
        old = os.path.join(self.out, "leaky-one__2.json")
        with open(old, "w", encoding="utf-8") as fh:
            fh.write("{}\n")
        code, output = self.run_main(fake)
        self.assertEqual(code, 1)
        files = sorted(os.listdir(self.out))
        self.assertEqual(files, ["clean-one__1.json", "manifest.json"])
        m = {s["id"]: s for s in self.manifest()["scenarios"]}
        self.assertTrue(m[2]["withheld"])
        self.assertIsNone(m[2]["file"])
        self.assertEqual(m[2]["withheld_pattern_types"], ["authorization_header_literal"])
        self.assertTrue(all("$.flow[1].mapper.headers[0].value" in loc for loc in m[2]["withheld_locations"]))
        self.assertFalse(m[1]["withheld"])
        self.assertEqual(self.manifest()["withheld_count"], 1)
        self.assertIn("WITHHELD 2", output)
        self.assertIn("authorization_header_literal", output)
        self.assertIn("leaky-one__2.json", output)

    def test_removing_a_tracked_file_for_a_withheld_scenario_is_called_out(self):
        """safety-R7: the audit findings on that scenario vanish with the file, which reads as progress."""
        with open(os.path.join(self.out, "leaky-one__2.json"), "w", encoding="utf-8") as fh:
            fh.write("{}\n")
        _code, output = self.run_main(self.make_secret_fake())
        self.assertIn("WARNING leaky-one__2.json was removed because the scenario is withheld", output)
        self.assertIn("drop in their findings is not progress", output)
        # No warning when no file was on disk for it.
        os.remove(os.path.join(self.out, "clean-one__1.json"))
        _code, output = self.run_main(self.make_secret_fake())
        self.assertNotIn("WARNING", output)

    def test_secret_value_never_printed_or_written(self):
        fake = self.make_secret_fake()
        secret = "lit" + ALNUM
        _, output = self.run_main(fake)
        self.assertNotIn(secret, output)
        for name in os.listdir(self.out):
            with open(os.path.join(self.out, name), encoding="utf-8") as fh:
                self.assertNotIn(secret, fh.read())

    def test_stripe_key_literal_withheld(self):
        mod = {"id": 2, "module": "util:SetVariable2", "version": 1,
               "mapper": {"value": "sk" + "_live_" + ALNUM}, "metadata": {}}
        fake = FakeMake([entry(5, "Pay")], {5: synthetic_blueprint("Pay", mod)})
        code, _ = self.run_main(fake)
        self.assertEqual(code, 1)
        self.assertEqual(self.manifest()["scenarios"][0]["withheld_pattern_types"], ["stripe_secret_key"])


class TestFiles(Base):
    def test_slugify(self):
        self.assertEqual(make_pull.slugify("Automating 'Pending Call' Clients"), "automating-pending-call-clients")
        self.assertEqual(make_pull.slugify("  The Interview Room (A) "), "the-interview-room-a")
        self.assertEqual(make_pull.slugify("Café -- Déjà"), "cafe-deja")
        self.assertEqual(make_pull.slugify("!!!"), "scenario")
        self.assertEqual(make_pull.slugify(None), "scenario")
        self.assertLessEqual(len(make_pull.slugify("a" * 300)), make_pull.SLUG_MAX)

    def test_file_format_key_order_unicode_lf_newline(self):
        bp = {"name": "Résumé ✓", "flow": [], "metadata": {"zeta": 1, "alpha": 2}}
        fake = FakeMake([entry(42, "Résumé ✓")], {42: bp})
        code, _ = self.run_main(fake)
        self.assertEqual(code, 0)
        path = os.path.join(self.out, "resume__42.json")
        with open(path, "rb") as fh:
            raw = fh.read()
        self.assertTrue(raw.endswith(b"}\n"))
        self.assertNotIn(b"\r\n", raw)
        text = raw.decode("utf-8")
        self.assertIn("Résumé ✓", text)
        self.assertEqual(text, json.dumps(bp, indent=2, ensure_ascii=False) + "\n")
        self.assertLess(text.index('"zeta"'), text.index('"alpha"'))
        self.assertFalse([n for n in os.listdir(self.out) if n.startswith(".tmp-")])

    def test_blueprint_file_holds_only_the_blueprint(self):
        fake = self.simple_fake(1)
        self.run_main(fake)
        with open(os.path.join(self.out, "scenario-1__1.json"), encoding="utf-8") as fh:
            data = json.load(fh)
        self.assertEqual(list(data.keys()), ["name", "flow", "metadata"])

    def test_stale_files_removed_and_listed(self):
        for name in ("gone__999.json", "notes.txt"):
            with open(os.path.join(self.out, name), "w", encoding="utf-8") as fh:
                fh.write("{}\n")
        code, output = self.run_main(self.simple_fake(1))
        self.assertEqual(code, 0)
        files = sorted(os.listdir(self.out))
        self.assertEqual(files, ["manifest.json", "notes.txt", "scenario-1__1.json"])
        self.assertIn("Removed: gone__999.json", output)

    def test_renamed_scenario_replaces_old_file(self):
        with open(os.path.join(self.out, "old-name__1.json"), "w", encoding="utf-8") as fh:
            fh.write("{}\n")
        code, output = self.run_main(self.simple_fake(1))
        self.assertEqual(code, 0)
        self.assertNotIn("old-name__1.json", os.listdir(self.out))
        self.assertIn("old-name__1.json", output)

    def test_repull_is_stable_only_manifest_carries_time(self):
        fake = self.simple_fake(2)
        self.run_main(fake)
        before = self.snapshot()
        global FIXED_NOW
        saved = FIXED_NOW
        FIXED_NOW = datetime(2026, 10, 29, 9, 30, 0, tzinfo=timezone.utc)
        try:
            _, output = self.run_main(self.simple_fake(2))
        finally:
            FIXED_NOW = saved
        after = self.snapshot()
        self.assertEqual(before.keys(), after.keys())
        changed = sorted(n for n in before if before[n] != after[n])
        self.assertEqual(changed, ["manifest.json"])
        self.assertIn("0 written, 2 unchanged", output)

    def test_scheduling_restrict(self):
        """"Daily at 10:00" in the Make UI is interval 900 restricted to 10:00-10:01 (measured on Daily API Cost Audit)."""
        daily = {"type": "indefinitely", "interval": 900,
                 "restrict": [{"days": [1, 2, 3, 4, 5, 6, 0], "time": ["10:00", "10:01"]}]}
        self.assertEqual(make_pull._scheduling_restrict(daily), daily["restrict"])
        self.assertIsNone(make_pull._scheduling_restrict({"type": "indefinitely", "interval": 900}))
        self.assertIsNone(make_pull._scheduling_restrict({"type": "indefinitely", "restrict": []}, None))
        self.assertEqual(make_pull._scheduling_restrict(None, daily), daily["restrict"])

    def test_manifest_fields(self):
        fake = self.simple_fake(2)
        fake.drafts[2] = synthetic_blueprint("Scenario 2 edited")
        code, output = self.run_main(fake)
        self.assertEqual(code, 0)
        m = self.manifest()
        self.assertEqual(m["pulled_at"], "2026-10-28T12:00:00Z")
        self.assertEqual(m["scenario_count"], 2)
        s1, s2 = m["scenarios"]
        for key in ("id", "name", "slug", "file", "is_active", "scheduling_type", "current_version",
                    "last_edit", "draft_differs", "live_missing", "withheld"):
            self.assertIn(key, s1)
        # Review finding make-api-F5: response.version is the newest version,
        # draft or published, so the field is not labelled as the live version.
        self.assertNotIn("version", s1)
        self.assertIn("draft", m["version_note"])
        self.assertEqual(s1["file"], "scenario-1__1.json")
        self.assertEqual(s1["slug"], "scenario-1")
        self.assertIs(s1["is_active"], True)
        self.assertEqual(s1["scheduling_type"], "indefinitely")
        self.assertEqual(s1["scheduling_interval"], 900)   # the manifest records each scenario's schedule
        self.assertIsNone(s1["scheduling_restrict"])   # no time window in the fake
        self.assertEqual(s1["current_version"], 7)
        self.assertEqual(s1["last_edit"], "2026-10-01T00:00:00.000Z")
        self.assertIs(s1["draft_differs"], False)
        self.assertIs(s2["draft_differs"], True)
        self.assertIn("Draft differs", output)
        with open(os.path.join(self.out, "manifest.json"), "rb") as fh:
            raw = fh.read()
        self.assertTrue(raw.endswith(b"\n"))
        self.assertNotIn(b"\r\n", raw)


class TestReviewRegressions(Base):
    """Regression tests for the 2026-10-28 adversarial review findings."""

    def seed(self, n=3, suffix=""):
        ids = range(1, n + 1)
        fake = FakeMake([entry(i, f"s{i}") for i in ids], {i: synthetic_blueprint(f"s{i}{suffix}") for i in ids})
        code, output = self.run_main(fake)
        self.assertEqual(code, 0, output)

    def test_empty_listing_with_snapshot_is_refused(self):
        # make-api-F2(a): an empty listing must not delete the snapshot.
        self.seed()
        before = self.snapshot()
        code, output = self.run_main(FakeMake([], {}))
        self.assertEqual(code, 3)
        self.assertIn("0 scenarios", output)
        self.assertIn("--allow-empty", output)
        self.assertEqual(self.snapshot(), before)

    def test_empty_listing_allowed_with_flag(self):
        self.seed()
        code, output = self.run_main(FakeMake([], {}), "--allow-empty")
        self.assertEqual(code, 0, output)
        self.assertEqual(os.listdir(self.out), ["manifest.json"])

    def test_empty_listing_on_empty_snapshot_is_fine(self):
        code, output = self.run_main(FakeMake([], {}))
        self.assertEqual(code, 0, output)

    def test_failure_while_staging_leaves_snapshot_untouched(self):
        # make-api-F3: a write failure before the swap changes nothing.
        self.seed()
        os.rename(os.path.join(self.out, "s1__1.json"), os.path.join(self.out, "old-name__1.json"))
        before = self.snapshot()
        real, calls = make_pull._stage, {"n": 0}

        def flaky(out_dir, content):
            calls["n"] += 1
            if calls["n"] == 2:
                raise PermissionError("locked")
            return real(out_dir, content)

        make_pull._stage = flaky
        try:
            ids = (1, 2, 3)
            code, output = self.run_main(FakeMake([entry(i, f"s{i}") for i in ids],
                                                  {i: synthetic_blueprint(f"s{i} v2") for i in ids}))
        finally:
            make_pull._stage = real
        self.assertEqual(code, 3)
        self.assertIn("before any file changed", output)
        self.assertEqual(self.snapshot(), before)

    def test_failure_during_swap_removes_manifest_and_says_so(self):
        # make-api-F3: once files start moving, a failure leaves no manifest,
        # so audit_blueprints refuses the mixed snapshot (input error, exit 2).
        self.seed()
        real, calls = os.replace, {"n": 0}

        def flaky(src, dst):
            calls["n"] += 1
            if calls["n"] == 2:
                raise PermissionError("locked")
            return real(src, dst)

        make_pull.os.replace = flaky
        try:
            ids = (1, 2, 3)
            code, output = self.run_main(FakeMake([entry(i, f"s{i}") for i in ids],
                                                  {i: synthetic_blueprint(f"s{i} v2") for i in ids}))
        finally:
            make_pull.os.replace = real
        self.assertEqual(code, 3)
        self.assertIn("manifest.json was removed", output)
        self.assertNotIn("nothing written", output)
        self.assertNotIn("manifest.json", os.listdir(self.out))
        self.assertFalse([n for n in os.listdir(self.out) if n.startswith(".tmp-")])
        import audit_blueprints
        err = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            rc = audit_blueprints.main(["--blueprints", self.out, "--no-report"])
        self.assertEqual(rc, 2)
        self.assertIn("no manifest", err.getvalue())

    def test_new_files_land_before_stale_deletes(self):
        self.seed()
        os.rename(os.path.join(self.out, "s1__1.json"), os.path.join(self.out, "old-name__1.json"))
        code, output = self.run_main(FakeMake(
            [entry(i, f"s{i}") for i in (1, 2, 3)], {i: synthetic_blueprint(f"s{i}") for i in (1, 2, 3)}))
        self.assertEqual(code, 0, output)
        self.assertEqual(sorted(os.listdir(self.out)), ["manifest.json", "s1__1.json", "s2__2.json", "s3__3.json"])
        self.assertIn("old-name__1.json", output)

    def test_incomplete_read_is_retried(self):
        # make-api-F6: http.client errors during read() are transient.
        import http.client
        fake = self.simple_fake(1)

        def incomplete(*_a):
            raise http.client.IncompleteRead(b"x")

        state = {"n": 0}

        def transport(method, url, headers, timeout):
            state["n"] += 1
            if state["n"] == 1:
                try:
                    incomplete()
                except http.client.HTTPException as exc:
                    raise make_pull.TransientError(type(exc).__name__) from None
            return fake(method, url, headers, timeout)

        code, output = self.run_main(transport)
        self.assertEqual(code, 0, output)
        self.assertEqual(len(self.sleeps), 1)

    def test_urllib_transport_maps_http_exception_to_transient(self):
        import http.client

        class Boom:
            def open(self, req, timeout):
                raise http.client.IncompleteRead(b"x")

        saved = make_pull._OPENER
        make_pull._OPENER = Boom()
        try:
            with self.assertRaises(make_pull.TransientError):
                make_pull.urllib_transport("GET", "https://example.invalid", {}, 1)
        finally:
            make_pull._OPENER = saved

    def test_live_404_is_recorded_not_fatal(self):
        # make-api-F6: a scenario with no live version (concept) does not abort the pull.
        scen = [dict(entry(1, "Concept"), concept=True), entry(2, "Live")]
        fake = FakeMake(scen, {2: synthetic_blueprint("Live")})
        fake.queue("/scenarios/1/blueprint", Response(404, {}, b'{"code":"IM005","message":"Not found"}'))
        code, output = self.run_main(fake)
        self.assertEqual(code, 0, output)
        m = {s["id"]: s for s in self.manifest()["scenarios"]}
        self.assertTrue(m[1]["live_missing"])
        self.assertIsNone(m[1]["file"])
        self.assertIs(m[1]["concept"], True)
        self.assertFalse(m[2]["live_missing"])
        self.assertEqual(self.manifest()["live_missing_count"], 1)
        self.assertIn("NO LIVE VERSION 1", output)
        self.assertEqual(sorted(os.listdir(self.out)), ["live__2.json", "manifest.json"])
        # Only the draft of the live scenario was fetched.
        self.assertNotIn(("/scenarios/1/blueprint", "true"),
                         [(p, q.get("draft")) for p, q in zip(fake.paths(), fake.queries())])

    def test_withheld_pull_then_audit_fails(self):
        # make-api-F1 / security-SEC-1 / audit-semantics-F1 end to end.
        scen = [entry(7, "Pay"), entry(8, "Clean")]
        fake = FakeMake(scen, {7: synthetic_blueprint("Pay", secret_http_module()), 8: synthetic_blueprint("Clean")})
        code, _ = self.run_main(fake)
        self.assertEqual(code, 1)
        import audit_blueprints
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            rc = audit_blueprints.main(["--blueprints", self.out, "--no-report"])
        self.assertEqual(rc, 1, out.getvalue())
        self.assertIn("Result: FAIL", out.getvalue())


HOOK_TAIL = "q1w2e3r4t5y6u7i8o9p0a1s2d3f4g5h6"
HOOK_URL = "https://hook." + "us2.make.com/" + HOOK_TAIL
OTHER_TAIL = "z9x8c7v6b5n4m3l2k1j0h9g8f7d6s5a4"


def raw_hook(hid, name="Hook", scenario=None, token=HOOK_TAIL, **data):
    h = {"id": hid, "name": name, "teamId": 123, "udid": token, "url": "https://hook." + "us2.make.com/" + token,
         "enabled": True, "gone": False, "typeName": "gateway-webhook", "data": {"headers": False, "method": False, **data}}
    if scenario is not None:
        h["scenarioId"] = scenario
    return h


def webhook_scenario(name, hook_id):
    bp = synthetic_blueprint(name)
    bp["flow"][0]["parameters"] = {"hook": hook_id}
    return bp


def sender_scenario(name, url=HOOK_URL):
    bp = synthetic_blueprint(name)
    bp["flow"].append({"id": 2, "module": "bland:sendACall", "version": 1, "mapper": {"task": "hi", "webhook": url}, "metadata": {}})
    return bp


ALLOW = [{"scenario_id": "1", "module_id": 2, "pattern_type": "make_webhook_url", "reason": "Points at the fetch-back hook",
          "requires_fetch_back_hook": "2", "token_sha256": hashlib.sha256(HOOK_TAIL.encode()).hexdigest()}]


class TestHooks(Base):
    def fake(self, hooks, n=2):
        scen = [entry(i, f"Scenario {i}") for i in range(1, n + 1)]
        bps = {i: webhook_scenario(f"Scenario {i}", 70 + i) for i in range(1, n + 1)}
        return FakeMake(scen, bps, hooks=hooks)

    def test_hooks_are_recorded_with_the_documented_fields_only(self):
        hooks = [raw_hook(72, "Fetch hook", scenario=2, keys=[{"id": 1}, {"id": 2}], headers=True),
                 raw_hook(71, "Key hook", scenario=1, token=OTHER_TAIL)]
        code, _ = self.run_main(self.fake(hooks))
        self.assertEqual(code, 0)
        m = self.manifest()
        self.assertIsNone(m["hooks_note"])
        self.assertEqual([h["id"] for h in m["hooks"]], [71, 72])
        self.assertEqual(m["hooks"][1], {"id": 72, "name": "Fetch hook", "scenario_ids": [2], "enabled": True, "apikey_count": 2,
                                          "ip_restricted": None, "headers": True})
        self.assertEqual(set(m["hooks"][0]), {"id", "name", "scenario_ids", "enabled", "apikey_count", "ip_restricted", "headers"})

    def test_no_url_token_or_key_reaches_the_manifest_or_the_output(self):
        hooks = [raw_hook(71, scenario=1, keys=["secretkeyvalue1234567"], keyId="k-1"), raw_hook(72, scenario=2, token=OTHER_TAIL)]
        code, output = self.run_main(self.fake(hooks))
        text = json.dumps(self.manifest())
        for needle in (HOOK_TAIL, OTHER_TAIL, "secretkeyvalue1234567", "hook." + "us2.make.com"):
            self.assertNotIn(needle, text)
            self.assertNotIn(needle, output)

    def test_apikey_count_is_none_when_the_response_has_no_key_field(self):
        code, _ = self.run_main(self.fake([raw_hook(71, scenario=1)]))
        self.assertEqual(code, 0)
        self.assertIsNone(self.manifest()["hooks"][0]["apikey_count"])

    def test_apikey_count_reads_list_scalar_and_empty_forms(self):
        c = make_pull.hook_apikey_count
        self.assertEqual(c({"id": 1, "data": {"keys": []}}), 0)
        self.assertEqual(c({"id": 1, "data": {"keyIds": [3]}}), 1)
        self.assertEqual(c({"id": 1, "keys": [1, 2, 3]}), 3)
        self.assertEqual(c({"id": 1, "data": {"keyId": 12}}), 1)
        self.assertEqual(c({"id": 1, "data": {"keyId": None}}), 0)
        self.assertIsNone(c({"id": 1, "data": {"headers": True}}))

    def test_apikey_count_counts_only_real_enabled_keys(self):
        """R6 probes: each of these used to count as 1 key and would have passed F1."""
        c = make_pull.hook_apikey_count
        self.assertEqual(c({"id": 1, "data": {"keys": [None]}}), 0)
        self.assertEqual(c({"id": 1, "data": {"keyId": "0"}}), 0)
        self.assertEqual(c({"id": 1, "data": {"keyId": 0}}), 0)
        self.assertEqual(c({"id": 1, "data": {"keys": [{"enabled": False}]}}), 0)
        self.assertEqual(c({"id": 1, "data": {"keys": [{"id": 4, "enabled": False}]}}), 0)
        self.assertEqual(c({"id": 1, "data": {"keys": [{}, "", 0, False, True]}}), 0)
        self.assertEqual(c({"id": 1, "data": {"keys": [None, 7, {"id": 9}, {"id": 5, "enabled": True}]}}), 3)
        self.assertEqual(c({"id": 1, "apiKey": "x"}), 1)
        self.assertEqual(c({"id": 1, "data": {"headers": True}}), None)

    def test_hook_matching_needs_every_token_to_match(self):
        """R5 probe: any() let one matching token clear a second, foreign token."""
        h = raw_hook(72, scenario=2)
        self.assertTrue(make_pull._hook_matches_token(h, [HOOK_TAIL]))
        self.assertFalse(make_pull._hook_matches_token(h, [HOOK_TAIL, OTHER_TAIL]))
        self.assertFalse(make_pull._hook_matches_token(h, [OTHER_TAIL, HOOK_TAIL]))
        self.assertFalse(make_pull._hook_matches_token(h, []))

    def test_the_pull_prints_hook_field_names_only_when_the_key_state_is_unknown(self):
        hooks = [raw_hook(71, scenario=1, secretish="value-should-never-print")]
        code, output = self.run_main(self.fake(hooks))
        self.assertEqual(code, 0)
        self.assertIn("Hook response fields (names only", output)
        self.assertIn("data.headers", output)
        self.assertIn("secretish", output.replace("data.secretish", "secretish"))
        for needle in ("value-should-never-print", HOOK_TAIL, "hook." + "us2.make.com"):
            self.assertNotIn(needle, output)
        code, output = self.run_main(self.fake([raw_hook(71, scenario=1, keys=[{"id": 1}], ipRestrict=[])]))
        self.assertNotIn("Hook response fields", output)

    def test_ip_restricted_is_a_bool_or_unknown(self):
        f = make_pull.hook_ip_restricted
        self.assertTrue(f({"id": 1, "data": {"ipRestrict": ["1.2.3.4"]}}))
        self.assertFalse(f({"id": 1, "data": {"ipRestrict": []}}))
        self.assertIsNone(f({"id": 1, "data": {}}))

    def test_scenario_ids_merge_the_hook_scenario_and_the_blueprint_triggers(self):
        code, _ = self.run_main(self.fake([raw_hook(71), raw_hook(72, scenario=1, token=OTHER_TAIL)]))
        self.assertEqual({h["id"]: h["scenario_ids"] for h in self.manifest()["hooks"]}, {71: [1], 72: [1, 2]})

    def test_a_403_records_null_with_a_note_and_does_not_fail_the_pull(self):
        code, output = self.run_main(self.fake(None))
        self.assertEqual(code, 0)
        m = self.manifest()
        self.assertIsNone(m["hooks"])
        self.assertIn("Webhooks: View", m["hooks_note"])
        self.assertIn("Hooks: not recorded", output)
        self.assertEqual(m["scenario_count"], 2)

    def test_a_401_on_hooks_is_a_missing_scope_too(self):
        """Measured 2026-10-28: Make answers a token without hooks:read with 401 IM001."""
        fake = self.fake([])
        fake.queue("/hooks", Response(401, {}, b'{"code":"IM001","message":"Unauthorized"}'))
        code, output = self.run_main(fake)
        self.assertEqual(code, 0)
        m = self.manifest()
        self.assertIsNone(m["hooks"])
        self.assertIn("returned 401", m["hooks_note"])

    def test_any_other_hooks_error_fails_the_pull_and_writes_nothing(self):
        fake = self.fake([])
        fake.queue("/hooks", Response(400, {}, b'{"code":"SC400"}'))
        code, output = self.run_main(fake)
        self.assertEqual(code, 3)
        self.assertFalse(os.path.exists(os.path.join(self.out, "manifest.json")))

    def test_only_get_requests_are_made_for_hooks_and_the_team_is_passed(self):
        fake = self.fake([raw_hook(71, scenario=1)])
        self.run_main(fake)
        calls = [c for c in fake.calls if "/hooks" in c[1]]
        self.assertTrue(calls)
        self.assertTrue(all(c[0] == "GET" for c in calls))
        self.assertEqual(urllib.parse.parse_qs(urllib.parse.urlsplit(calls[0][1]).query)["teamId"], ["123"])

    def test_a_server_that_ignores_pagination_does_not_loop_or_fail(self):
        hooks = [raw_hook(71, scenario=1), raw_hook(72, scenario=2, token=OTHER_TAIL)]

        class Ignores(FakeMake):
            def __call__(self, method, url, headers, timeout):
                if urllib.parse.urlsplit(url).path.endswith("/hooks"):
                    self.calls.append((method, url, dict(headers), timeout))
                    return self._json({"hooks": self.hooks})
                return super().__call__(method, url, headers, timeout)

        base = self.fake(hooks)
        fake = Ignores(base.scenarios, base.blueprints, hooks=hooks)
        code, _ = self.run_main(fake)
        self.assertEqual(code, 0)
        self.assertEqual([h["id"] for h in self.manifest()["hooks"]], [71, 72])
        self.assertLessEqual(len([c for c in fake.calls if "/hooks" in c[1]]), 2)

    def test_many_hooks_are_paged(self):
        hooks = [raw_hook(1000 + i, token=f"t{i:031d}") for i in range(7)]
        fake = self.fake(hooks)
        client = make_pull.MakeClient(make_pull.Config("tok-" + ALNUM, "us2", "123"), transport=fake, sleep=lambda s: None)
        got = make_pull.list_hooks(client, "123", page_limit=3)
        self.assertEqual([h["id"] for h in got], [1000 + i for i in range(7)])


class TestAllowlistedSecrets(Base):
    def fake(self, hooks, url=HOOK_URL, target_hook_token=HOOK_TAIL):
        scen = [entry(1, "Sender"), entry(2, "Receiver")]
        bps = {1: sender_scenario("Sender", url), 2: webhook_scenario("Receiver", 72)}
        hooks = None if hooks is None else [raw_hook(72, "Receiver hook", scenario=2, token=target_hook_token)]
        return FakeMake(scen, bps, hooks=hooks)

    def pull(self, fake, allow=ALLOW, *extra):
        out, err = io.StringIO(), io.StringIO()
        client = make_pull.MakeClient(make_pull.Config(TOKEN, "us2", "123"), transport=fake, sleep=lambda s: None)
        res = make_pull.pull(client, "123", self.out, now=lambda: FIXED_NOW, secret_allowlist=allow)
        return res

    def test_without_an_allowlist_the_url_withholds_the_scenario(self):
        res = self.pull(self.fake(True), allow=None)
        self.assertEqual([w["id"] for w in res.withheld], [1])
        self.assertFalse(os.path.exists(os.path.join(self.out, "sender__1.json")))

    def test_a_pinned_url_whose_token_matches_the_target_hook_is_written_and_listed(self):
        res = self.pull(self.fake(True))
        self.assertEqual(res.withheld, [])
        self.assertTrue(os.path.exists(os.path.join(self.out, "sender__1.json")))
        m = self.manifest()
        e = m["scenarios"][0]
        self.assertFalse(e["withheld"])
        self.assertEqual(e["allowlisted_findings"], [{"module_id": 2, "pattern_type": "make_webhook_url", "requires_fetch_back_hook": "2",
                                                      "reason": "Points at the fetch-back hook",
                                                      "target_check": "token matches the hook of scenario 2"}])
        self.assertEqual(m["scenarios"][1]["allowlisted_findings"], [])
        self.assertEqual([a["module_id"] for a in res.allowlisted], [2])
        text = json.dumps(m)
        self.assertNotIn(HOOK_TAIL, text)

    def test_a_token_that_does_not_match_the_target_hook_withholds_the_scenario(self):
        res = self.pull(self.fake(True, target_hook_token=OTHER_TAIL))
        self.assertEqual([w["id"] for w in res.withheld], [1])
        self.assertEqual([(m["id"], m["target"]) for m in res.allowlist_mismatch], [(1, 2)])
        self.assertFalse(os.path.exists(os.path.join(self.out, "sender__1.json")))
        self.assertIn("ALLOWLIST MISMATCH", make_pull.format_summary(res, 1))

    def test_a_pinned_url_plus_a_foreign_url_in_the_same_field_withholds_the_scenario(self):
        """R5 probe: findings dedupe per location, so the pinned entry used to clear both URLs."""
        foreign = "https://hook." + "us2.make.com/" + OTHER_TAIL
        res = self.pull(self.fake(True, url=HOOK_URL + " " + foreign))
        self.assertEqual([w["id"] for w in res.withheld], [1])
        self.assertFalse(os.path.exists(os.path.join(self.out, "sender__1.json")))

    def test_a_different_url_than_the_pinned_one_withholds_the_scenario_even_without_hook_data(self):
        res = self.pull(self.fake(None, url="https://hook." + "us2.make.com/" + OTHER_TAIL))
        self.assertEqual([w["id"] for w in res.withheld], [1])

    def test_with_an_unreadable_hook_list_the_pinned_mapping_is_accepted_and_says_so(self):
        res = self.pull(self.fake(None))
        self.assertEqual(res.withheld, [])
        self.assertEqual(self.manifest()["scenarios"][0]["allowlisted_findings"][0]["target_check"], "not checked (hook list unreadable)")

    def test_another_secret_in_the_same_blueprint_still_withholds_it(self):
        fake = self.fake(True)
        fake.blueprints[1]["flow"][1]["mapper"]["task"] = "k " + "sk" + "_live_" + ALNUM
        res = self.pull(fake)
        self.assertEqual([(w["id"], w["pattern_types"]) for w in res.withheld], [(1, ["stripe_secret_key"])])

    def test_the_cli_loads_the_allowlist_file_and_reports_it(self):
        path = os.path.join(self.tmp, "secret_allowlist.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"entries": ALLOW}, fh)
        code, output = self.run_main(self.fake(True), "--secret-allowlist", path)
        self.assertEqual(code, 0, output)
        self.assertIn("ALLOWLISTED 1 module 2 make_webhook_url", output)
        self.assertNotIn(HOOK_TAIL, output)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("{bad")
        code, output = self.run_main(self.fake(True), "--secret-allowlist", path)
        self.assertEqual(code, 2)
        self.assertIn("config error", output)

    def test_without_the_flag_the_url_exits_1(self):
        code, _ = self.run_main(self.fake(True), "--secret-allowlist", os.path.join(self.tmp, "missing.json"))
        self.assertEqual(code, 1)


class TestSource(unittest.TestCase):
    def test_source_has_no_write_verbs(self):
        with open(os.path.join(ROOT, "scripts", "make_pull.py"), encoding="utf-8") as fh:
            src = fh.read()
        for verb in ('"POST"', '"PATCH"', '"PUT"', '"DELETE"', "method=\"P", "/activate", "/run", "/clone"):
            self.assertNotIn(verb, src)


if __name__ == "__main__":
    unittest.main()


class TestHookApiKeyShape(unittest.TestCase):
    """The GET /hooks shape measured 2026-10-29: data.authenticationMethod.apikey is a list of key IDs."""

    def test_measured_shape_counts_keys(self):
        h = {"id": 1, "data": {"authenticationMethod": {"apiKeyHeaderName": "x-make-apikey", "apikey": [243610]}}}
        self.assertEqual(make_pull.hook_apikey_count(h), 1)

    def test_measured_shape_empty_list_is_zero(self):
        h = {"id": 1, "data": {"authenticationMethod": {"apiKeyHeaderName": "x-make-apikey", "apikey": []}}}
        self.assertEqual(make_pull.hook_apikey_count(h), 0)

    def test_non_integer_entries_do_not_count(self):
        h = {"id": 1, "data": {"authenticationMethod": {"apikey": ["x", True, 0, -3]}}}
        self.assertEqual(make_pull.hook_apikey_count(h), 0)
