import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
import urllib.parse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import make_create  # noqa: E402
import make_pull  # noqa: E402
import make_push  # noqa: E402

READ = "r" + "eadtok" + "en0123456789abcdef"
WRITE = "w" + "ritetok" + "en0123456789abcdef"


def blueprint(trigger="gateway:CustomWebHook"):
    return {"name": "x", "flow": [{"id": 1, "module": trigger, "version": 1, "parameters": {}},
                                  {"id": 2, "module": "slack:CreateMessage", "version": 4, "mapper": {"text": "hi"}}],
            "metadata": {"version": 1, "scenario": {"sequential": False}}}


class FakeMake:
    def __init__(self, names=("Pending Call",), active_after=False, post_status=200):
        self.names, self.active_after, self.post_status = list(names), active_after, post_status
        self.calls, self.created = [], None

    def __call__(self, method, url, headers, timeout, body=None):
        self.calls.append((method, url, dict(headers), body))
        p = urllib.parse.urlsplit(url)
        path = p.path[len("/api/v2"):]
        if method == "GET" and path == "/scenarios":
            q = dict(urllib.parse.parse_qsl(p.query))
            off = int(q.get("pg[offset]", 0))
            items = [{"id": 100 + i, "name": n} for i, n in enumerate(self.names)][off:off + int(q.get("pg[limit]", 100))]
            return make_pull.Response(200, {}, json.dumps({"scenarios": items, "pg": {}}).encode())
        if method == "POST" and path == "/scenarios":
            if self.post_status != 200:
                return make_pull.Response(self.post_status, {}, json.dumps({"code": "IM007", "message": "bad"}).encode())
            self.created = json.loads(body.decode())
            return make_pull.Response(200, {}, json.dumps({"scenario": {"id": 999, "name": "Logger"}}).encode())
        if method == "GET" and path == "/scenarios/999":
            return make_pull.Response(200, {}, json.dumps({"scenario": {"id": 999, "isActive": self.active_after}}).encode())
        return make_pull.Response(404, {}, b"{}")


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="make_create_")
        self.specs = os.path.join(self.tmp, "specs")
        os.makedirs(self.specs)
        self.bp = os.path.join(self.specs, "logger.blueprint.json")
        self.write_bp(blueprint())
        self.env = os.path.join(self.tmp, ".env")
        with open(self.env, "w") as fh:
            fh.write(f"MAKE_API_TOKEN={READ}\nMAKE_WRITE_TOKEN={WRITE}\nMAKE_ZONE=us2\nMAKE_TEAM_ID=123\n")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write_bp(self, bp):
        with open(self.bp, "w", encoding="utf-8") as fh:
            json.dump(bp, fh)

    def run_main(self, fake, *extra, git=lambda p: None, bp=None):
        argv = ["--blueprint", bp or self.bp, "--name", "Logger", "--scheduling", "immediately",
                "--env", self.env, "--specs", self.specs, "--records", os.path.join(self.tmp, "rec"), *extra]
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = make_create.main(argv, transport=fake, environ={}, git_state=git)
        text = out.getvalue() + err.getvalue()
        self.assertNotIn(READ, text)
        self.assertNotIn(WRITE, text)
        return code, text


class TestCreate(Base):
    def test_dry_run_sends_no_post(self):
        fake = FakeMake()
        code, text = self.run_main(fake)
        self.assertEqual(code, make_create.EXIT_OK, text)
        self.assertEqual({c[0] for c in fake.calls}, {"GET"})
        self.assertIn("DRY RUN", text)

    def test_apply_creates_inactive_with_write_token_and_string_fields(self):
        fake = FakeMake()
        code, text = self.run_main(fake, "--apply", "--folder-id", "199043")
        self.assertEqual(code, make_create.EXIT_OK, text)
        posts = [c for c in fake.calls if c[0] == "POST"]
        self.assertEqual(len(posts), 1)
        self.assertEqual(posts[0][2]["Authorization"], "Token " + WRITE)
        self.assertNotIn("confirmed", posts[0][1])
        for m, _u, h, _b in fake.calls:
            if m == "GET":
                self.assertEqual(h["Authorization"], "Token " + READ)
        body = fake.created
        self.assertIsInstance(body["blueprint"], str)
        self.assertIsInstance(body["scheduling"], str)
        self.assertEqual(json.loads(body["blueprint"])["name"], "Logger")
        self.assertEqual(body["teamId"], 123)
        self.assertEqual(body["folderId"], 199043)
        self.assertIn("Created scenario 999", text)

    def test_existing_name_aborts(self):
        code, text = self.run_main(FakeMake(names=("logger",)), "--apply")
        self.assertEqual(code, make_create.EXIT_ABORT)
        self.assertIn("already exists", text)

    def test_uncommitted_blueprint_aborts(self):
        fake = FakeMake()
        code, text = self.run_main(fake, "--apply", git=lambda p: "it differs from the last commit")
        self.assertEqual(code, make_create.EXIT_ABORT)
        self.assertEqual(fake.calls, [])

    def test_blueprint_outside_specs_aborts(self):
        other = os.path.join(self.tmp, "x.blueprint.json")
        shutil.copy(self.bp, other)
        code, text = self.run_main(FakeMake(), "--apply", bp=other)
        self.assertEqual(code, make_create.EXIT_ABORT)

    def test_watch_trigger_aborts_unless_allowed(self):
        self.write_bp(blueprint("airtable:TriggerWatchRecords"))
        code, text = self.run_main(FakeMake(), "--apply")
        self.assertEqual(code, make_create.EXIT_ABORT)
        self.assertIn("watch trigger", text)
        code, _ = self.run_main(FakeMake(), "--allow-watch-trigger")
        self.assertEqual(code, make_create.EXIT_OK)

    def test_secret_in_blueprint_aborts(self):
        bp = blueprint()
        bp["flow"][1]["mapper"]["text"] = "sk" + "_live_" + "A1b2C3d4E5f6G7h8J9k0L1m2"
        self.write_bp(bp)
        code, text = self.run_main(FakeMake(), "--apply")
        self.assertEqual(code, make_create.EXIT_ABORT)
        self.assertIn("secret", text)

    def test_active_after_create_alarms(self):
        code, text = self.run_main(FakeMake(active_after=True), "--apply")
        self.assertEqual(code, make_create.EXIT_ACTIVE)
        self.assertIn("ALARM", text)

    def test_rejected_post_reports_and_creates_nothing(self):
        code, text = self.run_main(FakeMake(post_status=400), "--apply")
        self.assertEqual(code, make_create.EXIT_REJECTED)
        self.assertIn("Nothing was created", text)


class TestLoggerPlaceholder(unittest.TestCase):
    TOKEN = "Lg" + "q7Rz0vN3kT8wX2bY5cJ9mH4dF6s"

    def setUp(self):
        import secret_scan
        self.ss = secret_scan
        self.url = "https://hook.us2.make.com/" + self.TOKEN
        self.logger = secret_scan.LoggerAllowance("6832527", 3000983, secret_scan.token_digest(self.TOKEN), "The Logger hook.", True)
        self.tmp = tempfile.mkdtemp(prefix="snap_")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def call(self, mid, url, module="http:MakeRequest"):
        return {"id": mid, "module": module, "parameters": {"authenticationType": "apiKeyConnection"},
                "mapper": {"url": url, "method": "post"}}

    def snapshot(self, url):
        with open(os.path.join(self.tmp, "x__1.json"), "w", encoding="utf-8") as fh:
            json.dump({"name": "x", "flow": [{"id": 1, "module": "airtable:ActionUpdateRecords",
                                              "onerror": [self.call(9, url)]}]}, fh)

    def test_placeholder_is_filled_from_a_pinned_snapshot(self):
        self.snapshot(self.url)
        bp = {"flow": [{"id": 2, "module": "stripe:makeAnApiCall", "onerror": [self.call(21, make_create.LOGGER_URL_PLACEHOLDER)]}]}
        self.assertEqual(make_create.resolve_logger_url(bp, self.logger, self.tmp), 1)
        self.assertEqual(bp["flow"][0]["onerror"][0]["mapper"]["url"], self.url)
        blocking, allowed = self.ss.split_findings(bp, None, [], self.logger)
        self.assertEqual((blocking, len(allowed)), ([], 1))

    def test_no_matching_snapshot_aborts(self):
        self.snapshot("https://hook.us2.make.com/" + "Other0123456789abcdefABCDE")
        bp = {"flow": [self.call(21, make_create.LOGGER_URL_PLACEHOLDER)]}
        with self.assertRaises(make_create.Abort):
            make_create.resolve_logger_url(bp, self.logger, self.tmp)

    def test_placeholder_outside_a_logger_call_aborts(self):
        self.snapshot(self.url)
        bp = {"flow": [self.call(21, make_create.LOGGER_URL_PLACEHOLDER, module="http:ActionSendData")]}
        with self.assertRaises(make_create.Abort):
            make_create.resolve_logger_url(bp, self.logger, self.tmp)

    def test_inactive_logger_aborts_and_no_placeholder_is_a_no_op(self):
        self.snapshot(self.url)
        bp = {"flow": [self.call(21, make_create.LOGGER_URL_PLACEHOLDER)]}
        with self.assertRaises(make_create.Abort):
            make_create.resolve_logger_url(bp, None, self.tmp)
        self.assertEqual(make_create.resolve_logger_url({"flow": [self.call(21, "https://x.test/")]}, None, self.tmp), 0)


class TestBuildPlaceholders(Base):
    """A __NAME__ placeholder left in a committed blueprint runs as literal text in Make (the F-F10 test folder ID), and
    only a call row's Prompt SHA256 may wait for its push, since check R4b FAILs it until then."""

    LINKS = os.path.join(ROOT, "audit", "airtable_links.json")

    def sha_keys(self):
        return make_create.sha_stamp_keys(self.LINKS)

    def test_a_placeholder_aborts_before_any_request(self):
        bp = blueprint()
        bp["flow"][1]["mapper"]["folderId"] = "/__FF10_TEST_FOLDER_ID__"
        self.write_bp(bp)
        fake = FakeMake()
        code, text = self.run_main(fake, "--apply")
        self.assertEqual(code, make_create.EXIT_ABORT)
        self.assertIn("build placeholders", text)
        self.assertIn("module 2 mapper.folderId (__FF10_TEST_FOLDER_ID__)", text)
        self.assertEqual(fake.calls, [])

    def test_make_names_and_mappings_are_not_placeholders(self):
        bp = {"flow": [{"id": 3, "module": "util:SetVariable2", "parameters": {"__IMTCONN__": 5},
                        "mapper": {"value": "{{2.__IMTLENGTH__}}", "x": "{{ifempty(2.__FOO__; 1)}}"}}]}
        self.assertEqual(make_create.leftover_placeholders(bp, self.sha_keys()), [])

    def test_only_the_call_row_sha_stamp_may_hold_one(self):
        sha = next(iter(k for k in self.sha_keys() if k.startswith("fld")))
        row = {"id": 7, "module": "airtable:ActionCreateRecord",
               "mapper": {"table": "tblf73Cdii3CsLKfL", "record": {sha: "__FF10_OUTLINE_SHA256__"}}}
        self.assertEqual(make_create.leftover_placeholders({"flow": [row]}, self.sha_keys()), [])
        row["mapper"]["record"]["fldH5cTvDOJf8p5WP"] = "__FF10_VERSION__"
        self.assertEqual(len(make_create.leftover_placeholders({"flow": [row]}, self.sha_keys())), 1)
        other = {"id": 8, "module": "airtable:ActionUpdateRecords",
                 "mapper": {"table": "tblf73Cdii3CsLKfL", "record": {sha: "__FF10_OUTLINE_SHA256__"}}}
        self.assertEqual(len(make_create.leftover_placeholders({"flow": [other]}, self.sha_keys())), 1)
        nested = {"id": 9, "module": "builtin:BasicRouter", "routes": [{"flow": [{"id": 10, "module": "x:y",
                                                                                 "filter": {"conditions": [[{"b": "__X_Y__"}]]}}]}]}
        self.assertEqual(make_create.leftover_placeholders({"flow": [nested]}, self.sha_keys()),
                         ["module 10 filter.conditions[0][0].b (__X_Y__)"])

    def test_the_committed_f_f10_blueprint_is_clean_after_the_logger_fill(self):
        with open(os.path.join(ROOT, "specs", "f-f10-drafting-chain.blueprint.json"), encoding="utf-8") as fh:
            bp = json.load(fh)
        for m in make_create._modules(bp.get("flow")):
            if (m.get("mapper") or {}).get("url") == make_create.LOGGER_URL_PLACEHOLDER:
                m["mapper"]["url"] = "https://logger.example.test/"
        self.assertEqual(make_create.leftover_placeholders(bp, self.sha_keys()), [])


class TestTransport(unittest.TestCase):
    def setUp(self):
        self.t = make_create.CreateTransport(lambda *a, **k: make_pull.Response(200, {}, b"{}"), "https://us2.make.com/api/v2")

    def test_refuses_activate_run_patch_delete_and_second_post(self):
        base = "https://us2.make.com/api/v2/scenarios"
        for m, u, b in [("POST", base + "/5/start", b"{}"), ("POST", base + "/5/run", b"{}"),
                        ("PATCH", base + "/5", b"{}"), ("DELETE", base + "/5", None),
                        ("POST", base + "?confirmed=true", b"{}"), ("POST", "https://evil.make.com/api/v2/scenarios", b"{}"),
                        ("POST", base + "/5/clone", b"{}")]:
            with self.assertRaises(make_push.TransportRefused, msg=f"{m} {u}"):
                self.t.check(m, u, b)
        self.t.check("POST", base, b"{}")
        with self.assertRaises(make_push.TransportRefused):
            self.t.check("POST", base, b"{}")


if __name__ == "__main__":
    unittest.main()
