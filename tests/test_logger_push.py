"""Tests for the Logger side of Option C (decided by Rizwan 2026-10-29) in the push tooling.

- secret_scan: the Logger hook allowance (audit/secret_allowlist.json logger_hook), active only while audit/webhooks.json registers
  that hook with protection api_key, allowed only as the url field of a Logger call (R6), pinned by token digest, and
  x-make-apikey as a key header.
- make_pull: the Logger URL compared with the hook list in memory, the logger_hook manifest row with its apikey_count, and no
  Error Monitor log read.
- make_push: fix F-E5.3 (the Logger swap, check_logger_swap), the Logger readiness gate (check_logger_ready) and the retired
  F-E5.2.

No network: every test injects a fake transport. Tokens and hook URLs are assembled at runtime so this file holds no literal the
pre-commit hook would block. Fixtures are synthetic.
"""

import contextlib
import copy
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import urllib.parse
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TESTS = os.path.dirname(os.path.abspath(__file__))
for _p in (os.path.join(ROOT, "scripts"), TESTS):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import audit_blueprints  # noqa: E402
import make_pull  # noqa: E402
import make_push  # noqa: E402
import secret_scan  # noqa: E402
import test_make_pull as tpl  # noqa: E402  (helpers only, no test class is imported into this module)
import test_make_push as tp  # noqa: E402

LOGGER_TAIL = "".join(["m1n2b3v4", "c5x6z7l8", "k9j0h1g2", "f3d4s5a6"])
FOREIGN_TAIL = "".join(["p0o9i8u7", "y6t5r4e3", "w2q1a2s3", "d4f5g6h7"])
HOST = "https://hook." + "us2.make.com/"
LOGGER_URL = HOST + LOGGER_TAIL
FOREIGN_URL = HOST + FOREIGN_TAIL
LOGGER_SID = "900777"
LOGGER_HOOK = 5551
CONN = 4242
URL_VAR = "var.team.IMMIOS_LOGGER_URL"
REASON = "Every error handler calls the shared Logger, whose hook needs x-make-apikey"


def digest(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def logger_pin(sid=LOGGER_SID, hook=LOGGER_HOOK, token=LOGGER_TAIL):
    return {"scenario_id": sid, "hook_id": hook, "token_sha256": digest(token), "reason": REASON}


def registry(protection="api_key", hook=LOGGER_HOOK, sid=LOGGER_SID, where="scenarios", url_variable=URL_VAR, connection_id=CONN):
    entry = {"scenario_id": sid, "hook_id": hook, "caller": "make_http", "protection": protection,
             "reason": "The shared Logger is called by Make HTTP modules that send the key"}
    if url_variable is not None:
        entry["url_variable"] = url_variable
    if connection_id is not None:
        entry["connection_id"] = connection_id
    if where == "scenarios":
        return {"scenarios": [entry]}
    return {"scenarios": [], "logger": entry}


def allowlist(pin=None, entries=(), webhooks="default"):
    data = {"entries": list(entries), "logger_hook": logger_pin() if pin is None else pin}
    return secret_scan.parse_secret_allowlist(data, webhooks_data=registry() if webhooks == "default" else webhooks)


def http_call(mid, url=None, **mapper):
    mp = {"url": url if url is not None else "{{" + URL_VAR + "}}", "method": "post", "headers": [], "queryParameters": [],
          "contentType": "urlEncoded",
          "urlEncodedBodyContent": [
              {"name": "label", "value": tp.NAME}, {"name": "outcome", "value": "Error"},
              {"name": "module_id", "value": "2"}, {"name": "module_name", "value": "OpenAI completion"},
              {"name": "error_type", "value": "{{2.error.type}}"}, {"name": "error_message", "value": "{{2.error.message}}"},
              {"name": "execution_id", "value": "{{var.scenario.executionId}}"}],
          "parseResponse": False, "stopOnHttpError": False, "timeout": 40, "allowRedirects": False}
    mp.update(mapper)
    return tp.mod(mid, "http:MakeRequest", version=4, parameters={"authenticationType": "apiKeyConnection", "apiKeyAccount": CONN},
                  mapper=mp)


def blueprint(*flow):
    return {"name": "Synthetic", "flow": list(flow), "metadata": {"version": 1}}


# ==========================================================================================================
# secret_scan: the Logger hook allowance
# ==========================================================================================================

class TestLoggerAllowanceParsing(unittest.TestCase):
    def test_the_repo_file_pins_the_logger_and_keeps_its_entries(self):
        al = secret_scan.load_secret_allowlist(os.path.join(ROOT, "audit", "secret_allowlist.json"))
        self.assertIsNotNone(al.logger)  # literal-URL mode, Rizwan 2026-10-29
        self.assertEqual((al.logger.scenario_id, al.logger.hook_id), ("6832527", 3000983))
        self.assertEqual([(e["scenario_id"], e["module_id"]) for e in al], [("3961751", 7), ("3975140", 2), ("3920821", 103),
                                                                                  ("3953105", 32)])

    def test_a_hook_registered_with_api_key_activates_the_allowance(self):
        for where in ("scenarios", "logger"):
            al = allowlist(webhooks=registry(where=where))
            self.assertTrue(al.logger.active, where)
            self.assertIsNone(al.logger.inactive_reason)
            self.assertEqual((al.logger.scenario_id, al.logger.hook_id), (LOGGER_SID, LOGGER_HOOK))

    def test_the_allowance_stays_inactive_unless_the_registry_backs_it(self):
        cases = {
            "no registry": None,
            "not listed": {"scenarios": []},
            "other hook": registry(hook=LOGGER_HOOK + 1),
            "fetch_back": registry(protection="fetch_back"),
            "pending entry with null IDs": {"scenarios": [], "logger": {"scenario_id": None, "hook_id": None, "protection": "api_key"}},
        }
        for what, reg in cases.items():
            al = allowlist(webhooks=reg)
            self.assertFalse(al.logger.active, what)
            self.assertTrue(al.logger.inactive_reason, what)

    def test_a_malformed_pin_is_refused_without_echoing_a_value(self):
        good = logger_pin()
        for bad in ({**good, "scenario_id": "abc"}, {**good, "hook_id": 0}, {**good, "hook_id": True},
                    {**good, "token_sha256": "ABC"}, {**good, "reason": "x"}, {**good, "url": LOGGER_URL}, "not an object"):
            with self.assertRaises(secret_scan.SecretAllowlistError) as ctx:
                secret_scan.parse_secret_allowlist({"entries": [], "logger_hook": bad}, webhooks_data=registry())
            self.assertNotIn(LOGGER_TAIL, str(ctx.exception))

    def test_the_logger_may_not_be_a_fetch_back_target_of_a_pinned_entry(self):
        entry = {"scenario_id": "1", "module_id": 2, "pattern_type": "make_webhook_url", "reason": "Points at a fetch-back hook",
                 "requires_fetch_back_hook": LOGGER_SID, "token_sha256": digest(FOREIGN_TAIL)}
        with self.assertRaises(secret_scan.SecretAllowlistError):
            secret_scan.parse_secret_allowlist({"entries": [entry], "logger_hook": logger_pin()}, webhooks_data=registry())

    def test_iteration_yields_the_pinned_entries_and_a_logger_alone_is_truthy(self):
        al = allowlist()
        self.assertEqual(list(al), [])
        self.assertTrue(al)
        self.assertIs((al or []).logger, al.logger)
        self.assertFalse(secret_scan.SecretAllowlist())

    def test_load_reads_the_registry_next_to_the_allowlist(self):
        tmp = tempfile.mkdtemp()
        try:
            path = os.path.join(tmp, "secret_allowlist.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"entries": [], "logger_hook": logger_pin()}, fh)
            self.assertFalse(secret_scan.load_secret_allowlist(path).logger.active)   # no webhooks.json yet
            with open(os.path.join(tmp, "webhooks.json"), "w", encoding="utf-8") as fh:
                json.dump(registry(), fh)
            self.assertTrue(secret_scan.load_secret_allowlist(path).logger.active)
            other = os.path.join(tmp, "other.json")
            with open(other, "w", encoding="utf-8") as fh:
                json.dump(registry(protection="fetch_back"), fh)
            self.assertFalse(secret_scan.load_secret_allowlist(path, other).logger.active)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_registered_loggers_reads_both_places_and_the_caller_fields(self):
        self.assertEqual(secret_scan.registered_loggers(registry()),
                         [{"scenario_id": LOGGER_SID, "hook_id": LOGGER_HOOK, "protection": "api_key", "url_variable": URL_VAR,
                           "connection_id": CONN}])
        self.assertEqual(len(secret_scan.registered_loggers(registry(where="logger"))), 1)
        self.assertEqual(secret_scan.registered_loggers({"scenarios": [], "logger": {"scenario_id": None, "hook_id": None}}), [])
        fetch = {"scenarios": [{"scenario_id": "1", "hook_id": 2, "caller": "bland_post_call", "protection": "fetch_back"}]}
        self.assertEqual(secret_scan.registered_loggers(fetch), [])


class TestLoggerAllowanceMatching(unittest.TestCase):
    def split(self, bp, al=None, sid="5"):
        return secret_scan.split_findings(bp, sid, allowlist() if al is None else al)

    def test_the_logger_url_is_allowed_only_in_a_logger_calls_url_field(self):
        # R6: the allowance covers <module path>.mapper.url of a Logger call. The same URL in another module (here a
        # util:SetVariable2 inside a router route) blocks.
        router = tp.mod(4, "builtin:BasicRouter", routes=[{"flow": [tp.mod(5, "util:SetVariable2", mapper={"value": LOGGER_URL})]}])
        bp = blueprint(tp.mod(1, "gateway:CustomWebHook"),
                       tp.mod(2, "openai-gpt-3:CreateCompletion", onerror=[http_call(3, url=LOGGER_URL), tp.mod(6, "builtin:Break")]),
                       router)
        blocking, allowed = self.split(bp)
        self.assertEqual([(f["pattern_type"], f["location"]) for f in blocking],
                         [("make_webhook_url", "$.flow[2].routes[0].flow[0].mapper.value")])
        self.assertNotIn(LOGGER_TAIL, json.dumps(blocking))
        self.assertEqual(sorted(a["module_id"] for a in allowed), [3])
        for a in allowed:
            self.assertEqual((a["kind"], a["requires_api_key_hook"], a["hook_id"], a["requires_fetch_back_hook"]),
                             ("logger_hook", LOGGER_SID, LOGGER_HOOK, None))
            self.assertNotIn(LOGGER_TAIL, json.dumps(a))

    def test_a_url_that_is_not_the_logger_blocks(self):
        bp = blueprint(http_call(3, url=FOREIGN_URL))
        blocking, allowed = self.split(bp)
        self.assertEqual(([f["pattern_type"] for f in blocking], allowed), (["make_webhook_url"], []))

    def test_a_foreign_url_riding_along_in_the_same_field_blocks(self):
        for value in (LOGGER_URL + " " + FOREIGN_URL, LOGGER_URL + " " + urllib.parse.quote(FOREIGN_URL, safe="")):
            blocking, allowed = self.split(blueprint(tp.mod(3, "util:SetVariable2", mapper={"value": value})))
            self.assertEqual([f["pattern_type"] for f in blocking], ["make_webhook_url"], value[-12:])
            self.assertEqual(allowed, [])

    def test_an_inactive_allowance_allows_nothing(self):
        bp = blueprint(http_call(3, url=LOGGER_URL))
        blocking, allowed = self.split(bp, allowlist(webhooks=registry(protection="fetch_back")))
        self.assertEqual((len(blocking), allowed), (1, []))
        blocking, allowed = self.split(bp, secret_scan.SecretAllowlist())
        self.assertEqual((len(blocking), allowed), (1, []))

    def test_a_module_shaped_object_inside_a_mapper_or_the_metadata_is_not_a_module(self):
        nested = tp.mod(3, "util:SetVariable2", mapper={"value": {"id": 9, "module": "http:MakeRequest", "mapper": {"url": LOGGER_URL}}})
        bp = blueprint(nested)
        bp["metadata"]["designer"] = {"note": LOGGER_URL}
        blocking, allowed = self.split(bp)
        self.assertEqual(len(blocking), 2)
        self.assertEqual(allowed, [])

    def test_pinned_entries_still_work_and_say_their_kind(self):
        send = {"id": 7, "module": "bland:sendACall", "mapper": {"webhook": FOREIGN_URL}}
        entry = {"scenario_id": "5", "module_id": 7, "pattern_type": "make_webhook_url", "reason": "Points at a fetch-back hook",
                 "requires_fetch_back_hook": "6", "token_sha256": digest(FOREIGN_TAIL)}
        blocking, allowed = self.split(blueprint(send, http_call(3, url=LOGGER_URL)), allowlist(entries=[entry]))
        self.assertEqual(blocking, [])
        self.assertEqual(sorted((a["module_id"], a["kind"]) for a in allowed), [(3, "logger_hook"), (7, "pinned")])

    def test_a_literal_x_make_apikey_header_is_a_credential(self):
        lit = tp.mod(3, "http:MakeRequest", mapper={"url": "{{" + URL_VAR + "}}", "headers": [{"name": "x-make-apikey", "value": "k3y" + "Z" * 12}]})
        mapped = tp.mod(4, "http:MakeRequest", mapper={"url": "{{" + URL_VAR + "}}", "headers": [{"name": "X-Make-ApiKey", "value": "{{1.key}}"}]})
        self.assertEqual([f["pattern_type"] for f in secret_scan.scan_obj(blueprint(lit))], ["api_key_header_literal"])
        self.assertEqual(secret_scan.scan_obj(blueprint(mapped)), [])


class TestStagedLoggerBlueprint(unittest.TestCase):
    """The pre-commit hook accepts a staged Logger URL only when the staged registry backs the pin and the staged manifest
    lists the finding as a logger_hook finding of that exact file."""

    BP = "blueprints/caller__5.json"

    def setUp(self):
        self.repo = tempfile.mkdtemp()
        for args in (("init", "-q"), ("config", "user.name", "Test"), ("config", "user.email", "test@example.invalid"),
                     ("config", "commit.gpgsign", "false")):
            self.git(*args)

    def tearDown(self):
        shutil.rmtree(self.repo, ignore_errors=True)

    def git(self, *args):
        return subprocess.run(["git", *args], cwd=self.repo, capture_output=True, text=True)

    def write(self, rel, obj):
        p = os.path.join(self.repo, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(json.dumps(obj, indent=2))

    def stage(self, reg=None, listed=None):
        self.write(self.BP, blueprint(http_call(3, url=LOGGER_URL)))
        self.write("audit/secret_allowlist.json", {"entries": [], "logger_hook": logger_pin()})
        self.write("audit/webhooks.json", registry() if reg is None else reg)
        row = {"module_id": 3, "pattern_type": "make_webhook_url", "kind": "logger_hook"} if listed is None else listed
        self.write("blueprints/manifest.json", {"scenarios": [{"id": 5, "file": "caller__5.json", "allowlisted_findings": [row]}]})
        self.git("add", "-A")

    def test_a_vouched_logger_url_is_accepted(self):
        self.stage()
        self.assertEqual(secret_scan.scan_staged(cwd=self.repo), [])

    def test_an_unbacked_or_unvouched_logger_url_blocks(self):
        for reg, listed in ((registry(protection="fetch_back"), None),
                            (None, {"module_id": 3, "pattern_type": "make_webhook_url"}),   # listed as a pinned finding
                            (None, {"module_id": 4, "pattern_type": "make_webhook_url", "kind": "logger_hook"})):
            self.stage(reg, listed)
            found = secret_scan.scan_staged(cwd=self.repo)
            self.assertEqual([f["pattern_type"] for f in found], ["make_webhook_url"])
            self.assertNotIn(LOGGER_TAIL, json.dumps(found))


# ==========================================================================================================
# make_pull: the Logger hook
# ==========================================================================================================

class TestPullLogger(tpl.Base):
    def fake(self, hooks=True, logger_hook=LOGGER_HOOK, hook_token=LOGGER_TAIL, url=LOGGER_URL, apikey=True):
        scen = [tpl.entry(1, "Caller"), tpl.entry(int(LOGGER_SID), "Logger")]
        caller = tpl.synthetic_blueprint("Caller")
        caller["flow"].append({"id": 2, "module": "openai-gpt-3:CreateCompletion", "version": 1, "mapper": {}, "metadata": {},
                               "onerror": [{"id": 3, "module": "http:MakeRequest", "version": 4,
                                            "parameters": {"authenticationType": "apiKeyConnection", "apiKeyAccount": CONN},
                                            "mapper": {"url": url, "method": "post"}, "metadata": {}},
                                           {"id": 4, "module": "builtin:Break", "version": 1, "metadata": {}}]})
        bps = {1: caller, int(LOGGER_SID): tpl.webhook_scenario("Logger", logger_hook)}
        raw = None
        if hooks:
            extra = {"apiKeys": [{"id": 77, "enabled": True}]} if apikey else {}
            raw = [tpl.raw_hook(LOGGER_HOOK, "Immi-OS Logger", scenario=int(LOGGER_SID), token=hook_token, **extra)]
        return tpl.FakeMake(scen, bps, hooks=raw)

    def pull(self, fake, al=None):
        client = make_pull.MakeClient(make_pull.Config(tpl.TOKEN, "us2", "123"), transport=fake, sleep=lambda s: None)
        return make_pull.pull(client, "123", self.out, now=lambda: tpl.FIXED_NOW, secret_allowlist=allowlist() if al is None else al)

    def test_a_logger_url_whose_token_matches_the_logger_hook_is_written_and_listed(self):
        fake = self.fake()
        res = self.pull(fake)
        self.assertEqual(res.withheld, [])
        self.assertTrue(os.path.exists(os.path.join(self.out, "caller__1.json")))
        m = self.manifest()
        self.assertEqual(m["scenarios"][0]["allowlisted_findings"], [{
            "module_id": 3, "pattern_type": "make_webhook_url", "requires_fetch_back_hook": None, "reason": REASON,
            "target_check": f"token matches the Logger hook {LOGGER_HOOK}", "kind": "logger_hook",
            "requires_api_key_hook": LOGGER_SID, "hook_id": LOGGER_HOOK}])
        self.assertNotIn(LOGGER_TAIL, json.dumps(m))
        self.assertFalse(any("/logs" in p for p in fake.paths()))   # the Error Monitor log read is gone
        self.assertNotIn("monitor", m)

    def test_the_logger_hook_apikey_count_is_recorded_like_every_other_hook(self):
        self.pull(self.fake())
        m = self.manifest()
        hook = next(h for h in m["hooks"] if h["id"] == LOGGER_HOOK)
        self.assertEqual((hook["apikey_count"], hook["scenario_ids"]), (1, [int(LOGGER_SID)]))
        self.assertEqual(m["logger_hook"], {"scenario_id": int(LOGGER_SID), "hook_id": LOGGER_HOOK, "allowance_active": True,
                                            "inactive_reason": None, "in_pull": True, "trigger_hook_matches": True,
                                            "hook_listed": True, "apikey_count": 1})
        self.pull(self.fake(apikey=False))
        self.assertIsNone(self.manifest()["logger_hook"]["apikey_count"])   # no key field: unknown, never a guessed zero

    def test_a_token_that_is_not_the_logger_hooks_withholds_the_caller(self):
        res = self.pull(self.fake(hook_token=FOREIGN_TAIL))
        self.assertEqual([w["id"] for w in res.withheld], [1])
        self.assertEqual([(x["id"], x["kind"]) for x in res.allowlist_mismatch], [(1, "logger_hook")])
        self.assertFalse(os.path.exists(os.path.join(self.out, "caller__1.json")))
        self.assertIn("does not match the Logger hook", make_pull.format_summary(res, 1))

    def test_a_logger_whose_trigger_uses_another_hook_withholds_the_caller(self):
        res = self.pull(self.fake(logger_hook=LOGGER_HOOK + 1))
        self.assertEqual([w["id"] for w in res.withheld], [1])
        self.assertFalse(self.manifest()["logger_hook"]["trigger_hook_matches"])

    def test_with_an_unreadable_hook_list_the_url_is_written_and_says_so(self):
        res = self.pull(self.fake(hooks=False))
        self.assertEqual(res.withheld, [])
        m = self.manifest()
        self.assertEqual(m["scenarios"][0]["allowlisted_findings"][0]["target_check"], "not checked (hook list unreadable)")
        self.assertEqual((m["logger_hook"]["hook_listed"], m["logger_hook"]["apikey_count"]), (None, None))
        self.assertIn("API key state unknown (hook list unreadable)", make_pull.format_summary(res, 1))

    def test_an_inactive_allowance_withholds_the_caller_and_the_summary_says_why(self):
        res = self.pull(self.fake(), allowlist(webhooks=registry(protection="fetch_back")))
        self.assertEqual([w["id"] for w in res.withheld], [1])
        summary = make_pull.format_summary(res, 1)
        self.assertIn("allowance INACTIVE", summary)
        self.assertNotIn(LOGGER_TAIL, summary)

    def test_the_cli_reads_the_registry_given_with_webhooks(self):
        al_path = os.path.join(self.tmp, "secret_allowlist.json")
        reg_path = os.path.join(self.tmp, "registry.json")
        with open(al_path, "w", encoding="utf-8") as fh:
            json.dump({"entries": [], "logger_hook": logger_pin()}, fh)
        with open(reg_path, "w", encoding="utf-8") as fh:
            json.dump(registry(), fh)
        code, output = self.run_main(self.fake(), "--secret-allowlist", al_path, "--webhooks", reg_path)
        self.assertEqual(code, 0, output)
        self.assertIn(f"Logger hook {LOGGER_HOOK} (scenario {LOGGER_SID}, trigger uses the pinned hook): allowance active, apikey_count 1.", output)
        self.assertNotIn(LOGGER_TAIL, output)
        code, _ = self.run_main(self.fake(), "--secret-allowlist", al_path)   # no webhooks.json next to it: inactive, withheld
        self.assertEqual(code, 1)


# ==========================================================================================================
# make_push: F-E5.3 units
# ==========================================================================================================

TARGET = make_push.LoggerTarget(LOGGER_SID, LOGGER_HOOK, URL_VAR, CONN)


class TestLoggerCallShape(unittest.TestCase):
    def test_the_spec_call_is_a_logger_call(self):
        self.assertEqual(make_push.logger_call_problems(http_call(13), TARGET), [])
        self.assertEqual(make_push.logger_call_problems(http_call(13, url="{{ " + URL_VAR + " }}"), TARGET), [])

    def test_each_transport_rule_is_enforced(self):
        def broken(change):
            m = http_call(13)
            change(m)
            return " ".join(make_push.logger_call_problems(m, TARGET))
        cases = {
            "not the HTTP module": (lambda m: m.update(module="http:ActionSendData"), "not the HTTP module"),
            "no keychain": (lambda m: m["parameters"].update(authenticationType="noAuth"), "API key keychain"),
            "other connection": (lambda m: m["parameters"].update(apiKeyAccount=CONN + 1), "not the Logger key connection"),
            "GET": (lambda m: m["mapper"].update(method="get"), "not post"),
            "other variable": (lambda m: m["mapper"].update(url="{{var.team.OTHER}}"), "mapper.url is not"),
            "mapped into the URL": (lambda m: m["mapper"].update(url="{{" + URL_VAR + "}}?x={{1.id}}"), "mapper.url is not"),
            "key header by hand": (lambda m: m["mapper"].update(headers=[{"name": "x-make-apikey", "value": "{{1.k}}"}]), "by hand"),
            "stopOnHttpError on": (lambda m: m["mapper"].update(stopOnHttpError=True), "stopOnHttpError is not false"),
            "stopOnHttpError missing": (lambda m: m["mapper"].pop("stopOnHttpError"), "stopOnHttpError is not false"),
            "redirects": (lambda m: m["mapper"].pop("allowRedirects"), "allowRedirects"),
            "filter": (lambda m: m.update(filter={"name": "f", "conditions": [[{"a": "{{1.x}}", "o": "exist"}]]}), "filter"),
            "own handler": (lambda m: m.update(onerror=[tp.mod(99, "builtin:Resume")]), "error handler of its own"),
        }
        for what, (change, expect) in cases.items():
            self.assertIn(expect, broken(change), what)

    def test_a_literal_url_needs_an_active_pin_for_the_same_hook(self):
        call = http_call(13, url=LOGGER_URL)
        self.assertIn("mapper.url is not", " ".join(make_push.logger_call_problems(call, TARGET)))
        pinned = make_push.LoggerTarget(LOGGER_SID, LOGGER_HOOK, URL_VAR, CONN, allowlist().logger)
        self.assertEqual(make_push.logger_call_problems(call, pinned), [])
        inactive = make_push.LoggerTarget(LOGGER_SID, LOGGER_HOOK, URL_VAR, CONN, allowlist(webhooks=None).logger)
        self.assertIn("mapper.url is not", " ".join(make_push.logger_call_problems(call, inactive)))
        self.assertIn("mapper.url is not", " ".join(make_push.logger_call_problems(http_call(13, url=FOREIGN_URL), pinned)))

    def test_without_a_registered_variable_the_variable_url_is_not_accepted(self):
        bare = make_push.LoggerTarget(LOGGER_SID, LOGGER_HOOK, None, CONN)
        self.assertIn("none registered", " ".join(make_push.logger_call_problems(http_call(13), bare)))


def live_bp():
    """Module 2 (an OpenAI call) has the legacy handler [ledger 10, Slack 11, Resume 12]. Module 3 (an email send) has a handler
    router 20 with a ledger route and a Slack plus Break route. Module 5 follows, so the Resume substitutes output for something."""
    router = tp.mod(20, "builtin:BasicRouter", routes=[{"flow": [tp.ledger(21)]}, {"flow": [tp.slack(22), tp.mod(23, "builtin:Break")]}])
    return {
        "name": tp.NAME,
        "flow": [
            tp.mod(1, "airtable:ActionSearchRecords", mapper={"table": tp.LEAD}),
            tp.mod(2, "openai-gpt-3:CreateCompletion", onerror=[tp.ledger(10), tp.slack(11), tp.mod(12, "builtin:Resume")]),
            tp.mod(3, "google-email:sendAnEmail", mapper={"to": ["{{1.Email}}"]}, onerror=[router]),
            tp.mod(5, "util:SetVariable2", mapper={"name": "v", "value": "1"}),
        ],
        "metadata": {"instant": False, "version": 1, "designer": {"orphans": []}, "scenario": {"maxErrors": 3, "autoCommit": True}},
    }


def swapped_bp(second=True):
    bp = live_bp()
    tp.find_module(bp, 2)["onerror"] = [http_call(30), tp.mod(12, "builtin:Resume")]
    if second:
        call = http_call(31)
        call["mapper"]["urlEncodedBodyContent"] = [dict(x) for x in call["mapper"]["urlEncodedBodyContent"]]
        for x in call["mapper"]["urlEncodedBodyContent"]:
            x["value"] = x["value"].replace("{{2.", "{{3.") if x["name"].startswith("error") else ("3" if x["name"] == "module_id" else x["value"])
        tp.find_module(bp, 3)["onerror"] = [call, tp.mod(23, "builtin:Break")]
    return bp


class TestLoggerSwapShape(unittest.TestCase):
    def swap(self, cand, live=None, sid=tp.SID):
        live = live_bp() if live is None else live
        return make_push.check_logger_swap(sid, live, cand, make_push.diff_modules(live, cand), TARGET)

    def refused(self, cand, live=None, sid=tp.SID):
        with self.assertRaises(make_push.Abort) as ctx:
            self.swap(cand, live, sid)
        return str(ctx.exception)

    def test_both_handler_shapes_swap_and_the_router_gives_way_to_its_directive(self):
        self.assertEqual(self.swap(swapped_bp()), {2: 30, 3: 31})

    def test_a_ledger_write_module_swaps_its_slack_message_for_the_call(self):
        live = live_bp()
        live["flow"][1] = tp.mod(2, "airtable:ActionCreateRecord", mapper={"table": tp.LEDGER},
                                 onerror=[tp.slack(11), tp.mod(12, "builtin:Resume")])
        cand = copy.deepcopy(live)
        cand["flow"][1]["onerror"] = [http_call(30), tp.mod(12, "builtin:Resume")]
        self.assertEqual(self.swap(cand, live), {2: 30})

    def test_a_directive_is_never_removed(self):
        cand = swapped_bp(second=False)
        tp.find_module(cand, 2)["onerror"] = [http_call(30)]
        self.assertIn("module 12 (builtin:Resume) is not a Shadow Ledger write", self.refused(cand))

    def test_removing_without_a_call_is_refused(self):
        cand = live_bp()
        tp.find_module(cand, 2)["onerror"] = [tp.mod(12, "builtin:Resume")]
        self.assertIn("get no Logger call", self.refused(cand))

    def test_the_call_goes_where_the_replaced_modules_sat_ahead_of_the_directive(self):
        cand = live_bp()
        tp.find_module(cand, 2)["onerror"] = [tp.mod(12, "builtin:Resume"), http_call(30)]
        self.assertIn("belongs where the first replaced module sat", self.refused(cand))

    def test_two_calls_in_one_handler_are_refused(self):
        cand = live_bp()
        tp.find_module(cand, 2)["onerror"] = [http_call(30), http_call(32), tp.mod(12, "builtin:Resume")]
        self.assertIn("two Logger calls", self.refused(cand))

    def test_a_partial_swap_that_leaves_a_slack_message_is_refused(self):
        cand = live_bp()
        tp.find_module(cand, 2)["onerror"] = [http_call(30), tp.slack(11), tp.mod(12, "builtin:Resume")]
        self.assertIn("still holds Shadow Ledger or Slack modules [11]", self.refused(cand))

    def test_a_call_that_breaks_the_transport_rules_is_refused(self):
        cand = swapped_bp(second=False)
        tp.find_module(cand, 30)["mapper"]["stopOnHttpError"] = True
        self.assertIn("module 30 is not a Logger call", self.refused(cand))

    def test_nothing_else_may_change_or_be_added(self):
        cand = swapped_bp(second=False)
        tp.find_module(cand, 2)["mapper"] = {"model": "other"}
        self.assertIn("module 2 changes beyond its error routes", self.refused(cand))
        cand = swapped_bp(second=False)
        cand["flow"].append(tp.mod(40, "util:SetVariable2"))
        self.assertIn("module 40 is added at flow", self.refused(cand))
        cand = swapped_bp(second=False)
        tp.find_module(cand, 5)["onerror"] = [tp.mod(41, "builtin:Ignore")]
        self.assertIn("module 41 is added", self.refused(cand))

    def test_a_filtered_ledger_write_ahead_of_a_survivor_is_refused(self):
        live = live_bp()
        tp.find_module(live, 10)["filter"] = {"name": "only some", "conditions": [[{"a": "{{1.x}}", "o": "exist"}]]}
        cand = copy.deepcopy(live)
        tp.find_module(cand, 2)["onerror"] = [http_call(30), tp.mod(12, "builtin:Resume")]
        self.assertIn("carries a filter", self.refused(cand, live))

    def test_the_logger_itself_is_never_swapped(self):
        self.assertIn("is the Logger itself", self.refused(swapped_bp(), sid=int(LOGGER_SID)))

    # --- guards ported from the retired F-E5.2 simplify tests (R1), now on the F-E5.3 swap ---

    def handler_live(self, onerror):
        live = live_bp()
        tp.find_module(live, 2)["onerror"] = onerror
        return live

    def test_no_directive_is_ever_removed_whatever_its_kind(self):
        for kind in ("Break", "Resume", "Ignore"):
            live = self.handler_live([tp.ledger(10), tp.slack(11), tp.mod(12, f"builtin:{kind}")])
            cand = copy.deepcopy(live)
            tp.find_module(cand, 2)["onerror"] = [http_call(30)]
            self.assertIn(f"module 12 (builtin:{kind}) is not a Shadow Ledger write", self.refused(cand, live), kind)

    def test_a_directive_inside_a_handler_router_is_not_removed_with_the_router(self):
        cand = live_bp()
        tp.find_module(cand, 3)["onerror"] = [http_call(31)]
        self.assertIn("module 23 (builtin:Break) is not a Shadow Ledger write", self.refused(cand))

    def test_a_directive_behind_a_real_filter_does_not_take_the_routers_place(self):
        live = live_bp()
        tp.find_module(live, 23)["filter"] = {"name": "f", "conditions": [[{"a": "{{1.x}}", "b": "1", "o": "number:equal"}]]}
        self.assertIn("router 20 is removed but module(s) [23] inside it stay", self.refused(swapped_bp(), live))

    def test_a_filtered_slack_message_in_the_directive_route_blocks_the_router_shrink(self):
        live = live_bp()
        tp.find_module(live, 22)["filter"] = {"name": "f", "conditions": [[{"a": "{{error.message}}", "b": "x", "o": "text:contain"}]]}
        self.assertIn("router 20 is removed but module(s) [23] inside it stay", self.refused(swapped_bp(), live))

    def test_an_empty_condition_list_is_a_route_name_not_a_filter(self):
        live = live_bp()
        tp.find_module(live, 22)["filter"] = {"name": "Alert", "conditions": []}
        self.assertEqual(self.swap(swapped_bp(), live), {2: 30, 3: 31})

    def test_the_fallback_route_is_never_the_directive_that_takes_over(self):
        live = live_bp()
        tp.find_module(live, 20)["parameters"] = {"else": 1}
        self.assertIn("router 20 is removed but module(s) [23] inside it stay", self.refused(swapped_bp(), live))

    def test_the_directive_moves_only_into_the_router_place(self):
        live = live_bp()
        live["flow"].append(tp.mod(40, "builtin:BasicRouter", routes=[{"flow": [tp.mod(41, "util:SetVariable2")]}]))
        cand = copy.deepcopy(live)
        tp.find_module(cand, 3)["onerror"] = [http_call(31)]
        tp.find_module(cand, 40)["routes"][0]["flow"].append(tp.mod(23, "builtin:Break"))
        self.assertIn("module 23 moves", self.refused(cand, live))

    def test_a_router_left_empty_by_the_removal_may_go(self):
        router = tp.mod(40, "builtin:BasicRouter", routes=[{"flow": [tp.ledger(41)]}, {"flow": [tp.slack(42)]}])
        live = self.handler_live([router, tp.mod(12, "builtin:Resume")])
        cand = copy.deepcopy(live)
        tp.find_module(cand, 2)["onerror"] = [http_call(30), tp.mod(12, "builtin:Resume")]
        self.assertEqual(self.swap(cand, live), {2: 30})

    def test_an_ordinary_module_in_the_handler_is_not_removed(self):
        live = self.handler_live([tp.ledger(10), tp.mod(13, "util:SetVariable2", mapper={"name": "v", "value": "1"}),
                                  tp.mod(12, "builtin:Resume")])
        cand = copy.deepcopy(live)
        tp.find_module(cand, 2)["onerror"] = [http_call(30), tp.mod(12, "builtin:Resume")]
        self.assertIn("module 13 (util:SetVariable2) is not a Shadow Ledger write", self.refused(cand, live))

    def test_survivors_keep_their_order(self):
        live = self.handler_live([tp.ledger(10), tp.slack(11), tp.mod(13, "util:SetVariable2"), tp.mod(12, "builtin:Resume")])
        cand = copy.deepcopy(live)
        tp.find_module(cand, 2)["onerror"] = [http_call(30), tp.mod(12, "builtin:Resume"), tp.mod(13, "util:SetVariable2")]
        self.assertIn("keeps the survivors in their order", self.refused(cand, live))

    def test_a_filtered_slack_message_ahead_of_the_directive_may_not_go(self):
        sl = tp.slack(11)
        sl["filter"] = {"name": "f", "conditions": [[{"a": "{{error.message}}", "b": "x", "o": "text:contain"}]]}
        live = self.handler_live([tp.ledger(10), sl, tp.mod(12, "builtin:Resume")])
        cand = copy.deepcopy(live)
        tp.find_module(cand, 2)["onerror"] = [http_call(30), tp.mod(12, "builtin:Resume")]
        self.assertIn("module 11 carries a filter that decides whether the modules after it in its route run, and [12] stay",
                      self.refused(cand, live))

    def test_a_ledger_update_in_a_handler_is_not_swapped_away(self):
        """R9: an update marks an existing row, so it carries state the Logger does not replace. Only a ledger create goes."""
        upd = tp.mod(10, "airtable:ActionUpdateRecords",
                     mapper={"table": tp.LEDGER, "id": "{{1.id}}", "record": {"fldgzlLkRAwc6KGoh": "Error"}})
        live = self.handler_live([upd, tp.slack(11), tp.mod(12, "builtin:Resume")])
        cand = copy.deepcopy(live)
        tp.find_module(cand, 2)["onerror"] = [http_call(30), tp.mod(12, "builtin:Resume")]
        self.assertIn("module 10 (airtable:ActionUpdateRecords) is not a Shadow Ledger write (a create)", self.refused(cand, live))


class TestLoggerRegistration(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def reg(self, data):
        path = os.path.join(self.tmp, "webhooks.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        return path

    def test_the_one_registered_logger_is_the_target(self):
        t = make_push.registered_logger(self.reg(registry()), allowlist())
        self.assertEqual((t.scenario_id, t.hook_id, t.url_variable, t.connection_id), (LOGGER_SID, LOGGER_HOOK, URL_VAR, CONN))
        self.assertIsNotNone(t.pin)
        other = allowlist(pin=logger_pin(hook=LOGGER_HOOK + 1), webhooks=registry(hook=LOGGER_HOOK + 1))
        self.assertIsNone(make_push.registered_logger(self.reg(registry()), other).pin)   # a pin for another hook does not ride along

    def test_no_logger_two_loggers_or_a_logger_without_api_key_are_refused(self):
        two = registry()
        two["scenarios"].append({**two["scenarios"][0], "scenario_id": "900778", "hook_id": 5552})
        for data, expect in (({"scenarios": []}, "registers none"),
                             ({"scenarios": [], "logger": {"scenario_id": None, "hook_id": None, "caller": "make_http"}}, "registers none"),
                             (two, "registers 2 Loggers"),
                             (registry(protection="fetch_back"), "must be api_key")):
            with self.assertRaises(make_push.Abort) as ctx:
                make_push.registered_logger(self.reg(data), secret_scan.SecretAllowlist())
            self.assertIn(expect, str(ctx.exception))


def finding(check, status, detail, scenario="Logger", mid=1):
    return audit_blueprints.Finding(check, status, scenario, mid, "gateway:CustomWebHook", detail)


class TestLoggerReadiness(unittest.TestCase):
    """check_logger_ready on a committed pull, with the audit's Logger rows scripted, so the gate is tested apart from check L."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.bp_dir = os.path.join(self.tmp, "blueprints")
        os.makedirs(self.bp_dir)
        with open(os.path.join(self.bp_dir, f"logger__{LOGGER_SID}.json"), "w", encoding="utf-8") as fh:
            json.dump(tpl.webhook_scenario("Logger", LOGGER_HOOK), fh)
        with open(os.path.join(self.bp_dir, "manifest.json"), "w", encoding="utf-8") as fh:
            json.dump({"pulled_at": "2026-10-29T12:00:00Z",
                       "scenarios": [{"id": int(LOGGER_SID), "name": "Logger", "file": f"logger__{LOGGER_SID}.json", "is_active": True}]}, fh)
        self.webhooks = os.path.join(self.tmp, "webhooks.json")
        with open(self.webhooks, "w", encoding="utf-8") as fh:
            json.dump(registry(), fh)
        self.args = mock.Mock(blueprints=self.bp_dir, webhooks=self.webhooks)
        self.kw = {"labels": audit_blueprints.Labels(True, {}), "schema": audit_blueprints.Schema([], []), "links": None,
                   "allowlist": None, "webhooks": None, "hooks": None, "status_designs": None}

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def ready(self, rows, committed=lambda path: None):
        res = audit_blueprints.AuditResult(blueprints=[], findings=rows)
        with mock.patch.object(audit_blueprints, "audit", autospec=True, return_value=res) as audit:
            out = make_push.check_logger_ready(self.args, secret_scan.SecretAllowlist(), self.kw, committed)
        self.assertFalse(audit.call_args.kwargs.get("partial", False))   # the whole pull, so the Logger check runs
        self.assertIn("schedule", audit.call_args.kwargs)
        return out

    def refused(self, rows, committed=lambda path: None):
        with self.assertRaises(make_push.Abort) as ctx:
            self.ready(rows, committed)
        return str(ctx.exception)

    def test_a_logger_that_passes_its_check_is_ready(self):
        target, notes = self.ready([finding("L", audit_blueprints.PASS, "L1 ok"), finding("F", audit_blueprints.PASS, "F1 ok")])
        self.assertEqual((target.scenario_id, notes), (LOGGER_SID, []))

    def test_the_hook_key_may_be_unconfirmed_and_nothing_else(self):
        unconf = "L1 UNCONFIRMED, no proof that a key exists: the hook list has no API key field for hook 5551"
        _t, notes = self.ready([finding("L", audit_blueprints.FAIL, unconf), finding("L", audit_blueprints.PASS, "L2 ok")])
        self.assertEqual(len(notes), 1)
        self.assertIn("no proof that a key exists", notes[0])
        self.assertIn("does not", self.refused([finding("L", audit_blueprints.FAIL, "L1 UNCONFIRMED, no scenario state: no is_active")]))
        self.assertIn("does not", self.refused([finding("L", audit_blueprints.PASS, "ok"),
                                                finding("F", audit_blueprints.FAIL, "F1 hook 5551 has no API key configured")]))

    def test_only_check_l_counts_and_the_retired_g_letter_does_not(self):
        self.assertEqual(make_push.LOGGER_CHECKS, ("L",))
        self.assertIn("returned no rows", self.refused([finding("G", audit_blueprints.PASS, "ok")]))

    def test_no_logger_rows_or_a_failing_row_refuses(self):
        self.assertIn("returned no rows", self.refused([finding("B", audit_blueprints.PASS, "unrelated")]))
        self.assertIn("does not", self.refused([finding("L", audit_blueprints.FAIL, "L0 Logger not deployed")]))

    def test_the_logger_snapshot_must_be_committed(self):
        def state(path):
            return "it differs from the last commit" if path.endswith(f"logger__{LOGGER_SID}.json") else None
        self.assertIn("Logger snapshot", self.refused([finding("L", audit_blueprints.PASS, "ok")], state))

    def test_a_logger_missing_from_the_pull_refuses(self):
        os.remove(os.path.join(self.bp_dir, f"logger__{LOGGER_SID}.json"))
        with open(os.path.join(self.bp_dir, "other__1.json"), "w", encoding="utf-8") as fh:
            json.dump(tpl.synthetic_blueprint("Other"), fh)
        with open(os.path.join(self.bp_dir, "manifest.json"), "w", encoding="utf-8") as fh:
            json.dump({"scenarios": [{"id": 1, "name": "Other", "file": "other__1.json", "is_active": True}]}, fh)
        self.assertIn("has no snapshot", self.refused([finding("L", audit_blueprints.PASS, "ok")]))


# ==========================================================================================================
# make_push: F-E5.3 end to end on the real audit
# ==========================================================================================================

class TestLoggerSwapPush(tp.Base):
    """A dry run and an apply of F-E5.3 on the real audit (check B v3 and check L) with the shipped Logger blueprint."""

    SPEC = "F-E5.3-batch-outbound-caller.md"

    def setUp(self):
        super().setUp()
        with open(os.path.join(self.specs, self.SPEC), "w", encoding="utf-8") as fh:
            fh.write(f"# F-E5.3\n\nScenario `{tp.NAME}`, ID `{tp.SID}`. Module 2 loses ledger 10 and Slack 11 for Logger call 30 and keeps "
                     f"Resume 12. Module 3 loses router 20 (ledger 21, Slack 22) for Logger call 31 and keeps Break 23 as it is.\n")
        self.webhooks = os.path.join(self.tmp, "webhooks.json")
        with open(self.webhooks, "w", encoding="utf-8") as fh:
            json.dump(registry(), fh)
        with open(os.path.join(ROOT, "specs", "logger.blueprint.json"), encoding="utf-8") as fh:
            lg = json.load(fh)
        lg["flow"][0].setdefault("parameters", {})["hook"] = LOGGER_HOOK
        with open(os.path.join(self.bp_dir, f"logger__{LOGGER_SID}.json"), "w", encoding="utf-8") as fh:
            fh.write(make_pull.render_json(lg))
        with open(os.path.join(self.bp_dir, "manifest.json"), "w", encoding="utf-8") as fh:
            json.dump({"pulled_at": "2026-10-29T12:00:00Z",
                       "hooks": [{"id": LOGGER_HOOK, "name": "Immi-OS Logger", "scenario_ids": [int(LOGGER_SID)], "enabled": True,
                                  "apikey_count": 1, "ip_restricted": None, "headers": None}],
                       "scenarios": [{"id": tp.SID, "name": tp.NAME, "file": f"batch-outbound-caller__{tp.SID}.json", "is_active": False},
                                     {"id": int(LOGGER_SID), "name": "Logger", "file": f"logger__{LOGGER_SID}.json", "is_active": True,
                                      "scheduling_type": "immediately"}]}, fh)
        self.use(live_bp(), swapped_bp())

    def use(self, live, cand):
        self.write_snapshot(live)
        self.write_candidate(cand)
        self.fake = tp.FakeMake(live)
        self.fake.others[int(LOGGER_SID)] = {"id": int(LOGGER_SID), "name": "Logger", "teamId": 123, "hookId": LOGGER_HOOK,
                                             "isActive": True, "isinvalid": False, "isPaused": False}

    def push(self, **kw):
        kw.setdefault("fix", "F-E5.3")
        kw.setdefault("modules", "2,3,10,11,20,21,22,23,30,31")
        kw.setdefault("closes", "B:2,B:3")
        kw["extra"] = ("--webhooks", self.webhooks) + tuple(kw.get("extra", ()))
        return self.run_main(self.fake, **kw)

    def test_the_fix_ids(self):
        self.assertEqual(make_push.fix_checks("F-E5.3"), ("B",))
        self.assertTrue(make_push.is_logger_fix("F-E5.3"))
        self.assertTrue(make_push.is_logger_fix("F-E5.3.1"))
        self.assertFalse(make_push.is_logger_fix("F-E5.31"))
        self.assertFalse(make_push.is_logger_fix("F-E5"))

    def test_a_dry_run_swaps_both_handlers_and_closes_their_review_rows(self):
        code, output = self.push()
        self.assertEqual(code, make_push.EXIT_OK, output)
        self.assertIn("Logger swap (F-E5.3): 2 handler(s) rewritten to [Logger call, directive], 2 -> call 30, 3 -> call 31", output)
        self.assertIn(f"Logger: scenario {LOGGER_SID}, hook {LOGGER_HOOK}, registered with api_key", output)
        self.assertIn("REVIEW targets closed: B:2:REVIEW, B:3:REVIEW.", output)
        self.assertIn("Residual risk", output)
        self.assertEqual(self.fake.patches(), [])

    def test_apply_saves_and_the_record_keeps_the_fail_count(self):
        code, output = self.push(apply=True)
        self.assertEqual(code, make_push.EXIT_OK, output)
        self.assertEqual(len(self.fake.patches()), 1)
        (_name, rec), = self.records()
        self.assertEqual(rec["fix"], "F-E5.3")
        self.assertEqual((rec["modules"]["added"], rec["modules"]["removed"]), ([30, 31], [10, 11, 20, 21, 22]))
        self.assertEqual(rec["audit_fail_count"]["before"], rec["audit_fail_count"]["after"])

    def test_every_rewritten_handler_names_its_b_row(self):
        code, output = self.push(closes="B:2")
        self.assertEqual(code, make_push.EXIT_ABORT)
        self.assertIn("rewrites the handlers of modules [3], and --closes does not name their B rows", output)

    def test_a_call_the_audit_rejects_adds_a_fail_and_is_refused(self):
        cand = swapped_bp()
        tp.find_module(cand, 30)["mapper"]["urlEncodedBodyContent"].append({"name": "email", "value": "{{1.Email}}"})
        self.use(live_bp(), cand)
        code, output = self.push()
        self.assertEqual(code, make_push.EXIT_ABORT)
        self.assertIn("FAIL", output)
        self.assertEqual(self.fake.patches(), [])

    def test_a_logger_that_is_not_active_stops_the_push_before_any_request(self):
        with open(os.path.join(self.bp_dir, "manifest.json"), encoding="utf-8") as fh:
            m = json.load(fh)
        m["scenarios"][1]["is_active"] = False
        with open(os.path.join(self.bp_dir, "manifest.json"), "w", encoding="utf-8") as fh:
            json.dump(m, fh)
        code, output = self.push()
        self.assertEqual(code, make_push.EXIT_ABORT)
        self.assertIn("needs the Logger to pass its check", output)
        self.assertEqual(self.fake.calls, [])

    def test_replaces_is_refused(self):
        code, output = self.push(replaces="10=30")
        self.assertEqual(code, make_push.EXIT_ABORT)
        self.assertIn("--replaces recreates modules", output)

    def test_f_e5_2_is_retired(self):
        code, output = self.push(fix="F-E5.2", closes="B:2")
        self.assertEqual(code, make_push.EXIT_ABORT)
        self.assertIn("F-E5.2 is retired", output)
        self.assertEqual(self.fake.calls, [])

    def test_the_monitor_flag_is_gone(self):
        code, _ = self.push(extra=("--monitor", os.path.join(self.tmp, "monitor.json")))
        self.assertEqual(code, make_push.EXIT_CONFIG)

    # --- R4: the Logger is read live, since the committed manifest can be stale ---

    LOGGER_PATH = f"/api/v2/scenarios/{LOGGER_SID}"

    def paths(self):
        return [urllib.parse.urlsplit(c[1]).path for c in self.fake.calls]

    def test_a_dry_run_reads_the_logger_live_first_and_says_what_it_cannot_check(self):
        code, output = self.push()
        self.assertEqual(code, make_push.EXIT_OK, output)
        self.assertEqual(self.paths()[0], self.LOGGER_PATH)
        self.assertEqual([c[0] for c in self.fake.calls if urllib.parse.urlsplit(c[1]).path == self.LOGGER_PATH], ["GET"])
        self.assertIn("active and not invalid live", output)
        self.assertIn("Not checked by this push", output)
        self.assertIn(URL_VAR, output)

    def test_a_logger_stopped_live_refuses_whatever_the_manifest_says(self):
        cases = {"inactive": ({"isActive": False}, "is INACTIVE live"),
                 "no state": ({"isActive": None}, "returned no isActive"),
                 "invalid": ({"isinvalid": True}, "flagged invalid"),
                 "paused": ({"isPaused": True}, "paused (isPaused)"),
                 "other hook": ({"hookId": LOGGER_HOOK + 1}, f"is live on hook {LOGGER_HOOK + 1}")}
        for what, (fields, expect) in cases.items():
            self.use(live_bp(), swapped_bp())
            self.fake.others[int(LOGGER_SID)].update(fields)
            if "isActive" in fields and fields["isActive"] is None:
                del self.fake.others[int(LOGGER_SID)]["isActive"]
            code, output = self.push(apply=True)
            self.assertEqual(code, make_push.EXIT_ABORT, what)
            self.assertIn(expect, output, what)
            self.assertEqual(self.paths(), [self.LOGGER_PATH], what)

    def test_the_spec_must_name_every_touched_module(self):
        """Ported from the retired F-E5.2 tests: the swap closes REVIEW rows, so the spec accounts for every module it touches."""
        with open(os.path.join(self.specs, self.SPEC), "w", encoding="utf-8") as fh:
            fh.write(f"# F-E5.3\n\nScenario `{tp.NAME}`, ID `{tp.SID}`. Module 2 loses ledger 10 and Slack 11 for Logger call 30 and keeps "
                     f"Resume 12. Module 3 loses router 20 (ledger 21) for Logger call 31 and keeps Break 23.\n")
        code, output = self.push()
        self.assertEqual(code, make_push.EXIT_ABORT)
        self.assertIn("does not name modules [22", output)
        self.assertEqual(self.fake.patches(), [])

    def test_a_logger_gone_live_refuses(self):
        del self.fake.others[int(LOGGER_SID)]
        code, output = self.push(apply=True)
        self.assertEqual(code, make_push.EXIT_ABORT)
        self.assertIn("returned 404", output)
        self.assertEqual(self.fake.patches(), [])

    def test_the_logger_transport_allows_one_get_and_nothing_else(self):
        t = make_push.ScenarioStateTransport(lambda *a, **k: None, tp.BASE, int(LOGGER_SID))
        t.check("GET", f"{tp.BASE}/scenarios/{LOGGER_SID}", None)
        for method, url, body in (("PATCH", f"{tp.BASE}/scenarios/{LOGGER_SID}", b"{}"),
                                  ("GET", f"{tp.BASE}/scenarios/{LOGGER_SID}/blueprint?draft=false", None),
                                  ("GET", f"{tp.BASE}/scenarios/{LOGGER_SID}?cols[]=isActive", None),
                                  ("GET", f"{tp.BASE}/scenarios/{tp.SID}", None),
                                  ("GET", f"https://other.invalid/api/v2/scenarios/{LOGGER_SID}", None)):
            with self.assertRaises(make_push.TransportRefused, msg=f"{method} {url}"):
                t.check(method, url, body)


if __name__ == "__main__":
    unittest.main()
