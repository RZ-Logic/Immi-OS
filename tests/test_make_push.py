"""Tests for scripts/make_push.py.

No network: every test injects a fake transport (wrapped by the real guard).
Tokens and secret-shaped values are assembled at runtime so this file holds
no literal the pre-commit hook would block. Fixtures are synthetic.
"""

import argparse
import contextlib
import copy
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import urllib.parse
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import make_pull  # noqa: E402
import make_push  # noqa: E402
from make_pull import Response, TransientError  # noqa: E402

FIX = os.path.join(ROOT, "tests", "fixtures")
READ_TOKEN = "-".join(["0a1b2c3d", "4e5f", "6a7b", "8c9d", "0e1f2a3b4c5d"]) + "r"
WRITE_TOKEN = "-".join(["9f8e7d6c", "5b4a", "3f2e", "1d0c", "b9a8f7e6d5c4"]) + "w"
ALNUM = "A1b2C3d4E5f6G7h8J9k0L1m2N3p4Q5r6"
SID = 900001
NAME = "Batch Outbound Caller"
FIXED_NOW = datetime(2026, 10, 28, 15, 30, 0, tzinfo=timezone.utc)
LEDGER = "tblf73Cdii3CsLKfL"
LEAD = "tblHk09sCKLcOJXr9"
LABEL = "fldFC0g1pzkgHOV3g"
BASE = "https://us2.make.com/api/v2"


def mod(mid, module, **extra):
    m = {"id": mid, "module": module, "version": 1, "parameters": {}, "mapper": {},
         "metadata": {"designer": {"x": mid * 100, "y": 0}}}
    m.update(extra)
    return m


def slack(mid):
    return mod(mid, "slack:CreateMessage", mapper={"text": "Error {{error.message}}", "channel": "C0"})


def ledger(mid):
    return mod(mid, "airtable:ActionCreateRecord",
               mapper={"table": LEDGER, "record": {LABEL: NAME, "fldgzlLkRAwc6KGoh": "Error"}})


def live_blueprint():
    """Two B FAILs: module 2 has no handler, module 4 (nested in a route) has
    Slack + Ignore but no ledger write."""
    return {
        "name": NAME,
        "flow": [
            mod(1, "airtable:ActionSearchRecords", mapper={"table": LEAD, "maxRecords": "1"}),
            mod(2, "airtable:ActionUpdateRecords", mapper={"table": LEAD, "id": "{{1.id}}"}),
            mod(3, "builtin:BasicRouter", routes=[
                {"flow": [mod(4, "http:ActionSendData", mapper={"url": "https://example.invalid/x"},
                              onerror=[slack(5), mod(6, "builtin:Ignore")])]},
                {"flow": [mod(7, "util:SetVariable2", mapper={"name": "v", "value": "1"})]},
            ]),
        ],
        "metadata": {"instant": False, "version": 1, "designer": {"orphans": []},
                     "scenario": {"maxErrors": 3, "autoCommit": True}},
    }


def fixed_candidate():
    """Module 2 gains a full handler (ledger 10, Slack 11, Resume 12)."""
    bp = live_blueprint()
    bp["flow"][1]["onerror"] = [ledger(10), slack(11), mod(12, "builtin:Resume")]
    return bp


def find_module(bp, mid):
    def visit(flow):
        for m in flow:
            if m.get("id") == mid:
                return m
            for r in m.get("routes") or []:
                got = visit(r.get("flow") or [])
                if got:
                    return got
            got = visit(m.get("onerror") or [])
            if got:
                return got
        return None
    return visit(bp["flow"])


def all_ids(bp):
    out = []
    def visit(flow):
        for m in flow:
            out.append(m["id"])
            for r in m.get("routes") or []:
                visit(r.get("flow") or [])
            visit(m.get("onerror") or [])
    visit(bp["flow"])
    return out


class FakeMake:
    """Scripted Make API. Records every call. PATCH saves the blueprint."""

    def __init__(self, live, version=10, active=False, draft=None, id_sequence="max"):
        self.live = copy.deepcopy(live)
        self.version = version
        self.active = active
        self.draft = draft
        # Make's module ID counter. "max" = the highest module ID in live.
        self.id_sequence = max(all_ids(live), default=0) if id_sequence == "max" else id_sequence
        self.advance_ids = True            # a save moves idSequence up to the highest saved ID
        self.scenario_extra = {}           # extra GET /scenarios/{id} fields (isinvalid, islocked)
        self.others = {}                   # other scenario ID -> its GET /scenarios/{id} object (the Logger, F-E5.3)
        self.calls = []
        self.queued = {}
        self.patch_responses = []          # queued Responses (or exceptions) for PATCH
        self.after_patch = {}              # state overrides applied on a successful save
        self.saves = 0

    def __call__(self, method, url, headers, timeout, body=None):
        self.calls.append((method, url, dict(headers), body))
        parts = urllib.parse.urlsplit(url)
        path = parts.path[len("/api/v2"):]
        q = dict(urllib.parse.parse_qsl(parts.query))
        if self.queued.get((method, path)):
            item = self.queued[(method, path)].pop(0)
            if isinstance(item, Exception):
                raise item
            return item
        if method == "PATCH":
            if self.patch_responses:
                item = self.patch_responses.pop(0)
                if isinstance(item, Exception):
                    raise item
                if item.status != 200:
                    return item
                self._save(body)
                return item
            self._save(body)
            return self._json({"scenario": {"id": SID, "name": NAME, "isActive": self.active}})
        if path == f"/scenarios/{SID}":
            scen = {"id": SID, "name": NAME, "teamId": 123, **self.scenario_extra}
            if self.active is not None:
                scen["isActive"] = self.active
            return self._json({"scenario": scen})
        if method == "GET" and path.startswith("/scenarios/") and path[len("/scenarios/"):].isdigit()                 and int(path[len("/scenarios/"):]) in self.others:
            return self._json({"scenario": self.others[int(path[len("/scenarios/"):])]})
        if path == f"/scenarios/{SID}/blueprint":
            if q.get("draft") == "true":
                return self._json({"code": "OK", "response": {"blueprint": self.draft, "version": self.version}})
            resp = {"blueprint": self.live, "scheduling": {"type": "indefinitely"},
                    "version": self.version, "last_edit": "2026-10-01T00:00:00.000Z"}
            if self.id_sequence is not None:
                resp["idSequence"] = self.id_sequence
            return self._json({"code": "OK", "response": resp})
        return Response(404, {}, b"{}")

    def _save(self, body):
        self.saves += 1
        payload = json.loads(body.decode("utf-8"))
        saved = json.loads(payload["blueprint"])
        # Make adds keys of its own on save, nested modules included.
        def add_keys(flow):
            for m in flow:
                m.setdefault("metadata", {})["restore"] = {"added": "by make"}
                for r in m.get("routes") or []:
                    add_keys(r.get("flow") or [])
                add_keys(m.get("onerror") or [])
        add_keys(saved["flow"])
        self.live = saved
        self.version += 1
        if self.advance_ids and self.id_sequence is not None:
            self.id_sequence = max(self.id_sequence, max(all_ids(saved), default=0))
        for k, v in self.after_patch.items():
            if callable(v):
                v(self)
            else:
                setattr(self, k, v)

    @staticmethod
    def _json(obj, status=200):
        return Response(status, {"content-type": "application/json"}, json.dumps(obj).encode("utf-8"))

    def methods(self):
        return [c[0] for c in self.calls]

    def patches(self):
        return [c for c in self.calls if c[0] == "PATCH"]


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="make_push_test_")
        self.bp_dir = os.path.join(self.tmp, "blueprints")
        self.specs = os.path.join(self.tmp, "specs")
        self.pushes = os.path.join(self.tmp, "pushes")
        os.makedirs(self.bp_dir)
        os.makedirs(self.specs)
        self.env = os.path.join(self.tmp, ".env")
        self.write_env(READ_TOKEN, WRITE_TOKEN)
        self.write_snapshot(live_blueprint())
        with open(os.path.join(self.specs, "F-E5-batch-outbound-caller.md"), "w", encoding="utf-8") as fh:
            fh.write(f"# F-E5\n\nScenario `{NAME}`, ID `{SID}`. Module 2 gains a full handler.\n")
        self.cand_path = os.path.join(self.tmp, "candidate.json")
        self.write_candidate(fixed_candidate())
        self.sleeps = []

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write_env(self, read, write):
        lines = ["MAKE_ZONE=us2", "MAKE_TEAM_ID=123"]
        if read is not None:
            lines.append("MAKE_API_TOKEN=" + read)
        if write is not None:
            lines.append("MAKE_WRITE_TOKEN=" + write)
        with open(self.env, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")

    def write_snapshot(self, bp):
        with open(os.path.join(self.bp_dir, f"batch-outbound-caller__{SID}.json"), "w", encoding="utf-8") as fh:
            fh.write(make_pull.render_json(bp))

    def write_candidate(self, bp):
        with open(self.cand_path, "w", encoding="utf-8") as fh:
            json.dump(bp, fh)

    def run_main(self, fake, modules="2,10,11,12", apply=False, extra=(), fix="F-E5", base_version=10,
                 closes="B:2", replaces=None, snapshot_state=lambda path: None):
        argv = ["--scenario", str(SID), "--candidate", self.cand_path, "--fix", fix,
                "--modules", modules, "--env", self.env, "--blueprints", self.bp_dir,
                "--labels", os.path.join(FIX, "labels_confirmed.json"),
                "--schema", os.path.join(FIX, "schema.json"),
                "--critical", os.path.join(FIX, "critical_all.json"),
                "--specs", self.specs, "--pushes-dir", self.pushes, *extra]
        if base_version is not None:
            argv += ["--base-version", str(base_version)]
        if closes is not None:
            argv += ["--closes", closes]
        if replaces is not None:
            argv += ["--replaces", replaces]
        if apply:
            argv.append("--apply")
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = make_push.main(argv, transport=fake, sleep=self.sleeps.append,
                                  environ={}, now=lambda: FIXED_NOW, snapshot_state=snapshot_state)
        output = out.getvalue() + err.getvalue()
        self.assert_no_token(output)
        for name in os.listdir(self.pushes) if os.path.isdir(self.pushes) else []:
            with open(os.path.join(self.pushes, name), encoding="utf-8") as fh:
                self.assert_no_token(fh.read())
        return code, output

    def assert_no_token(self, text):
        for tok in (READ_TOKEN, WRITE_TOKEN):
            for i in range(len(tok) - make_pull.REDACT_MIN_FRAGMENT + 1):
                frag = tok[i:i + make_pull.REDACT_MIN_FRAGMENT]
                self.assertNotIn(frag, text, "token fragment leaked into output")

    def records(self):
        if not os.path.isdir(self.pushes):
            return []
        out = []
        for name in sorted(os.listdir(self.pushes)):
            with open(os.path.join(self.pushes, name), encoding="utf-8") as fh:
                out.append((name, json.load(fh)))
        return out


# --------------------------------------------------------------------------
# Step 1: config
# --------------------------------------------------------------------------

class TestConfig(Base):
    def test_missing_write_token_exits_2_before_any_request(self):
        self.write_env(READ_TOKEN, None)
        fake = FakeMake(live_blueprint())
        code, output = self.run_main(fake)
        self.assertEqual(code, make_push.EXIT_CONFIG)
        self.assertIn("MAKE_WRITE_TOKEN", output)
        self.assertEqual(fake.calls, [])

    def test_missing_read_token_exits_2(self):
        self.write_env(None, WRITE_TOKEN)
        fake = FakeMake(live_blueprint())
        code, output = self.run_main(fake)
        self.assertEqual(code, make_push.EXIT_CONFIG)
        self.assertIn("MAKE_API_TOKEN", output)
        self.assertEqual(fake.calls, [])

    def test_equal_tokens_exit_2(self):
        self.write_env(READ_TOKEN, READ_TOKEN)
        fake = FakeMake(live_blueprint())
        code, output = self.run_main(fake)
        self.assertEqual(code, make_push.EXIT_CONFIG)
        self.assertIn("equals", output)
        self.assertEqual(fake.calls, [])

    def test_bad_arguments_exit_2(self):
        fake = FakeMake(live_blueprint())
        for modules in ("", "2,x", "0", "-1"):
            code, _ = self.run_main(fake, modules=modules)
            self.assertEqual(code, make_push.EXIT_CONFIG, modules)
        out = io.StringIO()
        with contextlib.redirect_stderr(out):
            code = make_push.main(["--scenario", str(SID), "--candidate", self.cand_path,
                                   "--fix", "../evil", "--modules", "2", "--env", self.env],
                                  transport=fake, environ={})
        self.assertEqual(code, make_push.EXIT_CONFIG)
        self.assertEqual(fake.calls, [])

    def test_missing_spec_aborts(self):
        os.remove(os.path.join(self.specs, "F-E5-batch-outbound-caller.md"))
        with open(os.path.join(self.specs, "F-E5-other.md"), "w", encoding="utf-8") as fh:
            fh.write("Scenario ID 1234567\n")
        fake = FakeMake(live_blueprint())
        code, output = self.run_main(fake)
        self.assertEqual(code, make_push.EXIT_ABORT)
        self.assertIn("spec", output)
        self.assertNotIn("PATCH", fake.methods())


# --------------------------------------------------------------------------
# Steps 2 to 4: live state guards
# --------------------------------------------------------------------------

class TestLiveGuards(Base):
    def test_active_scenario_aborts(self):
        fake = FakeMake(live_blueprint(), active=True)
        code, output = self.run_main(fake, apply=True)
        self.assertEqual(code, make_push.EXIT_ABORT)
        self.assertIn("ACTIVE", output)
        self.assertNotIn("PATCH", fake.methods())

    def test_missing_is_active_aborts(self):
        fake = FakeMake(live_blueprint(), active=None)
        code, output = self.run_main(fake, apply=True)
        self.assertEqual(code, make_push.EXIT_ABORT)
        self.assertIn("isActive", output)
        self.assertNotIn("PATCH", fake.methods())

    def test_live_differs_from_snapshot_aborts(self):
        live = live_blueprint()
        find_module(live, 7)["mapper"]["value"] = "2"
        fake = FakeMake(live)
        code, output = self.run_main(fake, apply=True)
        self.assertEqual(code, make_push.EXIT_ABORT)
        self.assertIn("live differs from snapshot", output)
        self.assertIn("Re-pull, then rebuild the candidate from the new snapshot", output)
        self.assertNotIn("PATCH", fake.methods())

    def test_designer_move_in_live_still_counts_as_differs(self):
        live = live_blueprint()
        find_module(live, 7)["metadata"]["designer"]["x"] = 9999
        code, output = self.run_main(FakeMake(live), apply=True)
        self.assertEqual(code, make_push.EXIT_ABORT)
        self.assertIn("Re-pull", output)

    def test_missing_snapshot_aborts(self):
        os.remove(os.path.join(self.bp_dir, f"batch-outbound-caller__{SID}.json"))
        fake = FakeMake(live_blueprint())
        code, output = self.run_main(fake, apply=True)
        self.assertEqual(code, make_push.EXIT_ABORT)
        self.assertIn("snapshot", output)
        self.assertEqual(fake.calls, [])

    def test_unpublished_draft_aborts(self):
        fake = FakeMake(live_blueprint(), draft=fixed_candidate())
        code, output = self.run_main(fake, apply=True)
        self.assertEqual(code, make_push.EXIT_ABORT)
        self.assertIn("unpublished draft", output)
        self.assertNotIn("PATCH", fake.methods())

    def test_get_failure_exits_3(self):
        fake = FakeMake(live_blueprint())
        fake.queued[("GET", f"/scenarios/{SID}")] = [
            Response(401, {}, json.dumps({"code": "IM005", "message": "bad token " + READ_TOKEN[:12]}).encode())]
        code, output = self.run_main(fake, apply=True)
        self.assertEqual(code, make_push.EXIT_API)
        self.assertIn("IM005", output)
        self.assertNotIn("bad token", output)

    def test_get_retries_on_5xx_like_make_pull(self):
        fake = FakeMake(live_blueprint())
        fake.queued[("GET", f"/scenarios/{SID}")] = [Response(503, {}, b""), TransientError("timeout")]
        code, _ = self.run_main(fake)
        self.assertEqual(code, make_push.EXIT_OK)
        self.assertEqual(len(self.sleeps), 2)


# --------------------------------------------------------------------------
# Step 5: module diff
# --------------------------------------------------------------------------

class TestModuleDiff(Base):
    def test_changed_module_outside_allow_list_aborts(self):
        cand = fixed_candidate()
        find_module(cand, 7)["mapper"]["value"] = "2"
        self.write_candidate(cand)
        fake = FakeMake(live_blueprint())
        code, output = self.run_main(fake, apply=True)
        self.assertEqual(code, make_push.EXIT_ABORT)
        self.assertIn("not in --modules: [7]", output)
        self.assertNotIn("PATCH", fake.methods())

    def test_listed_module_that_does_not_change_aborts(self):
        fake = FakeMake(live_blueprint())
        code, output = self.run_main(fake, modules="2,10,11,12,13", apply=True)
        self.assertEqual(code, make_push.EXIT_ABORT)
        self.assertIn("do not change (typo?): [13]", output)
        self.assertNotIn("PATCH", fake.methods())

    def test_added_modules_must_be_listed(self):
        code, output = self.run_main(FakeMake(live_blueprint()), modules="2,10,11")
        self.assertEqual(code, make_push.EXIT_ABORT)
        self.assertIn("[12]", output)

    def test_parent_gaining_a_handler_must_be_listed(self):
        code, output = self.run_main(FakeMake(live_blueprint()), modules="10,11,12")
        self.assertEqual(code, make_push.EXIT_ABORT)
        self.assertIn("not in --modules: [2]", output)

    def test_removed_module_must_be_listed(self):
        live = live_blueprint()
        cand = fixed_candidate()
        find_module(cand, 3)["routes"][1]["flow"] = []
        self.write_candidate(cand)
        code, output = self.run_main(FakeMake(live), modules="2,10,11,12")
        self.assertEqual(code, make_push.EXIT_ABORT)
        self.assertIn("not in --modules: [3, 7]", output)
        d = make_push.diff_modules(live, cand)
        self.assertEqual(d.removed, [7])
        self.assertIn(3, d.changed)

    def test_nested_onerror_module_inside_route_is_detected(self):
        live = live_blueprint()
        cand = copy.deepcopy(live)
        find_module(cand, 5)["mapper"]["text"] = "changed"
        d = make_push.diff_modules(live, cand)
        self.assertEqual(sorted(d.changed), [5])
        self.assertEqual(d.changed[5], ["mapper.text"])
        self.assertEqual(d.added, [])
        self.assertEqual(d.removed, [])

    def test_nested_route_module_is_detected(self):
        live = live_blueprint()
        cand = copy.deepcopy(live)
        find_module(cand, 7)["mapper"]["value"] = "2"
        d = make_push.diff_modules(live, cand)
        self.assertEqual(sorted(d.changed), [7])

    def test_module_added_inside_nested_onerror(self):
        live = live_blueprint()
        cand = copy.deepcopy(live)
        find_module(cand, 4)["onerror"].insert(0, ledger(13))
        d = make_push.diff_modules(live, cand)
        self.assertEqual(d.added, [13])
        self.assertEqual(sorted(d.changed), [4])
        self.assertIn("onerror modules [5, 6] -> [13, 5, 6]", d.changed[4])

    def test_moved_module_is_detected(self):
        live = live_blueprint()
        cand = copy.deepcopy(live)
        m7 = find_module(cand, 7)
        find_module(cand, 3)["routes"][1]["flow"] = []
        find_module(cand, 3)["routes"][0]["flow"].append(m7)
        d = make_push.diff_modules(live, cand)
        self.assertEqual(sorted(d.changed), [3, 7])
        self.assertTrue(any("moved" in r for r in d.changed[7]))

    def test_top_level_reorder_is_detected(self):
        live = live_blueprint()
        cand = copy.deepcopy(live)
        cand["flow"][1], cand["flow"][2] = cand["flow"][2], cand["flow"][1]
        d = make_push.diff_modules(live, cand)
        self.assertEqual(sorted(d.changed), [2, 3])

    def test_type_strict_compare(self):
        live = live_blueprint()
        cand = copy.deepcopy(live)
        find_module(cand, 7)["version"] = True
        self.assertEqual(sorted(make_push.diff_modules(live, cand).changed), [7])

    def test_designer_only_changes_are_ignored(self):
        live = live_blueprint()
        cand = copy.deepcopy(live)
        for mid in (1, 4, 5, 7):
            find_module(cand, mid)["metadata"]["designer"] = {"x": 1, "y": 2}
        cand["metadata"]["designer"] = {"orphans": [], "notes": "moved"}
        self.assertEqual(make_push.diff_modules(live, cand).touched, set())
        self.write_candidate(cand)
        code, output = self.run_main(FakeMake(live), modules="2", apply=True)
        self.assertEqual(code, make_push.EXIT_ABORT)
        self.assertIn("Nothing to push", output)

    def test_designer_moves_do_not_need_listing(self):
        cand = fixed_candidate()
        for mid in (1, 4, 7):
            find_module(cand, mid)["metadata"]["designer"] = {"x": -5, "y": 42}
        self.write_candidate(cand)
        code, _ = self.run_main(FakeMake(live_blueprint()))
        self.assertEqual(code, make_push.EXIT_OK)

    def test_top_level_metadata_change_aborts(self):
        cand = fixed_candidate()
        cand["metadata"]["scenario"]["maxErrors"] = 9
        self.write_candidate(cand)
        code, output = self.run_main(FakeMake(live_blueprint()))
        self.assertEqual(code, make_push.EXIT_ABORT)
        self.assertIn("metadata.scenario.maxErrors", output)

    def test_name_change_aborts(self):
        cand = fixed_candidate()
        cand["name"] = "Renamed"
        self.write_candidate(cand)
        code, output = self.run_main(FakeMake(live_blueprint()))
        self.assertEqual(code, make_push.EXIT_ABORT)
        self.assertIn("name differs", output)

    def test_wrapped_candidate_is_refused(self):
        self.write_candidate({"response": {"blueprint": fixed_candidate()}})
        code, output = self.run_main(FakeMake(live_blueprint()))
        self.assertEqual(code, make_push.EXIT_ABORT)
        self.assertIn("export-format", output)

    def test_duplicate_module_id_aborts(self):
        cand = fixed_candidate()
        find_module(cand, 2)["onerror"].append(slack(7))
        self.write_candidate(cand)
        code, output = self.run_main(FakeMake(live_blueprint()))
        self.assertEqual(code, make_push.EXIT_ABORT)
        self.assertIn("more than once", output)

    def test_diff_report_lists_paths_not_values(self):
        cand = fixed_candidate()
        find_module(cand, 7)["mapper"]["value"] = "very-distinct-value-xyz"
        self.write_candidate(cand)
        code, output = self.run_main(FakeMake(live_blueprint()), modules="2,7,10,11,12")
        self.assertIn("7: mapper.value", output)
        self.assertNotIn("very-distinct-value-xyz", output)


# --------------------------------------------------------------------------
# Steps 6 and 7: secrets and audit
# --------------------------------------------------------------------------

class TestSecretsAndAudit(Base):
    def test_secret_in_candidate_aborts_without_printing_it(self):
        cand = fixed_candidate()
        literal = "Bearer " + "lit" + ALNUM
        find_module(cand, 4)["mapper"]["headers"] = [{"name": "Authorization", "value": literal}]
        self.write_candidate(cand)
        fake = FakeMake(live_blueprint())
        code, output = self.run_main(fake, modules="2,4,10,11,12", apply=True)
        self.assertEqual(code, make_push.EXIT_ABORT)
        self.assertIn("credential literal", output)
        self.assertNotIn(ALNUM, output)
        self.assertNotIn("PATCH", fake.methods())

    def test_new_fail_aborts(self):
        cand = fixed_candidate()
        find_module(cand, 3)["routes"][1]["flow"].append(mod(14, "http:ActionSendData", mapper={"url": "u"}))
        self.write_candidate(cand)
        fake = FakeMake(live_blueprint())
        code, output = self.run_main(fake, modules="2,3,10,11,12,14", apply=True)
        self.assertEqual(code, make_push.EXIT_ABORT)
        self.assertIn("adds FAIL", output)
        self.assertIn("module 14", output)
        self.assertNotIn("PATCH", fake.methods())

    def test_no_fail_reduction_aborts(self):
        cand = live_blueprint()
        find_module(cand, 7)["mapper"]["value"] = "2"
        self.write_candidate(cand)
        fake = FakeMake(live_blueprint())
        code, output = self.run_main(fake, modules="7", apply=True)
        self.assertEqual(code, make_push.EXIT_ABORT)
        self.assertIn("does not reduce the FAIL count (2 -> 2)", output)
        self.assertNotIn("PATCH", fake.methods())


# --------------------------------------------------------------------------
# Happy paths
# --------------------------------------------------------------------------

def with_samples(bp, samples):
    bp = copy.deepcopy(bp)
    bp.setdefault("metadata", {}).setdefault("designer", {})["samples"] = samples
    return bp


class TestSamples(Base):
    """Snapshots carry no metadata.designer.samples (hard rule 5). Live does."""

    SAMPLES = {"1": [{"email": "test" + "@" + "example.com"}]}

    def test_live_samples_ignored_in_snapshot_match_and_kept_on_save(self):
        fake = FakeMake(with_samples(live_blueprint(), self.SAMPLES), version=10)
        code, output = self.run_main(fake, apply=True)
        self.assertEqual(code, make_push.EXIT_OK, output)
        saved = json.loads(json.loads(fake.patches()[0][3].decode("utf-8"))["blueprint"])
        self.assertEqual(saved["metadata"]["designer"]["samples"], self.SAMPLES)
        self.assertEqual(saved["flow"], fixed_candidate()["flow"])

    def test_candidate_with_different_samples_aborts(self):
        fake = FakeMake(with_samples(live_blueprint(), self.SAMPLES))
        self.write_candidate(with_samples(fixed_candidate(), {"1": []}))
        code, output = self.run_main(fake)
        self.assertEqual(code, make_push.EXIT_ABORT, output)
        self.assertEqual(fake.patches(), [])

    def test_snapshot_with_other_drift_still_aborts(self):
        live = with_samples(live_blueprint(), self.SAMPLES)
        find_module(live, 2)["mapper"] = {"changed": "in the UI"}
        code, output = self.run_main(FakeMake(live))
        self.assertEqual(code, make_push.EXIT_ABORT, output)
        self.assertIn("live differs from snapshot", output)


class TestHappyPath(Base):
    def test_dry_run_checks_everything_and_never_patches(self):
        fake = FakeMake(live_blueprint())
        code, output = self.run_main(fake)
        self.assertEqual(code, make_push.EXIT_OK, output)
        self.assertEqual(fake.methods(), ["GET", "GET", "GET"])
        self.assertIn("DRY RUN", output)
        self.assertIn("Audit FAIL 2 -> 1", output)
        self.assertIn("FAIL B module 2: Missing error handler", output)
        self.assertIn("REVIEW B module 2", output)
        self.assertIn("added [10, 11, 12]", output)
        self.assertEqual(self.records(), [])

    def test_apply_saves_post_checks_and_writes_record(self):
        fake = FakeMake(live_blueprint(), version=10)
        code, output = self.run_main(fake, apply=True)
        self.assertEqual(code, make_push.EXIT_OK, output)
        self.assertEqual(fake.methods(), ["GET", "GET", "GET", "PATCH", "GET", "GET", "GET"])
        method, url, headers, body = fake.patches()[0]
        self.assertEqual(url, f"{BASE}/scenarios/{SID}")
        self.assertNotIn("confirmed", url)
        self.assertEqual(headers["Authorization"], "Token " + WRITE_TOKEN)
        for m, _u, h, _b in fake.calls:
            if m == "GET":
                self.assertEqual(h["Authorization"], "Token " + READ_TOKEN)
        payload = json.loads(body.decode("utf-8"))
        self.assertEqual(set(payload), {"blueprint", "baseVersion"})
        self.assertEqual(payload["baseVersion"], 10)
        self.assertIsInstance(payload["blueprint"], str)
        self.assertEqual(json.loads(payload["blueprint"]), fixed_candidate())
        self.assertIn("version 10 -> 11", output)

        recs = self.records()
        self.assertEqual(len(recs), 1)
        name, rec = recs[0]
        self.assertEqual(name, f"2026-10-28__F-E5__{SID}.json")
        self.assertEqual(rec["fix"], "F-E5")
        self.assertEqual(rec["scenario"], {"id": SID, "name": NAME})
        self.assertEqual((rec["version_before"], rec["version_after"]), (10, 11))
        self.assertEqual(rec["modules"], {"changed": [2], "added": [10, 11, 12], "removed": []})
        self.assertEqual(rec["result"], "ok")
        self.assertEqual(rec["pushed_at"], "2026-10-28T15:30:00Z")
        self.assertTrue(rec["post_check"]["flow_matches"])
        # The record carries the closed B row as the audit words it. The exact text belongs to the audit (check B v3), so match
        # the row and the start of its detail.
        closed_b = [f for f in rec["findings_closed"] if (f["check"], f["module_id"], f["status"]) == ("B", "2", "FAIL")]
        self.assertEqual(len(closed_b), 1, rec["findings_closed"])
        self.assertTrue(closed_b[0]["detail"].startswith("Missing error handler."), closed_b[0]["detail"])
        text = json.dumps(rec)
        self.assertNotIn("flow", [k for k in rec])
        self.assertNotIn("Error {{error.message}}", text)

    def test_record_write_failure_after_save_is_reported(self):
        with open(self.pushes, "w", encoding="utf-8") as fh:
            fh.write("not a folder")
        fake = FakeMake(live_blueprint())
        code, output = self.run_main(fake, apply=True)
        self.assertEqual(code, make_push.EXIT_POSTCHECK)
        self.assertEqual(fake.saves, 1)
        self.assertIn("push record not written", output)
        os.remove(self.pushes)

    def test_second_push_same_day_does_not_overwrite_record(self):
        self.run_main(FakeMake(live_blueprint()), apply=True)
        self.run_main(FakeMake(live_blueprint()), apply=True)
        self.assertEqual([n for n, _ in self.records()],
                         [f"2026-10-28__F-E5__{SID}-2.json", f"2026-10-28__F-E5__{SID}.json"])


# --------------------------------------------------------------------------
# Step 8: PATCH outcomes
# --------------------------------------------------------------------------

class TestPatch(Base):
    def test_409_aborts_nothing_changed_no_retry(self):
        fake = FakeMake(live_blueprint())
        fake.patch_responses = [Response(409, {}, json.dumps({"code": "SC409", "message": "x"}).encode())]
        code, output = self.run_main(fake, apply=True)
        self.assertEqual(code, make_push.EXIT_REJECTED)
        self.assertIn("409", output)
        self.assertIn("Nothing changed", output)
        self.assertEqual(len(fake.patches()), 1)
        self.assertEqual(fake.methods()[-1], "PATCH")
        self.assertEqual(fake.saves, 0)
        self.assertEqual(self.records(), [])

    def test_sc409_code_on_other_status_is_a_conflict(self):
        fake = FakeMake(live_blueprint())
        fake.patch_responses = [Response(400, {}, json.dumps({"code": "SC409"}).encode())]
        code, output = self.run_main(fake, apply=True)
        self.assertEqual(code, make_push.EXIT_REJECTED)
        self.assertIn("newer version", output)

    def test_403_shows_code_only(self):
        fake = FakeMake(live_blueprint())
        msg = "denied for " + WRITE_TOKEN + " plus secret words"
        fake.patch_responses = [Response(403, {}, json.dumps({"code": "SC403", "message": msg}).encode())]
        code, output = self.run_main(fake, apply=True)
        self.assertEqual(code, make_push.EXIT_REJECTED)
        self.assertIn("SC403", output)
        self.assertNotIn("secret words", output)
        self.assertEqual(len(fake.patches()), 1)

    def test_400_shows_code_and_redacted_validation_message(self):
        # A 400 is a blueprint validation error and its message is needed to fix
        # the candidate. Token fragments are still redacted.
        fake = FakeMake(live_blueprint())
        msg = "module detail " + WRITE_TOKEN
        fake.patch_responses = [Response(400, {}, json.dumps({"code": "IM007", "message": msg}).encode())]
        code, output = self.run_main(fake, apply=True)
        self.assertEqual(code, make_push.EXIT_REJECTED)
        self.assertIn("IM007", output)
        self.assertIn("module detail", output)

    def test_401_and_403_never_show_message(self):
        for status in (401, 403):
            fake = FakeMake(live_blueprint())
            fake.patch_responses = [Response(status, {}, json.dumps({"code": "IM005", "message": "secret-ish"}).encode())]
            code, output = self.run_main(fake, apply=True)
            self.assertEqual(code, make_push.EXIT_REJECTED)
            self.assertNotIn("secret-ish", output)

    def test_429_is_retried(self):
        fake = FakeMake(live_blueprint())
        fake.patch_responses = [Response(429, {"retry-after": "3"}, b""),
                                FakeMake._json({"scenario": {"id": SID}})]
        code, output = self.run_main(fake, apply=True)
        self.assertEqual(code, make_push.EXIT_OK, output)
        self.assertEqual(len(fake.patches()), 2)
        self.assertEqual(self.sleeps, [3.0])

    def test_500_is_not_retried_and_post_check_decides(self):
        # guard-PUSH-4 / api-R4: an unknown outcome is never "Nothing changed".
        fake = FakeMake(live_blueprint())
        fake.patch_responses = [Response(500, {}, b"")]
        code, output = self.run_main(fake, apply=True)
        self.assertEqual(code, make_push.EXIT_POSTCHECK)
        self.assertIn("outcome unknown", output)
        self.assertIn("Re-pull before retrying", output)
        self.assertNotIn("Nothing changed", output)
        self.assertEqual(len(fake.patches()), 1)
        self.assertEqual(self.sleeps, [make_push.UNKNOWN_RECHECK_S])
        recs = self.records()
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0][1]["result"], "unknown_not_observed")
        self.assertEqual(recs[0][1]["version_after"], 10)

    def test_network_error_is_not_retried(self):
        fake = FakeMake(live_blueprint())
        fake.patch_responses = [TransientError("timeout")]
        code, output = self.run_main(fake, apply=True)
        self.assertEqual(code, make_push.EXIT_POSTCHECK)
        self.assertEqual(len(fake.patches()), 1)
        # The only sleep is the post-check re-read, never a PATCH retry.
        self.assertEqual(self.sleeps, [make_push.UNKNOWN_RECHECK_S])
        self.assertNotIn("Nothing changed", output)


# --------------------------------------------------------------------------
# Step 9: post-check
# --------------------------------------------------------------------------

class TestPostCheck(Base):
    def test_active_after_save_raises_alarm(self):
        fake = FakeMake(live_blueprint())
        fake.after_patch = {"active": True}
        code, output = self.run_main(fake, apply=True)
        self.assertEqual(code, make_push.EXIT_ALARM)
        self.assertIn("ALARM", output)
        self.assertIn("deactivate it in the Make UI", output)
        rec = self.records()[0][1]
        self.assertEqual(rec["result"], "ALARM_ACTIVE")
        self.assertTrue(rec["post_check"]["is_active"])

    def test_draft_after_save_is_reported(self):
        fake = FakeMake(live_blueprint())
        fake.after_patch = {"draft": fixed_candidate()}
        code, output = self.run_main(fake, apply=True)
        self.assertEqual(code, make_push.EXIT_POSTCHECK)
        self.assertIn("landed as a draft and needs publishing", output)
        self.assertEqual(self.records()[0][1]["result"], "post_check_failed")

    def test_flow_difference_after_save_is_reported(self):
        def mangle(f):
            find_module(f.live, 11)["mapper"]["text"] = "rewritten"
        fake = FakeMake(live_blueprint())
        fake.after_patch = {"mangle": mangle}
        code, output = self.run_main(fake, apply=True)
        self.assertEqual(code, make_push.EXIT_POSTCHECK)
        self.assertIn("live flow differs", output)
        self.assertIn("mapper.text", output)
        self.assertNotIn("rewritten", output)

    def test_version_not_increased_is_reported(self):
        def keep_version(f):
            f.version -= 1
        fake = FakeMake(live_blueprint())
        fake.after_patch = {"v": keep_version}
        code, output = self.run_main(fake, apply=True)
        self.assertEqual(code, make_push.EXIT_POSTCHECK)
        self.assertIn("did not increase", output)

    def test_keys_make_adds_are_not_differences(self):
        fake = FakeMake(live_blueprint())
        code, _ = self.run_main(fake, apply=True)
        self.assertEqual(code, make_push.EXIT_OK)
        self.assertIn("restore", find_module(fake.live, 10)["metadata"])

    def test_unknown_outcome_that_landed_is_reported(self):
        fake = FakeMake(live_blueprint())
        fake.patch_responses = [Response(502, {}, b"")]
        fake.queued[("GET", f"/scenarios/{SID}")] = [
            FakeMake._json({"scenario": {"id": SID, "isActive": False}})]

        # Simulate the save landing despite the 502.
        def landed_then_get(method, url, headers, timeout, body=None):
            if method == "PATCH":
                fake.calls.append((method, url, dict(headers), body))
                fake._save(body)
                return Response(502, {}, b"")
            return fake(method, url, headers, timeout)

        code, output = self.run_main(landed_then_get, apply=True)
        self.assertEqual(code, make_push.EXIT_POSTCHECK)
        self.assertIn("outcome unknown", output)
        self.assertEqual(self.records()[0][1]["version_after"], 11)


# --------------------------------------------------------------------------
# Review fixes (guard-PUSH-1..6, api-R1..R7)
# --------------------------------------------------------------------------

def versioned_transport(fake, first):
    """PATCH saves on the first call but answers `first` (a Response or an
    exception). Later PATCHes get 409 when baseVersion is stale, like Make."""
    state = {"n": 0}

    def t(method, url, headers, timeout, body=None):
        if method == "PATCH":
            state["n"] += 1
            fake.calls.append((method, url, dict(headers), body))
            if json.loads(body)["baseVersion"] != fake.version:
                return Response(409, {}, json.dumps({"code": "SC409"}).encode())
            if state["n"] == 1:
                fake._save(body)
                if isinstance(first, Exception):
                    raise first
                return first
        return fake(method, url, headers, timeout, body)
    return t


class TestSnapshotTie(Base):
    """guard-PUSH-1: the candidate is tied to the snapshot it was built from."""

    def test_stale_candidate_after_repull_aborts(self):
        live = live_blueprint()
        find_module(live, 2)["mapper"]["id"] = "{{1.id}} ui-edit"
        self.write_snapshot(live)                    # re-pulled at version 11
        self.write_candidate(fixed_candidate())      # still built from version 10
        fake = FakeMake(live, version=11)
        code, output = self.run_main(fake, apply=True, base_version=10)
        self.assertEqual(code, make_push.EXIT_ABORT)
        self.assertIn("live version 11 is not --base-version 10", output)
        self.assertIn("rebuild the candidate from the new snapshot", output)
        self.assertEqual(fake.patches(), [])
        self.assertEqual(find_module(fake.live, 2)["mapper"]["id"], "{{1.id}} ui-edit")

    def test_base_version_is_required(self):
        fake = FakeMake(live_blueprint())
        code, _ = self.run_main(fake, base_version=None)
        self.assertEqual(code, make_push.EXIT_CONFIG)
        self.assertEqual(fake.calls, [])

    def test_uncommitted_snapshot_aborts_before_any_request(self):
        fake = FakeMake(live_blueprint())
        code, output = self.run_main(fake, apply=True,
                                     snapshot_state=lambda path: "it differs from the last commit")
        self.assertEqual(code, make_push.EXIT_ABORT)
        self.assertIn("not the committed snapshot: it differs from the last commit", output)
        self.assertEqual(fake.calls, [])

    @unittest.skipUnless(shutil.which("git"), "git not installed")
    def test_git_snapshot_state_against_a_real_repo(self):
        repo = os.path.join(self.tmp, "repo")
        os.makedirs(repo)
        env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.invalid",
                   GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid")

        def git(*args):
            return subprocess.run(["git", "-C", repo, *args], env=env, capture_output=True,
                                  text=True, check=True).stdout.strip()

        git("init", "-q")
        snap = os.path.join(repo, f"x__{SID}.json")
        with open(snap, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("{}\n")
        self.assertEqual(make_push.git_snapshot_state(snap), "it is not tracked by git")
        git("update-index", "--add", f"x__{SID}.json")
        self.assertEqual(make_push.git_snapshot_state(snap), "git could not compare it with HEAD")
        # Commit with plumbing so no hook or signing config is involved.
        tree = git("write-tree")
        commit = git("commit-tree", tree, "-m", "snapshot")
        git("update-ref", "HEAD", commit)
        self.assertIsNone(make_push.git_snapshot_state(snap))
        with open(snap, "w", encoding="utf-8", newline="\n") as fh:
            fh.write('{"a": 1}\n')
        self.assertEqual(make_push.git_snapshot_state(snap), "it differs from the last commit")


class TestTargets(Base):
    """guard-PUSH-2 and api-R2: the fix ID and --closes are tied to the
    findings the candidate closes."""

    def write_spec(self, name, text):
        with open(os.path.join(self.specs, name), "w", encoding="utf-8") as fh:
            fh.write(text)

    def test_wrong_fix_id_for_the_check_aborts(self):
        self.write_spec("X-19-ledger-labels.md", f"labels only, scenario {SID}, module 2\n")
        fake = FakeMake(live_blueprint())
        code, output = self.run_main(fake, apply=True, fix="X-19", closes="B:2")
        self.assertEqual(code, make_push.EXIT_ABORT)
        self.assertIn("fix X-19 closes check C findings only", output)
        self.assertEqual(fake.patches(), [])
        code, output = self.run_main(fake, apply=True, fix="X-19", closes="C:2")
        self.assertEqual(code, make_push.EXIT_ABORT)
        self.assertIn("does not fully close: C:2", output)
        self.assertEqual(fake.patches(), [])
        self.assertEqual(self.records(), [])

    def test_closes_is_required_and_validated(self):
        fake = FakeMake(live_blueprint())
        for closes in (None, "B2", "b:2", "B:0", "B:x", ""):
            code, _ = self.run_main(fake, closes=closes)
            self.assertEqual(code, make_push.EXIT_CONFIG, closes)
        self.assertEqual(fake.calls, [])

    def test_target_outside_modules_aborts(self):
        code, output = self.run_main(FakeMake(live_blueprint()), closes="B:2,B:4")
        self.assertEqual(code, make_push.EXIT_ABORT)
        self.assertIn("--closes names modules not in --modules: B:4", output)

    def both_fixed(self):
        cand = fixed_candidate()
        find_module(cand, 4)["onerror"].insert(0, ledger(13))
        self.write_candidate(cand)

    def test_undeclared_closed_fail_aborts(self):
        self.both_fixed()
        code, output = self.run_main(FakeMake(live_blueprint()), modules="2,4,10,11,12,13", closes="B:2")
        self.assertEqual(code, make_push.EXIT_ABORT)
        self.assertIn("also closes FAILs not in --closes: B:4", output)

    def test_spec_must_name_every_target(self):
        self.both_fixed()
        code, output = self.run_main(FakeMake(live_blueprint()), modules="2,4,10,11,12,13", closes="B:2,B:4")
        self.assertEqual(code, make_push.EXIT_ABORT)
        self.assertIn("does not name modules [4]", output)
        self.write_spec("F-E5-batch-outbound-caller.md",
                        f"Scenario ID `{SID}`. Module 2 gains a handler. Module 4 gains a ledger write.\n")
        code, output = self.run_main(FakeMake(live_blueprint()), modules="2,4,10,11,12,13", closes="B:2,B:4")
        self.assertEqual(code, make_push.EXIT_OK, output)
        self.assertIn("Targets: B:2, B:4 (F-E5 -> check B), all closed.", output)

    def test_spec_id_match_ignores_dates_and_versions(self):
        texts = ["Pulled 2026-10-28, slack v4, ratio 2.5, module 16"]
        self.assertEqual(make_push.spec_missing_ids(texts, [10, 4, 2, 16]), [10, 4, 2])

    def test_unmapped_fix_uses_the_declared_targets(self):
        self.write_spec("F-H6-cost-audit.md", f"Scenario {SID}, module 2\n")
        code, output = self.run_main(FakeMake(live_blueprint()), fix="F-H6", closes="B:2")
        self.assertEqual(code, make_push.EXIT_OK, output)
        self.assertIn("check as declared", output)

    def test_record_lists_targets(self):
        code, _ = self.run_main(FakeMake(live_blueprint()), apply=True)
        self.assertEqual(code, make_push.EXIT_OK)
        self.assertEqual(self.records()[0][1]["targets"], ["B:2"])


class TestFixMapForEandF(unittest.TestCase):
    """X-41 closes check E, X-23 closes check F. X-6, X-9, X-10 and X-11 are
    declared --closes only. The older mappings stay."""

    def test_new_and_old_mappings(self):
        fc = make_push.fix_checks
        self.assertEqual(fc("X-41"), ("E",))
        self.assertEqual(fc("X-41.2"), ("E",))
        self.assertEqual(fc("X-23"), ("F",))
        self.assertEqual((fc("X-19"), fc("X-28"), fc("F-E5"), fc("X-31"), fc("F-31")),
                         (("C",), ("C",), ("B",), ("A",), ("A",)))
        for fix in ("X-6", "X-9", "X-10", "X-11"):
            self.assertEqual(fc(fix), (), fix)
        for fix in ("X-60", "X-4", "X-231", "X-100", "X-1"):
            self.assertIsNone(fc(fix), fix)

    def delta(self, *closed):
        keys = [(c, m, "FAIL", "d") for c, m in closed]
        return make_push.AuditDelta(fails_before=len(keys), fails_after=0, new_fails=[], closed=keys, new_other=[])

    def test_x41_closes_e_only(self):
        make_push.check_targets("X-41", [("E", "12")], self.delta(("E", "12")), {12})
        with self.assertRaises(make_push.Abort) as cm:
            make_push.check_targets("X-41", [("B", "2")], self.delta(("B", "2")), {2})
        self.assertIn("fix X-41 closes check E findings only", str(cm.exception))

    def test_x23_closes_f_only(self):
        make_push.check_targets("X-23", [("F", "1")], self.delta(("F", "1")), {1})
        with self.assertRaises(make_push.Abort) as cm:
            make_push.check_targets("X-23", [("E", "1")], self.delta(("E", "1")), {1})
        self.assertIn("closes check F findings only", str(cm.exception))

    def test_declared_only_fixes_take_any_check_but_still_need_a_full_close(self):
        for fix in ("X-6", "X-9", "X-10", "X-11"):
            make_push.check_targets(fix, [("E", "12"), ("F", "1")], self.delta(("E", "12"), ("F", "1")), {12, 1})
            with self.assertRaises(make_push.Abort) as cm:
                make_push.check_targets(fix, [("E", "12")], self.delta(), {12})
            self.assertIn("does not fully close", str(cm.exception))
            with self.assertRaises(make_push.Abort) as cm:
                make_push.check_targets(fix, [("E", "12")], self.delta(("E", "12"), ("F", "1")), {12})
            self.assertIn("also closes FAILs not in --closes", str(cm.exception))

    def test_compare_audits_sees_an_e_fix_close(self):
        labels = audit_blueprints_module().load_labels(os.path.join(FIX, "labels_confirmed.json"))
        schema = audit_blueprints_module().load_schema(os.path.join(FIX, "schema.json"))
        trig = {"id": 1, "module": "google-email:triggerWatchNewEmails", "mapper": {}, "parameters": {}}
        live = {"name": NAME, "metadata": {}, "flow": [trig, mod(3, "slack:CreateMessage", mapper={"text": "{{Video}}"})]}
        cand = copy.deepcopy(live)
        cand["flow"][1]["mapper"]["text"] = "{{1.subject}}"
        delta = make_push.compare_audits(live, cand, SID, NAME, labels, schema)
        self.assertIn(("E", "3"), {(k[0], k[1]) for k in delta.closed})
        self.assertEqual(delta.new_fails, [])
        make_push.check_targets("X-41", [("E", "3")], delta, {3})


def audit_blueprints_module():
    import audit_blueprints
    return audit_blueprints


class TestDesignerAndContainers(Base):
    """guard-PUSH-3, guard-PUSH-5, guard-PUSH-6."""

    def test_nested_metadata_designer_key_is_a_change(self):
        live = live_blueprint()
        find_module(live, 7)["mapper"]["metadata"] = {"designer": "a"}
        self.write_snapshot(live)
        cand = fixed_candidate()
        find_module(cand, 7)["mapper"]["metadata"] = {"designer": {"anything": "changed"}}
        self.write_candidate(cand)
        fake = FakeMake(live)
        code, output = self.run_main(fake, apply=True)
        self.assertEqual(code, make_push.EXIT_ABORT)
        self.assertIn("not in --modules: [7]", output)
        self.assertEqual(fake.patches(), [])
        self.assertEqual(make_push.diff_paths({"xmetadata": {"designer": 1}}, {"xmetadata": {"designer": 2}}),
                         ["xmetadata.designer"])

    def test_orphan_module_added_aborts(self):
        cand = fixed_candidate()
        cand["metadata"]["designer"]["orphans"] = [[mod(99, "http:ActionSendData", mapper={"url": "u"})]]
        self.write_candidate(cand)
        fake = FakeMake(live_blueprint())
        code, output = self.run_main(fake, apply=True)
        self.assertEqual(code, make_push.EXIT_ABORT)
        self.assertIn("metadata.designer.orphans", output)
        self.assertEqual(fake.patches(), [])

    def test_samples_change_aborts(self):
        cand = fixed_candidate()
        cand["metadata"]["designer"]["samples"] = {"1": [{"x": 1}]}
        self.write_candidate(cand)
        code, output = self.run_main(FakeMake(live_blueprint()))
        self.assertEqual(code, make_push.EXIT_ABORT)
        self.assertIn("metadata.designer.samples", output)

    def test_empty_onerror_added_outside_modules_aborts(self):
        cand = fixed_candidate()
        find_module(cand, 7)["onerror"] = []
        self.write_candidate(cand)
        fake = FakeMake(live_blueprint())
        code, output = self.run_main(fake, apply=True)
        self.assertEqual(code, make_push.EXIT_ABORT)
        self.assertIn("not in --modules: [7]", output)
        self.assertEqual(fake.patches(), [])

    def test_empty_route_flow_added_is_a_change(self):
        live = live_blueprint()
        find_module(live, 3)["routes"].append({"filter": {"name": "spare"}})
        cand = copy.deepcopy(live)
        find_module(cand, 3)["routes"][2]["flow"] = []
        d = make_push.diff_modules(live, cand)
        self.assertEqual(sorted(d.changed), [3])
        self.assertIn("routes[2].flow (added)", d.changed[3])


def ledger_label(mid, label):
    m = ledger(mid)
    m["mapper"]["record"][LABEL] = label
    return m


class TestReplaces(Base):
    """api-R1: a module recreated under a new ID keeps its other findings."""

    def setUp(self):
        super().setUp()
        self.live = live_blueprint()
        find_module(self.live, 3)["routes"][1]["flow"].append(ledger_label(8, "Batch Outband Caller"))
        self.write_snapshot(self.live)
        with open(os.path.join(self.specs, "X-19-ledger-labels.md"), "w", encoding="utf-8") as fh:
            fh.write(f"Scenario {SID}: module 8 is recreated with the full label.\n")

    def recreate(self, at_index=1, module_type=None):
        cand = copy.deepcopy(self.live)
        route = find_module(cand, 3)["routes"][1]["flow"]
        route.pop()
        new = ledger_label(13, NAME)
        if module_type:
            new["module"] = module_type
        route.insert(at_index, new)
        self.write_candidate(cand)

    def test_recreate_without_replaces_shows_a_new_fail(self):
        self.recreate()
        code, output = self.run_main(FakeMake(self.live), modules="3,8,13", fix="X-19", closes="C:8")
        self.assertEqual(code, make_push.EXIT_ABORT)
        self.assertIn("FAIL B module 13", output)

    def test_recreate_with_replaces_passes_and_saves(self):
        self.recreate()
        fake = FakeMake(self.live)
        code, output = self.run_main(fake, modules="3,8,13", fix="X-19", closes="C:8",
                                     replaces="8=13", apply=True)
        self.assertEqual(code, make_push.EXIT_OK, output)
        self.assertIn("Replaces: 8 -> 13", output)
        self.assertEqual(fake.saves, 1)
        self.assertEqual(self.records()[0][1]["replaces"], {"8": 13})

    def test_in_place_label_edit_needs_no_id_sequence(self):
        cand = copy.deepcopy(self.live)
        find_module(cand, 8)["mapper"]["record"][LABEL] = NAME
        self.write_candidate(cand)
        fake = FakeMake(self.live, id_sequence=None)
        code, output = self.run_main(fake, modules="8", fix="X-19", closes="C:8", apply=True)
        self.assertEqual(code, make_push.EXIT_OK, output)
        self.assertEqual(fake.saves, 1)

    def test_replaces_must_keep_the_position(self):
        self.recreate(at_index=0)
        code, output = self.run_main(FakeMake(self.live), modules="3,8,13", fix="X-19", closes="C:8",
                                     replaces="8=13")
        self.assertEqual(code, make_push.EXIT_ABORT)
        self.assertIn("not at module 8's position", output)

    def test_replaces_must_keep_the_module_type(self):
        self.recreate(module_type="airtable:ActionUpdateRecords")
        code, output = self.run_main(FakeMake(self.live), modules="3,8,13", fix="X-19", closes="C:8",
                                     replaces="8=13")
        self.assertEqual(code, make_push.EXIT_ABORT)
        self.assertIn("module types differ", output)

    def test_replaces_ids_must_be_listed_and_valid(self):
        self.recreate()
        code, output = self.run_main(FakeMake(self.live), modules="3,8,13", fix="X-19", closes="C:8",
                                     replaces="8=14")
        self.assertEqual(code, make_push.EXIT_ABORT)
        self.assertIn("both IDs must be in --modules", output)
        for bad in ("8", "8=8", "8=13,9=13", "x=1"):
            code, _ = self.run_main(FakeMake(self.live), modules="3,8,13", fix="X-19", closes="C:8",
                                    replaces=bad)
            self.assertEqual(code, make_push.EXIT_CONFIG, bad)


class TestIdSequence(Base):
    """api-R3."""

    def test_new_ids_at_or_below_id_sequence_abort(self):
        fake = FakeMake(live_blueprint(), id_sequence=11)
        code, output = self.run_main(fake, apply=True)
        self.assertEqual(code, make_push.EXIT_ABORT)
        self.assertIn("new module IDs [10, 11] are at or below the scenario's idSequence 11", output)
        self.assertEqual(fake.patches(), [])

    def test_missing_id_sequence_aborts_when_modules_are_added(self):
        fake = FakeMake(live_blueprint(), id_sequence=None)
        code, output = self.run_main(fake, apply=True)
        self.assertEqual(code, make_push.EXIT_ABORT)
        self.assertIn("no idSequence", output)

    def test_id_sequence_not_advanced_after_save_is_reported(self):
        fake = FakeMake(live_blueprint())
        fake.advance_ids = False
        code, output = self.run_main(fake, apply=True)
        self.assertEqual(code, make_push.EXIT_POSTCHECK)
        self.assertIn("idSequence 7 is below the highest module ID 12", output)


class TestPatchOutcomes(Base):
    """guard-PUSH-4, api-R4, api-R7."""

    def test_408_after_a_save_is_not_nothing_changed(self):
        fake = FakeMake(live_blueprint())
        code, output = self.run_main(
            versioned_transport(fake, Response(408, {}, json.dumps({"code": "IM408"}).encode())), apply=True)
        self.assertEqual(code, make_push.EXIT_POSTCHECK)
        self.assertNotIn("Nothing changed", output)
        self.assertIn("outcome unknown (HTTP 408 [IM408]) but the scenario changed", output)
        rec = self.records()[0][1]
        self.assertEqual((rec["version_after"], rec["result"]), (11, "post_check_failed"))

    def test_409_after_a_429_retry_goes_to_the_post_check(self):
        fake = FakeMake(live_blueprint())
        code, output = self.run_main(
            versioned_transport(fake, Response(429, {"retry-after": "1"}, b"{}")), apply=True)
        self.assertEqual(code, make_push.EXIT_POSTCHECK)
        self.assertNotIn("Nothing changed", output)
        self.assertIn("after a retried attempt", output)
        self.assertEqual(fake.saves, 1)
        self.assertEqual(len(self.records()), 1)

    def test_late_save_after_the_first_post_check_is_caught_by_the_reread(self):
        fake = FakeMake(live_blueprint())
        pending = {}

        def t(method, url, headers, timeout, body=None):
            if method == "PATCH":
                fake.calls.append((method, url, dict(headers), body))
                pending["body"] = body
                raise TransientError("TimeoutError")
            r = fake(method, url, headers, timeout, body)
            if "draft=true" in url and "body" in pending and fake.saves == 0:
                fake._save(pending["body"])          # lands after the first post-check read
            return r

        code, output = self.run_main(t, apply=True)
        self.assertEqual(code, make_push.EXIT_POSTCHECK)
        self.assertNotIn("Nothing changed", output)
        self.assertEqual(self.sleeps, [make_push.UNKNOWN_RECHECK_S])
        rec = self.records()[0][1]
        self.assertEqual(rec["version_after"], 11)
        self.assertEqual(rec["result"], "post_check_failed")

    def test_definitive_rejections_change_nothing(self):
        for status in (404, 422):
            fake = FakeMake(live_blueprint())
            fake.patch_responses = [Response(status, {}, json.dumps({"code": "IM0"}).encode())]
            code, output = self.run_main(fake, apply=True)
            self.assertEqual(code, make_push.EXIT_REJECTED, status)
            self.assertIn("Nothing changed", output)
        self.assertEqual(self.records(), [])

    def test_409_reason_version_conflict(self):
        fake = FakeMake(live_blueprint())
        body = {"code": "SC409", "metadata": {"reason": "scenario_version_conflict"}}
        fake.patch_responses = [Response(409, {}, json.dumps(body).encode())]
        code, output = self.run_main(fake, apply=True)
        self.assertEqual(code, make_push.EXIT_REJECTED)
        self.assertIn("a newer version was saved since version 10", output)

    def test_409_other_reason_is_a_concurrent_change_and_not_echoed(self):
        fake = FakeMake(live_blueprint())
        body = {"code": "SC409", "metadata": {"reason": "zz_unlisted_reason"}}
        fake.patch_responses = [Response(409, {}, json.dumps(body).encode())]
        code, output = self.run_main(fake, apply=True)
        self.assertEqual(code, make_push.EXIT_REJECTED)
        self.assertIn("concurrent change", output)
        self.assertNotIn("zz_unlisted_reason", output)
        self.assertNotIn("newer version was saved since", output)

    def test_403_im002_gets_the_locked_connection_hint(self):
        fake = FakeMake(live_blueprint())
        fake.patch_responses = [Response(403, {}, json.dumps({"code": "IM002"}).encode())]
        code, output = self.run_main(fake, apply=True)
        self.assertEqual(code, make_push.EXIT_REJECTED)
        self.assertIn("locked", output)
        self.assertNotIn("scenarios:write", output)


class TestPostCheckSplit(Base):
    """api-R5, api-R6."""

    def test_locked_or_invalid_scenario_aborts_before_the_save(self):
        for key in ("islocked", "isinvalid"):
            fake = FakeMake(live_blueprint())
            fake.scenario_extra = {key: True}
            code, output = self.run_main(fake, apply=True)
            self.assertEqual(code, make_push.EXIT_ABORT, key)
            self.assertIn(f"({key})", output)
            self.assertEqual(fake.patches(), [])

    def test_top_level_change_after_save_is_reported(self):
        def mangle(f):
            f.live["metadata"]["scenario"]["maxErrors"] = 9
        fake = FakeMake(live_blueprint())
        fake.after_patch = {"m": mangle}
        code, output = self.run_main(fake, apply=True)
        self.assertEqual(code, make_push.EXIT_POSTCHECK)
        self.assertIn("top-level settings differ from the candidate at: metadata.scenario.maxErrors", output)

    def test_patch_body_active_raises_the_alarm(self):
        fake = FakeMake(live_blueprint())
        fake.patch_responses = [FakeMake._json({"scenario": {"id": SID, "isActive": True}})]
        code, output = self.run_main(fake, apply=True)
        self.assertEqual(code, make_push.EXIT_ALARM)
        self.assertIn("PATCH response reports the scenario active", output)

    def test_patch_body_invalid_is_a_problem(self):
        fake = FakeMake(live_blueprint())
        fake.patch_responses = [FakeMake._json({"scenario": {"id": SID, "isActive": False, "isinvalid": True}})]
        code, output = self.run_main(fake, apply=True)
        self.assertEqual(code, make_push.EXIT_POSTCHECK)
        self.assertIn("isinvalid", output)

    def test_server_filled_key_on_touched_module_is_a_warning(self):
        def bump(f):
            find_module(f.live, 10)["version"] = 2
        fake = FakeMake(live_blueprint())
        fake.after_patch = {"b": bump}
        code, output = self.run_main(fake, apply=True)
        self.assertEqual(code, make_push.EXIT_OK, output)
        self.assertIn("warning (server-filled key on a touched module): module 10 version", output)
        self.assertEqual(self.records()[0][1]["warnings"], ["module 10 version"])

    def test_untouched_module_change_is_a_problem(self):
        def bump(f):
            find_module(f.live, 7)["version"] = 2
        fake = FakeMake(live_blueprint())
        fake.after_patch = {"b": bump}
        code, output = self.run_main(fake, apply=True)
        self.assertEqual(code, make_push.EXIT_POSTCHECK)
        self.assertIn("module 7 version", output)

    def test_unexpected_module_after_save_is_a_problem(self):
        def extra(f):
            find_module(f.live, 3)["routes"][1]["flow"].append(mod(30, "util:SetVariable2"))
        fake = FakeMake(live_blueprint())
        fake.after_patch = {"e": extra}
        code, output = self.run_main(fake, apply=True)
        self.assertEqual(code, make_push.EXIT_POSTCHECK)
        self.assertIn("modules not in the candidate: [30]", output)


# --------------------------------------------------------------------------
# Transport guard
# --------------------------------------------------------------------------

class TestTransportGuard(unittest.TestCase):
    def setUp(self):
        self.seen = []
        self.guard = make_push.GuardedTransport(
            lambda *a: self.seen.append(a) or Response(200, {}, b"{}"), BASE, SID)

    def refused(self, method, url, body=None):
        with self.assertRaises(make_push.TransportRefused):
            self.guard(method, url, {}, 1.0, body)
        self.assertEqual(self.seen, [])

    def test_allowed_requests_pass(self):
        self.guard("GET", f"{BASE}/scenarios/{SID}", {}, 1.0)
        self.guard("GET", f"{BASE}/scenarios/{SID}/blueprint?draft=false", {}, 1.0)
        self.guard("GET", f"{BASE}/scenarios/{SID}/blueprint?draft=true", {}, 1.0)
        self.guard("PATCH", f"{BASE}/scenarios/{SID}", {}, 1.0, b"{}")
        self.assertEqual(len(self.seen), 4)

    def test_other_methods_refused(self):
        for method in ("POST", "PUT", "DELETE", "HEAD", "OPTIONS"):
            self.refused(method, f"{BASE}/scenarios/{SID}", b"{}")
            self.refused(method, f"{BASE}/scenarios/{SID}")

    def test_other_paths_refused(self):
        for path in ("/scenarios", f"/scenarios/{SID}/run", f"/scenarios/{SID}/start",
                     f"/scenarios/{SID}/clone", f"/scenarios/{SID}/blueprints",
                     f"/scenarios/{SID + 1}", f"/scenarios/{SID + 1}/blueprint?draft=false",
                     f"/scenarios/{SID}/", f"/scenarios/{SID}/blueprint",
                     f"/scenarios/{SID}/blueprint?draft=false&x=1", "/connections"):
            self.refused("GET", BASE + path)

    def test_patch_shape_refused(self):
        self.refused("PATCH", f"{BASE}/scenarios/{SID}?confirmed=true", b"{}")
        self.refused("PATCH", f"{BASE}/scenarios/{SID}/blueprint", b"{}")
        self.refused("PATCH", f"{BASE}/scenarios/{SID}")
        self.refused("GET", f"{BASE}/scenarios/{SID}", b"{}")

    def test_other_hosts_refused(self):
        self.refused("GET", f"http://us2.make.com/api/v2/scenarios/{SID}")
        self.refused("GET", f"https://eu1.make.com/api/v2/scenarios/{SID}")
        self.refused("GET", f"https://evil.invalid/api/v2/scenarios/{SID}")
        self.refused("GET", f"https://user@us2.make.com/api/v2/scenarios/{SID}")

    def test_urllib_transport_refuses_other_methods_before_network(self):
        for method in ("POST", "DELETE", "PUT"):
            with self.assertRaises(ValueError):
                make_push.urllib_transport(method, f"{BASE}/scenarios/{SID}", {}, 1.0, b"{}")
        with self.assertRaises(ValueError):
            make_push.urllib_transport("GET", f"{BASE}/scenarios/{SID}", {}, 1.0, b"{}")

    def test_urllib_patch_uses_make_pull_no_redirect_opener(self):
        handlers = [type(h) for h in make_pull._OPENER.handlers]
        self.assertIn(make_pull._NoRedirect, handlers)


def handler(base):
    return [ledger(base), slack(base + 1), mod(base + 2, "builtin:Break")]


def fetch_call(mid):
    return mod(mid, "bland:getCallDetails", mapper={"call_id": "{{1.call_id}}"}, onerror=handler(mid * 10))


CALLER_LABEL = "Caller Label"


def gate_lookup(mid, fetch):
    """The pinned lookup with the F2d replay gates: one record, the row kind of the calling scenario, an unreconciled
    formula (Voice AI cost is a number field, so the length test) and a completion filter on the link into it."""
    m = mod(mid, "airtable:ActionSearchRecords",
            mapper={"table": LEDGER, "maxRecords": "1",
                    "formula": "AND({External Call ID} = '{{%d.call_id}}', {Scenario name} = '%s', LEN({Voice AI cost}&'') = 0)" % (fetch, CALLER_LABEL)},
            onerror=handler(mid * 10))
    m["filter"] = {"name": "Call completed", "conditions": [[{"a": "{{%d.status}}" % fetch, "b": "completed", "o": "text:equal"}]]}
    return m


def with_found_filter(m, src):
    m = copy.deepcopy(m)
    m["filter"] = {"name": "Found", "conditions": [[{"a": "{{%d.id}}" % src, "o": "exist"}]]}
    return m


def webhook_blueprint(router=False):
    """A fetch-back webhook scenario (Bland post-call hook). Check F FAILs: no call-details module,
    the write reads the request directly and nothing gates it. With router=True the write sits
    in a route, like the Interview Room (B) Grader."""
    hook = mod(1, "gateway:CustomWebHook", parameters={"hook": 1})
    write = mod(4, "airtable:ActionCreateRecord", mapper={"table": LEDGER, "record": {LABEL: NAME, "fldeAVW2SAkT6KpZw": "{{1.price}}"}},
                onerror=[slack(11), mod(12, "builtin:Resume")])
    if router:
        write = mod(3, "builtin:BasicRouter", routes=[{"flow": [write]}, {"flow": [slack(5)]}])
    return {"name": NAME, "flow": [hook, write],
            "metadata": {"instant": True, "version": 1, "designer": {"orphans": []}, "scenario": {"maxErrors": 3, "sequential": True}}}


def fixed_webhook_blueprint(router=False, gate=True):
    """The fix: call-details module 20 right after the webhook, a lookup 21 by the call ID, a found filter on
    the next module, and the write reads the call-details output instead of the request. The reconciliation is
    an update of the looked-up row with a Break handler, the first effect after the gates: the write itself when
    there is no router, a new module 22 in front of the router otherwise."""
    bp = webhook_blueprint(router)
    first = bp["flow"][1]
    write = first["routes"][0]["flow"][0] if router else first
    write["mapper"]["record"]["fldeAVW2SAkT6KpZw"] = "{{20.call_id}}"
    write["mapper"]["record"]["fldx2WzOb94Iyf5pK"] = "{{20.price}}"   # Voice AI cost, the field the unreconciled formula tests
    update = mod(22, "airtable:ActionUpdateRecords",
                 mapper={"table": LEDGER, "id": "{{21.id}}", "record": {"fldx2WzOb94Iyf5pK": "{{20.price}}"}},
                 onerror=[slack(23), mod(24, "builtin:Break")])
    if router:
        flow_tail = [update, first]
    else:
        write["module"] = "airtable:ActionUpdateRecords"
        write["mapper"]["id"] = "{{21.id}}"
        write["onerror"] = [slack(11), mod(12, "builtin:Break")]
        flow_tail = [first]
    if gate:
        flow_tail[0] = with_found_filter(flow_tail[0], 21)
    bp["flow"] = [bp["flow"][0], fetch_call(20), gate_lookup(21, 20)] + flow_tail
    return bp


def modules_arg(live, cand):
    return ",".join(str(i) for i in sorted(make_push.diff_modules(live, cand).touched))


class TestX23WebhookPush(Base):
    """An X-23 push closes F2 rows. The row sits on the module that has to change, and a fix that adds a
    call-details module, a lookup and a found filter closes rows through those modules."""

    def setUp(self):
        super().setUp()
        with open(os.path.join(self.specs, "X-23-webhook-auth.md"), "w", encoding="utf-8") as fh:
            fh.write(f"# X-23\n\nScenario `{NAME}`, ID `{SID}`. Modules 20 and 21 verify the call. Modules 3, 4 and 5 are gated or read the call details.\n")
        with open(os.path.join(self.specs, "X-41-webhook.md"), "w", encoding="utf-8") as fh:
            fh.write(f"# X-41\n\nScenario `{NAME}`, ID `{SID}`.\n")
        self.registry = os.path.join(self.tmp, "webhooks.json")
        with open(self.registry, "w", encoding="utf-8") as fh:
            json.dump({"scenarios": [{"scenario_id": str(SID), "hook_id": 1, "caller": "bland_post_call",
                                      "protection": "fetch_back", "reason": "Called by the Bland post-call webhook",
                                      "lookup_label": CALLER_LABEL}]}, fh)

    def push(self, fake, **kw):
        kw["extra"] = tuple(kw.get("extra", ())) + ("--webhooks", self.registry)
        return self.run_main(fake, **kw)

    def use(self, live, cand):
        self.write_snapshot(live)
        self.write_candidate(cand)
        return FakeMake(live)

    def audit_delta(self, live, cand):
        import audit_blueprints
        labels = audit_blueprints.load_labels(os.path.join(FIX, "labels_confirmed.json"))
        schema = audit_blueprints.load_schema(os.path.join(FIX, "schema.json"))
        reg = audit_blueprints.load_webhooks(self.registry)
        return make_push.compare_audits(live, cand, SID, NAME, labels, schema,
                                        links=audit_blueprints.load_links(audit_blueprints.DEFAULT_LINKS), webhooks=reg,
                                        secret_allowlist=[])

    def test_the_audit_attaches_f2_to_the_first_module_after_the_webhook_and_to_the_writes(self):
        live = webhook_blueprint()
        delta = self.audit_delta(live, fixed_webhook_blueprint())
        self.assertEqual({(k[0], k[1]) for k in delta.closed if k[2] == "FAIL" and k[0] == "F"}, {("F", "4")})
        self.assertEqual(delta.new_fails, [])
        self.assertEqual(delta.remaining_fails & {("F", "4")}, set())

    def test_a_missing_webhook_registry_aborts_the_push(self):
        """R9: with the registry deleted locally every webhook scenario collapsed to one F0 row on both sides, hiding new F2 rows."""
        live = webhook_blueprint()
        cand = fixed_webhook_blueprint()
        fake = self.use(live, cand)
        os.remove(self.registry)
        code, output = self.push(fake, fix="X-23", modules=modules_arg(live, cand), closes="F:4", apply=True)
        self.assertEqual(code, make_push.EXIT_ABORT)
        self.assertIn("no webhook registry", output)
        self.assertEqual(fake.patches(), [])

    def test_a_fix_that_adds_modules_pushes_end_to_end(self):
        live = webhook_blueprint()
        cand = fixed_webhook_blueprint()
        fake = self.use(live, cand)
        code, output = self.push(fake, fix="X-23", modules=modules_arg(live, cand), closes="F:4", apply=True)
        self.assertEqual(code, make_push.EXIT_OK, output)
        self.assertIn("(X-23 -> check F), all closed.", output)
        self.assertEqual(len(fake.patches()), 1)

    def test_a_candidate_that_leaves_a_row_open_aborts(self):
        live = webhook_blueprint()
        cand = fixed_webhook_blueprint(gate=False)
        fake = self.use(live, cand)
        code, output = self.push(fake, fix="X-23", modules=modules_arg(live, cand), closes="F:4", apply=True)
        self.assertEqual(code, make_push.EXIT_ABORT)
        self.assertIn("F2b", output)
        self.assertEqual(fake.patches(), [])

    def test_a_router_scenario_is_gated_by_a_found_filter_on_the_router(self):
        live = webhook_blueprint(router=True)
        cand = fixed_webhook_blueprint(router=True)
        fake = self.use(live, cand)
        code, output = self.push(fake, fix="X-23", modules=modules_arg(live, cand), closes="F:3,F:4,F:5", apply=True)
        self.assertEqual(code, make_push.EXIT_OK, output)
        self.assertEqual(len(fake.patches()), 1)

    def test_an_f_target_is_checked_against_the_fix_id(self):
        live = webhook_blueprint()
        cand = fixed_webhook_blueprint()
        code, output = self.push(self.use(live, cand), fix="X-41", modules=modules_arg(live, cand), closes="F:4")
        self.assertEqual(code, make_push.EXIT_ABORT)
        self.assertIn("closes check E findings only", output)

    def test_check_targets_exempts_only_f_targets_from_the_modules_rule(self):
        delta = make_push.AuditDelta(1, 0, [], [("F", "2", "FAIL", "d")], [])
        make_push.check_targets("X-23", [("F", "2")], delta, {3})
        with self.assertRaises(make_push.Abort) as cm:
            make_push.check_targets("X-6", [("E", "2")], make_push.AuditDelta(1, 0, [], [("E", "2", "FAIL", "d")], []), {3})
        self.assertIn("not in --modules: E:2", str(cm.exception))



    # --- PUSH-4: a push never changes the trigger's module type ------------------------------------------

    def test_push_4_a_push_cannot_swap_the_webhook_trigger(self):
        live = webhook_blueprint()
        cand = fixed_webhook_blueprint()
        cand["flow"][0]["module"] = "google-email:triggerWatchNewEmails"
        fake = self.use(live, cand)
        code, output = self.push(fake, fix="X-23", modules=modules_arg(live, cand), closes="F:1,F:4", apply=True)
        self.assertEqual(code, make_push.EXIT_ABORT)
        self.assertIn("changes the type of the trigger module", output)
        self.assertEqual(fake.patches(), [])

    def test_push_4_the_audit_flags_the_registered_scenario_without_a_webhook_trigger(self):
        live = webhook_blueprint()
        cand = fixed_webhook_blueprint()
        cand["flow"][0]["module"] = "google-email:triggerWatchNewEmails"
        delta = self.audit_delta(live, cand)
        self.assertTrue(any(k[0] == "F" and k[1] == "1" and "not a gateway:CustomWebHook trigger" in k[3] for k in delta.new_fails))

    def test_push_4_check_trigger_type_compares_the_first_module_only(self):
        a, b = webhook_blueprint(), webhook_blueprint()
        make_push.check_trigger_type(a, b)
        b["flow"][0]["parameters"] = {"hook": 2}
        make_push.check_trigger_type(a, b)   # the hook parameter is a module change, not a type change
        b["flow"][0]["module"] = "gateway:WebhookRespond"
        with self.assertRaises(make_push.Abort):
            make_push.check_trigger_type(a, b)


class TestDecisionRouterPush(Base):
    """A-1 and PUSH-3 at the push: the F-31 router row closes only with a fallback that leaves a trace, and a fallback that
    carries a filter (or only sets a variable) does not turn the FAIL into a REVIEW the push can call closed."""

    SPEC = "F-31-decision-router.md"

    def live(self):
        flt = lambda v: {"name": v, "conditions": [[{"a": "{{1.status}}", "b": v, "o": "text:equal:ci"}]]}   # noqa: E731
        return {
            "name": NAME,
            "flow": [
                mod(1, "airtable:ActionSearchRecords", mapper={"table": LEAD, "maxRecords": "1"}),
                mod(3, "builtin:BasicRouter", routes=[
                    {"flow": [dict(mod(4, "util:SetVariable2", mapper={"name": "v", "value": "a"}), filter=flt("VIP"))]},
                    {"flow": [dict(mod(5, "util:SetVariable2", mapper={"name": "v", "value": "b"}), filter=flt("Nurture"))]},
                ]),
            ],
            "metadata": {"instant": False, "version": 1, "designer": {"orphans": []}, "scenario": {"maxErrors": 3, "autoCommit": True}},
        }

    def with_fallback(self, flow):
        bp = self.live()
        bp["flow"][1]["routes"].append({"flow": flow})
        bp["flow"][1]["parameters"] = {"else": 2}
        return bp

    @staticmethod
    def trace():
        row = mod(30, "airtable:ActionCreateRecord",
                  mapper={"table": LEDGER, "record": {LABEL: NAME, "fldgzlLkRAwc6KGoh": "Error", "fldx9nJ4XmlQx1frF": ["{{1.id}}"],
                                                      "fldHf8yjOMGfgyJhc": "{{1.call_id}}", "fldeAVW2SAkT6KpZw": "UNMATCHED {{1.status}}"}},
                  onerror=[slack(32), mod(33, "builtin:Break")])
        alert = mod(31, "slack:CreateMessage", mapper={"text": "Unmatched decision, lead {{1.id}}", "channel": "C0"},
                    onerror=[ledger(34), slack(35), mod(36, "builtin:Break")])
        return [row, alert]

    def setUp(self):
        super().setUp()
        with open(os.path.join(self.specs, self.SPEC), "w", encoding="utf-8") as fh:
            fh.write(f"# F-31\n\nScenario `{NAME}`, ID `{SID}`. Router 3 gains a fallback with modules 30, 31, 32, 33, 34, 35 and 36 (all new).\n")

    def push(self, cand, **kw):
        self.write_snapshot(self.live())
        self.write_candidate(cand)
        fake = FakeMake(self.live())
        kw.setdefault("modules", "3,30,31,32,33,34,35,36")
        kw.setdefault("fix", "F-31")
        kw.setdefault("closes", "A:3")
        return fake, self.run_main(fake, **kw)

    def test_the_live_router_is_an_a_fail(self):
        import audit_blueprints
        labels = audit_blueprints.load_labels(os.path.join(FIX, "labels_confirmed.json"))
        schema = audit_blueprints.load_schema(os.path.join(FIX, "schema.json"))
        d = make_push.compare_audits(self.live(), self.with_fallback(self.trace()), SID, NAME, labels, schema,
                                     links=audit_blueprints.load_links(audit_blueprints.DEFAULT_LINKS), secret_allowlist=[])
        self.assertIn(("A", "3"), d.live_fails)
        self.assertEqual(d.new_fails, [])
        self.assertNotIn(("A", "3"), d.remaining_fails)

    def test_a_fallback_with_a_ledger_row_and_a_slack_alert_closes_the_router(self):
        fake, (code, output) = self.push(self.with_fallback(self.trace()), apply=True)
        self.assertEqual(code, make_push.EXIT_OK, output)
        self.assertEqual(len(fake.patches()), 1)

    def test_a_1_a_fallback_that_only_sets_a_variable_does_not_close_the_router(self):
        setvar = mod(30, "util:SetVariable2", mapper={"name": "v", "value": "x"})
        fake, (code, output) = self.push(self.with_fallback([setvar]), modules="3,30", apply=True)
        self.assertEqual(code, make_push.EXIT_ABORT)
        self.assertIn("FAIL A module 3", output)   # the row stays a FAIL with new text, which counts as a new FAIL
        self.assertEqual(fake.patches(), [])

    def test_push_3_a_fallback_with_a_filter_does_not_turn_the_fail_into_a_review(self):
        never = {"name": "never", "conditions": [[{"a": "{{1.status}}", "b": "zzz", "o": "text:equal"}]]}
        setvar = dict(mod(30, "util:SetVariable2", mapper={"name": "v", "value": "x"}), filter=never)
        fake, (code, output) = self.push(self.with_fallback([setvar]), modules="3,30", apply=True)
        self.assertEqual(code, make_push.EXIT_ABORT)
        self.assertIn("FAIL A module 3", output)
        self.assertIn("carries filter conditions", output)
        self.assertEqual(fake.patches(), [])

    def test_push_3_the_audit_row_for_a_filtered_fallback_is_a_fail_not_a_review(self):
        import audit_blueprints
        never = {"name": "never", "conditions": [[{"a": "{{1.status}}", "b": "zzz", "o": "text:equal"}]]}
        setvar = dict(mod(30, "util:SetVariable2", mapper={"name": "v", "value": "x"}), filter=never)
        b = audit_blueprints.Blueprint(name=NAME, scenario_id=str(SID), source="t", bp=self.with_fallback([setvar]))
        rows = [f for f in audit_blueprints.check_a(b, audit_blueprints.load_schema(os.path.join(FIX, "schema.json"))) if f.module_id == 3]
        self.assertEqual([f.status for f in rows], [audit_blueprints.FAIL])

    def test_the_f31_fix_may_write_the_status_when_the_spec_names_the_module(self):
        cand = self.with_fallback(self.trace())
        status = mod(6, "airtable:ActionUpdateRecords", mapper={"table": LEAD, "id": "{{1.id}}", "record": {"fldFrKT1VdHwzYwrG": "Nurture"}},
                     onerror=[ledger(37), slack(38), mod(39, "builtin:Break")])
        status["filter"] = {"name": "Lead found", "conditions": [[{"a": "{{1.id}}", "o": "exist"}]]}  # A-3 (bug sweep H2)
        cand["flow"][1]["routes"][0]["flow"].append(status)
        mods = "3,30,31,32,33,34,35,36,6,37,38,39"
        fake, (code, output) = self.push(cand, modules=mods)
        self.assertEqual(code, make_push.EXIT_ABORT)
        self.assertIn("does not name modules", output)
        self.assertIn("6", output)
        with open(os.path.join(self.specs, self.SPEC), "a", encoding="utf-8") as fh:
            fh.write("Module 6 writes the Status Nurture, modules 37, 38 and 39 are its handler (done)\n")
        fake, (code, output) = self.push(cand, modules=mods)
        self.assertEqual(code, make_push.EXIT_OK, output)
        fake, (code, output) = self.push(cand, modules=mods, fix="F-E5", closes="B:3")
        self.assertEqual(code, make_push.EXIT_ABORT)


class TestInterfaceEditsCannotCloseE1(Base):
    """safety-R2: E1 reads metadata.interface, so editing it is not a fix."""

    def live(self):
        trig = mod(1, "google-email:triggerWatchNewEmails", parameters={"limit": 1})
        trig["metadata"]["interface"] = [{"name": "subject", "type": "text", "label": "Subject"}]
        note = mod(2, "slack:CreateMessage", mapper={"text": "{{1.Gone}}", "channel": "C0"})
        return {"name": NAME, "flow": [trig, note],
                "metadata": {"instant": False, "version": 1, "designer": {"orphans": []}, "scenario": {"maxErrors": 3}}}

    def setUp(self):
        super().setUp()
        with open(os.path.join(self.specs, "X-41-mapping.md"), "w", encoding="utf-8") as fh:
            fh.write(f"# X-41\n\nScenario `{NAME}`, ID `{SID}`. Module 2 text is repointed. Module 1 interface is untouched.\n")
        self.live_bp = self.live()
        self.write_snapshot(self.live_bp)

    def compare(self, cand):
        import audit_blueprints
        labels = audit_blueprints.load_labels(os.path.join(FIX, "labels_confirmed.json"))
        schema = audit_blueprints.load_schema(os.path.join(FIX, "schema.json"))
        return make_push.compare_audits(self.live_bp, cand, SID, NAME, labels, schema,
                                        links=audit_blueprints.load_links(audit_blueprints.DEFAULT_LINKS))

    def test_adding_the_missing_field_to_the_interface_is_refused(self):
        cand = copy.deepcopy(self.live_bp)
        cand["flow"][0]["metadata"]["interface"].append({"name": "Gone", "type": "text", "label": "Gone"})
        with self.assertRaises(make_push.Abort) as cm:
            self.compare(cand)
        self.assertIn("metadata.interface of modules [1]", str(cm.exception))

    def test_removing_the_interface_to_turn_e1_into_a_skip_is_refused(self):
        cand = copy.deepcopy(self.live_bp)
        del cand["flow"][0]["metadata"]["interface"]
        with self.assertRaises(make_push.Abort):
            self.compare(cand)
        cand["flow"][0]["metadata"]["interface"] = [{"name": "__IMTHEADERS__", "type": "array", "label": "Headers"}]
        with self.assertRaises(make_push.Abort):
            self.compare(cand)

    def test_the_end_to_end_push_aborts_before_any_save(self):
        cand = copy.deepcopy(self.live_bp)
        cand["flow"][0]["metadata"]["interface"].append({"name": "Gone", "type": "text", "label": "Gone"})
        cand["flow"][0]["metadata"]["note"] = "touched"
        self.write_candidate(cand)
        fake = FakeMake(self.live_bp)
        code, output = self.run_main(fake, fix="X-41", modules="1", closes="E:2", apply=True)
        self.assertEqual(code, make_push.EXIT_ABORT)
        self.assertIn("metadata.interface", output)
        self.assertEqual(fake.patches(), [])

    def test_repointing_the_mapping_still_pushes(self):
        cand = copy.deepcopy(self.live_bp)
        cand["flow"][1]["mapper"]["text"] = "{{1.subject}}"
        self.write_candidate(cand)
        fake = FakeMake(self.live_bp)
        code, output = self.run_main(fake, fix="X-41", modules="2", closes="E:2", apply=True)
        self.assertEqual(code, make_push.EXIT_OK, output)
        self.assertEqual(len(fake.patches()), 1)

    def test_a_new_module_may_carry_its_own_interface(self):
        cand = copy.deepcopy(self.live_bp)
        extra = mod(9, "airtable:ActionSearchRecords", mapper={"table": LEAD})
        extra["metadata"]["interface"] = [{"name": "Name", "type": "text", "label": "Name"}]
        cand["flow"].append(extra)
        make_push.check_interfaces_unchanged(self.live_bp, cand)


class TestAuditInputsMustBeCommitted(Base):
    """safety-R4: the no-new-FAIL rule is only as strong as the files the audit reads."""

    def test_a_missing_links_map_aborts_instead_of_auditing_blind(self):
        fake = FakeMake(live_blueprint())
        code, output = self.run_main(fake, extra=("--links", os.path.join(self.tmp, "missing-links.json")))
        self.assertEqual(code, make_push.EXIT_ABORT)
        self.assertIn("no Airtable map", output)
        self.assertEqual(fake.calls, [])

    def test_an_uncommitted_allowlist_links_labels_or_schema_aborts_before_any_request(self):
        for name in ("allowlist.json", "airtable_links.json", "labels_confirmed.json", "schema.json"):
            fake = FakeMake(live_blueprint())
            code, output = self.run_main(
                fake, snapshot_state=lambda path, name=name: "it is not tracked by git" if os.path.basename(path) == name else None)
            self.assertEqual(code, make_push.EXIT_ABORT, name)
            self.assertIn(name, output)
            self.assertIn("not the committed version", output)
            self.assertEqual(fake.calls, [], name)

    def test_a_missing_allowlist_file_is_allowed_because_it_is_the_strictest(self):
        code, output = self.run_main(FakeMake(live_blueprint()), extra=("--allowlist", os.path.join(self.tmp, "none.json")))
        self.assertEqual(code, make_push.EXIT_OK, output)
        self.assertIn("Allowlist entries: 0", output)

    def test_the_plan_prints_the_allowlist_size(self):
        code, output = self.run_main(FakeMake(live_blueprint()))
        self.assertEqual(code, make_push.EXIT_OK, output)
        self.assertRegex(output, r"Audit inputs equal HEAD\. Allowlist entries: \d+\.")


class TestReviewTargets(Base):
    """A fix may close REVIEW rows (the F-31 router needs a fallback, an E7 row). --closes names it as
    CHECK:MODULE:REVIEW, or CHECK:MODULE when live has a REVIEW and no FAIL on that module. The REVIEW must be on
    live and gone from the candidate, no FAIL may be added, and the FAIL count may stay equal only because a
    declared REVIEW closed."""

    SPEC = "X-41-review-router.md"

    def live(self):
        """Router 3 routes on a filter each and has no fallback, and route 2 writes to Airtable: an E7 REVIEW on
        module 3. Modules 2 and 8 have no handler, so there are B FAILs on both sides of a push."""
        flt = lambda v: {"name": v, "conditions": [[{"a": "{{1.Status}}", "b": v, "o": "text:equal"}]]}   # noqa: E731
        return {
            "name": NAME,
            "flow": [
                mod(1, "airtable:ActionSearchRecords", mapper={"table": LEAD, "maxRecords": "1"}),
                mod(2, "airtable:ActionUpdateRecords", mapper={"table": LEAD, "id": "{{1.id}}"}),
                mod(3, "builtin:BasicRouter", routes=[
                    {"flow": [dict(mod(4, "util:SetVariable2", mapper={"name": "v", "value": "1"}), filter=flt("a"))]},
                    {"flow": [dict(mod(8, "airtable:ActionUpdateRecords", mapper={"table": LEAD, "id": "{{1.id}}"}), filter=flt("b"))]},
                ]),
            ],
            "metadata": {"instant": False, "version": 1, "designer": {"orphans": []}, "scenario": {"maxErrors": 3, "autoCommit": True}},
        }

    MODULES = "3,30,31,32,33,34,35,36"

    @staticmethod
    def trace_flow():
        """A fallback that leaves a trace: a ledger row 30 and a Slack alert 31, each with the handler check B asks for."""
        row = mod(30, "airtable:ActionCreateRecord", mapper={"table": LEDGER, "record": {LABEL: NAME, "fldgzlLkRAwc6KGoh": "Error"}},
                  onerror=[slack(32), mod(33, "builtin:Break")])
        alert = mod(31, "slack:CreateMessage", mapper={"text": "Unmatched bundle {{var.scenario.executionId}}", "channel": "C0"},
                    onerror=[ledger(34), slack(35), mod(36, "builtin:Break")])
        return [row, alert]

    def fixed(self):
        """Route 3 is the fallback and leaves a trace (ledger row 30, Slack alert 31)."""
        bp = self.live()
        router = bp["flow"][2]
        router["routes"].append({"flow": self.trace_flow()})
        router["parameters"] = {"else": 2}
        return bp

    def setUp(self):
        super().setUp()
        with open(os.path.join(self.specs, self.SPEC), "w", encoding="utf-8") as fh:
            fh.write(f"# X-41\n\nScenario `{NAME}`, ID `{SID}`. Router 3 gains a fallback route with modules 30 and 31, whose handler modules are 32, 33, 34, 35 and 36 (all new). In the renumbering test router 40 replaces router 3 and modules 4 and 8 move into it (done)\n")

    def use(self, live, cand):
        self.write_snapshot(live)
        self.write_candidate(cand)
        return FakeMake(live)

    def delta(self, live, cand):
        import audit_blueprints
        labels = audit_blueprints.load_labels(os.path.join(FIX, "labels_confirmed.json"))
        schema = audit_blueprints.load_schema(os.path.join(FIX, "schema.json"))
        return make_push.compare_audits(live, cand, SID, NAME, labels, schema,
                                        links=audit_blueprints.load_links(audit_blueprints.DEFAULT_LINKS), secret_allowlist=[])

    def push(self, fake, **kw):
        kw.setdefault("fix", "X-41")
        kw.setdefault("modules", self.MODULES)
        return self.run_main(fake, **kw)

    def test_the_fixture_has_the_review_on_live_and_not_on_the_candidate(self):
        d = self.delta(self.live(), self.fixed())
        self.assertIn(("E", "3"), d.live_reviews)
        self.assertNotIn(("E", "3"), d.remaining_reviews)
        self.assertEqual(d.fails_before, d.fails_after)
        self.assertEqual(d.new_fails, [])
        self.assertNotIn(("E", "3"), d.live_fails)

    def test_a_review_target_closes_with_the_fail_count_equal(self):
        for closes in ("E:3", "E:3:REVIEW"):
            live, cand = self.live(), self.fixed()
            fake = self.use(live, cand)
            code, output = self.push(fake, closes=closes, apply=True)
            self.assertEqual(code, make_push.EXIT_OK, output)
            self.assertIn("REVIEW targets closed: E:3:REVIEW.", output)
            self.assertIn("Targets: E:3", output)
            self.assertRegex(output, r"Audit FAIL (\d+) -> \1\.")
            self.assertEqual(len(fake.patches()), 1)
        name, rec = self.records()[-1]
        self.assertEqual(rec["targets"], ["E:3"])
        self.assertTrue(any(f["check"] == "E" and f["module_id"] == "3" and f["status"] == "REVIEW" for f in rec["findings_closed"]))

    def test_the_explicit_form_is_recorded_as_a_review_target(self):
        fake = self.use(self.live(), self.fixed())
        code, output = self.push(fake, closes="E:3:REVIEW", apply=True)
        self.assertEqual(code, make_push.EXIT_OK, output)
        self.assertEqual(self.records()[-1][1]["targets"], ["E:3:REVIEW"])

    def test_a_review_that_the_candidate_keeps_is_not_closed(self):
        """The module changed, the row is still there: a third route without a fallback marker."""
        live, cand = self.live(), self.fixed()
        del cand["flow"][2]["parameters"]
        cand["flow"][2]["routes"][2]["flow"] = [dict(mod(30, "util:SetVariable2", mapper={"name": "v", "value": "c"}),
                                                       filter={"name": "c", "conditions": [[{"a": "{{1.Status}}", "b": "c", "o": "text:equal"}]]})]
        fake = self.use(live, cand)
        code, output = self.push(fake, closes="E:3:REVIEW", modules="3,30", apply=True)
        self.assertEqual(code, make_push.EXIT_ABORT)
        self.assertIn("does not fully close: E:3:REVIEW (the REVIEW is still on the candidate)", output)
        self.assertEqual(fake.patches(), [])

    def test_equal_fail_counts_need_a_declared_review_that_closes(self):
        """Closing the REVIEW without declaring it leaves the count equal, which still aborts."""
        live, cand = self.live(), self.fixed()
        fake = self.use(live, cand)
        code, output = self.push(fake, closes="B:2", apply=True)
        self.assertEqual(code, make_push.EXIT_ABORT)
        self.assertIn("does not reduce the FAIL count", output)
        self.assertEqual(fake.patches(), [])

    def test_a_review_that_is_not_on_live_cannot_be_named(self):
        live, cand = self.live(), self.fixed()
        fake = self.use(live, cand)
        for closes in ("E:30:REVIEW", "E:-:REVIEW"):
            code, output = self.push(fake, closes=closes)
            self.assertEqual(code, make_push.EXIT_ABORT, closes)
            self.assertIn("REVIEW rows that are not on live", output)
        self.assertEqual(fake.patches(), [])

    def test_a_review_target_still_sits_on_the_modules_list(self):
        fake = self.use(self.live(), self.fixed())
        code, output = self.push(fake, closes="E:2:REVIEW")
        self.assertEqual(code, make_push.EXIT_ABORT)
        self.assertIn("--closes names modules not in --modules: E:2:REVIEW", output)

    def test_the_review_target_must_match_the_fix_id(self):
        fake = self.use(self.live(), self.fixed())
        code, output = self.push(fake, fix="F-E5", closes="E:3:REVIEW")
        self.assertEqual(code, make_push.EXIT_ABORT)
        self.assertIn("fix F-E5 closes check B findings only", output)

    def test_closing_a_review_never_makes_room_for_a_new_fail(self):
        """The fallback route also adds a Slack module with no handler: a new B FAIL, so the push aborts."""
        live, cand = self.live(), self.fixed()
        cand["flow"][2]["routes"][2]["flow"].append(slack(37))
        fake = self.use(live, cand)
        code, output = self.push(fake, closes="E:3:REVIEW", modules=self.MODULES + ",37", apply=True)
        self.assertEqual(code, make_push.EXIT_ABORT)
        self.assertIn("candidate adds FAIL findings not present on live", output)
        self.assertEqual(fake.patches(), [])

    def test_a_bare_target_is_the_fail_when_live_has_both(self):
        delta = make_push.AuditDelta(1, 0, [], [], [], live_fails={("E", "3")}, live_reviews={("E", "3")})
        self.assertEqual(make_push.split_targets([("E", "3")], delta), ([("E", "3")], []))
        self.assertEqual(make_push.split_targets([("E", "3", "REVIEW")], delta), ([], [("E", "3")]))
        only_review = make_push.AuditDelta(1, 0, [], [], [], live_reviews={("E", "3")})
        self.assertEqual(make_push.split_targets([("E", "3")], only_review), ([], [("E", "3")]))
        neither = make_push.AuditDelta(1, 0, [], [], [])
        self.assertEqual(make_push.split_targets([("E", "3")], neither), ([("E", "3")], []))

    def test_check_a_target_on_the_no_lead_lookup_is_exempt_from_the_modules_rule(self):
        """F-31.1: the A-2 row sits on the lead search while the fix changes the router routes that test its aggregator."""
        delta = make_push.AuditDelta(fails_before=1, fails_after=0, new_fails=[], new_other=[], closed=[("A", "7", "FAIL", "d")])
        with self.assertRaises(make_push.Abort) as cm:
            make_push.check_targets("F-31.1", [("A", "7")], delta, {114, 121})
        self.assertIn("not in --modules", str(cm.exception))
        make_push.check_targets("F-31.1", [("A", "7")], delta, {114, 121}, {7})
        with self.assertRaises(make_push.Abort):
            make_push.check_targets("F-31.1", [("A", "9")], delta, {114, 121}, {7})

    def test_check_targets_rules_for_review_rows(self):
        base = dict(fails_before=1, fails_after=1, new_fails=[], new_other=[])
        ok = make_push.AuditDelta(closed=[("E", "3", "REVIEW", "d")], live_reviews={("E", "3")}, remaining_reviews=set(), **base)
        make_push.check_targets("X-41", [("E", "3", "REVIEW")], ok, {3})
        make_push.check_targets("X-41", [("E", "3")], ok, {3})
        for kw, msg in ((dict(live_reviews=set(), remaining_reviews=set()), "not on live"),
                        (dict(live_reviews={("E", "3")}, remaining_reviews={("E", "3")}), "still on the candidate")):
            bad = make_push.AuditDelta(closed=[], **kw, **base)
            with self.assertRaises(make_push.Abort) as cm:
                make_push.check_targets("X-41", [("E", "3", "REVIEW")], bad, {3})
            self.assertIn(msg, str(cm.exception))
        # A FAIL target keeps its rules: a bare target on a REVIEW-only module that is not closed hints at the suffix.
        with self.assertRaises(make_push.Abort) as cm:
            make_push.check_targets("X-6", [("B", "3")], make_push.AuditDelta(closed=[], live_reviews={("B", "3")}, live_fails=set(),
                                                                                remaining_reviews={("B", "3")}, **base), {3})
        self.assertIn("still on the candidate", str(cm.exception))

    def test_undeclared_review_rows_that_close_are_listed_not_refused(self):
        """Only declared FAILs must be declared. An extra closed REVIEW is advisory and shows in the plan."""
        live, cand = self.live(), self.fixed()
        cand["flow"][1]["onerror"] = [ledger(10), slack(11), mod(12, "builtin:Resume")]
        fake = self.use(live, cand)
        mods = "2,10,11,12," + self.MODULES
        code, output = self.push(fake, closes="B:2", modules=mods)
        self.assertEqual(code, make_push.EXIT_ABORT)   # module 3 also closes a REVIEW, but B:2 is the declared FAIL: fix ID X-41 is check E
        self.assertIn("fix X-41 closes check E findings only", output)
        code, output = self.push(fake, fix="F-E5", closes="B:2", modules=mods)
        self.assertEqual(code, make_push.EXIT_OK, output)
        self.assertIn("REVIEW E module 3", output)

    # --- PUSH-1: a renumbered module carries the row off and closes nothing ---------------------------

    def test_push_1_a_router_recreated_under_a_new_id_closes_nothing(self):
        live = self.live()
        cand = self.live()
        cand["flow"][2]["id"] = 40
        fake = self.use(live, cand)
        for closes in ("E:3:REVIEW", "E:3"):
            code, output = self.push(fake, closes=closes, modules="3,40,4,8", apply=True)
            self.assertEqual(code, make_push.EXIT_ABORT, closes)
            self.assertIn("recreating the module under a new ID closed nothing", output)
        self.assertEqual(fake.patches(), [])

    def test_push_1_the_same_row_on_an_untouched_module_does_not_block_a_real_fix(self):
        """Only a REVIEW on a module the push touched can be the moved row. Another router that keeps the same text stays advisory."""
        sig = make_push.review_signature("E", "Every route has a filter. Routes write state in modules [4, 8]")
        other_sig = make_push.review_signature("E", "Every route has a filter. Routes write state in modules [14, 18]")
        self.assertEqual(sig, other_sig)
        base = dict(fails_before=1, fails_after=1, new_fails=[], new_other=[], closed=[("E", "3", "REVIEW", "d")],
                    live_reviews={("E", "3")}, remaining_reviews=set(), live_review_sigs={("E", "3"): {sig}})
        make_push.check_targets("X-41", [("E", "3", "REVIEW")], make_push.AuditDelta(remaining_review_sigs=set(), **base), {3})
        with self.assertRaises(make_push.Abort) as cm:
            make_push.check_targets("X-41", [("E", "3", "REVIEW")], make_push.AuditDelta(remaining_review_sigs={other_sig}, **base), {3})
        self.assertIn("recreating the module under a new ID closed nothing", str(cm.exception))

    def test_push_1_the_signature_ignores_numbers_only(self):
        a = make_push.review_signature("E", "Router 3 routes [4, 8]")
        self.assertEqual(a, make_push.review_signature("E", "Router 40 routes [41, 80]"))
        self.assertNotEqual(a, make_push.review_signature("B", "Router 3 routes [4, 8]"))
        self.assertNotEqual(a, make_push.review_signature("E", "Router 3 has a fallback [4, 8]"))

    # --- PUSH-2: the REVIEW path is not a way to slip other changes through ------------------------

    def test_push_2_a_fallback_that_only_sets_a_variable_closes_nothing(self):
        live, cand = self.live(), self.live()
        cand["flow"][2]["routes"].append({"flow": [mod(30, "util:SetVariable2", mapper={"name": "v", "value": "none"})]})
        cand["flow"][2]["parameters"] = {"else": 2}
        fake = self.use(live, cand)
        code, output = self.push(fake, closes="E:3:REVIEW", modules="3,30", apply=True)
        self.assertEqual(code, make_push.EXIT_ABORT)
        self.assertIn("the REVIEW is still on the candidate", output)
        self.assertEqual(fake.patches(), [])

    def test_push_2_a_lead_status_write_cannot_ride_along(self):
        status = {"fldFrKT1VdHwzYwrG": "Send Contract"}
        api = {"url": "/v0/appX/" + LEAD, "method": "PATCH", "body": json.dumps({"fields": {"Status": "Send Contract"}})}
        for name, change in {"update": lambda m: m["mapper"].update(record=status),
                             "api call": lambda m: (m.update(module="airtable:makeApiCall"), m.update(mapper=api))}.items():
            live, cand = self.live(), self.fixed()
            change(find_module(cand, 8))
            fake = self.use(live, cand)
            code, output = self.push(fake, closes="E:3:REVIEW", modules=self.MODULES + ",8", apply=True)
            self.assertEqual(code, make_push.EXIT_ABORT, name)
            self.assertIn("adds or changes lead Status writes in modules [8]", output, name)
            self.assertEqual(fake.patches(), [], name)

    def test_push_2_the_status_guard_leaves_modules_that_do_not_write_it_alone(self):
        live, cand = self.live(), self.fixed()
        find_module(cand, 8)["mapper"]["record"] = {"fldOTHER000000000": "x"}
        code, output = self.push(self.use(live, cand), closes="E:3:REVIEW", modules=self.MODULES + ",8")
        self.assertEqual(code, make_push.EXIT_OK, output)
        self.assertNotIn("lead Status", output)

    def test_push_2_the_review_path_needs_every_touched_module_in_the_spec(self):
        live, cand = self.live(), self.fixed()
        find_module(cand, 2)["mapper"]["note"] = "touched"
        fake = self.use(live, cand)
        code, output = self.push(fake, closes="E:3:REVIEW", modules=self.MODULES + ",2", apply=True)
        self.assertEqual(code, make_push.EXIT_ABORT)
        self.assertIn("does not name modules [2]", output)
        self.assertEqual(fake.patches(), [])
        with open(os.path.join(self.specs, self.SPEC), "a", encoding="utf-8") as fh:
            fh.write("Module 2 gets a note field in this test (done)\n")
        code, output = self.push(fake, closes="E:3:REVIEW", modules=self.MODULES + ",2")
        self.assertEqual(code, make_push.EXIT_OK, output)

    def test_closes_argument_forms(self):
        self.assertEqual(make_push._closes_arg("E:3:REVIEW,B:2,E:3"), [("E", "3", "REVIEW"), ("B", "2"), ("E", "3")])
        self.assertEqual(make_push._closes_arg("C:-"), [("C", "-")])
        self.assertEqual(make_push._closes_arg("E:03:REVIEW"), [("E", "3", "REVIEW")])
        for bad in ("E:3:INFO", "E:3:review", "E:3:FAIL", "E:3:", "E:0:REVIEW", "E7:3", "E:3:REVIEW:x"):
            with self.assertRaises(argparse.ArgumentTypeError, msg=bad):
                make_push._closes_arg(bad)
        self.assertEqual(make_push._fmt_target(("E", "3", "REVIEW")), "E:3:REVIEW")
        self.assertEqual(make_push._fmt_target(("E", "3")), "E:3")


# TestSimplifyPush (fix F-E5.2, the simplify push that leaned on the Error Monitor) was removed with the monitor (Option C,
# decided by Rizwan 2026-10-29). make_push refuses F-E5.2 (test_logger_push.TestLoggerSwapPush.test_f_e5_2_is_retired). Its guard
# cases that still apply to the F-E5.3 Logger swap live in test_logger_push.TestLoggerSwapShape.


class TestCombinedFixId(unittest.TestCase):
    def test_x23_plus_x41_closes_e_and_f_only(self):
        self.assertEqual(make_push.fix_checks("X-23+X-41"), ("E", "F"))
        self.assertEqual(make_push.fix_checks("X-23"), ("F",))
        self.assertEqual(make_push.fix_checks("X-41"), ("E",))

    def test_combined_fix_id_is_a_valid_argument(self):
        self.assertEqual(make_push._fix_arg("X-23+X-41"), "X-23+X-41")
        for bad in ("X-23+", "+X-41", "X-23++X-41", "X-23+X-41+X-19", "X 23"):
            with self.assertRaises(Exception):
                make_push._fix_arg(bad)


class TestCombinedSchemaFix(unittest.TestCase):
    """X-18+X-36 (2026-11-14): one push closes the P7 row and the R2 row of a Claude module, and the combined key shadows no
    single fix ID."""

    def test_mapping(self):
        self.assertEqual(make_push.fix_checks("X-18+X-36"), ("P", "R"))
        self.assertEqual(make_push.fix_checks("X-18.1"), ("P",))
        self.assertEqual(make_push.fix_checks("X-36.2"), ("R",))
        self.assertEqual(make_push.fix_checks("X-36.2.1"), ("R",))


if __name__ == "__main__":
    unittest.main()
