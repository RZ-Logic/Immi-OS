"""scripts/call_rows.py, the X-36.2 candidate builder: synthetic flows plus the committed snapshots. No network."""

import copy
import json
import os
import re
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import audit_blueprints as ab  # noqa: E402
import call_rows  # noqa: E402
import make_push as mp  # noqa: E402
import prompt_registry as pr  # noqa: E402
from test_prompt_registry import MAPPER, Files, version  # noqa: E402
from test_x362_call_rows import LOGGER, LINKS, logger_call  # noqa: E402

SID = 900001
LABEL = "Synthetic Scenario"


def claude(mid):
    return {"id": mid, "module": pr.CLAUDE_MODULE, "version": 1, "mapper": copy.deepcopy(MAPPER),
            "metadata": {"designer": {"x": 300 * mid, "y": 0}},
            "onerror": [logger_call(mid * 10), {"id": mid * 10 + 1, "module": "builtin:Break", "version": 1}]}


def ledger(mid, record):
    return {"id": mid, "module": "airtable:ActionCreateRecord", "version": 3, "parameters": {"__IMTCONN__": 1},
            "mapper": {"base": "appSYNTHETIC0000", "table": ab.LEDGER_TABLE, "record": record, "typecast": False, "useColumnId": True},
            "metadata": {"designer": {"x": 0, "y": 0}, "expect": [{"name": "record", "spec": []}]}}


class TestBuild(unittest.TestCase):
    def setUp(self):
        self.f = Files([version()], [{"scenario_id": SID, "module_id": 2, "stage": "test.sorter", "version": 1},
                                     {"scenario_id": SID, "module_id": 3, "stage": "test.sorter", "version": 1}])
        self.reg = pr.load(self.f.prompts, self.f.bindings)
        self.labels = ab.Labels(confirmed=True, scenarios={str(SID): {"name": "Synthetic", "expected_label": LABEL}})

    def tearDown(self):
        self.f.close()

    def build(self, flow, id_sequence=50):
        bp = {"name": "Synthetic", "flow": flow, "metadata": {}}
        return call_rows.build(bp, SID, id_sequence, self.reg, self.labels, LINKS, LOGGER)

    def test_two_claude_modules_in_one_flow_each_get_their_own_row(self):
        tokens = {ab.TOKEN_IN_FIELD: "{{2.usage.input_tokens}}", ab.TOKEN_OUT_FIELD: "{{3.usage.output_tokens}}"}
        cand, plan = self.build([{"id": 1, "module": "gateway:CustomWebHook"}, claude(2), claude(3), ledger(4, tokens)])
        self.assertEqual([m["id"] for m in cand["flow"]], [1, 2, 51, 3, 54, 4])
        self.assertEqual([(r["claude"], r["call_row"]) for r in plan["call_rows"]], [(2, 51), (3, 54)])
        out = ab.check_r_stamps(ab.Blueprint("Synthetic", str(SID), "x", cand), self.reg, LINKS, LOGGER)
        self.assertEqual([f for f in out if f.status == ab.FAIL], [])
        rec = cand["flow"][-1]["mapper"]["record"]
        self.assertNotIn(ab.TOKEN_IN_FIELD, rec)
        self.assertEqual(rec["fldeAVW2SAkT6KpZw"], "Call rows: {{51.id}} {{54.id}}")

    def test_new_ids_start_above_id_sequence(self):
        _cand, plan = self.build([{"id": 1, "module": "gateway:CustomWebHook"}, claude(2), ledger(4, {})], id_sequence=700)
        self.assertEqual([plan["call_rows"][0][k] for k in ("call_row", "logger", "resume")], [701, 702, 703])

    def test_a_prompt_copy_keeps_only_the_mappings_it_held(self):
        system = MAPPER["system"] * 4   # a copy long enough for R6
        f = Files([version(mapper=dict(MAPPER, system=system))],
                  [{"scenario_id": SID, "module_id": 2, "stage": "test.sorter", "version": 1}])
        try:
            self.reg = pr.load(f.prompts, f.bindings)
            n = claude(2)
            n["mapper"]["system"] = system
            row = ledger(4, {ab.TOKEN_IN_FIELD: "{{2.usage.input_tokens}}",
                             "fldeAVW2SAkT6KpZw": "System: [" + system + "] User: [{{1.subject}}]"})
            cand, plan = self.build([{"id": 1, "module": "gateway:CustomWebHook"}, n, ledger(3, {}), row])
            payload = cand["flow"][-1]["mapper"]["record"]["fldeAVW2SAkT6KpZw"]
            self.assertNotIn("You sort", payload)
            self.assertEqual(re.findall(r"\{\{.*?\}\}", payload), ["{{1.subject}}", "{{51.id}}"])
            self.assertEqual(plan["outcome_rows"][0]["payload_rewritten_from"], ["test.sorter"])
        finally:
            f.close()

    def test_an_existing_call_row_is_refused(self):
        cand, _plan = self.build([{"id": 1, "module": "gateway:CustomWebHook"}, claude(2), ledger(4, {})])
        with self.assertRaises(call_rows.BuildError):
            self.build(cand["flow"], id_sequence=60)

    def test_an_unbound_or_drifted_claude_module_is_refused(self):
        drift = claude(2)
        drift["mapper"]["system"] += " Be brief."
        for flow in ([{"id": 1, "module": "gateway:CustomWebHook"}, claude(9)], [{"id": 1, "module": "gateway:CustomWebHook"}, drift]):
            with self.assertRaises(call_rows.BuildError):
                self.build(flow + [ledger(4, {})])

    def test_a_stale_unregistered_copy_loses_its_text_and_keeps_its_mappings(self):
        # Pending Call 81: a hand copy of a prompt that is no registered version, so R6 cannot see it.
        stale = "System: [" + "You are an expert sales analyst who reads the transcript and summarises it. " * 2 + "] {{1.transcript}}"
        row = ledger(4, {ab.TOKEN_IN_FIELD: "{{2.usage.input_tokens}}", "fldeAVW2SAkT6KpZw": stale})
        cand, plan = self.build([{"id": 1, "module": "gateway:CustomWebHook"}, claude(2), ledger(3, {}), row])
        self.assertEqual(cand["flow"][-1]["mapper"]["record"]["fldeAVW2SAkT6KpZw"], "Inputs: [{{1.transcript}}] Call row: {{51.id}}")
        self.assertEqual(plan["outcome_rows"][0]["payload_rewritten_from"], ["an unregistered prompt"])

    def test_tokens_through_another_module_are_refused(self):
        setvar = {"id": 50, "module": "util:SetVariable2", "mapper": {"name": "tin", "value": "{{2.usage.input_tokens}}"}}
        with self.assertRaises(call_rows.BuildError):
            self.build([{"id": 1, "module": "gateway:CustomWebHook"}, claude(2), setvar, ledger(9, {ab.TOKEN_IN_FIELD: "{{50.tin}}"})])

    def test_applicant_link_uses_positions_before_any_insert(self):
        search = {"id": 5, "module": "airtable:ActionSearchRecords", "mapper": {"table": ab.LEAD_TABLE}}
        row = ledger(4, {ab.TOKEN_IN_FIELD: "{{2.usage.input_tokens}} {{3.usage.input_tokens}}", ab.LEAD_LINK_FIELD: "{{5.id}}"})
        _cand, plan = self.build([{"id": 1, "module": "gateway:CustomWebHook"}, claude(2), search, claude(3), row])
        self.assertEqual([(r["claude"], r["applicant_link"]) for r in plan["call_rows"]], [(2, None), (3, "{{5.id}}")])

    def test_new_modules_land_on_free_spots(self):
        cand, plan = self.build([{"id": 1, "module": "gateway:CustomWebHook", "metadata": {"designer": {"x": 750, "y": 150}}},
                                 claude(2), ledger(4, {})])
        pos = {m.get("id"): ((m.get("metadata") or {}).get("designer") or {}) for m, _e, _c in ab.walk(cand["flow"])}
        new = {plan["call_rows"][0][k] for k in ("call_row", "logger", "resume")}
        for a in new:
            for b, q in pos.items():
                if b != a and q:
                    self.assertFalse(abs(pos[a]["x"] - q["x"]) < 120 and abs(pos[a]["y"] - q["y"]) < 120, (a, b))

    def test_out_inside_the_repo_is_refused_in_any_case(self):
        for out in (os.path.join(ROOT, "blueprints"), os.path.join(ROOT.lower(), "blueprints"), ROOT.upper()):
            self.assertEqual(call_rows.main(["--scenario", "3920821", "--id-sequence", "106", "--base-version", "35", "--out", out]), 2)


class TestCommittedSnapshots(unittest.TestCase):
    """Every AI scenario without call rows yet builds to a candidate that make_push's local guards accept with check R at 0,
    and no outcome row gains a mapping. A scenario already pushed is skipped (the builder refuses an existing call row)."""

    def test_each_scenario_builds_clean(self):
        links = ab.load_links(ab.DEFAULT_LINKS, required=True)
        prompts = ab.load_prompts()
        labels = ab.load_labels(os.path.join(ROOT, "audit", "scenario_labels.json"))
        logger = ab.load_webhooks(ab.DEFAULT_WEBHOOKS, required=True).logger
        built = 0
        for sid in call_rows.SCENARIOS:
            live = json.load(open(mp.find_snapshot(os.path.join(ROOT, "blueprints"), sid), encoding="utf-8"))
            ids = [m.get("id") for m, _e, _c in ab.walk(live["flow"])]
            try:
                cand, plan = call_rows.build(live, sid, max(ids), prompts, labels, links, logger)
            except call_rows.BuildError as exc:
                if "already has a call row" in str(exc):
                    continue
                raise
            result = call_rows.check(live, cand, sid, plan, links)
            self.assertEqual(result["status_touched"], [], sid)
            self.assertTrue(result["closes"], sid)
            built += 1
        if built == 0:
            self.skipTest("every AI scenario already has its call rows (X-36.2 pushed)")


if __name__ == "__main__":
    unittest.main()
