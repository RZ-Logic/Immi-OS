"""X-32 (specs/X-32-exemplars.md section 8): E35 no Make module writes the Exemplars table and only the F-F10 owner reads it,
E36 the selection shape (one search, its pinned formula, the aggregator, the ranker), E37 the exemplar mappings (the
drafter's skeleton, the validator's @08 terms, the ranker's Rank Key lines), E31 widened to ff13.rank_exemplars, E6
widened to exemplar text, the audit/x32.json pin, FIX_CHECKS X-32, prompt_registry --no-bind and the candidate builder.

The must-pass fixture is the planned candidate, built in memory by scripts/x32_candidate.py from the committed snapshot of
7049689. Every must-fail is one change to it, or a small synthetic scenario. No network, no client data.
"""

import copy
import json
import subprocess
import os
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
sys.path.insert(0, os.path.join(ROOT, "tests"))

import audit_blueprints as ab  # noqa: E402
import make_push  # noqa: E402
import prompt_registry as pr  # noqa: E402
import x32_candidate as xc  # noqa: E402
from test_prompt_registry import MAPPER, claude  # noqa: E402

SID = "7049689"
LINKS = ab.load_links(ab.DEFAULT_LINKS, required=True)
PROMPTS = ab.load_prompts()
PIN = ab.load_x32(ab.DEFAULT_X32, required=True)
FF10 = ab.load_ff10(ab.DEFAULT_FF10, required=True)
LOGGER = ab.load_webhooks(ab.DEFAULT_WEBHOOKS, required=True).logger
# The candidate was designed against version 8 of 7049689, the snapshot before the X-16.1 push (2026-11-17, version 9).
# It is read from git at the last commit that held it, so the fixture stays fixed while the committed pull moves on.
PRE_X16_COMMIT = "f1d733f"
SNAPSHOT = "blueprints/module-f-drafting-chain__7049689.json"
LIVE = json.loads(subprocess.run(["git", "show", f"{PRE_X16_COMMIT}:{SNAPSHOT}"], cwd=ROOT, capture_output=True,
                                 check=True).stdout.decode("utf-8"))
with open(os.path.join(ROOT, SNAPSHOT), encoding="utf-8") as _f:
    COMMITTED = json.load(_f)
CAND, PLAN = xc.build(LIVE, 171, PROMPTS, PIN, LINKS)
X32_RULES = ("E35", "E36", "E37")


def x16_row(rule, detail):
    """A row X-16 Phase A (audit/x16.json, 2026-11-16) adds on 7049689 by design until the X-16.1 push: the review trail
    (E38) and the production Doc's review folder (E32 (X-16)). The X-32 candidate does not carry that push."""
    return rule == "E38" or str(detail).startswith(("E32 (X-16)", "E38 "))


def index(bp):
    return {m.get("id"): m for m in xc._walk(bp.get("flow"))}


def cand():
    c = copy.deepcopy(CAND)
    return c, index(c)


def rows(bp, rule=None, status=ab.FAIL, sid=SID, name=None, pin=PIN, allow=None):
    b = ab.Blueprint(name=name or bp.get("name", ""), scenario_id=sid, source="test", bp=bp)
    return [f for f in ab.check_e(b, LINKS, allow or ab.Allowlist(), LOGGER, None, ab.BlandAgents(), FF10, pin)
            if (rule is None or f.rule == rule) and (status is None or f.status == status)]


def fails(bp, rules=X32_RULES + ("E31", "E6"), **kw):
    return [(f.rule, f.module_id) for f in rows(bp, **kw) if f.rule in rules]


def synthetic(*flow, name="Other scenario"):
    return {"name": name, "flow": list(flow), "metadata": {}}


def search(mid=2, table="Exemplars", **mapper):
    mp = {"base": "appdQ4ThUSMpdVK21", "table": table, "formula": "", "maxRecords": "10", "useColumnId": False}
    mp.update(mapper)
    return {"id": mid, "module": "airtable:ActionSearchRecords", "version": 3, "mapper": mp, "parameters": {"__IMTCONN__": 1}}


TRIGGER = {"id": 1, "module": "gateway:CustomWebHook", "version": 1, "parameters": {"hook": 1}, "mapper": {}}


class TestPin(unittest.TestCase):
    def test_the_committed_pin_loads(self):
        self.assertEqual(PIN.table_name, "Exemplars")
        self.assertEqual(PIN.max_candidates, 100)
        self.assertIn("Skeleton", PIN.pii_fields)

    def test_invalid_pins_are_input_errors(self):
        with open(ab.DEFAULT_X32, encoding="utf-8") as fh:
            good = json.load(fh)
        bad = [dict(good, firm_code="firm 1"), dict(good, firm_code="F'1"), dict(good, max_candidates=101),
               dict(good, max_candidates=True), dict(good, exemplars_table_id="tblshort"), dict(good, extra=1),
               dict(good, fields={k: v for k, v in good["fields"].items() if k != "skeleton"}),
               dict(good, fields=dict(good["fields"], skeleton="Ske'leton")),
               dict(good, fields=dict(good["fields"], terms="Skeleton")),
               dict(good, pii_fields=["Source Note"]), dict(good, field_ids={"skeleton": "nope"}),
               dict(good, selection_directive="Resume"), dict(good, selection_directive="ignore"),
               {k: v for k, v in good.items() if k != "selection_directive"}]
        d = tempfile.mkdtemp()
        try:
            for i, data in enumerate(bad):
                p = os.path.join(d, f"x{i}.json")
                with open(p, "w", encoding="utf-8") as fh:
                    json.dump(data, fh)
                with self.assertRaises(ab.InputError, msg=str(i)):
                    ab.load_x32(p)
            with self.assertRaises(ab.InputError):
                ab.load_x32(os.path.join(d, "missing.json"))
            self.assertEqual(ab.load_x32(os.path.join(d, "missing.json"), required=False), ab.X32Pin())
        finally:
            shutil.rmtree(d, ignore_errors=True)


class TestCandidate(unittest.TestCase):
    def test_the_committed_snapshot_has_no_x32_row(self):
        self.assertEqual(fails(LIVE), [])

    def test_the_planned_candidate_passes_every_e_rule(self):
        got = [(f.rule, f.module_id, f.detail[:120]) for f in rows(CAND) if f.status in (ab.FAIL, ab.REVIEW)]
        self.assertEqual([r for r in got if not x16_row(r[0], r[2])], [])
        live = [(f.rule, f.module_id, f.detail[:120]) for f in rows(LIVE) if f.status in (ab.FAIL, ab.REVIEW)]
        self.assertEqual(sorted(r for r in got if x16_row(r[0], r[2])), sorted(live))

    def test_the_candidate_touches_only_the_planned_modules(self):
        diff = make_push.diff_modules(LIVE, CAND)
        self.assertEqual(sorted(diff.touched), [8, 9, 10, 11, 172, 173, 174, 175, 176, 177, 178])
        self.assertEqual(sorted(diff.changed), [8, 9, 10, 11])
        idx = index(CAND)
        self.assertEqual([m["id"] for m in idx[8]["routes"][0]["flow"]], [172, 173, 174, 9, 10, 11, 12])
        self.assertEqual([m["id"] for m in idx[172]["onerror"]], [175, 176])
        self.assertEqual([m["id"] for m in idx[174]["onerror"]], [177, 178])

    def test_draft2_is_draft1_with_exactly_the_three_changes(self):
        d1 = index(LIVE)[9]["mapper"]
        d2 = index(CAND)[9]["mapper"]
        self.assertEqual({k: v for k, v in d1.items() if k not in ("system", "messages")},
                         {k: v for k, v in d2.items() if k not in ("system", "messages")})
        back = d2["system"].replace(xc.SYSTEM_NEW_1, xc.SYSTEM_OLD_1).replace("\n\n" + xc.SYSTEM_PARAGRAPH_2, "")
        self.assertEqual(back, d1["system"])
        self.assertEqual(d2["messages"][0]["content"], d1["messages"][0]["content"] + xc.exemplar_block(173, 174))
        self.assertEqual(PLAN["draft_version"], "drafting-chain.submission-letter-draft@2")
        self.assertEqual(PLAN["draft_sha256"], pr.template_sha256(d2))
        rec = index(CAND)[10]["mapper"]["record"]
        self.assertEqual((rec[xc.PROMPT_VERSION_FIELD], rec[xc.PROMPT_SHA_FIELD]), (PLAN["draft_version"], PLAN["draft_sha256"]))

    def test_draft2_says_details_may_remain_in_words(self):
        """Every exemplar keeps residual quasi-identifiers in plain words (the Status formula requires at least one, and
        each seed lists its own), so draft@2 must not tell the drafter that every detail is bracketed."""
        import x32_seeds as xs
        par = xc.SYSTEM_PARAGRAPH_2
        self.assertNotIn("Its names, places, dates, amounts and other details are replaced", par)
        self.assertIn("a few distinctive details may remain in plain words", par)
        self.assertIn("unless case_facts states it", par)
        self.assertIn(par, index(CAND)[9]["mapper"]["system"])
        with open(os.path.join(ROOT, "specs", "X-32-draft2-prompt.md"), encoding="utf-8") as fh:
            spec = fh.read()
        self.assertIn(PLAN["draft_sha256"], spec)
        self.assertIn(par, spec)
        for s in xs.load_seeds():
            self.assertTrue(s["terms"])
            for t in s["terms"]:
                self.assertIn(t, xs.PLACEHOLDER_RE.sub(" ", xs.skeleton(s)), s["code"])

    def test_the_candidate_is_never_written_into_the_repo(self):
        self.assertEqual(xc.main(["--id-sequence", "171", "--out", os.path.join(ROOT, "audit")]), 2)

    def test_the_builder_refuses(self):
        with self.assertRaises(xc.BuildError):
            xc.build(LIVE, 172, PROMPTS, PIN, LINKS, ids=xc.ids_above(171))   # the new IDs must sit above idSequence

    def test_the_harness_names_the_push_numbering(self):
        """draft@2 is registered from the candidate built on PUSH_ID_SEQUENCE, so the F-F14 harness must name the same
        aggregator and ranker, and the expressions must be exactly the builder's."""
        ids = xc.ids_above(xc.PUSH_ID_SEQUENCE)
        with open(os.path.join(ROOT, "scripts", "ff14", "x32.mjs"), encoding="utf-8") as fh:
            js = fh.read()
        self.assertIn(f"export const X32_AGGREGATOR = {ids['aggregator']};", js)
        self.assertIn(f"export const X32_RANKER = {ids['ranker']};", js)
        block = xc.exemplar_block(ids["aggregator"], ids["ranker"])
        expr = block.split("{{", 1)[1].rsplit("}}", 1)[0]
        js_expr = ('replace(first(map(${X32_AGGREGATOR}.array; "skeleton"; "id"; ${X32_RANKER}.exemplar_record_id)); '
                   '"/</g"; " less than ")')
        self.assertIn(js_expr, js)
        self.assertEqual(js_expr.replace("${X32_AGGREGATOR}", str(ids["aggregator"])).replace("${X32_RANKER}", str(ids["ranker"])), expr)
        self.assertEqual(xc.terms_mapping(ids["aggregator"], ids["ranker"]),
                         '{{first(map(%d.array; "terms"; "id"; %d.exemplar_record_id))}}' % (ids["aggregator"], ids["ranker"]))
        edited = copy.deepcopy(LIVE)
        index(edited)[9]["mapper"]["system"] += " Edited."
        with self.assertRaises(xc.BuildError):
            xc.build(edited, 171, PROMPTS, PIN, LINKS)   # module 9 is not its bound version
        with self.assertRaises(xc.BuildError):
            xc.draft2_mapper(dict(MAPPER, messages=[{"role": "user", "content": "x", "inputType": "single"}]), 173, 174)

    def test_the_offline_push_audit(self):
        """Registry as committed: exactly R2 on 9 and R4b on 10 are added. With draft@2 registered from the candidate and
        bound in a throwaway registry, the push closes both and adds no FAIL (step 7 of the push plan)."""
        d = tempfile.mkdtemp()
        try:
            path = os.path.join(d, "candidate.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(CAND, fh)
            res = xc.check(LIVE, CAND, PLAN, LINKS, PROMPTS, None, os.path.join(ROOT, "specs"))
            self.assertEqual(sorted((c, m) for c, m, _d in res["new_fails"]), [("R", "10"), ("R", "9")])
            # The spec names the push numbering (test_the_v10_push_candidate), not this v8 fixture's 172 to 178.
            self.assertEqual(sorted(set(res["spec_missing"]) - set(xc.NEW_IDS.values())), [])
            note, bound = xc.with_draft2_bound(path, lambda reg: xc.check(LIVE, CAND, PLAN, LINKS, reg,
                                                                        [("R", "9"), ("R", "10")]))
            self.assertIn("registered drafting-chain.submission-letter-draft@2", note)
            x16 = [r for r in bound["candidate_rows"] if x16_row(r[0], r[3])]
            self.assertEqual((bound["fails_before"], bound["fails_after"]), (2 + len(x16), len(x16)))
            self.assertEqual([r for r in bound["candidate_rows"] if not x16_row(r[0], r[3])], [])
            with open(pr.DEFAULT_BINDINGS, encoding="utf-8") as fh:
                self.assertNotIn('"version": 2', fh.read().split('"module_id": 9', 1)[1][:80])
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_the_v10_push_candidate(self):
        """The candidate the push will use (rebuilt 2026-11-19): version 10 from git (cf87ea1, after X-16.2), numbered on
        PUSH_ID_SEQUENCE. It touches 8, 9, 10, 11 and 208 to 214, the spec names every one, and with draft@2 bound it
        closes R:9 and R:10 and adds nothing."""
        v10 = json.loads(subprocess.run(["git", "show", f"cf87ea1:{SNAPSHOT}"], cwd=ROOT, capture_output=True,
                                        check=True).stdout.decode("utf-8"))
        cand, plan = xc.build(v10, xc.PUSH_ID_SEQUENCE, PROMPTS, PIN, LINKS)
        self.assertEqual(plan["added"], list(range(208, 215)))
        self.assertEqual([m["id"] for m in xc._index(cand)[8]["routes"][0]["flow"]], [208, 209, 210, 9, 10, 11, 204, 12])
        d = tempfile.mkdtemp()
        try:
            path = os.path.join(d, "candidate.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(cand, fh)
            res = xc.check(v10, cand, plan, LINKS, PROMPTS, None, os.path.join(ROOT, "specs"))
            self.assertEqual(res["spec_missing"], [])
            self.assertEqual(sorted((c, m) for c, m, _d in res["new_fails"]), [("R", "10"), ("R", "9")])
            _note, bound = xc.with_draft2_bound(path, lambda reg: xc.check(v10, cand, plan, LINKS, reg, [("R", "9"), ("R", "10")]))
            self.assertEqual((bound["fails_before"], bound["fails_after"]), (2, 0))
            self.assertEqual(bound["candidate_rows"], [])
        finally:
            shutil.rmtree(d, ignore_errors=True)


class TestE35(unittest.TestCase):
    def test_a_write_in_any_scenario_fails(self):
        for module in ("airtable:ActionCreateRecord", "airtable:ActionUpdateRecords", "airtable:ActionDeleteRecord",
                       "airtable:ActionBulkCreateRecords"):
            m = {"id": 2, "module": module, "mapper": {"table": "exemplars", "record": {}}}
            self.assertEqual(fails(synthetic(TRIGGER, m), sid="5"), [("E35", 2)], module)
            self.assertEqual(fails(synthetic(TRIGGER, m), sid=SID, name=FF10.owner_name), [("E35", 2)], module)

    def test_a_write_by_the_pinned_table_id_and_in_an_error_route_fails(self):
        pin = ab.X32Pin(table_id="tblZZTESTZZTEST01", firm_code="FIRM-01")
        w = {"id": 3, "module": "airtable:ActionUpdateRecords", "mapper": {"table": "tblZZTESTZZTEST01", "record": {}}}
        owner = {"id": 2, "module": "airtable:ActionSearchRecords", "mapper": {"table": "tblHk09sCKLcOJXr9"}, "onerror": [w]}
        self.assertEqual(fails(synthetic(TRIGGER, owner), sid="5", pin=pin), [("E35", 3)])

    def test_a_mapped_table_fails_for_writes_and_reads(self):
        """Spec section 8: a module that may reach the table and hides which table FAILs, reads included, in any
        scenario. E6 then also sees an Exemplars text field the mapped module hands to Slack."""
        w = {"id": 2, "module": "airtable:ActionCreateRecord", "mapper": {"table": "{{1.table}}", "record": {}}}
        self.assertEqual(fails(synthetic(TRIGGER, w), sid="5"), [("E35", 2)])
        r = search(table="{{1.table}}")
        self.assertEqual(fails(synthetic(TRIGGER, r), sid="5"), [("E35", 2)])
        self.assertEqual(fails(synthetic(TRIGGER, search(base="{{1.base}}")), sid="5"), [("E35", 2)])
        slack = {"id": 3, "module": "slack:CreateMessage", "version": 4,
                 "mapper": {"text": "{{2.Skeleton}} {{2.`Residual Quasi-Identifiers`}}"}}
        got = fails(synthetic(TRIGGER, r, slack), sid="5")
        self.assertIn(("E35", 2), got)
        self.assertEqual(got.count(("E6", 3)), 2)
        c, idx = cand()
        get = {"id": 190, "module": "airtable:ActionGetRecord", "mapper": {"table": "{{1.`Visa Code`}}", "id": "{{1.id}}"}}
        idx[8]["routes"][1]["flow"].append(get)
        self.assertIn(("E35", 190), fails(c))   # the owner too

    def test_an_api_call_with_a_mapped_url_fails(self):
        for url in ("{{1.url}}", "/v0/appdQ4ThUSMpdVK21/{{1.table}}", "/v0/{{1.base}}/{{1.table}}/recAAAAAAAAAAAAAA",
                    "/v0/{{1.path}}", "https://api.airtable.com/v0/appdQ4ThUSMpdVK21/{{1.table}}?maxRecords=3"):
            for method in ("PATCH", "GET"):
                module = ab.AIRTABLE_API_CALL if url.startswith("/") or url.startswith("{{") else "http:MakeRequest"
                api = {"id": 2, "module": module, "version": 4, "mapper": {"url": url, "method": method}}
                self.assertEqual(fails(synthetic(TRIGGER, api), sid="5"), [("E35", 2)], (url, method))
        for url in ("/v0/appdQ4ThUSMpdVK21/tblHk09sCKLcOJXr9/{{1.id}}", "/v0/{{1.base}}/Applicants",
                    "/v0/meta/bases/{{1.base}}/tables", "/v0/appdQ4ThUSMpdVK21/Applicants?filterByFormula={{1.f}}"):
            api = {"id": 2, "module": ab.AIRTABLE_API_CALL, "mapper": {"url": url, "method": "PATCH"}}
            self.assertEqual(fails(synthetic(TRIGGER, api), sid="5"), [], url)

    def test_an_api_write_naming_the_table_fails_and_a_get_reads(self):
        api = {"id": 2, "module": ab.AIRTABLE_API_CALL, "mapper": {"url": "/v0/appdQ4ThUSMpdVK21/Exemplars", "method": "PATCH"}}
        self.assertEqual(fails(synthetic(TRIGGER, api), sid="5"), [("E35", 2)])
        get = copy.deepcopy(api)
        get["mapper"]["method"] = "GET"
        self.assertEqual(fails(synthetic(TRIGGER, get), sid="5"), [("E35", 2)])   # a read outside the owner
        other = copy.deepcopy(api)
        other["mapper"]["url"] = "/v0/appdQ4ThUSMpdVK21/ExemplarsArchive"
        self.assertEqual(fails(synthetic(TRIGGER, other), sid="5"), [])

    def test_a_read_outside_the_owner_fails(self):
        self.assertEqual(fails(synthetic(TRIGGER, search()), sid="5"), [("E35", 2)])

    def test_the_owner_reads_only_through_search_records(self):
        c, idx = cand()
        get = {"id": 190, "module": "airtable:ActionGetRecord", "mapper": {"table": "Exemplars", "id": "{{1.id}}"}}
        idx[8]["routes"][1]["flow"].append(get)
        self.assertIn(("E35", 190), fails(c))

    def test_x32_rows_cannot_be_allowlisted(self):
        for rule in X32_RULES:
            self.assertNotIn(rule, ab.ALLOW_RULES)
        allow = ab.Allowlist(entries=[{"check": "E35", "scenario": "5", "module": "2", "reason": "a real reason here"},
                                      {"check": "E6", "scenario": "5", "module": "3", "reason": "a real reason here"}])
        self.assertEqual([f.status for f in rows(synthetic(TRIGGER, search()), "E35", sid="5", allow=allow)], [ab.FAIL])
        slack = {"id": 3, "module": "slack:CreateMessage", "version": 4, "mapper": {"text": "{{2.Skeleton}}"}}
        got = rows(synthetic(TRIGGER, search(), slack), "E6", sid="5", allow=allow)
        self.assertEqual([f.status for f in got], [ab.FAIL])


class TestE36(unittest.TestCase):
    def assertOnly(self, c, mid, text, rule="E36"):
        got = [f for f in rows(c) if f.rule in X32_RULES + ("E31",)]
        self.assertTrue(got, "no X-32 row")
        self.assertIn((rule, mid), [(f.rule, f.module_id) for f in got])
        self.assertTrue(any(text in f.detail for f in got if f.module_id == mid), [f.detail for f in got])

    def test_formula(self):
        for old, new in (("'FIRM-01'", "'FIRM-02'"), ('"TEST"; "Active"', '"Active"; "Active"'), ("4.gate_mode", "11.verdict"),
                         ("{{1.`Visa Code`}}", "{{1.`Document Code`}}"), ("AND(", "OR(")):
            c, idx = cand()
            f = idx[172]["mapper"]["formula"]
            self.assertIn(old, f)
            idx[172]["mapper"]["formula"] = f.replace(old, new, 1)
            self.assertOnly(c, 172, "formula is not exactly the pinned one")

    def test_formula_layout_is_ignored(self):
        c, idx = cand()
        idx[172]["mapper"]["formula"] = idx[172]["mapper"]["formula"].replace(", ", ",\n   ").replace(" = ", "=")
        self.assertEqual(fails(c), [])

    def test_settings(self):
        for key, value, text in (("maxRecords", "50", "maxRecords"), ("maxRecords", None, "maxRecords"),
                                 ("sort", [], "sort"), ("sort", [{"field": "Exemplar Code", "direction": "desc"}], "sort"),
                                 ("view", "viwZZTEST", "view"), ("fields", ["Exemplar Code", "Rank Key", "Skeleton"], "output fields"),
                                 ("fields", None, "output fields"), ("useColumnId", True, "useColumnId"),
                                 ("base", "appZZTESTZZTEST01", "base")):
            c, idx = cand()
            if value is None:
                idx[172]["mapper"].pop(key)
            else:
                idx[172]["mapper"][key] = value
            self.assertOnly(c, 172, text)

    def test_the_end_turn_filter(self):
        c, idx = cand()
        idx[172].pop("filter")
        self.assertOnly(c, 172, "end_turn")
        c, idx = cand()
        idx[172]["filter"]["conditions"].append([{"a": "{{1.id}}", "o": "exist"}])
        self.assertOnly(c, 172, "end_turn")

    def test_the_aggregator_and_the_ranker(self):
        c, idx = cand()
        idx[173]["mapper"]["extra"] = "{{172.Status}}"
        self.assertOnly(c, 172, "does not map exactly id, rank_key, skeleton and terms")
        c, idx = cand()
        idx[173]["filter"] = {"name": "x", "conditions": [[{"a": "{{172.id}}", "o": "exist"}]]}
        self.assertOnly(c, 172, "carries a filter")
        c, idx = cand()
        idx[174]["filter"] = {"name": "x", "conditions": [[{"a": "{{172.id}}", "o": "exist"}]]}
        self.assertOnly(c, 172, "carries a filter")
        c, idx = cand()
        route = idx[8]["routes"][0]["flow"]
        route[1], route[2] = route[2], route[1]
        self.assertOnly(c, 172, "next module is not an array aggregator")

    def test_a_second_search_aggregator_or_ranker_fails(self):
        c, idx = cand()
        extra = copy.deepcopy(idx[172])
        extra.update(id=190, onerror=[])
        idx[8]["routes"][0]["flow"].insert(4, extra)
        self.assertOnly(c, 190, "second Exemplars search")
        c, idx = cand()
        agg = copy.deepcopy(idx[173])
        agg["id"] = 191
        idx[8]["routes"][0]["flow"].insert(3, agg)
        self.assertOnly(c, 191, "second aggregator")
        c, idx = cand()
        rk = copy.deepcopy(idx[174])
        rk.update(id=192, onerror=[])
        idx[8]["routes"][0]["flow"].insert(3, rk)
        self.assertOnly(c, 192, "not the one right after")

    def test_the_handlers_hold_the_pinned_directive_and_never_resume(self):
        """A Resume with a literal substitute on the search (an Active-looking Rank Key and a Skeleton) or on the ranker (a
        literal exemplar_record_id) would bypass the Status formula and the ranker's test-seed refusal. E36 FAILs it."""
        row = {"id": "recAAAAAAAAAAAAAA", "Rank Key": "recAAAAAAAAAAAAAA|EX-TR-VISIT-900|Active|TR-VISIT|SUBMISSION-LETTER|1|"
                                                      "home-ties-thin", "Skeleton": "Unreviewed text.",
               "Residual Quasi-Identifiers": "x"}
        for owner, ignore, sub in ((172, 176, row), (174, 178, {"exemplar_record_id": "recAAAAAAAAAAAAAA"}),
                                   (172, 176, {}), (174, 178, {})):
            c, idx = cand()
            hand = idx[owner]["onerror"]
            hand[1] = {"id": ignore, "module": "builtin:Resume", "version": 1, "mapper": sub, "parameters": {},
                       "metadata": hand[1].get("metadata", {})}
            self.assertOnly(c, owner, "holds a Resume")
        c, idx = cand()
        idx[172]["onerror"] = idx[172]["onerror"][1:]   # Ignore alone, no Logger call
        self.assertOnly(c, 172, "not exactly [Logger call, Ignore]")
        c, idx = cand()
        idx[174]["onerror"][1]["module"] = "builtin:Break"
        self.assertOnly(c, 174, "not exactly [Logger call, Ignore]")
        c, idx = cand()
        idx[174]["onerror"] = []
        self.assertOnly(c, 174, "not exactly [Logger call, Ignore]")
        # The pin decides: with Break pinned (go-ahead 8, option A), Break passes and Ignore FAILs.
        brk = ab.X32Pin(firm_code=PIN.firm_code, selection_directive="Break")
        c, idx = cand()
        for owner in (172, 174):
            idx[owner]["onerror"][1]["module"] = "builtin:Break"
        self.assertEqual([r for r in fails(c, pin=brk) if r[0] in X32_RULES], [])
        got = [(f.rule, f.module_id) for f in rows(CAND, pin=brk) if f.rule == "E36"]
        self.assertEqual(sorted(got), [("E36", 172), ("E36", 174)])

    def test_a_ranker_without_a_search_fails(self):
        c, idx = cand()
        route = idx[8]["routes"][0]["flow"]
        del route[0:2]
        self.assertOnly(c, 174, "no Exemplars search")

    def test_the_search_after_the_drafter_fails(self):
        c, idx = cand()
        route = idx[8]["routes"][0]["flow"]
        sel = route[0:3]
        del route[0:3]
        route[1:1] = sel   # 9, 172, 173, 174, 10, ...
        self.assertOnly(c, 172, "no drafter")


class TestE37(unittest.TestCase):
    def assertRow(self, c, mid, text):
        got = [f for f in rows(c) if f.rule == "E37" and f.module_id == mid]
        self.assertTrue(got and any(text in f.detail for f in got), [f.detail for f in rows(c) if f.rule in X32_RULES])

    def test_skeleton_outside_the_tag_or_twice_fails(self):
        c, idx = cand()
        msg = idx[9]["mapper"]["messages"][0]
        msg["content"] = msg["content"].replace("<exemplar>", "<example>").replace("</exemplar>", "</example>")
        self.assertRow(c, 9, "does not map the exemplar skeleton exactly once")
        c, idx = cand()
        msg = idx[9]["mapper"]["messages"][0]
        msg["content"] += xc.exemplar_block(173, 174)
        self.assertRow(c, 9, "does not map the exemplar skeleton exactly once")
        c, idx = cand()
        msg = idx[9]["mapper"]["messages"][0]
        msg["content"] = msg["content"].replace('" less than ")}}\n</exemplar>', '"")}}\n</exemplar>')
        self.assertRow(c, 9, "does not map the exemplar skeleton exactly once")

    def test_terms_must_be_exact(self):
        for bad in ('{{first(map(173.array; "skeleton"; "id"; 174.exemplar_record_id))}}', '{{first(map(173.array; "terms"))}}',
                    '{{first(map(173.array; "terms"; "id"; 174.exemplar_code))}}'):
            c, idx = cand()
            idx[11]["mapper"]["@08:text"] = bad
            self.assertRow(c, 11, "does not map @08:text exactly")

    def test_a_drafter_without_skeleton_while_terms_flow_fails(self):
        c, idx = cand()
        msg = idx[9]["mapper"]["messages"][0]
        msg["content"] = msg["content"].split("\n\n<exemplar>")[0]
        self.assertRow(c, 9, "maps no exemplar skeleton while validator 11")

    def test_any_other_module_mapping_the_aggregator_or_the_search_fails(self):
        c, idx = cand()
        idx[15]["mapper"]["record"]["fld7oKusxba5RuIZR"] = '{{first(map(173.array; "skeleton"))}}'
        self.assertRow(c, 15, "Only the drafter")
        c, idx = cand()
        idx[15]["mapper"]["record"]["fld7oKusxba5RuIZR"] = "{{172.Skeleton}}"
        self.assertRow(c, 15, "maps the output of the Exemplars search 172")
        c, idx = cand()
        idx[175]["mapper"]["urlEncodedBodyContent"][5]["value"] = "{{172.error.message}}"
        self.assertEqual(fails(c), [])   # the search's own handler reads its error


class TestE31AndE6(unittest.TestCase):
    def test_the_ranker_arguments(self):
        for key, bad in (("@05:text", '{{first(map(9.content; "text"; "type"; "text"))}}'),
                         ("@06:text", '{{join(map(173.array; "skeleton"); newline)}}'),
                         ("@01:text", "{{var.scenario.executionId}}"), ("@03:text", "TR-VISIT")):
            c, idx = cand()
            idx[174]["mapper"][key] = bad
            self.assertIn(("E31", 174), fails(c), key)
        c, idx = cand()
        a = idx[174]["mapper"]
        a["@03:text"], a["@04:text"] = a["@04:text"], a["@03:text"]
        self.assertIn(("E31", 174), fails(c))

    def test_the_ranker_runs_only_in_the_owner(self):
        rk = copy.deepcopy(index(CAND)[174])
        rk["onerror"] = []
        self.assertIn(("E31", 174), fails(synthetic(TRIGGER, rk), sid="5"))

    def test_slack_or_logger_mapping_of_exemplar_text_fails_strict(self):
        c, idx = cand()
        idx[16]["mapper"]["text"] += ' {{first(map(173.array; "terms"))}}'
        got = [f for f in rows(c, "E6")]
        self.assertTrue(got and all("Exemplars aggregator 173" in f.detail for f in got))
        c, idx = cand()
        idx[177]["mapper"]["urlEncodedBodyContent"][5]["value"] = "{{172.Skeleton}}"
        self.assertIn(("E6", 177), fails(c))
        s = search()
        slack = {"id": 3, "module": "slack:CreateMessage", "version": 4, "mapper": {"text": "{{2.`Residual Quasi-Identifiers`}}"}}
        self.assertIn(("E6", 3), fails(synthetic(TRIGGER, s, slack), sid="5"))
        ok = {"id": 3, "module": "slack:CreateMessage", "version": 4, "mapper": {"text": "{{2.`Exemplar Code`}} {{174.exemplar_code}}"}}
        self.assertNotIn(("E6", 3), fails(synthetic(TRIGGER, s, ok), sid="5"))


class TestPushWiring(unittest.TestCase):
    def test_fix_checks(self):
        self.assertEqual(make_push.fix_checks("X-32"), ("E", "R"))
        self.assertEqual(make_push.fix_checks("X-32.1"), ("E", "R"))

    def test_the_pin_is_an_audit_input(self):
        args = make_push.build_parser().parse_args(["--scenario", "7049689", "--candidate", "c.json", "--fix", "X-32",
                                                    "--modules", "8", "--base-version", "8", "--closes", "R:9"])
        self.assertEqual(args.x32, make_push.DEFAULT_X32)
        with open(os.path.join(ROOT, "scripts", "make_push.py"), encoding="utf-8") as fh:
            self.assertIn('("X-32 exemplar pin", args.x32)', fh.read())


class TestNoBind(unittest.TestCase):
    def test_no_bind_registers_insert_only_then_binds_on_reuse(self):
        d = tempfile.mkdtemp()
        try:
            bps = os.path.join(d, "blueprints")
            os.makedirs(bps)
            snap = os.path.join(bps, "synthetic__900001.json")
            prompts, bindings = os.path.join(d, "prompts.json"), os.path.join(d, "prompt_bindings.json")
            with open(snap, "w", encoding="utf-8") as f:
                json.dump({"name": "Synthetic", "flow": [claude(2)], "metadata": {}}, f)
            kw = dict(blueprints=bps, prompts_path=prompts, bindings_path=bindings, today="2026-11-16")
            pr.register(900001, 2, "test.sorter", "Sorts synthetic test emails.", **kw)
            cand_path = os.path.join(d, "candidate.json")
            with open(cand_path, "w", encoding="utf-8") as f:
                json.dump({"name": "Synthetic", "flow": [claude(2, dict(MAPPER, system="Exemplar sorter."))], "metadata": {}}, f)
            note = pr.register(900001, 2, "test.sorter", "Sorts synthetic test emails.", candidate=cand_path, bind=False, **kw)
            self.assertIn("registered test.sorter@2", note)
            self.assertIn("not bound", note)
            reg = pr.load(prompts, bindings)
            self.assertEqual(sorted(reg.versions), [("test.sorter", 1), ("test.sorter", 2)])
            self.assertEqual(reg.bindings[("900001", 2)], ("test.sorter", 1))
            note = pr.register(900001, 2, "test.sorter", "Sorts synthetic test emails.", candidate=cand_path, **kw)
            self.assertIn("reused test.sorter@2", note)
            self.assertEqual(pr.load(prompts, bindings).bindings[("900001", 2)], ("test.sorter", 2))
            self.assertEqual(pr.main(["register", "--scenario", "900001", "--module", "2", "--stage", "test.sorter",
                                      "--description", "Sorts synthetic test emails.", "--no-bind",
                                      "--candidate", os.path.join(d, "missing.json")]), 2)
        finally:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
