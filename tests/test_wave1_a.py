"""Check A rules from the 2026-10-31 bug sweep, wave 1: A-3 (H2, a lead Status write that takes its record ID from a search
needs a {{N.id}} exists gate, with re-lookup credit) and A-4 (M3, no silent lookup gate on the path of a lead Status write,
a search that is the scenario's first module exempt, exist tests only). Synthetic fixtures shaped like the live modules.
No network.
"""

import copy
import glob
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import audit_blueprints as ab  # noqa: E402

LEAD = ab.LEAD_TABLE
LEDGER = ab.LEDGER_TABLE
STATUS = ab.STATUS_FIELD
LINKS = ab.load_links(ab.DEFAULT_LINKS, required=True)
SCHEMA = ab.load_schema(os.path.join(ROOT, "audit", "airtable_ledger_schema.json"))
PHONE = "{Phone} = '{{3.phone}}'"


def bp(*flow, sid="1"):
    return ab.Blueprint(name="S", scenario_id=sid, source="test", bp={"name": "S", "flow": list(flow), "metadata": {}})


def rows(b, code):
    return [f for f in ab.check_a(b, SCHEMA, LINKS, ab.StatusDesigns()) if f.rule == code]


def fails(b, code):
    return [f.module_id for f in rows(b, code) if f.status == ab.FAIL]


def webhook(mid=3):
    return {"id": mid, "module": "gateway:CustomWebHook", "parameters": {"hook": 1}}


def mail_trigger(mid=1):
    return {"id": mid, "module": "google-email:triggerWatchNewEmails", "parameters": {"limit": 1}}


def search(mid, table=LEAD, formula=PHONE):
    return {"id": mid, "module": "airtable:ActionSearchRecords", "mapper": {"table": table, "formula": formula, "maxRecords": "1"}}


def agg(mid, feeder):
    return {"id": mid, "module": "builtin:BasicAggregator", "parameters": {"feeder": feeder}, "mapper": {"id": f"{{{{{feeder}.id}}}}"}}


def update(mid, rid, status="Calling", onerror=None):
    m = {"id": mid, "module": "airtable:ActionUpdateRecords", "mapper": {"id": rid, "table": LEAD, "record": {STATUS: status}}}
    if onerror:
        m["onerror"] = onerror
    return m


def setvar(mid):
    return {"id": mid, "module": "util:SetVariable2", "mapper": {"name": "v", "value": "x"}}


def http(mid, onerror=None):
    m = {"id": mid, "module": "http:MakeRequest", "mapper": {"url": "https://example.com", "method": "post"}}
    if onerror:
        m["onerror"] = onerror
    return m


def error_row(mid):
    return {"id": mid, "module": "airtable:ActionCreateRecord",
            "mapper": {"table": LEDGER, "record": {ab.OUTCOME_FIELD: "Error", "fld7oKusxba5RuIZR": "NO LEAD"}}}


def slack(mid):
    return {"id": mid, "module": "slack:CreateMessage", "mapper": {"text": "no lead"}}


def filt(m, conditions, name="f"):
    m = copy.deepcopy(m)
    m["filter"] = {"name": name, "conditions": conditions}
    return m


def cond(a, op, b=None):
    c = {"a": a, "o": op}
    if b is not None:
        c["b"] = b
    return [[c]]


def first_id(aid):
    return f'{{{{first(map({aid}.array; "id"))}}}}'


def router(mid, *routes, fallback=None):
    r = {"id": mid, "module": "builtin:BasicRouter", "routes": [{"flow": list(x)} for x in routes]}
    if fallback is not None:
        r["parameters"] = {"else": fallback}
    return r


def pending_shape(formula_121=PHONE, table_121=LEAD, route0=None):
    """Pending Call 3943741: search 7, aggregator 113, router 146 with the no-lead route [114, 117] and the found route
    [121 re-lookup behind the first-ID exists test, Status write 8 from 121]."""
    if route0 is None:
        route0 = [filt(error_row(114), cond(first_id(113), "notexist")), slack(117)]
    return bp(webhook(), search(7), agg(113, 7),
              router(146, route0, [filt(search(121, table_121, formula_121), cond(first_id(113), "exist")),
                                   update(8, "{{121.id}}", "{{3.status}}")]))


def signed_m3_candidate(route0=None, gate_first=True):
    """Signed Contracts 3974254 after F-31.4 (M3), critic IDs: gate search 43, aggregator 46, router 47 with the unmatched route
    [48 Error row, 51 Slack] and the found route [7 behind the first-ID exists test, Status write 8 unfiltered, 9, 10]."""
    if route0 is None:
        route0 = [filt(error_row(48), cond(first_id(46), "notexist")), slack(51)]
    found = [filt(search(7, LEAD, "{Email} = '{{1.fromEmail}}'"), cond(first_id(46), "exist")), update(8, "{{7.id}}", "Review Contract")]
    if not gate_first:
        found.insert(0, setvar(5))
    return bp(mail_trigger(), search(43, LEAD, "{Email} = '{{1.fromEmail}}'"), agg(46, 43), router(47, route0, found))


# ---------------------------------------------------------------------------
# A-3
# ---------------------------------------------------------------------------


class A3SearchIdGateTests(unittest.TestCase):
    def test_batch_shape_fails_on_the_status_write(self):
        """H2: Batch Outbound Caller 3953105, search 1 then Status write 2 with id {{1.id}} and no filter."""
        b = bp(search(1), update(2, "{{1.id}}"))
        got = rows(b, "A-3")
        self.assertEqual([(f.module_id, f.status) for f in got], [(2, ab.FAIL)])
        self.assertTrue(got[0].detail.startswith("A-3 "))
        self.assertIn("{{1.id}} exists", got[0].detail)
        self.assertIn("one empty bundle", got[0].detail)
        self.assertNotIn(";", got[0].detail)

    def test_exists_filter_on_the_write_passes(self):
        """The F-31.3 candidate: filter {{1.id}} exists on module 2."""
        self.assertEqual(rows(bp(search(1), filt(update(2, "{{1.id}}"), cond("{{1.id}}", "exist"))), "A-3"), [])

    def test_exists_filter_on_a_module_between_passes(self):
        b = bp(search(1), filt(setvar(5), cond("{{ 1.id }}", "exist")), update(2, "{{1.id}}"))
        self.assertEqual(rows(b, "A-3"), [])

    def test_only_the_canonical_exist_test_counts(self):
        for c in (cond("{{1.id}}", "notexist"), cond("{{1.id}}", "text:notequal", ""), cond("{{ifempty(1.id; \"\")}}", "exist"),
                  cond("{{length(1.id)}}", "number:greater", "0")):
            with self.subTest(c=c):
                self.assertEqual(fails(bp(search(1), filt(update(2, "{{1.id}}"), c)), "A-3"), [2])

    def test_an_or_group_without_the_test_fails(self):
        conds = [[{"a": "{{1.id}}", "o": "exist"}], [{"a": "{{1.Phone}}", "o": "exist"}]]
        self.assertEqual(fails(bp(search(1), filt(update(2, "{{1.id}}"), conds)), "A-3"), [2])

    def test_a_filter_on_another_module_fails(self):
        b = bp(search(4), search(1), filt(update(2, "{{1.id}}"), cond("{{4.id}}", "exist")))
        self.assertEqual(fails(b, "A-3"), [2])

    def test_a_gate_before_the_search_does_not_count(self):
        b = bp(webhook(), filt(setvar(5), cond("{{3.id}}", "exist")), search(1), update(2, "{{1.id}}"))
        self.assertEqual(fails(b, "A-3"), [2])

    def test_signed_contracts_live_shape_is_gated(self):
        """3974254 module 8 on live: filter {{7.id}} exists on the write itself (A-4 judges that gate)."""
        b = bp(mail_trigger(), search(7, LEAD, "{Email} = '{{1.fromEmail}}'"), filt(update(8, "{{7.id}}"), cond("{{7.id}}", "exist")))
        self.assertEqual(rows(b, "A-3"), [])

    def test_pending_call_re_lookup_passes(self):
        """3943741 module 8: re-lookup 121 behind the first-ID exists test on aggregator 113 of the identical search 7."""
        self.assertEqual(rows(pending_shape(), "A-3"), [])

    def test_re_lookup_with_another_formula_or_table_fails(self):
        self.assertEqual(fails(pending_shape(formula_121="{Phone} = '{{3.other}}'"), "A-3"), [8])
        self.assertEqual(fails(pending_shape(formula_121=" {Phone}  =  '{{3.phone}}' "), "A-3"), [])  # whitespace is ignored
        self.assertEqual(fails(pending_shape(table_121="tblOther"), "A-3"), [8])

    def test_signed_m3_candidate_passes_by_re_lookup(self):
        self.assertEqual(rows(signed_m3_candidate(), "A-3"), [])

    def test_a_write_in_an_error_route_is_judged(self):
        b = bp(search(1), http(3, onerror=[update(2, "{{1.id}}", "Call Later")]))
        self.assertEqual(fails(b, "A-3"), [2])

    def test_out_of_scope_record_ids_and_modules(self):
        trig = {"id": 1, "module": "airtable:TriggerWatchRecords", "parameters": {"table": LEAD}}
        get = {"id": 11, "module": "airtable:ActionGetRecord", "mapper": {"id": "{{first(4.`Applicant Link`)}}", "table": LEAD}}
        other = {"id": 2, "module": "airtable:ActionUpdateRecords", "mapper": {"id": "{{4.id}}", "table": LEAD, "record": {"fldX": "y"}}}
        self.assertEqual(rows(bp(trig, update(2, "{{1.id}}")), "A-3"), [])                        # the trigger record
        self.assertEqual(rows(bp(search(4, LEDGER), get, update(2, "{{11.id}}")), "A-3"), [])     # a get by link
        self.assertEqual(rows(bp(search(4), update(2, "{{first(4.`Link`)}}")), "A-3"), [])        # not N.id
        self.assertEqual(rows(bp(search(4), other), "A-3"), [])                                    # not a Status write
        self.assertEqual(rows(bp(webhook(), router(5, [search(4)], [update(2, "{{4.id}}")])), "A-3"), [])   # search not on the path


# ---------------------------------------------------------------------------
# A-4
# ---------------------------------------------------------------------------


class A4SilentLookupGateTests(unittest.TestCase):
    def test_signed_contracts_shape_fails(self):
        """M3: 3974254, Gmail trigger 1, lead search 7, Status write 8 behind filter {{7.id}} exists."""
        b = bp(mail_trigger(), search(7, LEAD, "{Email} = '{{1.fromEmail}}'"), filt(update(8, "{{7.id}}", "Review Contract"), cond("{{7.id}}", "exist")))
        got = rows(b, "A-4")
        self.assertEqual([(f.module_id, f.status) for f in got], [(8, ab.FAIL)])
        self.assertTrue(got[0].detail.startswith("A-4 "))
        self.assertIn("filter on module 8 finds the result of lead search 7", got[0].detail)
        self.assertNotIn(";", got[0].detail)

    def test_any_reference_to_the_lead_search_on_the_path_fails_once(self):
        b = bp(mail_trigger(), search(7), filt(setvar(5), cond("{{7.Status}}", "text:equal", "Send Contract")),
               filt(update(8, "{{7.id}}"), cond("{{7.id}}", "exist")))
        got = rows(b, "A-4")
        self.assertEqual([f.module_id for f in got], [8])
        self.assertIn("filter on module 5", got[0].detail)

    def test_first_module_search_is_exempt_and_the_batch_candidate_passes(self):
        """Critic 1B.1: the F-31.3 candidate adds {{1.id}} exists on module 2, and search 1 is the scheduled poll."""
        b = bp(search(1), filt(update(2, "{{1.id}}"), cond("{{1.id}}", "exist")), http(3))
        self.assertEqual(rows(b, "A-4"), [])
        self.assertEqual(rows(b, "A-3"), [])

    def test_does_not_exist_gates_are_out_of_scope(self):
        """VIP intake 3920821: Status creates 7 and 8 behind a dedupe {{first(map(88.array; "id"))}} does not exist on 81."""
        create = {"id": 7, "module": "airtable:ActionCreateRecord", "mapper": {"table": LEAD, "record": {STATUS: "VIP"}}}
        b = bp(mail_trigger(), search(85), agg(88, 85), filt(setvar(81), cond(first_id(88), "notexist")), create)
        self.assertEqual(rows(b, "A-4"), [])
        b = bp(mail_trigger(), search(85), filt(update(8, "{{3.id}}"), cond("{{85.id}}", "notexist")))
        self.assertEqual(rows(b, "A-4"), [])

    def test_gate_on_a_non_lead_search_is_out_of_scope(self):
        """Batch Call Reconciliation 6847022: the gates test System Logs searches, not the lead table."""
        b = bp(webhook(1), search(3, LEDGER), filt(update(8, "{{3.id}}"), cond("{{3.id}}", "exist")))
        self.assertEqual(rows(b, "A-4"), [])

    def test_pending_call_route_first_gate_with_a_traced_sibling_passes(self):
        self.assertEqual(rows(pending_shape(), "A-4"), [])

    def test_signed_m3_candidate_passes(self):
        b = signed_m3_candidate()
        self.assertEqual(rows(b, "A-4"), [])
        self.assertEqual(rows(b, "A-3"), [])

    def test_aggregator_gate_not_first_in_the_route_fails(self):
        got = rows(signed_m3_candidate(gate_first=False), "A-4")
        self.assertEqual([f.module_id for f in got], [8])
        self.assertIn("not the first module of a router route", got[0].detail)

    def test_aggregator_gate_on_a_plain_module_fails(self):
        b = bp(mail_trigger(), search(43), agg(46, 43), filt(search(7), cond(first_id(46), "exist")), update(8, "{{7.id}}"))
        got = rows(b, "A-4")
        self.assertEqual([f.module_id for f in got], [8])
        self.assertIn("module 7 is not the first module of a router route", got[0].detail)

    def test_sibling_route_must_trace_the_empty_result(self):
        cases = {
            "no Slack": [filt(error_row(48), cond(first_id(46), "notexist"))],
            "not an Error row": [filt(dict(error_row(48), mapper={"table": LEDGER, "record": {ab.OUTCOME_FIELD: "Success"}}),
                                      cond(first_id(46), "notexist")), slack(51)],
            "filtered Slack": [filt(error_row(48), cond(first_id(46), "notexist")), filt(slack(51), cond("{{1.id}}", "exist"))],
            "no empty test": [filt(error_row(48), cond("{{1.id}}", "exist")), slack(51)],
            "empty test on another aggregator": [filt(error_row(48), cond(first_id(99), "notexist")), slack(51)],
        }
        for name, route0 in cases.items():
            with self.subTest(name):
                got = rows(signed_m3_candidate(route0=route0), "A-4")
                self.assertEqual([f.module_id for f in got], [8])
                self.assertIn("router 47 has no fallback", got[0].detail)

    def test_a_traced_fallback_passes(self):
        b = bp(mail_trigger(), search(43), agg(46, 43),
               router(47, [error_row(48), slack(51)], [filt(search(7), cond(first_id(46), "exist")), update(8, "{{7.id}}")], fallback=0))
        self.assertEqual(rows(b, "A-4"), [])

    def test_a_status_write_of_unknown_target_is_included(self):
        api = {"id": 8, "module": "airtable:makeApiCall",
               "mapper": {"url": f"/v0/app/{LEAD}/{{{{7.id}}}}", "method": "PATCH", "body": "{{5.json}}"}}
        self.assertEqual(ab.lead_status(api), (None, True))
        b = bp(mail_trigger(), search(7), filt(api, cond("{{7.id}}", "exist")))
        self.assertEqual(fails(b, "A-4"), [8])
        self.assertEqual(rows(b, "A-3"), [])

    def test_error_route_writes_are_out_of_scope(self):
        b = bp(mail_trigger(), search(7), http(3, onerror=[filt(update(8, "{{7.id}}"), cond("{{7.id}}", "exist"))]))
        self.assertEqual(rows(b, "A-4"), [])


# ---------------------------------------------------------------------------
# The committed snapshots
# ---------------------------------------------------------------------------


class SnapshotRowsTests(unittest.TestCase):
    """A-3 and A-4 on blueprints/ (pulled 2026-10-31) FAIL exactly the modules the sweep names."""

    EXPECTED = {"A-3": set(), "A-4": set()}  # after the wave 1 pushes (2026-10-31): F-31.3 and F-31.4 closed Batch 2 and Signed 8

    def test_rows_on_live_snapshots(self):
        files = sorted(glob.glob(os.path.join(ROOT, "blueprints", "*__*.json")))
        if not files:
            self.skipTest("no committed snapshots")
        got = {"A-3": set(), "A-4": set()}
        for path in files:
            b = ab._load_blueprint_file(path)
            for f in ab.check_a(b, SCHEMA, LINKS):
                if f.rule in got:
                    self.assertEqual(f.status, ab.FAIL)
                    self.assertNotIn(";", f.detail)
                    self.assertNotIn("—", f.detail)
                    got[f.rule].add((str(b.scenario_id), f.module_id))
        self.assertEqual(got, self.EXPECTED)


if __name__ == "__main__":
    unittest.main()
