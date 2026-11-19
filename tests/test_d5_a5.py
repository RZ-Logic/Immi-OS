"""Check A rule A-5 (D5, 2026-11-01): for a scenario in audit/status_allow_list.json every allowed value passes the
allow-list filter of the dynamic lead Status write, and when the first router after the write on its flow branches on the
same mapping, every allowed value has a route of its own that is not the fallback, whose first module tests the value with
text:equal or text:equal:ci. Synthetic fixtures shaped like Pending Call 3943741 (write 8, router 10, router 135 above).
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
SID = "900"
ALLOWED = ("VIP", "Nurture", "Call Later", "Do Not Call")
DESIGNS = ab.StatusDesigns({SID: {"allowed": list(ALLOWED), "no_lead_lookup": 7, "reason": "The Bland agent sends four values"}})
REF = "{{3.status}}"


def bp(*flow, sid=SID):
    return ab.Blueprint(name="S", scenario_id=sid, source="test", bp={"name": "S", "flow": list(flow), "metadata": {}})


def rows(b, designs=DESIGNS):
    return [f for f in ab.check_a(b, SCHEMA, LINKS, designs) if f.rule == "A-5"]


def fails(b, designs=DESIGNS):
    return [f.module_id for f in rows(b, designs) if f.status == ab.FAIL]


def filt(m, conditions, name="f"):
    m = copy.deepcopy(m)
    m["filter"] = {"name": name, "conditions": conditions}
    return m


def is_value(value, op="text:equal", ref=REF):
    return [[{"a": ref, "b": value, "o": op}]]


def allow(values=ALLOWED, op="text:equal"):
    return [[{"a": REF, "b": v, "o": op}] for v in values]


def webhook(mid=3):
    return {"id": mid, "module": "gateway:CustomWebHook", "parameters": {"hook": 1}}


def search(mid):
    return {"id": mid, "module": "airtable:ActionSearchRecords", "mapper": {"table": LEAD, "formula": PHONE, "maxRecords": "1"}}


def agg(mid, feeder):
    return {"id": mid, "module": "builtin:BasicAggregator", "parameters": {"feeder": feeder}, "mapper": {"id": f"{{{{{feeder}.id}}}}"}}


def first_id(aid):
    return f'{{{{first(map({aid}.array; "id"))}}}}'


def update(mid, rid, status):
    return {"id": mid, "module": "airtable:ActionUpdateRecords", "mapper": {"id": rid, "table": LEAD, "record": {STATUS: status}}}


def row(mid, outcome="Success"):
    return {"id": mid, "module": "airtable:ActionCreateRecord",
            "mapper": {"table": LEDGER, "record": {ab.OUTCOME_FIELD: outcome, ab.LEAD_LINK_FIELD: ["{{121.id}}"],
                                                   ab.PAYLOAD_FIELD: "{{3.status}} because {{3.reason}}, previous {{121.Status}}",
                                                   ab.CALL_ID_FIELD: "{{5.call_id}}"}}}


def slack(mid):
    return {"id": mid, "module": "slack:CreateMessage", "mapper": {"text": "unmatched status, call {{5.call_id}}"}}


def sms(mid):
    return {"id": mid, "module": "twilio:SendSMS", "mapper": {"body": "link"}}


def router(mid, *routes, fallback=None):
    r = {"id": mid, "module": "builtin:BasicRouter", "routes": [{"flow": list(x)} for x in routes]}
    if fallback is not None:
        r["parameters"] = {"else": fallback}
    return r


def router_10(routes=None, fallback=3):
    """Live router 10 after write 8, with route 4 of the D5 candidate: 11 "Is VIP?" (text:equal:ci), 176 "Is Nurture?", 136
    "Is Call Later?", the fallback 139 and 142 (parameters.else 3), then 184 "Is Do Not Call?"."""
    if routes is None:
        routes = [[filt(sms(11), is_value("VIP", "text:equal:ci"))],
                  [filt(sms(176), is_value("Nurture"))],
                  [filt(row(136), is_value("Call Later"))],
                  [row(139, "Error"), slack(142)],
                  [filt(row(184), is_value("Do Not Call"))]]
    return router(10, *routes, fallback=fallback)


def pending_shape(filter_8=None, r10=None, after_8=None):
    """Pending Call 3943741: lead search 7, aggregator 113, router 146 [no-lead route 114 and 117, found route 121, decision
    row 125, router 135]. Router 135 holds [write 8 behind the allow-list, router 10] on route 0 and the fallback [128, 131]."""
    write = filt(update(8, "{{121.id}}", REF), filter_8 if filter_8 is not None else allow(), "Allowed status")
    route0 = [write] + (after_8 if after_8 is not None else [r10 if r10 is not None else router_10()])
    r135 = router(135, route0, [row(128, "Error"), slack(131)], fallback=1)
    found = [filt(search(121), [[{"a": first_id(113), "o": "exist"}]]), row(125), r135]
    no_lead = [filt(row(114, "Error"), [[{"a": first_id(113), "o": "notexist"}]]), slack(117)]
    return bp(webhook(), {"id": 5, "module": "bland:getCallDetails", "mapper": {"callId": "{{3.call_id}}"}}, search(7), agg(113, 7),
              router(146, no_lead, found))


class A5Tests(unittest.TestCase):
    def test_all_four_values_filtered_and_routed_pass(self):
        self.assertEqual(rows(pending_shape()), [])

    def test_do_not_call_missing_from_the_filter_fails_on_the_write(self):
        b = pending_shape(filter_8=allow(ALLOWED[:3]))
        self.assertEqual(fails(b), [8])
        f = rows(b)[0]
        self.assertIn("'Do Not Call'", f.detail)
        self.assertIn("module 8", f.detail)
        self.assertEqual(f.module_type, "airtable:ActionUpdateRecords")

    def test_do_not_call_with_no_route_fails_on_the_router(self):
        r10 = router_10()
        del r10["routes"][4]
        b = pending_shape(r10=r10)
        self.assertEqual(fails(b), [10])
        f = rows(b)[0]
        self.assertIn("router 10 after lead Status write 8", f.detail)
        self.assertIn("['Do Not Call']", f.detail)
        self.assertNotIn("VIP", f.detail)

    def test_both_missing_gives_two_rows(self):
        r10 = router_10()
        del r10["routes"][4]
        self.assertEqual(fails(pending_shape(filter_8=allow(ALLOWED[:3]), r10=r10)), [8, 10])

    def test_text_equal_ci_is_accepted_on_a_route(self):
        r10 = router_10()
        r10["routes"][4]["flow"] = [filt(row(184), is_value("do not call", "text:equal:ci"))]
        self.assertEqual(rows(pending_shape(r10=r10)), [])

    def test_text_equal_is_exact(self):
        r10 = router_10()
        r10["routes"][4]["flow"] = [filt(row(184), is_value("do not call"))]
        self.assertEqual(fails(pending_shape(r10=r10)), [10])

    def test_the_filter_on_the_write_is_read_case_aware(self):
        """A text:equal:ci allow-list lets the exact value through. A text:equal one with another case does not."""
        self.assertEqual(rows(pending_shape(filter_8=allow([v.upper() for v in ALLOWED], "text:equal:ci"))), [])
        self.assertEqual(fails(pending_shape(filter_8=allow(ALLOWED[:3] + ("do not call",)))), [8])

    def test_the_fallback_does_not_count(self):
        """Route 4 made the fallback (else 4) leaves Do Not Call with no route of its own."""
        b = pending_shape(r10=router_10(fallback=4))
        self.assertEqual(fails(b), [10])
        self.assertIn("['Do Not Call']", rows(b)[0].detail)

    def test_a_fallback_alone_with_no_routes_for_the_value_fails(self):
        r10 = router_10()
        del r10["routes"][4]
        r10["routes"][3]["flow"].insert(0, filt(row(184), is_value("Do Not Call")))
        self.assertEqual(fails(pending_shape(r10=r10)), [10])

    def test_a_route_that_is_not_its_own_or_not_equal_does_not_count(self):
        for name, cond in {
            "two OR groups": [[{"a": REF, "b": "Do Not Call", "o": "text:equal"}], [{"a": REF, "b": "Call Later", "o": "text:equal"}]],
            "contain": is_value("Do Not Call", "text:contain"),
            "another reference": is_value("Do Not Call", ref="{{5.status}}"),
            "a mapped value": is_value("{{3.other}}"),
            "the value and another in one group": [[{"a": REF, "b": "Do Not Call", "o": "text:equal"},
                                                    {"a": REF, "b": "Call Later", "o": "text:equal"}]],
            "the value and not the value": [[{"a": REF, "b": "Do Not Call", "o": "text:equal"},
                                             {"a": REF, "b": "Do Not Call", "o": "text:notequal"}]],
            "the value and a contain it fails": [[{"a": REF, "b": "Do Not Call", "o": "text:equal"},
                                                  {"a": REF, "b": "zzz", "o": "text:contain"}]],
        }.items():
            r10 = router_10()
            r10["routes"][4]["flow"] = [filt(row(184), cond)]
            self.assertEqual(fails(pending_shape(r10=r10)), [10], name)

    def test_a_route_condition_on_another_reference_is_kept(self):
        """A route head that also requires the lead record still counts as the value's own route."""
        r10 = router_10()
        r10["routes"][4]["flow"] = [filt(row(184), [[{"a": REF, "b": "Do Not Call", "o": "text:equal"},
                                                     {"a": "{{121.id}}", "o": "exist"}]])]
        self.assertEqual(rows(pending_shape(r10=r10)), [])

    def test_an_exists_condition_in_every_group_of_the_write_filter_is_kept(self):
        """The A-3 shape: every OR group of the allow-list also holds {{121.id}} exists. A condition on another reference
        cannot be decided, so the value is not counted as dropped. Without Do Not Call the write still FAILs."""
        def with_exists(values):
            return [[{"a": REF, "b": v, "o": "text:equal"}, {"a": "{{121.id}}", "o": "exist"}] for v in values]
        self.assertEqual(rows(pending_shape(filter_8=with_exists(ALLOWED))), [])
        b = pending_shape(filter_8=with_exists(ALLOWED[:3]))
        self.assertEqual(fails(b), [8])
        self.assertIn("rejects ['Do Not Call']", rows(b)[0].detail)

    def test_the_route_test_must_be_on_the_first_module(self):
        r10 = router_10()
        r10["routes"][4]["flow"] = [{"id": 187, "module": "util:SetVariable2", "mapper": {"name": "v", "value": "x"}},
                                    filt(row(184), is_value("Do Not Call"))]
        self.assertEqual(fails(pending_shape(r10=r10)), [10])

    def test_the_router_above_the_write_is_not_the_router_after_it(self):
        """With no router after write 8, router 135 (which holds 8) and router 146 get no A-5 row."""
        self.assertEqual(rows(pending_shape(after_8=[])), [])
        self.assertEqual(rows(pending_shape(after_8=[slack(190)])), [])

    def test_the_first_router_after_the_write_on_its_flow_is_judged(self):
        r10 = router_10()
        del r10["routes"][4]
        self.assertEqual(fails(pending_shape(after_8=[slack(190), r10])), [10])

    def test_a_router_that_does_not_branch_on_the_status_is_out_of_scope(self):
        other = router(10, [filt(sms(11), is_value("x", ref="{{5.status}}"))], [slack(12)], fallback=1)
        self.assertEqual(rows(pending_shape(r10=other)), [])

    def test_a_scenario_not_listed_gets_no_a5_rows(self):
        r10 = router_10()
        del r10["routes"][4]
        self.assertEqual(rows(pending_shape(filter_8=allow(ALLOWED[:3]), r10=r10), ab.StatusDesigns()), [])

    def test_a_write_with_no_allow_list_is_left_to_the_ledger_rule(self):
        self.assertEqual(rows(pending_shape(filter_8=[[{"a": REF, "b": "Disqualified", "o": "text:notequal"}]])), [])

    def test_rows_hold_no_semicolon_or_em_dash(self):
        r10 = router_10()
        del r10["routes"][4]
        for f in rows(pending_shape(filter_8=allow(ALLOWED[:3]), r10=r10)):
            self.assertNotIn(";", f.detail)
            self.assertNotIn("—", f.detail)

    def test_the_real_input_allows_do_not_call(self):
        d = ab.load_status_designs(ab.DEFAULT_STATUS_ALLOW, required=True)
        self.assertEqual(d.entries["3943741"]["allowed"], list(ALLOWED))
        self.assertEqual(d.entries["3943741"]["no_lead_lookup"], 7)
        self.assertNotIn("only ever sends", d.entries["3943741"]["reason"])


class SnapshotRowsTests(unittest.TestCase):
    """A-5 on blueprints/ (pulled before F-31.5): Pending Call 3943741 FAILs on write 8 and router 10, nothing else. The
    F-31.5 closing commit sets EXPECTED to set(), since the push closes both rows."""

    EXPECTED: set = set()  # F-31.5 pushed 2026-11-01 (Pending Call v45) closed A:8 and A:10

    def test_rows_on_live_snapshots(self):
        files = sorted(glob.glob(os.path.join(ROOT, "blueprints", "*__*.json")))
        if not files:
            self.skipTest("no committed snapshots")
        designs = ab.load_status_designs(ab.DEFAULT_STATUS_ALLOW, required=True)
        got = set()
        for path in files:
            b = ab._load_blueprint_file(path)
            for f in ab.check_a(b, SCHEMA, LINKS, designs):
                if f.rule == "A-5":
                    self.assertEqual(f.status, ab.FAIL)
                    self.assertIn("Do Not Call", f.detail)
                    got.add((str(b.scenario_id), f.module_id))
        self.assertEqual(got, self.EXPECTED)


if __name__ == "__main__":
    unittest.main()
