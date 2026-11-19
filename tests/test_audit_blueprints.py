"""Tests for scripts/audit_blueprints.py.

All blueprints are synthetic. Secret-shaped values are assembled at runtime
so this file never holds a literal the pre-commit hook would block. Nothing
here touches the network or the Make API.
"""

import contextlib
import copy
import hashlib
import io
import json
import os
import re
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import audit_blueprints as ab  # noqa: E402

FIX = os.path.join(ROOT, "tests", "fixtures")
BP_DIR = os.path.join(FIX, "blueprints")
SCHEMA = os.path.join(FIX, "schema.json")
LABELS_OK = os.path.join(FIX, "labels_confirmed.json")
LABELS_DRAFT = os.path.join(FIX, "labels_unconfirmed.json")

LEDGER = ab.LEDGER_TABLE
LEAD = ab.LEAD_TABLE


# ---------------------------------------------------------------------------
# Synthetic module builders
# ---------------------------------------------------------------------------


def ledger(mid, label="Lead Qualifier", **record):
    rec = {ab.LABEL_FIELD: label}
    rec.update(record)
    return {"id": mid, "module": "airtable:ActionCreateRecord", "mapper": {"table": LEDGER, "record": rec}}


def full_ledger(mid, decision="{{1.status}}", label="Lead Qualifier"):
    return ledger(mid, label, **{
        ab.LEAD_LINK_FIELD: ["{{1.lead_id}}"],
        ab.PAYLOAD_FIELD: decision + " {{1.reason}}",
        ab.CALL_ID_FIELD: "{{1.call_id}}",
    })


def slack(mid):
    return {"id": mid, "module": "slack:CreateMessage", "mapper": {"text": "{{error.message}}"}}


def error_row(mid, decision="{{1.status}}", **over):
    """The fallback trace: an Error ledger row with the lead link, the decision value and the call ID, mapped from the trigger."""
    rec = {ab.OUTCOME_FIELD: "Error", ab.LEAD_LINK_FIELD: ["{{1.lead_id}}"], ab.CALL_ID_FIELD: "{{1.call_id}}",
           ab.PAYLOAD_FIELD: "UNMATCHED DECISION VALUE: " + decision}
    rec.update(over)
    return ledger(mid, "Lead Qualifier", **{k: v for k, v in rec.items() if v is not None})


def directive(mid, kind="Break"):
    return {"id": mid, "module": "builtin:" + kind}


def status_write(mid, value, module="airtable:ActionUpdateRecords"):
    return {"id": mid, "module": module, "mapper": {"table": LEAD, "id": "{{1.lead_id}}", "record": {ab.STATUS_FIELD: value}}}


def filt(m, conditions, name="f"):
    m = dict(m)
    m["filter"] = {"name": name, "conditions": conditions}
    return m


def eq(ref, lit, op="text:equal:ci"):
    return [[{"a": ref, "b": lit, "o": op}]]


def router(mid, *routes, fallback=None):
    m = {"id": mid, "module": "builtin:BasicRouter", "routes": [{"flow": list(r)} for r in routes]}
    if fallback is not None:
        m["parameters"] = {"else": fallback}
    return m


def with_handler(m, *handler):
    m = dict(m)
    m["onerror"] = list(handler)
    return m


def trigger(mid=1):
    """A neutral trigger. Webhook triggers need an auth filter (check F), see webhook()."""
    return {"id": mid, "module": "google-email:triggerWatchNewEmails", "parameters": {"limit": 1}}


def webhook(mid=1):
    return {"id": mid, "module": "gateway:CustomWebHook", "parameters": {"hook": 1}}


def blueprint(name, *flow, scenario_id=None, sequential=False):
    meta = {"scenario": {"sequential": True}} if sequential else {}
    return ab.Blueprint(name=name, scenario_id=scenario_id, source="test", bp={"name": name, "flow": list(flow), "metadata": meta})


def schema():
    return ab.load_schema(SCHEMA)


def by_status(findings, status):
    return [f for f in findings if f.status == status]


def run_main(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = ab.main(list(argv))
    return code, out.getvalue(), err.getvalue()


def assert_only_logger_fails(test, code, out):
    """The run exits 1 because the shared Logger is not deployed (check L, a single FAIL) and for no other reason."""
    test.assertEqual(code, 1, out)
    test.assertRegex(out, r"L  Logger\s+FAIL 1 ")
    fails = [line for line in out.splitlines() if re.match(r"^[A-FM]  ", line) and not re.search(r"FAIL 0 ", line)]
    test.assertEqual(fails, [], out)


def fake_secret():
    return "sk" + "_live_" + "A1b2C3d4E5f6G7h8J9k0L1m2"


# ---------------------------------------------------------------------------
# Check A
# ---------------------------------------------------------------------------


class CheckATests(unittest.TestCase):
    def test_literal_disqualified_write_with_full_ledger_passes(self):
        b = blueprint("S", trigger(), status_write(2, "Disqualified"), full_ledger(3, decision="Disqualified"))
        res = ab.check_a(b, schema())
        self.assertEqual([f.status for f in res], [ab.PASS])

    def test_ledger_before_decision_write_counts(self):
        b = blueprint("S", trigger(), full_ledger(2), status_write(3, "{{1.status}}"))
        self.assertEqual([f.status for f in ab.check_a(b, schema())], [ab.PASS])

    def test_literal_disqualified_write_without_ledger_fails(self):
        b = blueprint("S", trigger(), status_write(2, "Disqualified"))
        res = ab.check_a(b, schema())
        self.assertEqual(len(by_status(res, ab.FAIL)), 1)
        self.assertIn("No Shadow Ledger create", res[0].detail)
        self.assertEqual(res[0].module_id, 2)

    def test_ledger_missing_fields_are_named(self):
        b = blueprint("S", trigger(), status_write(2, "Disqualified"), ledger(3, **{ab.LEAD_LINK_FIELD: ["{{1.id}}"]}))
        res = by_status(ab.check_a(b, schema()), ab.FAIL)
        self.assertEqual(len(res), 1)
        for word in ("decision value", "evidence", "Bland call ID"):
            self.assertIn(word, res[0].detail)
        self.assertNotIn("lead link", res[0].detail)

    def test_evidence_must_be_a_mapping(self):
        rec = {ab.LEAD_LINK_FIELD: ["{{1.id}}"], ab.PAYLOAD_FIELD: "Disqualified", ab.CALL_ID_FIELD: "{{1.call_id}}"}
        b = blueprint("S", trigger(), status_write(2, "Disqualified"), ledger(3, **rec))
        res = by_status(ab.check_a(b, schema()), ab.FAIL)
        self.assertEqual(len(res), 1)
        self.assertIn("evidence", res[0].detail)

    def test_ledger_written_only_after_rejection_email_fails(self):
        email = {"id": 3, "module": "google-email:sendAnEmail", "mapper": {"to": "{{1.email}}"}}
        b = blueprint("S", trigger(), status_write(2, "Disqualified"), email, full_ledger(4, decision="Disqualified"))
        res = by_status(ab.check_a(b, schema()), ab.FAIL)
        self.assertEqual(len(res), 1)
        self.assertIn("after the rejection email", res[0].detail)

    def test_dynamic_status_with_router_missing_disqualified_branch_fails(self):
        # Pending Call shape: the status write is dynamic and the router logs VIP and Nurture only.
        b = ab.load_dir(BP_DIR)
        demo = next(x for x in b if x.name == "Pending Call Demo")
        res = ab.check_a(demo, schema())
        fails = by_status(res, ab.FAIL)
        self.assertEqual(sorted(f.module_id for f in fails), [2, 3])
        write = next(f for f in fails if f.module_id == 2)
        self.assertIn("No Shadow Ledger create on the Disqualified path", write.detail)
        rtr = next(f for f in fails if f.module_id == 3)
        self.assertIn("no fallback route", rtr.detail)

    def test_fallback_route_carries_disqualified_to_ledger(self):
        r = router(3,
                   [filt(full_ledger(4), eq("{{1.status}}", "VIP"))],
                   [error_row(5, **{ab.PAYLOAD_FIELD: "{{1.status}} {{1.reason}}"}), slack(6)],
                   fallback=1)
        b = blueprint("S", trigger(), status_write(2, "{{1.status}}"), r)
        res = ab.check_a(b, schema())
        self.assertEqual(by_status(res, ab.FAIL), [])
        self.assertEqual(sorted(f.module_id for f in by_status(res, ab.PASS)), [2, 3])

    def test_unfiltered_route_ledger_is_guaranteed(self):
        r = router(3, [filt(slack(4), eq("{{1.status}}", "VIP"))], [full_ledger(5)])
        b = blueprint("S", trigger(), status_write(2, "{{1.status}}"), r)
        res = ab.check_a(b, schema())
        write = next(f for f in res if f.module_id == 2)
        self.assertEqual(write.status, ab.PASS)
        # Router 3 still branches on a decision value without a marked fallback.
        rtr = next(f for f in res if f.module_id == 3)
        self.assertEqual(rtr.status, ab.FAIL)

    def test_ledger_on_route_with_unrelated_filter_is_conditional(self):
        r = router(3, [filt(full_ledger(4), eq("{{1.region}}", "CA"))])
        b = blueprint("S", trigger(), status_write(2, "{{1.status}}"), r)
        res = by_status(ab.check_a(b, schema()), ab.FAIL)
        self.assertEqual(len(res), 1)
        self.assertIn("conditional path", res[0].detail)

    def test_filter_on_disqualified_is_a_decision_point(self):
        r = router(3, [filt(full_ledger(4), eq("{{1.status}}", "Disqualified"))], [filt(slack(5), eq("{{1.status}}", "VIP"))], fallback=None)
        b = blueprint("S", trigger(), r)
        res = ab.check_a(b, schema())
        point = next(f for f in res if f.module_id == 4)
        self.assertEqual(point.status, ab.PASS)
        self.assertEqual(next(f for f in res if f.module_id == 3).status, ab.FAIL)

    def test_filter_on_disqualified_without_ledger_fails(self):
        r = router(3, [filt(slack(4), eq("{{1.status}}", "Disqualified"))], [error_row(5), slack(6)], fallback=1)
        b = blueprint("S", trigger(), r)
        res = ab.check_a(b, schema())
        self.assertEqual(next(f for f in res if f.module_id == 4).status, ab.FAIL)
        self.assertEqual(next(f for f in res if f.module_id == 3).status, ab.PASS)

    def test_fallback_detection_uses_router_else_index(self):
        r = router(3, [slack(4)], [slack(5)], [slack(6)], fallback=2)
        self.assertEqual(ab.fallback_index(r), 2)
        self.assertIsNone(ab.fallback_index(router(3, [slack(4)])))
        self.assertIsNone(ab.fallback_index(router(3, [slack(4)], fallback=5)))
        self.assertEqual(ab.fallback_index(router(3, [slack(4)], [slack(5)], fallback="1")), 1)

    def test_fallback_route_with_conditions_is_a_fail(self):
        """A filtered fallback was a REVIEW ("confirm in the Make UI"), so a push could turn the no-fallback FAIL into
        a REVIEW with a fallback Make never takes (PUSH-3). It is a FAIL now."""
        r = router(3, [filt(full_ledger(4), eq("{{1.status}}", "VIP"))], [filt(full_ledger(5), eq("{{1.status}}", "Nurture"))], fallback=1)
        b = blueprint("S", trigger(), r)
        rtr = next(f for f in ab.check_a(b, schema()) if f.module_id == 3)
        self.assertEqual(rtr.status, ab.FAIL)
        self.assertIn("carries filter conditions", rtr.detail)

    def test_router_on_non_decision_values_is_ignored(self):
        r = router(3, [filt(slack(4), eq("{{1.urgency}}", "High"))], [filt(slack(5), eq("{{1.urgency}}", "low"))])
        self.assertEqual(ab.check_a(blueprint("S", trigger(), r), schema()), [])

    def test_vip_tiering_is_info_not_fail(self):
        cond = [[{"a": "{{5.has_job_offer}}", "b": "yes", "o": "text:equal:ci"}],
                [{"a": "{{5.crs_score}}", "b": "500", "o": "number:greaterorequal"}]]
        r = router(6, [filt(status_write(7, "VIP", "airtable:ActionCreateRecord"), cond)], [status_write(8, "Pending Call", "airtable:ActionCreateRecord")], fallback=1)
        res = ab.check_a(blueprint("S", trigger(), r), schema())
        self.assertEqual(by_status(res, ab.FAIL), [])
        info = by_status(res, ab.INFO)
        self.assertEqual(len(info), 1)
        self.assertIn("crs_score", info[0].detail)

    def test_rejection_outcome_scenario_is_info(self):
        trig = {"id": 1, "module": "airtable:TriggerWatchRecords", "parameters": {"formula": "{Status} = \"Disqualified\""}}
        email = {"id": 2, "module": "google-email:sendAnEmail"}
        b = blueprint("S", trig, email, status_write(3, "Disqualified - Rejection Sent"), ledger(4, **{ab.LEAD_LINK_FIELD: ["{{1.id}}"]}))
        res = ab.check_a(b, schema())
        self.assertEqual(by_status(res, ab.FAIL), [])
        self.assertEqual(sorted(f.module_id for f in by_status(res, ab.INFO)), [1, 3])

    def test_decision_inside_error_route_router_is_found(self):
        handler = router(10, [status_write(11, "Disqualified")], [slack(12), directive(13)])
        b = blueprint("S", trigger(), with_handler({"id": 2, "module": "bland:getCallDetails"}, handler))
        res = ab.check_a(b, schema())
        self.assertEqual([(f.module_id, f.status) for f in res], [(11, ab.FAIL)])


class CheckAAllowListTests(unittest.TestCase):
    """F-31 for Automating 'Pending Call' Clients (decision by Rizwan 2026-10-28). The Bland pathway sends VIP,
    Nurture or Call Later and never Disqualified. The Status write sits behind an allow-list filter on a router
    route, and the router's fallback takes every other value, Disqualified included, writes no Status and leaves
    an Error ledger row and a Slack alert. Check A closes the Status write and the router only when the
    allow-list really rejects Disqualified, the values stay inside the scenario's allowed set, a decision row with
    the previous Status sits before the write, no sibling route matches every value and the fallback really
    writes no Status and really leaves a trace."""

    ALLOWED = ("VIP", "Nurture", "Call Later")
    DESIGNS = ab.StatusDesigns({"900": {"allowed": list(ALLOWED), "no_lead_lookup": None, "reason": "The Bland pathway sends three values"}})

    @staticmethod
    def allow(values=ALLOWED, ref="{{1.status}}", op="text:equal:ci"):
        return [[{"a": ref, "b": v, "o": op}] for v in values]

    @staticmethod
    def fallback_row(mid, **over):
        return error_row(mid, **over)

    @staticmethod
    def decision_row(mid, **over):
        """F-31 item 1: lead link, decision value, evidence, call ID and the lead's previous Status (module 3 is the lead lookup)."""
        rec = {ab.LEAD_LINK_FIELD: ["{{3.id}}"], ab.PAYLOAD_FIELD: "{{1.status}} because {{1.reason}}, previous {{3.Status}}",
               ab.CALL_ID_FIELD: "{{1.call_id}}"}
        rec.update(over)
        return ledger(mid, "Lead Qualifier", **{k: v for k, v in rec.items() if v is not None})

    def design(self, allow=None, write=None, fallback_flow=None, fallback=1, first=None, decision_row=True, row=None):
        """trigger, the lead lookup 3, the decision row, then router 5: route 0 holds the Status write behind the allow-list, route 1 is the fallback."""
        write = write or status_write(6, "{{1.status}}")
        route0 = [filt(write, allow if allow is not None else self.allow())] if first is None else first
        fb_flow = fallback_flow if fallback_flow is not None else [self.fallback_row(20), slack_text(21, "Unmatched decision, lead {{3.id}}, call {{1.call_id}}")]
        flow = [trigger(), at_search(3, LEAD, fields=("id", "Status"))] + ([row or self.decision_row(2)] if decision_row else [])
        return flow + [router(5, route0, fb_flow, fallback=fallback)]

    def run_a(self, flow, designs=None):
        return ab.check_a(blueprint("S", *flow, scenario_id="900"), schema(), None, designs or self.DESIGNS)

    def row(self, res, mid):
        return next(f for f in res if f.module_id == mid and f.status != ab.INFO)

    # --- the design that closes both FAILs --------------------------------------------------

    def test_the_f31_design_closes_the_status_write_and_the_router(self):
        res = self.run_a(self.design())
        self.assertEqual([(f.module_id, f.status) for f in res if f.status != ab.INFO], [(5, ab.PASS), (6, ab.PASS)])
        self.assertIn("allow-list filter on module 6", self.row(res, 6).detail)
        self.assertIn("writes no lead Status", self.row(res, 6).detail)
        self.assertIn("fallback route 1", self.row(res, 5).detail)

    def test_the_allow_list_may_sit_on_an_earlier_module_of_the_route(self):
        """A filter on a module stops the flow from there, so it covers the Status write behind it."""
        marker = {"id": 7, "module": "util:SetVariable2", "mapper": {"name": "v", "value": "1"}}
        flow = self.design(first=[filt(marker, self.allow()), status_write(6, "{{1.status}}")])
        self.assertEqual(self.row(self.run_a(flow), 6).status, ab.PASS)

    def test_a_full_pending_call_shape_passes_with_the_post_write_router(self):
        """Allow-list router, then the VIP, Nurture and Call Later router after the write. It is a decision router
        too, so its own fallback traces any other value."""
        post = router(10, [filt(sendmail(11), self.allow(("VIP",)))], [filt(sendmail(12), self.allow(("Nurture",)))],
                      [filt({"id": 13, "module": "util:SetVariable2", "mapper": {"name": "v", "value": "call later"}}, self.allow(("Call Later",)))],
                      [self.fallback_row(14), slack_text(15, "Unmatched decision, lead {{3.id}}, call {{1.call_id}}")], fallback=3)
        flow = self.design(first=[filt(status_write(6, "{{1.status}}"), self.allow()), post])
        res = self.run_a(flow)
        self.assertEqual([f.status for f in res if f.status in (ab.FAIL, ab.REVIEW)], [])
        self.assertEqual(sorted(f.module_id for f in res if f.status == ab.PASS), [5, 6, 10])

    # --- the fallback must write no Status ------------------------------------------------------

    def test_a_fallback_that_writes_the_status_lets_disqualified_through(self):
        for value in ("{{1.status}}", "Disqualified", '{{if(1.x; "Disqualified"; "Nurture")}}'):
            fb = [status_write(30, value), self.fallback_row(20), slack_text(21, "x")]
            res = self.run_a(self.design(fallback_flow=fb))
            self.assertEqual(self.row(res, 6).status, ab.FAIL, value)
            self.assertIn("writes lead Status in modules [30]", self.row(res, 6).detail)
            self.assertEqual(self.row(res, 5).status, ab.FAIL, value)   # the router rule says the same
            self.assertIn("Disqualified still gets through", self.row(res, 5).detail)

    def test_a_fallback_that_writes_a_fixed_other_status_is_fine(self):
        fb = [status_write(30, "Nurture"), self.fallback_row(20), slack_text(21, "x")]
        res = self.run_a(self.design(fallback_flow=fb))
        self.assertEqual([self.row(res, 6).status, self.row(res, 5).status], [ab.PASS, ab.PASS])

    def test_a_status_write_deeper_in_the_fallback_or_its_error_route_counts(self):
        nested = router(31, [status_write(32, "{{1.status}}")], [slack_text(33, "x")])
        for fb in ([self.fallback_row(20), slack_text(21, "x"), nested],
                   [self.fallback_row(20), with_handler(slack_text(21, "x"), status_write(34, "{{1.status}}"))]):
            res = self.run_a(self.design(fallback_flow=fb))
            self.assertEqual(self.row(res, 6).status, ab.FAIL)

    # --- the fallback must leave a trace --------------------------------------------------------

    def test_the_fallback_needs_an_error_ledger_row_with_lead_decision_and_call_id_and_a_slack_alert(self):
        full = [self.fallback_row(20), slack_text(21, "x")]
        cases = {
            "no ledger row": [slack_text(21, "x")],
            "outcome Success": [self.fallback_row(20, **{ab.OUTCOME_FIELD: "Success"}), slack_text(21, "x")],
            "no outcome": [self.fallback_row(20, **{ab.OUTCOME_FIELD: None}), slack_text(21, "x")],
            "no lead link": [self.fallback_row(20, **{ab.LEAD_LINK_FIELD: None}), slack_text(21, "x")],
            "no call id": [self.fallback_row(20, **{ab.CALL_ID_FIELD: None}), slack_text(21, "x")],
            "no decision value": [self.fallback_row(20, **{ab.PAYLOAD_FIELD: "unmatched"}), slack_text(21, "x")],
            "decision value of another module": [self.fallback_row(20, **{ab.PAYLOAD_FIELD: "{{13.status}}"}), slack_text(21, "x")],
            "no slack": [self.fallback_row(20)],
            "ledger row only in the error handler": [slack_text(21, "x"), with_handler(slack_text(22, "y"), self.fallback_row(23))],
        }
        for name, fb in cases.items():
            res = self.run_a(self.design(fallback_flow=fb))
            self.assertEqual(self.row(res, 6).status, ab.FAIL, name)
        self.assertEqual(self.row(self.run_a(self.design(fallback_flow=full)), 6).status, ab.PASS)

    def test_a_router_without_a_fallback_fails_both_rows(self):
        res = self.run_a(self.design(fallback=None))
        self.assertEqual([(f.module_id, f.status) for f in res if f.status != ab.INFO], [(5, ab.FAIL), (6, ab.FAIL)])
        self.assertIn("no fallback route", self.row(res, 6).detail)

    def test_a_fallback_with_filter_conditions_is_not_a_catch_all(self):
        fb = [filt(self.fallback_row(20), self.allow(("Anything",))), slack_text(21, "x")]
        res = self.run_a(self.design(fallback_flow=fb))
        self.assertEqual(self.row(res, 6).status, ab.FAIL)
        self.assertIn("carries filter conditions", self.row(res, 6).detail)
        self.assertEqual(self.row(res, 5).status, ab.FAIL)   # PUSH-3: no longer a REVIEW that a push can trade a FAIL for

    # --- what is not an allow-list ----------------------------------------------------------------

    def not_credited(self, allow, **kw):
        """Without a decision row: the write is judged as before and FAILs. With one: it passes on the trail,
        never on an allow-list."""
        bare = self.run_a(self.design(allow=allow, decision_row=False, **kw))
        self.assertEqual(self.row(bare, 6).status, ab.FAIL, allow)
        self.assertIn("can set Disqualified", self.row(bare, 6).detail)
        self.assertNotIn("allow-list", self.row(bare, 6).detail)
        trail = self.run_a(self.design(allow=allow, **kw))
        self.assertNotIn("allow-list", self.row(trail, 6).detail)

    def test_filters_that_do_not_really_reject_disqualified_get_no_allow_list_credit(self):
        a = self.allow
        self.not_credited(a(("Disqualified",)))                                              # names it
        self.not_credited(a(("VIP", "Disqualified")))                                         # one group lets it in
        self.not_credited(a(("VIP", "disqualified")))                                         # the case variant
        self.not_credited([[{"a": "{{1.status}}", "b": "Disqualified", "o": "text:notequal"}]])   # a deny-list
        self.not_credited([[{"a": "{{1.status}}", "b": "disqualified", "o": "text:notequal:ci"}]])
        self.not_credited(a(("qualified",), op="text:contain"))                              # contains "qualified"
        self.not_credited(a(("VIP",), op="text:startwith"))
        self.not_credited(a(("VIP",), ref="{{7.Status}}"))                                    # another reference
        self.not_credited(a(("VIP",), ref='{{trim(1.status)}}'))
        self.not_credited(self.allow(("VIP",)) + [[{"a": "{{9.other}}", "b": "x", "o": "text:equal"}]])   # an OR group without the decision
        self.not_credited(self.allow(("VIP",)) + [[{"a": "{{1.status}}", "o": "exist"}]])      # an OR group that passes any value
        self.not_credited([[{"a": "{{1.status}}", "b": "{{2.other}}", "o": "text:equal"}]])      # a mapped value
        self.not_credited([[{"a": "{{1.status}}", "b": "", "o": "text:equal"}]])
        self.not_credited([])                                                                 # no conditions at all

    def test_an_allow_list_after_the_write_or_on_its_own_flow_is_not_a_guard(self):
        write = status_write(6, "{{1.status}}")
        flow = self.design(first=[write, filt(slack_text(7, "x"), self.allow())], decision_row=False)
        res = self.run_a(flow)
        self.assertEqual(self.row(res, 6).status, ab.FAIL)
        self.assertNotIn("allow-list", self.row(res, 6).detail)

    def test_an_allow_list_off_a_router_route_leaves_rejected_values_untraced(self):
        """The filter is on a module that is not the first of a route, or there is no router: a bundle that fails it just stops."""
        flow = [trigger(), full_ledger(2), filt(status_write(6, "{{1.status}}"), self.allow())]
        res = self.run_a(flow)
        self.assertEqual(self.row(res, 6).status, ab.FAIL)
        self.assertIn("not the first module of a router route", self.row(res, 6).detail)
        marker = {"id": 7, "module": "util:SetVariable2", "mapper": {"name": "v", "value": "1"}}
        res = self.run_a(self.design(first=[marker, filt(status_write(6, "{{1.status}}"), self.allow())]))
        self.assertIn("not the first module of a router route", self.row(res, 6).detail)

    def test_the_old_rules_still_hold_without_an_allow_list(self):
        """A dynamic write with a decision row passes, one without it fails. The allow-list is a second way to close it."""
        flow = [trigger(), full_ledger(2), status_write(3, "{{1.status}}")]
        self.assertEqual([f.status for f in self.run_a(flow)], [ab.PASS])
        self.assertEqual([f.status for f in self.run_a([trigger(), status_write(3, "{{1.status}}")])], [ab.FAIL])

    def test_an_allow_list_ref_other_than_the_status_values_expression_is_not_credited(self):
        """The filter tests {{1.other}}, the write maps {{1.status}}."""
        self.not_credited(self.allow(("VIP", "Nurture"), ref="{{1.other}}"))

    def test_a_decision_branch_filter_is_not_an_allow_list(self):
        """Is Disqualified? route filters keep their old meaning."""
        flow = [trigger(), router(2, [filt(full_ledger(3, decision="Disqualified"), eq("{{1.status}}", "Disqualified"))],
                                  [filt(slack(4), eq("{{1.status}}", "Nurture"))], fallback=None)]
        res = ab.check_a(blueprint("S", *flow), schema())
        self.assertNotIn("allow-list", " ".join(f.detail for f in res))

    # --- A-1: a decision router's fallback must leave a trace, whatever else it does ----------------

    def pending_router(self, fallback_flow=None, fallback=2):
        """The live Pending Call shape (router 10): two routes filtered on the lead's Status and no fallback, plus an optional fallback."""
        routes = [[filt(sendmail(11), self.allow(("VIP",), ref="{{3.status}}"))], [filt(sendmail(12), self.allow(("Nurture",), ref="{{3.status}}"))]]
        if fallback_flow is not None:
            routes.append(fallback_flow)
        return router(10, *routes, fallback=fallback if fallback_flow is not None else None)

    def run_router(self, r):
        return ab.check_a(blueprint("S", trigger(), at_search(3, LEAD, fields=("id", "Status")), r, scenario_id="900"), schema(), None, self.DESIGNS)

    def test_a_1_the_live_router_fails_without_a_fallback(self):
        res = self.run_router(self.pending_router())
        self.assertEqual([(f.module_id, f.status) for f in res if f.status != ab.INFO], [(10, ab.FAIL)])

    def test_a_1_a_fallback_that_only_sets_a_variable_still_fails(self):
        setvar = {"id": 99, "module": "util:SetVariable2", "mapper": {"name": "v", "value": "x"}}
        res = self.run_router(self.pending_router([setvar]))
        self.assertEqual(self.row(res, 10).status, ab.FAIL)
        self.assertIn("no unfiltered Shadow Ledger row", self.row(res, 10).detail)
        self.assertIn("sends no unfiltered Slack alert", self.row(res, 10).detail)

    def test_a_1_a_fallback_with_the_trace_closes_the_router(self):
        trace = [error_row(20, decision="{{3.status}}", **{ab.LEAD_LINK_FIELD: ["{{3.id}}"]}), slack_text(21, "Unmatched: lead {{3.id}}, call {{1.call_id}}")]
        res = self.run_router(self.pending_router(trace))
        self.assertEqual(self.row(res, 10).status, ab.PASS, self.row(res, 10).detail)

    def test_a_1_the_trace_must_name_the_decision_value_of_that_router(self):
        trace = [error_row(20, decision="{{1.status}}"), slack_text(21, "x")]   # the request status, not {{3.status}}
        res = self.run_router(self.pending_router(trace))
        self.assertEqual(self.row(res, 10).status, ab.FAIL)

    # --- A-2: the allow-list is credited only for the whole F-31 design -----------------------------

    def test_a_2_values_outside_the_scenarios_allowed_set_get_no_credit(self):
        """A pathway that sends only VIP, Nurture or Call Later must not let Send Contract or Generate Submission through."""
        allow = self.allow(("VIP", "Send Contract", "Generate Submission"))
        res = self.run_a(self.design(allow=allow))
        self.assertEqual(self.row(res, 6).status, ab.FAIL)
        self.assertIn("outside the allowed set", self.row(res, 6).detail)
        self.assertIn("Send Contract", self.row(res, 6).detail)
        self.assertEqual(self.row(self.run_a(self.design(allow=self.allow(("VIP", "nurture")))), 6).status, ab.PASS)   # case does not matter

    def test_a_2_the_scenario_must_be_listed_in_the_input_file(self):
        res = self.run_a(self.design(), designs=ab.StatusDesigns())
        self.assertEqual(self.row(res, 6).status, ab.FAIL)
        self.assertIn("not in audit/status_allow_list.json", self.row(res, 6).detail)

    def test_a_2_a_decision_row_with_the_previous_status_must_sit_before_the_write(self):
        self.assertIn("no Shadow Ledger decision row", self.row(self.run_a(self.design(decision_row=False)), 6).detail)
        for name, row in {
            "no previous Status": self.decision_row(2, **{ab.PAYLOAD_FIELD: "{{1.status}} because {{1.reason}}"}),
            "previous Status of the request": self.decision_row(2, **{ab.PAYLOAD_FIELD: "{{1.status}} because {{1.reason}}, was {{1.Status}}"}),
            "no evidence": self.decision_row(2, **{ab.PAYLOAD_FIELD: "{{1.status}}"}),
            "no call id": self.decision_row(2, **{ab.CALL_ID_FIELD: None}),
            "no lead link": self.decision_row(2, **{ab.LEAD_LINK_FIELD: None}),
            "no decision value": self.decision_row(2, **{ab.PAYLOAD_FIELD: "{{1.reason}} was {{3.Status}}"}),
        }.items():
            res = self.run_a(self.design(row=row))
            self.assertEqual(self.row(res, 6).status, ab.FAIL, name)
            self.assertIn("decision row 2", self.row(res, 6).detail, name)
        late = [filt(status_write(6, "{{1.status}}"), self.allow()), self.decision_row(2)]
        self.assertEqual(self.row(self.run_a(self.design(first=late, decision_row=False)), 6).status, ab.FAIL)   # after the write
        ok = self.run_a(self.design())
        self.assertEqual(self.row(ok, 6).status, ab.PASS)
        self.assertIn("previous Status", self.row(ok, 6).detail)

    def lookup_flow(self, fb_route=None, with_aggregator=True):
        """The no-lead pattern (F-31 item 3) for lookup 3: an aggregator fed by it, then a router with a route for the empty result."""
        agg = {"id": 40, "module": "builtin:BasicAggregator", "parameters": {"feeder": 3}, "mapper": {}}
        empty_route = fb_route if fb_route is not None else [
            filt(error_row(42, **{ab.LEAD_LINK_FIELD: None}), [[{"a": "{{first(map(40.array; \"id\"))}}", "o": "notexist"}]]),
            slack_text(43, "No lead for call {{1.call_id}}")]
        gate = router(41, empty_route, [{"id": 44, "module": "util:SetVariable2", "mapper": {"name": "v", "value": "lead found"}}], fallback=1)
        return ([agg] if with_aggregator else []) + [gate]

    def designs_with_lookup(self):
        return ab.StatusDesigns({"900": {"allowed": list(self.ALLOWED), "no_lead_lookup": 3, "reason": "The Bland pathway sends three values"}})

    def test_a_2_a_length_test_on_the_aggregator_is_not_an_empty_test(self):
        """Measured 2026-10-30: a search that finds nothing can still emit one empty bundle, so the array is never empty."""
        base = self.design()
        flow = self.lookup_flow(fb_route=[filt(error_row(42, **{ab.LEAD_LINK_FIELD: None}),
                                               [[{"a": "{{length(40.array)}}", "b": "0", "o": "number:equal"}]]), slack_text(43, "x")])
        res = ab.check_a(blueprint("S", *base[:2], *flow, *base[2:], scenario_id="900"), schema(), None, self.designs_with_lookup())
        self.assertEqual(self.row(res, 3).status, ab.FAIL)

    def test_a_2_a_phone_with_no_lead_needs_a_ledger_row_and_a_slack_alert(self):
        base = self.design()
        res = ab.check_a(blueprint("S", *base[:2], *self.lookup_flow(), *base[2:], scenario_id="900"), schema(), None, self.designs_with_lookup())
        self.assertEqual(self.row(res, 3).status, ab.PASS, self.row(res, 3).detail)
        for name, flow in {
            "no aggregator": self.lookup_flow(with_aggregator=False),
            "route without the ledger row": self.lookup_flow(fb_route=[filt(slack_text(42, "x"), [[{"a": "{{first(map(40.array; \"id\"))}}", "o": "notexist"}]])]),
            "route without the slack alert": self.lookup_flow(fb_route=[filt(error_row(42, **{ab.LEAD_LINK_FIELD: None}), [[{"a": "{{first(map(40.array; \"id\"))}}", "o": "notexist"}]])]),
            "route that does not test the aggregator": self.lookup_flow(fb_route=[filt(error_row(42, **{ab.LEAD_LINK_FIELD: None}), [[{"a": "{{1.x}}", "b": "0", "o": "number:equal"}]]),
                                                                                  slack_text(43, "x")]),
            "a success row": self.lookup_flow(fb_route=[filt(error_row(42, **{ab.OUTCOME_FIELD: "Success"}), [[{"a": "{{first(map(40.array; \"id\"))}}", "o": "notexist"}]]),
                                                         slack_text(43, "x")]),
        }.items():
            res = ab.check_a(blueprint("S", *base[:2], *flow, *base[2:], scenario_id="900"), schema(), None, self.designs_with_lookup())
            self.assertEqual(self.row(res, 3).status, ab.FAIL, name)
            self.assertIn("leaves no trace", self.row(res, 3).detail, name)
        res = self.run_a(base, designs=self.designs_with_lookup())
        self.assertIn("no aggregator fed by it", self.row(res, 3).detail)

    def test_a_2_the_input_file_validates_its_entries(self):
        def load(entries):
            with tempfile.TemporaryDirectory() as tmp:
                path = os.path.join(tmp, "status_allow_list.json")
                with open(path, "w", encoding="utf-8") as fh:
                    json.dump({"scenarios": entries}, fh)
                return ab.load_status_designs(path, required=True)
        ok = {"scenario_id": "5", "allowed": ["VIP"], "no_lead_lookup": 7, "reason": "The pathway sends three values"}
        self.assertEqual(load([ok]).entries["5"]["allowed"], ["VIP"])
        for bad in ({**ok, "scenario_id": "x"}, {**ok, "allowed": []}, {**ok, "allowed": ["Disqualified"]}, {**ok, "allowed": ["disqualified"]},
                    {**ok, "no_lead_lookup": "7"}, {**ok, "no_lead_lookup": 0}, {**ok, "reason": ""}):
            with self.assertRaises(ab.InputError, msg=bad):
                load([bad])
        with self.assertRaises(ab.InputError):
            load([ok, ok])
        self.assertEqual(ab.load_status_designs(os.path.join(FIX, "none.json")).entries, {})
        with self.assertRaises(ab.InputError):
            ab.load_status_designs(os.path.join(FIX, "none.json"), required=True)

    def test_a_2_the_real_input_names_the_pending_call_scenario(self):
        d = ab.load_status_designs(ab.DEFAULT_STATUS_ALLOW, required=True)
        self.assertEqual(d.entries["3943741"]["allowed"], ["VIP", "Nurture", "Call Later", "Do Not Call"])
        self.assertEqual(d.entries["3943741"]["no_lead_lookup"], 7)

    # --- A-3: a sibling route that always matches means the fallback never runs --------------------

    def test_a_3_an_unfiltered_sibling_route_means_the_fallback_never_runs(self):
        write = filt(status_write(6, "{{1.status}}"), self.allow())
        always = {"id": 40, "module": "util:SetVariable2", "mapper": {"name": "v", "value": "1"}}
        flow = [trigger(), at_search(3, LEAD, fields=("id", "Status")), self.decision_row(2),
                router(5, [write], [always], [self.fallback_row(20), slack_text(21, "x")], fallback=2)]
        res = self.run_a(flow)
        for mid in (5, 6):
            self.assertEqual(self.row(res, mid).status, ab.FAIL, mid)
            self.assertIn("route 1 has no filter", self.row(res, mid).detail)

    def test_a_3_a_sibling_whose_filter_does_not_test_the_decision_value_fails(self):
        write = filt(status_write(6, "{{1.status}}"), self.allow())
        other = filt({"id": 40, "module": "util:SetVariable2", "mapper": {"name": "v", "value": "1"}}, eq("{{1.region}}", "CA"))
        flow = [trigger(), at_search(3, LEAD, fields=("id", "Status")), self.decision_row(2),
                router(5, [write], [other], [self.fallback_row(20), slack_text(21, "x")], fallback=2)]
        res = self.run_a(flow)
        self.assertEqual(self.row(res, 5).status, ab.FAIL)
        self.assertIn("does not test the decision value", self.row(res, 5).detail)

    # --- A-4: the trace cannot be faked ---------------------------------------------------------------

    def test_a_4_literal_ids_do_not_count_as_the_lead_link_and_the_call_id(self):
        for name, over in {"literal call id": {ab.CALL_ID_FIELD: "n/a"}, "literal lead link": {ab.LEAD_LINK_FIELD: "none"},
                           "call id of a module that is not Bland": {ab.CALL_ID_FIELD: "{{3.id}}"},
                           "lead link of a module that is not Airtable": {ab.LEAD_LINK_FIELD: ["{{5.id}}"]},
                           "call id inside text": {ab.CALL_ID_FIELD: "call {{1.call_id}}"},
                           "call id through a function": {ab.CALL_ID_FIELD: "{{trim(1.call_id)}}"},
                           "lead link of a module that is absent": {ab.LEAD_LINK_FIELD: ["{{99.id}}"]}}.items():
            res = self.run_a(self.design(fallback_flow=[self.fallback_row(20, **over), slack_text(21, "x")]))
            self.assertEqual(self.row(res, 6).status, ab.FAIL, name)
        bland = {"id": 8, "module": "bland:getCallDetails", "mapper": {}}
        ok = self.design(fallback_flow=[self.fallback_row(20, **{ab.CALL_ID_FIELD: "{{8.call_id}}"}), slack_text(21, "x")])
        res = self.run_a(ok[:1] + [bland] + ok[1:])
        self.assertEqual(self.row(res, 6).status, ab.PASS)

    def test_a_4_a_trace_module_that_can_never_run_does_not_count(self):
        never = eq("{{1.status}}", "zzz")
        for name, fb in {
            "slack with a filter": [self.fallback_row(20), filt(slack_text(21, "x"), never)],
            "ledger row with a filter": [filt(self.fallback_row(20), never), slack_text(21, "x")],
            "a filtered module ahead of both": [filt({"id": 22, "module": "util:SetVariable2", "mapper": {"name": "v", "value": "1"}}, never),
                                                 self.fallback_row(20), slack_text(21, "x")],
        }.items():
            res = self.run_a(self.design(fallback_flow=fb))
            self.assertEqual(self.row(res, 6).status, ab.FAIL, name)

    # --- A-5: Status writes through an alias ---------------------------------------------------------

    @staticmethod
    def api_call(mid, body, url="/v0/appX/" + LEAD, method="PATCH", module="airtable:makeApiCall"):
        return {"id": mid, "module": module, "mapper": {"url": url, "method": method, "body": body}}

    def run_alias(self, m, links=None):
        return ab.check_a(blueprint("S", trigger(), m), schema(), links, self.DESIGNS)

    def test_a_5_an_airtable_api_call_that_patches_the_status_is_a_status_write(self):
        res = self.run_alias(self.api_call(6, json.dumps({"fields": {"Status": "{{1.status}}"}})))
        self.assertEqual([(f.module_id, f.status) for f in res if f.status != ab.INFO], [(6, ab.FAIL)])
        self.assertIn("can set Disqualified", res[0].detail)
        res = self.run_alias(self.api_call(6, json.dumps({"fields": {"Status": "Disqualified"}})))
        self.assertEqual(res[0].status, ab.FAIL)
        res = self.run_alias(self.api_call(6, json.dumps({"fields": {"Status": "Nurture"}})))
        self.assertEqual([f for f in res if f.status != ab.INFO], [])
        res = self.run_alias(self.api_call(6, '{"fields": {"fldFrKT1VdHwzYwrG": "{{1.status}}"}}'))
        self.assertEqual(res[0].status, ab.FAIL)

    def test_a_5_the_http_module_counts_when_it_calls_the_airtable_api(self):
        url = "https://api.airtable.com/v0/appX/" + LEAD + "/{{1.lead_id}}"
        res = self.run_alias(self.api_call(6, json.dumps({"fields": {"Status": "{{1.status}}"}}), url=url, module="http:ActionSendData"))
        self.assertEqual(res[0].status, ab.FAIL)
        get = self.api_call(6, "", url=url, module="http:ActionSendData", method="get")
        self.assertEqual(self.run_alias(get), [])
        other_host = self.api_call(6, json.dumps({"fields": {"Status": "Disqualified"}}), url="https://example.com/x/" + LEAD, module="http:ActionSendData")
        self.assertEqual(self.run_alias(other_host), [])

    def test_a_5_a_table_named_by_its_name_is_resolved_through_the_airtable_map(self):
        by_name = {"id": 6, "module": "airtable:ActionUpdateRecords",
                   "mapper": {"table": "Applicants", "id": "{{1.lead_id}}", "record": {"Status": "{{1.status}}"}}}
        self.assertEqual([f for f in self.run_alias(by_name) if f.status != ab.INFO], [])   # without the map the name means nothing
        res = self.run_alias(by_name, link_map())
        self.assertEqual([(f.module_id, f.status) for f in res if f.status != ab.INFO], [(6, ab.FAIL)])
        res = self.run_alias(self.api_call(6, json.dumps({"fields": {"Status": "{{1.status}}"}}), url="/v0/appX/Applicants"), link_map())
        self.assertEqual(res[0].status, ab.FAIL)

    def test_a_5_a_target_that_cannot_be_decided_is_a_review(self):
        res = self.run_alias(self.api_call(6, "{{1.body}}", url="/v0/appX/" + LEAD))
        self.assertEqual([(f.module_id, f.status) for f in res if f.status != ab.INFO], [(6, ab.REVIEW)])
        res = self.run_alias(self.api_call(6, json.dumps({"fields": {"Status": "x"}}), url="/v0/appX/{{1.table}}"))
        self.assertEqual([(f.module_id, f.status) for f in res if f.status != ab.INFO], [(6, ab.REVIEW)])
        res = self.run_alias(self.api_call(6, json.dumps({"fields": {"Name": "x"}}), url="/v0/appX/tblOTHER000000000"))
        self.assertEqual(res, [])

    def test_a_5_the_push_helper_lists_every_module_that_may_write_the_status(self):
        bp = {"flow": [trigger(), status_write(2, "VIP"), self.api_call(3, json.dumps({"fields": {"Status": "x"}})),
                       self.api_call(4, "{{1.body}}"), at_update(5, LEAD, "{{1.id}}", {"Other": "x"}), slack_text(6, "x")]}
        self.assertEqual(ab.status_write_module_ids(bp), {2, 3, 4})
        self.assertEqual(ab.status_write_module_ids({"flow": []}), set())


class FilterEvalTests(unittest.TestCase):
    def test_operators(self):
        m = filt({}, eq("{{1.status}}", "disqualified", "text:equal:ci"))
        self.assertTrue(ab.eval_filter(m, "{{1.status}}"))
        self.assertFalse(ab.eval_filter(filt({}, eq("{{1.status}}", "disqualified", "text:equal")), "{{1.status}}"))
        self.assertFalse(ab.eval_filter(filt({}, eq("{{1.status}}", "VIP", "text:equal:ci")), "{{1.status}}"))
        self.assertTrue(ab.eval_filter(filt({}, eq("{{1.status}}", "VIP", "text:notequal")), "{{1.status}}"))
        self.assertTrue(ab.eval_filter(filt({}, eq("{{1.status}}", "Disq", "text:startwith")), "{{1.status}}"))
        self.assertIsNone(ab.eval_filter(filt({}, eq("{{1.other}}", "VIP")), "{{1.status}}"))
        self.assertTrue(ab.eval_filter({}, "{{1.status}}"))

    def test_or_of_and_groups(self):
        conds = [[{"a": "{{1.status}}", "b": "VIP", "o": "text:equal"}],
                 [{"a": "{{1.status}}", "b": "Disqualified", "o": "text:equal"}]]
        self.assertTrue(ab.eval_filter(filt({}, conds), "{{1.status}}"))
        conds = [[{"a": "{{1.status}}", "b": "Disqualified", "o": "text:equal"},
                  {"a": "{{1.status}}", "b": "VIP", "o": "text:equal"}]]
        self.assertFalse(ab.eval_filter(filt({}, conds), "{{1.status}}"))

    def test_whitespace_in_mapping_is_normalised(self):
        self.assertTrue(ab.eval_filter(filt({}, eq("{{ 1.status }}", "Disqualified")), "{{1.status}}"))


# ---------------------------------------------------------------------------
# Check B
# ---------------------------------------------------------------------------


class CheckBTests(unittest.TestCase):
    def ext(self, mid=2):
        return {"id": mid, "module": "openai-gpt-3:CreateCompletion"}

    def test_missing_handler_fails(self):
        res = ab.check_b(blueprint("S", trigger(), self.ext()))
        self.assertEqual([(f.status, f.module_id) for f in res], [(ab.FAIL, 2)])
        self.assertIn("Missing error handler", res[0].detail)

    def test_slack_and_break_only_is_partial(self):
        m = with_handler(self.ext(), slack(10), directive(11, "Break"))
        res = ab.check_b(blueprint("S", trigger(), m))
        self.assertEqual(res[0].status, ab.FAIL)
        self.assertIn("Shadow Ledger write", res[0].detail)
        self.assertIn("Directive Break", res[0].detail)

    def test_no_directive_is_partial(self):
        m = with_handler(self.ext(), ledger(10), slack(11))
        res = ab.check_b(blueprint("S", trigger(), m))
        self.assertEqual(res[0].status, ab.FAIL)
        self.assertIn("directive", res[0].detail)
        self.assertIn("Directive none", res[0].detail)

    def test_two_directives_is_partial(self):
        m = with_handler(self.ext(), router(10, [ledger(11), directive(12, "Resume")], [slack(13), directive(14, "Break")]))
        res = ab.check_b(blueprint("S", trigger(), m))
        self.assertEqual(res[0].status, ab.FAIL)
        self.assertIn("exactly one directive (found 2)", res[0].detail)
        self.assertIn("Resume, Break", res[0].detail)

    def test_complete_handler_is_review_with_directive(self):
        for kind in ("Break", "Resume", "Ignore"):
            m = with_handler(self.ext(), ledger(10), slack(11), directive(12, kind))
            res = ab.check_b(blueprint("S", trigger(), m))
            self.assertEqual(res[0].status, ab.REVIEW)
            self.assertIn("directive " + kind, res[0].detail)

    def test_nested_router_in_error_route_is_complete(self):
        handler = router(10, [ledger(11)], [slack(12), directive(13, "Break")])
        res = ab.check_b(blueprint("S", trigger(), with_handler(self.ext(), handler)))
        self.assertEqual([f.status for f in res], [ab.REVIEW])

    def test_deeply_nested_router_in_error_route(self):
        inner = router(20, [ledger(21)], [slack(22)])
        handler = router(10, [inner], [directive(13, "Ignore")])
        res = ab.check_b(blueprint("S", trigger(), with_handler(self.ext(), handler)))
        self.assertEqual(res[0].status, ab.REVIEW)

    def test_directive_on_handler_modules_own_error_route_does_not_count(self):
        handler_slack = with_handler(slack(10), directive(11, "Break"))
        m = with_handler(self.ext(), ledger(12), handler_slack)
        res = ab.check_b(blueprint("S", trigger(), m))
        self.assertEqual(res[0].status, ab.FAIL)
        self.assertIn("Directive none", res[0].detail)

    def test_trigger_internal_and_error_route_modules_are_skipped(self):
        flow = [
            {"id": 1, "module": "airtable:TriggerWatchRecords"},
            {"id": 2, "module": "util:FunctionSleep"},
            {"id": 3, "module": "json:ParseJSON"},
            with_handler(self.ext(4), ledger(10), slack(11), directive(12)),
        ]
        res = ab.check_b(blueprint("S", *flow))
        self.assertEqual([f.module_id for f in res], [4])

    def test_modules_inside_routes_are_checked(self):
        r = router(3, [self.ext(4)], [with_handler(self.ext(5), ledger(10), slack(11), directive(12))])
        res = ab.check_b(blueprint("S", trigger(), r))
        self.assertEqual(sorted((f.module_id, f.status) for f in res), [(4, ab.FAIL), (5, ab.REVIEW)])

    def test_ledger_write_needs_only_slack_and_directive(self):
        m = with_handler(ledger(2), slack(10), directive(11, "Resume"))
        res = ab.check_b(blueprint("S", trigger(), m))
        self.assertEqual(res[0].status, ab.REVIEW)
        self.assertIn("Ledger-write module", res[0].detail)

    def test_ledger_write_without_slack_still_fails(self):
        m = with_handler(ledger(2), directive(11, "Resume"))
        res = ab.check_b(blueprint("S", trigger(), m))
        self.assertEqual(res[0].status, ab.FAIL)
        self.assertIn("Slack message", res[0].detail)
        self.assertNotIn("Shadow Ledger write,", res[0].detail)

    def test_non_ledger_module_still_needs_ledger_in_handler(self):
        m = with_handler(self.ext(), slack(10), directive(11, "Resume"))
        res = ab.check_b(blueprint("S", trigger(), m))
        self.assertEqual(res[0].status, ab.FAIL)
        self.assertIn("Shadow Ledger write", res[0].detail)


class ScopeTests(unittest.TestCase):
    def test_out_of_scope_scenario_is_skipped(self):
        labels = ab.Labels(confirmed=True, scenarios={"900099": {
            "name": "Old Thing", "expected_label": None, "out_of_scope": True, "note": "disabled"}})
        b = blueprint("Old Thing", trigger(), {"id": 2, "module": "openai-gpt-3:CreateCompletion"}, scenario_id="900099")
        res = ab.audit([b], labels, schema(), by_id=True)
        # Check L judges the whole pull (the Logger is not deployed in this fixture), so it is left out here.
        rows = [f for f in res.findings if f.check != "L"]
        self.assertEqual([(f.check, f.status) for f in rows], [("M", ab.INFO)])
        self.assertIn("out of scope", rows[0].detail)


# ---------------------------------------------------------------------------
# Check C
# ---------------------------------------------------------------------------


class CheckCTests(unittest.TestCase):
    def setUp(self):
        self.ok = ab.load_labels(LABELS_OK)
        self.draft = ab.load_labels(LABELS_DRAFT)
        self.bps = {b.name: b for b in ab.load_dir(BP_DIR)}

    def test_may_2026_batch_outband_caller_must_fail(self):
        res = ab.check_c(self.bps["Batch Outbound Caller"], self.ok, schema(), by_id=False)
        fails = by_status(res, ab.FAIL)
        self.assertEqual(sorted(f.module_id for f in fails), [3, 20])
        self.assertTrue(all('"Batch Outband Caller"' in f.detail for f in fails))
        self.assertTrue(all("not a Single Select option" in f.detail for f in fails))
        self.assertEqual([f.module_id for f in by_status(res, ab.PASS)], [31])

    def test_may_2026_application_approved_label_must_fail(self):
        res = ab.check_c(self.bps["Application Approved - Auto-Celebrate"], self.ok, schema(), by_id=False)
        fails = by_status(res, ab.FAIL)
        self.assertEqual([f.module_id for f in fails], [2])
        self.assertIn('"Customer Support Bot for existing"', fails[0].detail)
        self.assertIn('expected "Application Approved - Auto-Celebrate"', fails[0].detail)

    def test_must_fail_bugs_exit_nonzero_end_to_end(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name in ("batch_outbound_caller.json", "application_approved.json"):
                d = os.path.join(tmp, name.split(".")[0])
                os.makedirs(d)
                with open(os.path.join(BP_DIR, name), encoding="utf-8") as src, open(os.path.join(d, name), "w", encoding="utf-8") as dst:
                    dst.write(src.read())
                code, out, _ = run_main("--dir", d, "--labels", LABELS_OK, "--schema", SCHEMA, "--no-report")
                self.assertEqual(code, 1, name)
                self.assertIn("Result: FAIL", out)

    def test_unconfirmed_labels_report_but_do_not_fail(self):
        res = ab.check_c(self.bps["Batch Outbound Caller"], self.draft, schema(), by_id=False)
        self.assertEqual(by_status(res, ab.FAIL), [])
        self.assertEqual(len(by_status(res, ab.UNCONFIRMED)), 2)
        # Only a C finding: the ledger write has a complete handler, so B is REVIEW.
        bp = {"name": "Batch Outbound Caller", "metadata": {}, "flow": [
            trigger(),
            with_handler(ledger(2, "Batch Outband Caller"), ledger(10, "Batch Outbound Caller"), slack(11), directive(12, "Resume")),
        ]}
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "b.json"), "w", encoding="utf-8") as dst:
                json.dump(bp, dst)
            code, out, _ = run_main("--dir", tmp, "--labels", LABELS_DRAFT, "--schema", SCHEMA, "--no-report")
            assert_only_logger_fails(self, code, out)
            self.assertIn("UNCONFIRMED 1", out)
            code, out, _ = run_main("--dir", tmp, "--labels", LABELS_OK, "--schema", SCHEMA, "--no-report")
            self.assertEqual(code, 1)

    def test_correct_labels_pass(self):
        res = ab.check_c(self.bps["Lead Qualifier"], self.ok, schema(), by_id=False)
        self.assertEqual({f.status for f in res}, {ab.PASS})
        # Ledger writes inside the nested router of an error route are found too.
        self.assertIn(41, [f.module_id for f in res])

    def test_ledger_writing_scenario_without_entry_fails(self):
        b = blueprint("Unknown Scenario", trigger(), ledger(2, "Lead Qualifier"))
        res = ab.check_c(b, self.ok, schema(), by_id=False)
        self.assertIn("no entry", by_status(res, ab.FAIL)[0].detail)

    def test_entry_without_expected_label_fails_and_lists_observed(self):
        labels = ab.Labels(confirmed=True, scenarios={"1": {"name": "Recon", "expected_label": None}})
        b = blueprint("Recon", trigger(), {"id": 2, "module": "airtable:ActionUpdateRecords",
                                           "mapper": {"table": LEDGER, "record": {ab.LABEL_FIELD: "Lead Qualifier"}}})
        res = ab.check_c(b, labels, schema(), by_id=False)
        self.assertEqual(len(by_status(res, ab.FAIL)), 1)
        self.assertIn('Observed "Lead Qualifier"', res[0].detail)

    def test_ledger_update_only_scenario_still_needs_an_entry(self):
        # Review finding audit-semantics-F6: "every scenario that writes to
        # the ledger has an entry" covers update-only scenarios too.
        upd = {"id": 2, "module": "airtable:ActionUpdateRecords",
               "mapper": {"table": LEDGER, "record": {"fldCostOnly0000001": "{{1.cost}}"}}}
        res = ab.check_c(blueprint("Not Listed", trigger(), upd), self.ok, schema(), by_id=False)
        self.assertEqual(len(by_status(res, ab.FAIL)), 1)
        self.assertIn("no entry", res[0].detail)
        res = ab.check_c(blueprint("Unknown", trigger(), upd, scenario_id="777777"), self.ok, schema(), by_id=True)
        self.assertIn("no entry", by_status(res, ab.FAIL)[0].detail)

    def test_ledger_update_without_label_needs_no_expected_label(self):
        labels = ab.Labels(confirmed=True, scenarios={"1": {"name": "Recon", "expected_label": None}})
        upd = {"id": 2, "module": "airtable:ActionUpdateRecords",
               "mapper": {"table": LEDGER, "record": {"fldCostOnly0000001": "{{1.cost}}"}}}
        self.assertEqual(ab.check_c(blueprint("Recon", trigger(), upd), labels, schema(), by_id=False), [])

    def test_expected_label_not_in_schema_fails(self):
        labels = ab.Labels(confirmed=True, scenarios={"1": {"name": "S", "expected_label": "Not An Option"}})
        res = ab.check_c(blueprint("S", trigger(), ledger(2, "Not An Option")), labels, schema(), by_id=False)
        details = " ".join(f.detail for f in by_status(res, ab.FAIL))
        self.assertIn("is not a Single Select option", details)

    def test_dynamic_or_missing_label_fails(self):
        no_label = {"id": 3, "module": "airtable:ActionCreateRecord", "mapper": {"table": LEDGER, "record": {}}}
        b = blueprint("Lead Qualifier", trigger(), ledger(2, "{{1.label}}"), no_label)
        res = by_status(ab.check_c(b, self.ok, schema(), by_id=False), ab.FAIL)
        self.assertEqual(sorted(f.module_id for f in res), [2, 3])

    def test_manifest_mode_matches_by_scenario_id(self):
        b = blueprint("Renamed In Make", trigger(), ledger(2, "Lead Qualifier"), scenario_id="900003")
        res = ab.check_c(b, self.ok, schema(), by_id=True)
        self.assertEqual({f.status for f in res}, {ab.PASS})
        b2 = blueprint("Lead Qualifier", trigger(), ledger(2, "Lead Qualifier"), scenario_id="123")
        res2 = ab.check_c(b2, self.ok, schema(), by_id=True)
        self.assertIn("no entry", res2[0].detail)


# ---------------------------------------------------------------------------
# Check D
# ---------------------------------------------------------------------------


class CheckDTests(unittest.TestCase):
    def test_secret_reports_module_and_type_only(self):
        secret = fake_secret()
        http = {"id": 7, "module": "http:ActionSendData",
                "mapper": {"headers": [{"name": "Authorization", "value": "Bearer " + secret}]}}
        r = router(3, [with_handler(http, ledger(10), slack(11), directive(12))])
        b = blueprint("S", trigger(), r)
        res = ab.check_d(b)
        self.assertTrue(res)
        self.assertTrue(all(f.module_id == 7 and f.module_type == "http:ActionSendData" for f in res))
        types = {f.detail for f in res}
        self.assertIn("Credential literal: stripe_secret_key", types)
        self.assertIn("Credential literal: authorization_header_literal", types)
        for f in res:
            self.assertNotIn(secret, f.detail)
            self.assertNotIn(secret[:10], f.detail)

    def test_secret_in_report_and_stdout_never_shows_value(self):
        secret = fake_secret()
        bp = {"name": "Leaky", "flow": [trigger(), {"id": 2, "module": "http:ActionSendData", "mapper": {"body": secret}}], "metadata": {}}
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "in")
            os.makedirs(src)
            with open(os.path.join(src, "leaky.json"), "w", encoding="utf-8") as fh:
                json.dump(bp, fh)
            reports = os.path.join(tmp, "reports")
            code, out, err = run_main("--dir", src, "--labels", LABELS_OK, "--schema", SCHEMA,
                                      "--reports-dir", reports, "--report-date", "2026-01-02")
            self.assertEqual(code, 1)
            with open(os.path.join(reports, "2026-01-02.md"), encoding="utf-8") as fh:
                report = fh.read()
            for text in (out, err, report):
                self.assertNotIn(secret, text)
                self.assertNotIn(secret[8:20], text)
            self.assertIn("stripe_secret_key", report)

    def test_logger_hook_url_is_info_in_a_full_run(self):
        """F-E5.3 regression: a Logger call holding the pinned Logger hook URL is INFO in a full run too. check_d used to
        judge it as a Bland fetch-back pin with no target scenario and FAIL it (97 rows on the first converted pull)."""
        import secret_scan
        token = "Lg" + "q7Rz0vN3kT8wX2bY5cJ9mH4dF6s"
        url = "https://hook.us2.make.com/" + token
        logger = secret_scan.LoggerAllowance("6832527", 3000983, secret_scan.token_digest(token), "The Logger hook.", True)
        call = {"id": 9, "module": "http:MakeRequest", "version": 4, "parameters": {"authenticationType": "apiKeyConnection"},
                "mapper": {"url": url, "method": "post"}}
        b = blueprint("S", trigger(), with_handler({"id": 5, "module": "slack:CreateMessage", "mapper": {"text": "x"}},
                                                   call, directive(10)))
        allow = secret_scan.SecretAllowlist([], logger)
        for f2_state in (None, {}):
            res = ab.check_d(b, allow, f2_state, set())
            self.assertEqual([(f.status, f.module_id) for f in res], [(ab.INFO, 9)], res)
            self.assertNotIn(token, res[0].detail)
        self.assertEqual([f.status for f in ab.check_d(b, secret_scan.SecretAllowlist([], None), {}, set())], [ab.FAIL])

    def test_clean_blueprint_has_no_d_findings(self):
        for b in ab.load_dir(BP_DIR):
            self.assertEqual(ab.check_d(b), [], b.name)

    def test_module_at_resolves_nested_paths(self):
        bp = {"flow": [trigger(), router(3, [slack(4)], [with_handler({"id": 5, "module": "x:y"}, router(10, [slack(11)]))])]}
        self.assertEqual(ab.module_at(bp, "$.flow[1].routes[1].flow[0].onerror[0].routes[0].flow[0].mapper.text")["id"], 11)
        self.assertEqual(ab.module_at(bp, "$.flow[1].routes[0].flow[0].mapper")["id"], 4)
        self.assertIsNone(ab.module_at(bp, "$.metadata.x"))
        self.assertEqual(ab.module_at(bp, '$.flow[0]["<redacted>"]')["id"], 1)


# ---------------------------------------------------------------------------
# Loading, report and CLI
# ---------------------------------------------------------------------------


class LoadingAndCliTests(unittest.TestCase):
    def test_api_wrapper_format_is_unwrapped(self):
        bps = ab.load_dir(os.path.join(FIX, "wrapped"))
        self.assertEqual(len(bps), 1)
        self.assertEqual(bps[0].name, "Lead Qualifier")
        self.assertEqual(bps[0].scenario_id, "900003")

    def test_manifest_mode_maps_files_to_ids_and_reports_withheld(self):
        d = os.path.join(FIX, "manifest")
        bps, coverage = ab.load_manifest_mode(d, os.path.join(d, "manifest.json"))
        self.assertEqual(sorted(b.scenario_id for b in bps), ["900001", "900003"])
        self.assertEqual([(f.check, f.status) for f in coverage], [("D", ab.FAIL)])
        self.assertIn("900009", coverage[0].detail)
        self.assertIn("authorization_header_literal", coverage[0].detail)
        self.assertIn("$.flow[1]", coverage[0].detail)

    def test_manifest_mode_cli_counts_label_bug(self):
        d = os.path.join(FIX, "manifest")
        code, out, _ = run_main("--blueprints", d, "--labels", LABELS_OK, "--schema", SCHEMA, "--no-report")
        self.assertEqual(code, 1)
        self.assertIn("Audited 2 blueprints", out)

    def test_clean_fixture_fails_only_on_the_undeployed_monitor(self):
        with tempfile.TemporaryDirectory() as tmp:
            reports = os.path.join(tmp, "reports")
            registry_path = os.path.join(tmp, "webhooks.json")
            with open(registry_path, "w", encoding="utf-8") as fh:
                json.dump({"scenarios": [{"scenario_id": "900003", "hook_id": 1, "caller": "bland_pathway_node",
                                          "protection": "api_key", "reason": "Pathway node sends the key"}]}, fh)
            manifest_path = os.path.join(tmp, "manifest.json")
            with open(manifest_path, "w", encoding="utf-8") as fh:
                json.dump({"hooks": [{"id": 1, "apikey_count": 1, "scenario_ids": [900003]}]}, fh)
            code, out, _ = run_main("--dir", os.path.join(FIX, "wrapped"), "--labels", LABELS_OK, "--schema", SCHEMA,
                                    "--webhooks", registry_path, "--manifest", manifest_path,
                                    "--reports-dir", reports, "--report-date", "2026-03-04")
            # The shared Logger is not deployed in this fixture (check L), and the fixture predates the F3 duplicate
            # gate (X-43), so its api_key webhook FAILs F3 on the trigger (Sequential off) and on the first ungated
            # write. Its two ledger rows map Applicant Link as ["{{1.lead_id}}"], a webhook field that can be absent, so
            # E11 (a) FAILs both (bug sweep L2). Nothing else fails (the deployed Logger case exits 0, see
            # test_logger_audit.AuditTests).
            self.assertEqual(code, 1, out)
            self.assertRegex(out, r"L  Logger\s+FAIL 1 ")
            self.assertRegex(out, r"F  Webhook authentication\s+FAIL 2 ")
            self.assertRegex(out, r"E  Mapping integrity\s+FAIL 2 ")
            fails = [line for line in out.splitlines() if re.match(r"^[A-DM]  ", line) and not re.search(r"FAIL 0 ", line)]
            self.assertEqual(fails, [], out)
            self.assertIn("Result: FAIL", out)
            path = os.path.join(reports, "2026-03-04.md")
            self.assertTrue(os.path.exists(path))
            with open(path, encoding="utf-8") as fh:
                report = fh.read()
            f_rows = [line for line in report.splitlines() if line.startswith("| FAIL") and "| L0 " not in line and " L0 " not in line]
            self.assertEqual(len(f_rows), 4, f_rows)
            self.assertEqual(sum("F3 " in line for line in f_rows), 2, f_rows)
            self.assertEqual(sum("E11 (a) " in line for line in f_rows), 2, f_rows)
            self.assertIn("# Blueprint audit 2026-03-04", report)
            self.assertIn("| A. X-31 disqualification trail |", report)

    def test_a_fresh_pull_cannot_pass_while_the_api_key_is_unconfirmed(self):
        """R6: with no hook data (the read token lacks Webhooks: View) the F1 row is a FAIL, so the audit exits 1."""
        with tempfile.TemporaryDirectory() as tmp:
            registry_path = os.path.join(tmp, "webhooks.json")
            with open(registry_path, "w", encoding="utf-8") as fh:
                json.dump({"scenarios": [{"scenario_id": "900003", "hook_id": 1, "caller": "bland_pathway_node",
                                          "protection": "api_key", "reason": "Pathway node sends the key"}]}, fh)
            code, out, _ = run_main("--dir", os.path.join(FIX, "wrapped"), "--labels", LABELS_OK, "--schema", SCHEMA,
                                    "--webhooks", registry_path, "--no-report")
            self.assertEqual(code, 1, out)
            self.assertIn("Result: FAIL", out)

    def test_no_report_writes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            reports = os.path.join(tmp, "reports")
            run_main("--dir", BP_DIR, "--labels", LABELS_OK, "--schema", SCHEMA, "--reports-dir", reports, "--no-report")
            self.assertFalse(os.path.exists(reports))

    def test_report_lists_scenario_module_and_detail_with_clean_prose(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, out, _ = run_main("--dir", BP_DIR, "--labels", LABELS_OK, "--schema", SCHEMA,
                                    "--reports-dir", tmp, "--report-date", "2026-05-17")
            self.assertEqual(code, 1)
            with open(os.path.join(tmp, "2026-05-17.md"), encoding="utf-8") as fh:
                report = fh.read()
            self.assertIn("| FAIL | Pending Call Demo | 3 | `builtin:BasicRouter` |", report)
            self.assertIn("Batch Outband Caller", report)
            self.assertNotIn("—", report)
            self.assertNotIn(";", report)

    def test_today_is_injectable(self):
        import datetime
        with tempfile.TemporaryDirectory() as tmp:
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                ab.main(["--dir", BP_DIR, "--labels", LABELS_OK, "--schema", SCHEMA, "--reports-dir", tmp],
                        today=datetime.date(2030, 1, 2))
            self.assertTrue(os.path.exists(os.path.join(tmp, "2030-01-02.md")))

    def test_bad_input_exits_2(self):
        code, _, err = run_main("--dir", os.path.join(FIX, "does-not-exist"), "--labels", LABELS_OK, "--schema", SCHEMA, "--no-report")
        self.assertEqual(code, 2)
        self.assertIn("not a folder", err)
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "x.json"), "w", encoding="utf-8") as fh:
                json.dump({"not": "a blueprint"}, fh)
            code, _, err = run_main("--dir", tmp, "--labels", LABELS_OK, "--schema", SCHEMA, "--no-report")
            self.assertEqual(code, 2)
            code, _, _ = run_main("--blueprints", tmp, "--labels", LABELS_OK, "--schema", SCHEMA, "--no-report")
            self.assertEqual(code, 2)

    def test_fixtures_do_not_mutate_between_runs(self):
        before = copy.deepcopy([b.bp for b in ab.load_dir(BP_DIR)])
        ab.audit(ab.load_dir(BP_DIR), ab.load_labels(LABELS_OK), schema(), by_id=False)
        self.assertEqual(before, [b.bp for b in ab.load_dir(BP_DIR)])


class ReviewRegressionTests(unittest.TestCase):
    """Must-fail shapes from the 2026-10-28 adversarial review."""

    def lead_row(self, mid, **fields):
        base = {ab.LEAD_LINK_FIELD: ["{{1.lead_id}}"], ab.CALL_ID_FIELD: "{{1.call_id}}"}
        base.update(fields)
        return ledger(mid, **base)

    def a(self, *flow):
        return ab.check_a(blueprint("S", trigger(), *flow), schema())

    # audit-semantics-F2: decision match is a whole token in a decision field.
    def test_p1_other_module_status_does_not_count(self):
        res = self.a(status_write(2, "{{1.status}}"),
                     self.lead_row(3, **{ab.AI_RESPONSE_FIELD: "{{11.status}}", ab.PAYLOAD_FIELD: "{{1.transcript}}"}))
        self.assertEqual(res[0].status, ab.FAIL)
        self.assertIn("decision value", res[0].detail)

    def test_p17_prefix_field_does_not_count(self):
        res = self.a(status_write(2, "{{1.status}}"),
                     self.lead_row(3, **{ab.AI_RESPONSE_FIELD: "{{1.status_reason}}"}))
        self.assertIn("decision value", res[0].detail)

    def test_p2_prompt_mentioning_disqualified_does_not_count(self):
        prompt = "Classify the lead as VIP, Nurture or Disqualified. Transcript: {{1.transcript}}"
        res = self.a(status_write(2, "{{1.status}}"), self.lead_row(3, **{ab.PAYLOAD_FIELD: prompt}))
        self.assertEqual(res[0].status, ab.FAIL)
        self.assertIn("decision value", res[0].detail)

    def test_p5_label_text_does_not_count(self):
        row = ledger(3, "Disqualified - Polite Rejection", **{
            ab.LEAD_LINK_FIELD: ["{{1.lead_id}}"], ab.AI_RESPONSE_FIELD: "{{1.transcript}}", ab.CALL_ID_FIELD: "{{1.call_id}}"})
        res = self.a(status_write(2, "Disqualified"), row)
        self.assertEqual(res[0].status, ab.FAIL)
        self.assertIn("decision value", res[0].detail)

    def test_whole_literal_and_labelled_literal_count(self):
        for value in ("Disqualified", "Disqualified: {{1.reason}}", ["Disqualified"]):
            with self.subTest(value=value):
                res = self.a(status_write(2, "Disqualified"),
                             self.lead_row(3, **{"fldDecision0000001": value, ab.PAYLOAD_FIELD: "{{1.reason}}"}))
                self.assertEqual(res[0].status, ab.PASS, res[0].detail)

    # audit-semantics-F3: the decision mapping alone is not evidence.
    def test_p13_decision_is_not_its_own_evidence(self):
        res = self.a(status_write(2, "{{1.status}}"), self.lead_row(3, **{ab.AI_RESPONSE_FIELD: "{{1.status}}"}))
        self.assertEqual(res[0].status, ab.FAIL)
        self.assertIn("evidence", res[0].detail)
        self.assertNotIn("decision value", res[0].detail)

    def test_ids_and_error_refs_are_not_evidence(self):
        res = self.a(status_write(2, "{{1.status}}"),
                     self.lead_row(3, **{ab.AI_RESPONSE_FIELD: "{{1.status}} {{1.lead_id}} {{error.message}}"}))
        self.assertIn("evidence", res[0].detail)

    # audit-semantics-F4: a row written after the rejection email is late,
    # even when it sits before the Status write.
    def test_p14_ledger_after_email_before_status_write_fails(self):
        email = {"id": 4, "module": "google-email:sendAnEmail", "mapper": {"to": "{{1.email}}"}}
        res = self.a(email, full_ledger(5, decision="Disqualified"), status_write(6, "Disqualified"))
        self.assertEqual(res[0].status, ab.FAIL)
        self.assertIn("after the rejection email", res[0].detail)

    def test_ledger_before_email_still_passes(self):
        email = {"id": 4, "module": "google-email:sendAnEmail", "mapper": {"to": "{{1.email}}"}}
        res = self.a(full_ledger(5, decision="Disqualified"), email, status_write(6, "Disqualified"))
        self.assertEqual(res[0].status, ab.PASS, res[0].detail)

    # audit-semantics-F5: earlier routes run first, one finding per module.
    def test_p4_ledger_in_earlier_route_counts_once(self):
        r = router(10, [full_ledger(11)], [filt(status_write(12, "Disqualified"), eq("{{1.status}}", "Disqualified"))],
                   [ledger(13, **{ab.PAYLOAD_FIELD: "{{1.x}}"})], fallback=2)
        res = self.a(r)
        on_12 = [f for f in res if f.module_id == 12]
        self.assertEqual(len(on_12), 1)
        self.assertEqual(on_12[0].status, ab.PASS, on_12[0].detail)
        self.assertIn("Ledger create 11", on_12[0].detail)

    def test_earlier_route_filtered_away_does_not_count(self):
        r = router(10, [filt(full_ledger(11), eq("{{1.status}}", "VIP"))],
                   [filt(status_write(12, "Disqualified"), eq("{{1.status}}", "Disqualified"))],
                   [ledger(13)], fallback=2)
        on_12 = [f for f in self.a(r) if f.module_id == 12]
        self.assertEqual(len(on_12), 1)
        self.assertEqual(on_12[0].status, ab.FAIL)

    # audit-semantics-F7: non-string values and fixed-output formulas.
    def test_p10_dict_wrapped_literal_is_a_decision_point(self):
        res = self.a(status_write(2, {"value": "Disqualified"}))
        self.assertEqual(res[0].status, ab.FAIL)
        self.assertIn("No Shadow Ledger create", res[0].detail)

    def test_formula_with_only_non_disqualified_outputs_is_skipped(self):
        for v in ('{{if(5.ok; "VIP"; "Nurture")}}', "{{if(5.ok; VIP; Nurture)}}",
                  '{{switch(5.tier; "a"; "VIP"; "b"; "Nurture"; "Call Later")}}'):
            with self.subTest(v=v):
                self.assertEqual(self.a(status_write(2, v)), [])

    def test_formula_that_can_yield_disqualified_or_a_reference_is_checked(self):
        for v in ('{{if(5.ok; "VIP"; "Disqualified")}}', '{{if(5.ok; "VIP"; 5.status)}}', "{{ifempty(1.status; \"Nurture\")}}"):
            with self.subTest(v=v):
                res = self.a(status_write(2, v))
                self.assertEqual([f.status for f in res], [ab.FAIL])

    # audit-semantics-F8: a status-writing router with no fallback is REVIEW.
    def test_status_router_without_fallback_is_review(self):
        r = router(2, [filt(status_write(3, "Send Contract"), [[{"a": "{{1.Balance}}", "b": "0", "o": "number:greater"}]])],
                   [filt(status_write(4, "Payment Verified - Ready"), [[{"a": "{{1.Fee}}", "b": "0", "o": "number:greater"}]])])
        res = self.a(r)
        self.assertEqual([(f.status, f.module_id) for f in res], [(ab.REVIEW, 2)])
        r2 = dict(r, parameters={"else": 1})
        self.assertEqual(self.a(r2), [])


class ManifestCoverageTests(unittest.TestCase):
    """Review findings make-api-F1, security-SEC-1 and audit-semantics-F1."""

    def run_dir(self, entries, files):
        with tempfile.TemporaryDirectory() as tmp:
            for name, bp in files.items():
                with open(os.path.join(tmp, name), "w", encoding="utf-8") as fh:
                    json.dump(bp, fh)
            with open(os.path.join(tmp, "manifest.json"), "w", encoding="utf-8") as fh:
                json.dump({"scenarios": entries}, fh)
            return run_main("--blueprints", tmp, "--labels", LABELS_DRAFT, "--schema", SCHEMA, "--no-report")

    def clean(self):
        return {"name": "Ok", "flow": [trigger()], "metadata": {}}

    def test_withheld_scenario_fails_check_d(self):
        entries = [{"id": 900101, "name": "Ok", "file": "ok__900101.json"},
                   {"id": 900102, "name": "Leaky", "file": None, "withheld": True,
                    "withheld_pattern_types": ["stripe_secret_key"],
                    "withheld_locations": ["stripe_secret_key at $.flow[2].routes[0].flow[1].mapper.value"]}]
        code, out, _ = self.run_dir(entries, {"ok__900101.json": self.clean()})
        self.assertEqual(code, 1, out)
        self.assertIn("Result: FAIL", out)
        self.assertRegex(out, r"D  Secrets\s+FAIL 1")

    def test_missing_file_fails_coverage(self):
        entries = [{"id": 900101, "name": "Ok", "file": "ok__900101.json"}, {"id": 900102, "name": "Gone"}]
        code, out, _ = self.run_dir(entries, {"ok__900101.json": self.clean()})
        self.assertEqual(code, 1, out)
        self.assertRegex(out, r"M  Manifest coverage\s+FAIL 1")

    def test_live_missing_is_review_not_fail(self):
        entries = [{"id": 900101, "name": "Ok", "file": "ok__900101.json"},
                   {"id": 900102, "name": "Concept", "file": None, "live_missing": True}]
        code, out, _ = self.run_dir(entries, {"ok__900101.json": self.clean()})
        assert_only_logger_fails(self, code, out)
        self.assertRegex(out, r"M  Manifest coverage\s+FAIL 0\s+UNCONFIRMED 0\s+REVIEW 1")

    def test_report_names_withheld_scenario_without_value(self):
        entries = [{"id": 900102, "name": "Leaky", "file": None, "withheld": True,
                    "withheld_pattern_types": ["authorization_header_literal"]}]
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "manifest.json"), "w", encoding="utf-8") as fh:
                json.dump({"scenarios": entries}, fh)
            code, out, _ = run_main("--blueprints", tmp, "--labels", LABELS_DRAFT, "--schema", SCHEMA,
                                    "--reports-dir", tmp, "--report-date", "2026-10-28")
            self.assertEqual(code, 1)
            with open(os.path.join(tmp, "2026-10-28.md"), encoding="utf-8") as fh:
                report = fh.read()
            self.assertIn("| FAIL | Leaky | - |", report)
            self.assertIn("Scenario 900102 withheld", report)
            self.assertIn("## M. Manifest coverage", report)
            self.assertNotIn(";", report)
            self.assertNotIn("—", report)


# ---------------------------------------------------------------------------
# Checks E and F
# ---------------------------------------------------------------------------

FILES = "tblFILES000000000"
VOICE = "tblVOICE00000000"
CONFIG = "tblCONFIG0000000"
F_NAME, F_PHONE, F_FILES = "fldNAME", "fldPHONE", "fldFILES"
F_RELATED, F_CLIENT_NAME = "fldRELATED", "fldCLIENTNAME"
F_VOICE_LINK = "fldVOICELINK"
F_COST = "fldVCOST"


def link_map():
    return ab.AirtableMap(
        tables={
            LEAD: {"name": "Applicants", "fields": {F_NAME: "Name", F_PHONE: "Phone", ab.STATUS_FIELD: "Status", F_FILES: "Files"},
                   "links": {F_FILES: {"name": "Files", "target": FILES}}},
            FILES: {"name": "Files", "fields": {F_RELATED: "Related Applicant", F_CLIENT_NAME: "Client Name", "fldFSTATUS": "File Status"},
                    "links": {F_RELATED: {"name": "Related Applicant", "target": LEAD}}},
            LEDGER: {"name": "System Logs", "fields": {ab.LEAD_LINK_FIELD: "Applicant Link", F_VOICE_LINK: "Voice AI Ledger",
                                                         ab.LABEL_FIELD: "Scenario name", F_COST: "Voice AI cost",
                                                         ab.CALL_ID_FIELD: "External Call ID"},
                     "links": {ab.LEAD_LINK_FIELD: {"name": "Applicant Link", "target": LEAD},
                               F_VOICE_LINK: {"name": "Voice AI Ledger", "target": VOICE}}},
            VOICE: {"name": "Voice AI Ledger", "fields": {"fldCALL": "Call ID"}, "links": {}},
            CONFIG: {"name": "Configuration", "fields": {"fldKEY": "Config Key"}, "links": {}},
        },
        pii_fields={LEAD: ["Name", "Phone"], FILES: ["Client Name"]},
        source_pii={"google-email:triggerWatchNewEmails": ["fromEmail", "fromName", "from"],
                    "gateway:CustomWebHook": ["phone", "email"], "google-drive:uploadAFile": ["webViewLink"]},
    )


def iface(*names):
    return [{"name": n, "type": "text", "label": n} for n in names]


def at_search(mid, table, fields=("id", "Name", "__IMTLENGTH__"), **extra):
    m = {"id": mid, "module": "airtable:ActionSearchRecords", "mapper": {"table": table, "formula": "{Name} = 'x'"},
         "metadata": {"interface": iface(*fields)}}
    m.update(extra)
    return m


def at_update(mid, table, record_id, record=None):
    return {"id": mid, "module": "airtable:ActionUpdateRecords",
            "mapper": {"table": table, "id": record_id, "record": record or {}}}


def at_get(mid, table, record_id):
    return {"id": mid, "module": "airtable:ActionGetRecord", "mapper": {"table": table, "id": record_id}}


def slack_text(mid, text):
    return {"id": mid, "module": "slack:CreateMessage", "mapper": {"text": text}}


def sendmail(mid, to="{{1.email}}"):
    return {"id": mid, "module": "google-email:sendAnEmail", "mapper": {"to": [to]}}


def run_e(*flow, allow=None, scenario_id=None):
    b = blueprint("S", *flow, scenario_id=scenario_id)
    return ab.check_e(b, link_map(), allow or ab.Allowlist())


def rule(findings, code, status=None):
    return [f for f in findings if f.rule == code and (status is None or f.status == status)]


class CheckE1Tests(unittest.TestCase):
    def test_reference_to_missing_output_field_fails_with_hint(self):
        res = run_e(trigger(), at_search(2, FILES, fields=("id", "File Status", "Client Name")),
                    slack_text(3, "{{2.Status}}"))
        fails = rule(res, "E1", ab.FAIL)
        self.assertEqual(len(fails), 1)
        self.assertEqual(fails[0].module_id, 3)
        self.assertIn("does not output `Status`", fails[0].detail)
        self.assertIn("File Status", fails[0].detail)

    def test_underscore_for_space_is_caught_with_closest_name(self):
        res = run_e(trigger(), at_search(2, FILES, fields=("id", "Approval Video Sent")), slack_text(3, "{{2.Approval_Video_Sent}}"))
        fail = rule(res, "E1", ab.FAIL)[0]
        self.assertIn("Closest outputs: Approval Video Sent", fail.detail)

    def test_existing_field_label_builtins_and_error_pass(self):
        s = at_search(2, FILES, fields=("id", "Client Name"))
        s["metadata"]["interface"].append({"name": "Email", "label": "Client Email", "type": "text"})
        res = run_e(trigger(), s, slack_text(3, "{{2.`Client Name`}} {{2.Email}} {{2.__IMTLENGTH__}} {{2.`__IMTINDEX__`}} {{2.error.message}}"))
        self.assertEqual(rule(res, "E1", ab.FAIL), [])

    def test_a_display_label_does_not_resolve_only_the_field_name_does(self):
        """sem-R9: Make resolves 2.fromEmail, not the label From (email)."""
        s = at_search(2, FILES, fields=("id",))
        s["metadata"]["interface"].append({"name": "fromEmail", "label": "From (email)", "type": "text"})
        res = run_e(trigger(), s, slack_text(3, "{{2.`From (email)`}} {{2.fromEmail}}"))
        fails = rule(res, "E1", ab.FAIL)
        self.assertEqual(len(fails), 1)
        self.assertIn("2.`From (email)`", fails[0].detail)
        self.assertIn("display label", fails[0].detail)
        self.assertIn("`fromEmail`", fails[0].detail)

    def test_reading_the_source_of_an_aggregator_after_it_gets_the_caveat(self):
        """sem-R7: the hint must not send the author to a mapping that is still unreadable."""
        agg = {"id": 4, "module": "util:FunctionAggregator2", "parameters": {"feeder": 2, "fn": "sum"}, "mapper": {"value": "{{2.Cost}}"}}
        feeder = at_search(2, FILES, fields=("id", "Cost", "Total number of bundles"))
        flow = (trigger(), feeder, agg, slack_text(5, "{{2.Total_Number_of_Bundles}}"))
        fail = rule(run_e(*flow), "E1", ab.FAIL)[0]
        self.assertEqual(fail.module_id, 5)
        self.assertIn("source of aggregator 4", fail.detail)
        self.assertIn("inferred", fail.detail)
        # Before the aggregator, or with no aggregator, there is no caveat.
        plain = rule(run_e(trigger(), feeder, slack_text(5, "{{2.Total_Number_of_Bundles}}")), "E1", ab.FAIL)[0]
        self.assertNotIn("aggregator", plain.detail)
        before = rule(run_e(trigger(), feeder, slack_text(3, "{{2.Total_Number_of_Bundles}}"), agg), "E1", ab.FAIL)[0]
        self.assertNotIn("aggregator", before.detail)

    def test_nested_paths_functions_and_quoted_text_are_read_correctly(self):
        s = at_search(2, FILES, fields=("id", "Attachment", "Related Applicant"))
        text = '{{2.Attachment[1].url}} {{first(2.`Related Applicant`)}} {{ifempty(2.id; "3.Nope 4.Gone")}} {{1.5 + 2.5}}'
        res = run_e(trigger(), s, slack_text(3, text))
        self.assertEqual(rule(res, "E1", ab.FAIL), [])

    def test_missing_nested_path_checks_only_the_top_level_name(self):
        s = at_search(2, FILES, fields=("id",))
        res = run_e(trigger(), s, slack_text(3, "{{2.Attachment[1].url}}"))
        self.assertEqual(len(rule(res, "E1", ab.FAIL)), 1)

    def test_filter_and_router_route_filters_are_scanned(self):
        s = at_search(2, FILES, fields=("id",))
        r = router(3, [filt(slack_text(4, "x"), eq("{{2.Gone}}", "1"))])
        res = run_e(trigger(), s, r)
        fails = rule(res, "E1", ab.FAIL)
        self.assertEqual([f.module_id for f in fails], [4])
        self.assertIn("filter.conditions", fails[0].detail)

    def test_same_bad_reference_in_mapper_and_filter_gives_a_row_each(self):
        gone = filt(slack_text(3, "{{2.Gone}}"), eq("{{2.Gone}}", "1"))
        res = run_e(trigger(), at_search(2, FILES, fields=("id",)), gone)
        paths = sorted(f.detail.split(" in ")[1].split(":")[0] for f in rule(res, "E1", ab.FAIL))
        self.assertEqual(len(paths), 2)
        self.assertTrue(any(p.startswith("filter") for p in paths) and any(p.startswith("mapper") for p in paths))

    def test_module_without_interface_is_skipped_as_info(self):
        res = run_e(trigger(), {"id": 2, "module": "bland:getCallDetails", "mapper": {}}, slack_text(3, "{{2.anything}}"))
        self.assertEqual(rule(res, "E1", ab.FAIL), [])
        info = rule(res, "E1", ab.INFO)
        self.assertEqual(len(info), 1)
        self.assertEqual(info[0].module_id, 2)
        self.assertIn("1 reference(s)", info[0].detail)

    def test_webhook_that_lists_only_headers_has_no_checkable_payload(self):
        hook = {"id": 1, "module": "gateway:CustomWebHook", "metadata": {"interface": [
            {"name": "__IMTHEADERS__", "label": "Headers", "type": "array"}]}}
        res = run_e(hook, slack_text(2, "{{1.call_id}}"))
        self.assertEqual(rule(res, "E1", ab.FAIL), [])
        self.assertEqual(len(rule(res, "E1", ab.INFO)), 1)

    def test_reference_to_a_module_that_does_not_exist_fails(self):
        res = run_e(trigger(), slack_text(2, "{{9.id}}"))
        fail = rule(res, "E1", ab.FAIL)[0]
        self.assertIn("module 9, which is not in this scenario", fail.detail)

    def test_references_inside_error_routes_are_checked(self):
        s = with_handler(at_search(2, FILES, fields=("id",)), slack_text(20, "{{2.error.message}} {{2.Gone}}"))
        res = run_e(trigger(), s)
        self.assertEqual([f.module_id for f in rule(res, "E1", ab.FAIL)], [20])

    def test_stale_interface_hint_names_the_real_table(self):
        res = run_e(trigger(), at_search(2, FILES, fields=("id",)), slack_text(3, "{{2.`File Status`}}"))
        self.assertIn("interface may be stale", rule(res, "E1", ab.FAIL)[0].detail)


class CheckE2Tests(unittest.TestCase):
    def test_bare_names_fail(self):
        res = run_e(trigger(), slack_text(2, "{{Video}}{{URL}} {{to}}"))
        names = sorted(f.detail.split("{{")[1].split("}}")[0] for f in rule(res, "E2", ab.FAIL))
        self.assertEqual(names, ["URL", "Video", "to"])

    def test_valid_bare_forms_pass(self):
        text = "{{var.team.token}} {{error.message}} {{item}} {{item.name}} {{now}} {{true}} {{false}} {{null}} {{emptystring}} {{`2`}} {{12}} {{1.5}}"
        res = run_e(trigger(), slack_text(2, text))
        self.assertEqual(rule(res, "E2"), [])

    def test_function_calls_and_operators_are_not_bare(self):
        res = run_e(trigger(), slack_text(2, '{{formatDate(now; "YYYY-MM-DD")}} {{if(1.a; "x"; "y")}} {{1.a + 1}} {{ifempty(1.a; error.message)}}'))
        self.assertEqual(rule(res, "E2"), [])

    def test_bare_words_inside_calls_and_operators_fail(self):
        """sem-R8: the bare word in if(7.call_id; 7.error.message; message) resolves to empty."""
        res = run_e(trigger(), slack_text(2, "{{if(1.call_id; 1.error.message; message)}} {{1.a + other}} {{formatDate(now; YYYY)}}"))
        words = sorted(f.detail.split("`")[1] for f in rule(res, "E2", ab.FAIL))
        self.assertEqual(words, ["YYYY", "message", "other"])
        self.assertIn("inside an expression", rule(res, "E2", ab.FAIL)[0].detail)

    def test_valid_words_in_compound_expressions_stay_clean(self):
        text = ('{{get(map(1.arr; "name"); 1)}} {{if(var.team.on = true; now; null)}} {{ifempty(1.`Visa Type`; "n/a")}} '
                '{{1.a.b[2].c + 1.5}} {{join(1.names; ", ")}} {{emptyarray}} {{newline}} {{carriagereturn}} {{7.error.message}} '
                '{{"quoted words are text, not bare"}} {{length(item.value)}}')
        self.assertEqual(rule(run_e(trigger(), slack_text(2, text)), "E2"), [])

    def test_execution_id_is_a_system_variable_not_a_bare_word(self):
        """sem-R9: executionId lives under var.scenario, so a bare {{executionId}} resolves to nothing."""
        res = run_e(trigger(), slack_text(2, "{{executionId}} {{scenarioId}} {{var.scenario.executionId}}"))
        self.assertEqual(sorted(f.detail.split("{{")[1].split("}}")[0] for f in rule(res, "E2", ab.FAIL)), ["executionId", "scenarioId"])

    def test_same_bare_name_reports_once_per_module(self):
        res = run_e(trigger(), slack_text(2, "{{Video}} again {{Video}}"))
        self.assertEqual(len(rule(res, "E2", ab.FAIL)), 1)


class CheckE3Tests(unittest.TestCase):
    def ledger_with_link(self, mid, ref):
        return ledger(mid, **{ab.LEAD_LINK_FIELD: [ref]})

    def test_files_record_id_in_lead_link_fails(self):
        res = run_e(trigger(), at_search(2, FILES), self.ledger_with_link(3, "{{2.id}}"))
        fail = rule(res, "E3", ab.FAIL)
        self.assertEqual(len(fail), 1)
        self.assertEqual(fail[0].module_id, 3)
        self.assertIn("Files", fail[0].detail)
        self.assertIn("Expected a Applicants", fail[0].detail)

    def test_lead_record_id_in_lead_link_passes(self):
        res = run_e(trigger(), at_search(2, LEAD), self.ledger_with_link(3, "{{2.id}}"))
        self.assertEqual(rule(res, "E3"), [])

    def test_webhook_id_in_a_link_fails(self):
        res = run_e(trigger(), webhook(2), self.ledger_with_link(3, "{{2.id}}"))
        fail = rule(res, "E3", ab.FAIL)
        self.assertEqual(len(fail), 1)
        self.assertIn("not an Airtable record", fail[0].detail)

    def test_link_field_of_a_files_row_leads_to_the_lead_table(self):
        # first(Related Applicant) of a Files row is an Applicants record ID.
        files = at_search(2, FILES, fields=("id", "Related Applicant"))
        res = run_e(trigger(), files, self.ledger_with_link(3, "{{first(2.`Related Applicant`)}}"))
        self.assertEqual(rule(res, "E3"), [])
        wrong = ledger(4, **{F_VOICE_LINK: ["{{first(2.`Related Applicant`)}}"]})
        res = run_e(trigger(), files, wrong)
        self.assertEqual(len(rule(res, "E3", ab.FAIL)), 1)

    def test_two_links_fed_by_one_id(self):
        m = ledger(3, **{ab.LEAD_LINK_FIELD: ["{{2.id}}"], F_VOICE_LINK: ["{{2.id}}"]})
        res = run_e(trigger(), at_search(2, LEDGER), m)
        self.assertEqual(len(rule(res, "E3", ab.FAIL)), 2)
        res = run_e(trigger(), at_search(2, LEAD), m)
        self.assertEqual(len(rule(res, "E3", ab.FAIL)), 1)

    def test_update_of_a_lead_with_a_ledger_row_id_fails(self):
        res = run_e(trigger(), ledger(9), at_update(4, LEAD, "{{9.id}}"))
        fail = rule(res, "E3", ab.FAIL)
        self.assertEqual(len(fail), 1)
        self.assertEqual(fail[0].module_id, 4)
        self.assertIn("Record ID of this Applicants", fail[0].detail)

    def test_update_with_a_matching_id_passes(self):
        res = run_e(at_search(1, LEAD), at_update(2, LEAD, "{{1.id}}"), at_get(3, LEAD, "{{1.id}}"))
        self.assertEqual(rule(res, "E3"), [])

    def test_unknown_sources_and_non_id_fields_are_not_flagged(self):
        res = run_e(trigger(), self.ledger_with_link(3, "{{1.lead_id}}"), at_update(4, LEAD, "{{1.lead_id}}"))
        self.assertEqual(rule(res, "E3"), [])


class CheckE4Tests(unittest.TestCase):
    REC = "rec" + "A1b2C3d4E5f6G7"

    def test_literal_record_id_fails_for_get_update_and_delete(self):
        delete = {"id": 5, "module": "airtable:ActionDeleteRecords", "mapper": {"table": LEAD, "id": self.REC}}
        res = run_e(trigger(), at_get(2, LEAD, self.REC), at_update(3, LEAD, self.REC), delete)
        self.assertEqual(sorted(f.module_id for f in rule(res, "E4", ab.FAIL)), [2, 3, 5])
        self.assertIn(self.REC, rule(res, "E4", ab.FAIL)[0].detail)

    def test_mapped_or_odd_ids_pass(self):
        res = run_e(trigger(), at_get(2, LEAD, "{{1.id}}"), at_get(3, LEAD, "rec123"), at_get(4, LEAD, ""))
        self.assertEqual(rule(res, "E4"), [])

    def test_allowlist_turns_a_fail_into_info_with_the_reason(self):
        allow = ab.Allowlist([{"check": "E4", "scenario": "77", "module": "2", "record_id": self.REC, "reason": "Configuration singleton"}])
        res = run_e(trigger(), at_get(2, CONFIG, self.REC), allow=allow, scenario_id="77")
        self.assertEqual(rule(res, "E4", ab.FAIL), [])
        info = rule(res, "E4", ab.INFO)
        self.assertEqual(len(info), 1)
        self.assertIn("Configuration singleton", info[0].detail)

    def test_allowlist_is_pinned_to_scenario_module_and_record(self):
        allow = ab.Allowlist([{"check": "E4", "scenario": "77", "module": "2", "record_id": self.REC, "reason": "r"}])
        other = "rec" + "Z9y8X7w6V5u4T3"
        cases = (([trigger(), at_get(2, CONFIG, other)], "77"), ([trigger(), at_get(3, CONFIG, self.REC)], "77"),
                 ([trigger(), at_get(2, CONFIG, self.REC)], "78"), ([trigger(), at_get(2, CONFIG, self.REC)], None))
        for flow, sid in cases:
            res = run_e(*flow, allow=allow, scenario_id=sid)
            self.assertEqual(len(rule(res, "E4", ab.FAIL)), 1, (sid, flow[1]["id"]))

    def test_allowlist_file_needs_a_reason_and_a_rule(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "allowlist.json")
            entries = ({"check": "E4", "scenario": "1", "module": 2}, {"check": "E4", "scenario": "1", "module": 2, "reason": "  "},
                       {"check": "bad", "scenario": "1", "module": 2, "reason": "x"}, {"check": "E4", "module": 2, "reason": "x"})
            for entry in entries:
                with open(path, "w", encoding="utf-8") as fh:
                    json.dump({"entries": [entry]}, fh)
                with self.assertRaises(ab.InputError, msg=entry):
                    ab.load_allowlist(path)
                code, _out, _err = run_main("--dir", BP_DIR, "--labels", LABELS_OK, "--schema", SCHEMA, "--allowlist", path, "--no-report")
                self.assertEqual(code, 2)
            self.assertEqual(ab.load_allowlist(os.path.join(tmp, "missing.json")).entries, [])

    def test_repo_allowlist_and_links_files_load(self):
        allow = ab.load_allowlist(ab.DEFAULT_ALLOWLIST)
        self.assertTrue(allow.entries)
        self.assertTrue(all(e["reason"] for e in allow.entries))
        links = ab.load_links(ab.DEFAULT_LINKS, required=True)
        self.assertEqual(links.link_target(LEDGER, ab.LEAD_LINK_FIELD), LEAD)
        self.assertTrue(links.is_pii(LEAD, "Name"))
        self.assertTrue(links.is_pii("tblSFR7Sg8uh8noO2", "Client Email"))
        self.assertFalse(links.is_pii(LEAD, "Status"))


class CheckE5Tests(unittest.TestCase):
    def zero(self, op="number:equal", lit="0", ref="{{2.`__IMTLENGTH__`}}"):
        return [[{"a": ref, "b": lit, "o": op}]]

    def test_zero_count_filter_after_a_search_fails(self):
        res = run_e(trigger(), at_search(2, FILES), filt(slack_text(3, "none"), self.zero(), name="Not found"))
        fail = rule(res, "E5", ab.FAIL)
        self.assertEqual([f.module_id for f in fail], [3])
        self.assertIn("never fires", fail[0].detail)

    def test_zero_test_on_a_route_behind_a_router_fails(self):
        r = router(3, [filt(slack_text(4, "found"), [[{"a": "{{2.id}}", "o": "exist"}]])],
                   [filt(slack_text(5, "none"), self.zero("text:equal"))])
        res = run_e(trigger(), at_search(2, FILES), r)
        self.assertEqual([f.module_id for f in rule(res, "E5", ab.FAIL)], [5])

    def test_other_ways_to_say_zero_and_the_bundle_total_name(self):
        for kw in (dict(op="number:less", lit="1"), dict(op="number:lessorequal", lit="0"), dict(ref="{{2.Total_Number_of_Bundles}}")):
            res = run_e(trigger(), at_search(2, FILES), filt(slack_text(3, "none"), self.zero(**kw)))
            self.assertEqual(len(rule(res, "E5", ab.FAIL)), 1, kw)

    def test_positive_tests_and_other_sources_pass(self):
        # A count compared with any number FAILs since the E5 extension (2026-10-30, tests/test_sweep_rules.py). The found
        # test that passes is {{2.id}} exists.
        res = run_e(trigger(), at_search(2, FILES), filt(slack_text(3, "x"), [[{"a": "{{2.id}}", "o": "exist"}]]))
        self.assertEqual(rule(res, "E5"), [])
        res = run_e(trigger(), {"id": 2, "module": "util:FunctionAggregator2", "mapper": {}}, filt(slack_text(3, "x"), self.zero()))
        self.assertEqual(rule(res, "E5"), [])

    def test_search_that_is_not_upstream_is_ignored(self):
        r = router(3, [at_search(2, FILES)], [filt(slack_text(4, "x"), self.zero())])
        res = run_e(trigger(), r)
        self.assertEqual(rule(res, "E5"), [])

    def test_dead_alternative_in_an_or_filter_is_review(self):
        conds = self.zero() + [[{"a": "{{1.go}}", "b": "yes", "o": "text:equal"}]]
        res = run_e(trigger(), at_search(2, FILES), filt(slack_text(3, "x"), conds))
        self.assertEqual(len(rule(res, "E5", ab.REVIEW)), 1)
        self.assertEqual(rule(res, "E5", ab.FAIL), [])


class CheckE6Tests(unittest.TestCase):
    def test_client_name_and_phone_in_slack_fail(self):
        res = run_e(trigger(), at_search(2, LEAD, fields=("id", "Name", "Phone")), slack_text(3, "Applicant {{2.Name}} {{2.Phone}} (ID {{2.id}})"))
        fails = rule(res, "E6", ab.FAIL)
        self.assertEqual(len(fails), 2)
        self.assertTrue(all(f.module_id == 3 for f in fails))

    def test_field_ids_files_table_and_error_routes_count(self):
        res = run_e(trigger(), at_search(2, LEAD, fields=("id", "Name")), slack_text(3, "{{2." + F_NAME + "}}"))
        self.assertEqual(len(rule(res, "E6", ab.FAIL)), 1)
        res = run_e(trigger(), at_search(2, FILES, fields=("id", "Client Name")), slack_text(3, "{{2.`Client Name`}}"))
        self.assertEqual(len(rule(res, "E6", ab.FAIL)), 1)
        res = run_e(trigger(), with_handler(at_search(2, LEAD), slack_text(20, "{{2.Name}} {{error.message}}")))
        self.assertEqual([f.module_id for f in rule(res, "E6", ab.FAIL)], [20])

    def test_record_ids_other_modules_and_other_tables_are_allowed(self):
        res = run_e(trigger(), at_search(2, LEAD), slack_text(3, "Lead {{2.id}} call {{1.call_id}} error {{error.message}}"))
        self.assertEqual(rule(res, "E6"), [])
        res = run_e(trigger(), at_search(2, CONFIG, fields=("id", "Name")), slack_text(3, "{{2.Name}}"))
        self.assertEqual(rule(res, "E6"), [])
        res = run_e(trigger(), at_search(2, LEAD), sendmail(3, "{{2.Name}}"))
        self.assertEqual(rule(res, "E6"), [])


class CheckE6SourceTests(unittest.TestCase):
    """sem-R3: client data that never touched Airtable still must not reach Slack."""

    def test_email_sender_webhook_phone_and_drive_link_in_slack_fail(self):
        res = run_e(trigger(), slack_text(2, "From {{1.fromName}} <{{1.fromEmail}}> {{1.from.address}}"))
        fails = rule(res, "E6", ab.FAIL)
        self.assertEqual(sorted(f.detail.split("`")[1] for f in fails), ["from", "fromEmail", "fromName"])
        self.assertIn("outside Airtable", fails[0].detail)
        res = run_e(webhook(), slack_text(2, "Call for {{1.phone}} and {{1.email}}"))
        self.assertEqual(len(rule(res, "E6", ab.FAIL)), 2)
        drive = {"id": 3, "module": "google-drive:uploadAFile", "mapper": {}}
        res = run_e(trigger(), drive, slack_text(4, "Signed contract {{3.webViewLink}}"))
        self.assertEqual(len(rule(res, "E6", ab.FAIL)), 1)

    def test_ids_subjects_and_other_modules_are_not_flagged(self):
        res = run_e(trigger(), slack_text(2, "{{1.id}} {{1.subject}} {{1.call_id}}"))
        self.assertEqual(rule(res, "E6"), [])
        # The same field name on a module type that is not listed carries no PII claim.
        other = {"id": 3, "module": "bland:getCallDetails", "mapper": {}}
        self.assertEqual(rule(run_e(trigger(), other, slack_text(4, "{{3.fromEmail}} {{3.phone}}")), "E6"), [])

    def test_the_repo_map_lists_the_sources(self):
        links = ab.load_links(ab.DEFAULT_LINKS, required=True)
        self.assertIn("fromEmail", links.source_pii["google-email:triggerWatchNewEmails"])
        self.assertIn("phone", links.source_pii["gateway:CustomWebHook"])
        self.assertIn("webViewLink", links.source_pii["google-drive:uploadAFile"])


class CheckE7Tests(unittest.TestCase):
    def two_filtered_routes(self, **kw):
        return router(3, [filt(status_write(4, "VIP"), eq("{{1.s}}", "VIP"))],
                      [filt(status_write(5, "Nurture"), eq("{{1.s}}", "Nurture"))], **kw)

    def test_all_filtered_routes_without_fallback_that_write_state_is_review(self):
        res = run_e(trigger(), self.two_filtered_routes())
        rows = rule(res, "E7")
        self.assertEqual([f.status for f in rows], [ab.REVIEW])
        self.assertIn("[4, 5]", rows[0].detail)

    def test_fallback_unfiltered_route_or_no_state_writes_pass(self):
        traced = router(3, [filt(status_write(4, "VIP"), eq("{{1.s}}", "VIP"))], [error_row(5), slack_text(6, "Unmatched")], fallback=1)
        self.assertEqual(rule(run_e(trigger(), traced), "E7"), [])
        r = router(3, [filt(status_write(4, "VIP"), eq("{{1.s}}", "VIP"))], [status_write(5, "Nurture")])
        self.assertEqual(rule(run_e(trigger(), r), "E7"), [])
        r = router(3, [filt(slack_text(4, "a"), eq("{{1.s}}", "VIP"))], [filt(slack_text(5, "b"), eq("{{1.s}}", "Nurture"))])
        self.assertEqual(rule(run_e(trigger(), r), "E7"), [])

    def test_push_2_a_fallback_that_leaves_no_trace_does_not_close_the_row(self):
        """The sanctioned fix used to be a fallback that only sets a variable, which closes the row and still drops the bundle."""
        setvar = {"id": 30, "module": "util:SetVariable2", "mapper": {"name": "v", "value": "none"}}
        base = [filt(status_write(4, "VIP"), eq("{{1.s}}", "VIP"))]
        cases = {
            "set variable only": [setvar],
            "ledger row only": [error_row(30)],
            "slack only": [slack_text(30, "x")],
            "a filter on the fallback": [filt(error_row(30), eq("{{1.s}}", "other")), slack_text(31, "x")],
            "a filter before the trace": [filt(setvar, eq("{{1.s}}", "other")), error_row(30), slack_text(31, "x")],
            "the trace in a nested route": [router(32, [error_row(30), slack_text(31, "x")], [setvar])],
            "the trace in an error handler": [with_handler(setvar, error_row(30), slack_text(31, "x"))],
        }
        for name, fb in cases.items():
            rows = rule(run_e(trigger(), router(3, base, fb, fallback=1)), "E7", ab.REVIEW)
            self.assertEqual(len(rows), 1, name)
            self.assertIn("leaves no trace", rows[0].detail, name)
        for fb in ([error_row(30), slack_text(31, "x")], [slack_text(31, "x"), error_row(30)]):
            self.assertEqual(rule(run_e(trigger(), router(3, base, fb, fallback=1)), "E7"), [])

    def test_two_exactly_opposite_filters_always_match_one_route(self):
        """sem-R12: startwith +1 and notstartwith +1 cannot both miss."""
        def pair(o1, o2, b2="+1"):
            return router(3, [filt(status_write(4, "NA"), [[{"a": "{{1.phone}}", "b": "+1", "o": o1}]])],
                          [filt(status_write(5, "INT"), [[{"a": "{{1.phone}}", "b": b2, "o": o2}]])])
        for o1, o2 in (("text:startwith", "text:notstartwith"), ("text:equal", "text:notequal"), ("text:notcontain", "text:contain"),
                       ("text:equal:ci", "text:notequal:ci"), ("number:greater", "number:lessorequal")):
            with self.subTest(o1=o1):
                self.assertEqual(rule(run_e(trigger(), pair(o1, o2)), "E7"), [])
        # Different operands, a different family, or a different case flag are not opposites.
        self.assertEqual(len(rule(run_e(trigger(), pair("text:startwith", "text:notstartwith", b2="+44")), "E7")), 1)
        self.assertEqual(len(rule(run_e(trigger(), pair("text:startwith", "text:notequal")), "E7")), 1)
        self.assertEqual(len(rule(run_e(trigger(), pair("text:equal:ci", "text:notequal")), "E7")), 1)
        self.assertEqual(len(rule(run_e(trigger(), pair("text:startwith", "text:startwith")), "E7")), 1)

    def test_mixed_case_sensitivity_on_one_operand_is_named(self):
        """sem-R5: Is VIP? is case-insensitive and Is Nurture? is not, so a lowercase nurture matches neither."""
        mixed = router(3, [filt(status_write(4, "VIP"), eq("{{1.s}}", "VIP", "text:equal:ci"))],
                       [filt(status_write(5, "Nurture"), eq("{{1.s}}", "Nurture", "text:equal"))])
        rows = rule(run_e(trigger(), mixed), "E7", ab.REVIEW)
        self.assertEqual(len(rows), 1)
        self.assertIn("{{1.s}} both with and without the case-insensitive operator", rows[0].detail)
        same = router(3, [filt(status_write(4, "VIP"), eq("{{1.s}}", "VIP", "text:equal:ci"))],
                      [filt(status_write(5, "Nurture"), eq("{{1.s}}", "Nurture", "text:equal:ci"))])
        self.assertNotIn("case-insensitive", rule(run_e(trigger(), same), "E7", ab.REVIEW)[0].detail)

    def test_email_and_sms_sends_count_as_state(self):
        sms = {"id": 5, "module": "twilio:SendSMS", "mapper": {"to": "{{1.phone}}"}}
        r = router(3, [filt(sendmail(4), eq("{{1.s}}", "VIP"))], [filt(sms, eq("{{1.s}}", "Nurture"))])
        self.assertEqual(len(rule(run_e(trigger(), r), "E7", ab.REVIEW)), 1)


def registry(*rows):
    """audit/webhooks.json as an object: rows of (scenario_id, hook_id, caller, protection)."""
    return ab.Webhooks({sid: ab.WebhookEntry(sid, hid, caller, prot, "A sentence of reason", "S" if prot == "fetch_back" else "")
                        for sid, hid, caller, prot in rows})


FETCH_REG = registry(("5", 1, "bland_post_call", "fetch_back"))
KEY_REG = registry(("5", 1, "bland_pathway_node", "api_key"))


def hook_info(**by_id):
    return ab.HookInfo(True, {int(k.lstrip("h")): v for k, v in by_id.items()})


def fetch_call(mid, call_id="{{1.call_id}}", **extra):
    m = {"id": mid, "module": "bland:getCallDetails", "mapper": {"call_id": call_id}}
    m.update(extra)
    return m


def done_filter(call_details=2):
    """The completion gate: the fetched call is complete (Bland call details status)."""
    return [[{"a": "{{%s.status}}" % call_details, "b": "completed", "o": "text:equal"}]]


LOOKUP_FORMULA = "AND({External Call ID} = '{{2.call_id}}', {Scenario name} = 'S', {Voice AI cost} = BLANK())"


def call_lookup(mid, table=LEDGER, formula=LOOKUP_FORMULA, module="airtable:ActionSearchRecords", done=True, max_records="1"):
    """The pinned lookup. By default it carries the F2d gates: one record at most, the row kind of the calling
    scenario (label S), an unreconciled formula and a completion filter on the link into it, which also cover
    every later module of the flow."""
    m = {"id": mid, "module": module, "mapper": {"table": table, "formula": formula, "maxRecords": max_records}}
    return filt(m, done_filter()) if done else m


def found(m, src, op="exist"):
    return filt(m, [[{"a": "{{%s.id}}" % src, "o": op}]])


def write_ledger(mid, **record):
    return {"id": mid, "module": "airtable:ActionCreateRecord", "mapper": {"table": LEDGER, "record": record}}


def reconcile(mid, lookup=3, handler=True, **record):
    """The reconciliation: an update of the row the lookup found that fills in the marker field, failing loudly (Break)."""
    m = {"id": mid, "module": "airtable:ActionUpdateRecords",
         "mapper": {"table": LEDGER, "id": "{{%s.id}}" % lookup, "record": record}}
    return with_handler(m, slack_text(mid + 100, "reconcile failed {{var.scenario.executionId}}"), directive(mid + 101, "Break")) if handler else m


def good_fetch_back():
    """A verified fetch-back flow: call-details 2, lookup 3 (completed gate, one record, row kind and unreconciled
    formula), a found filter on the update 4 of the looked-up row, which reconciles by filling in the Voice AI
    cost and is the first effect after the gates."""
    return [webhook(), fetch_call(2), call_lookup(3), found(reconcile(4, note="{{2.call_id}}", **{F_COST: "{{2.price}}"}), 3)]


class CheckFTests(unittest.TestCase):
    def run_f(self, *flow, reg=FETCH_REG, hooks=None, scenario_id="5", allow=None, links=None):
        return ab.check_f(blueprint("S", *flow, scenario_id=scenario_id, sequential=True), allow or ab.Allowlist(), reg, hooks, links)

    def rows(self, res, status=ab.FAIL, replay=False):
        """(rule, module) of the rows with this status. The replay rows (F2d) are left out unless asked
        for, so the F2a to F2c tests stay about F2a to F2c. The F2d tests pass replay=True."""
        return sorted({(f.rule, f.module_id) for f in res if f.status == status and (replay or f.rule != "F2d")})

    # --- F0: the registry -----------------------------------------------------------------

    def test_a_webhook_scenario_missing_from_the_registry_fails_on_the_trigger(self):
        res = self.run_f(*good_fetch_back(), reg=ab.Webhooks())
        self.assertEqual(self.rows(res), [("F0", 1)])
        self.assertIn("not in audit/webhooks.json", res[0].detail)
        res = self.run_f(*good_fetch_back(), scenario_id=None)
        self.assertEqual(self.rows(res), [("F0", 1)])

    def test_a_registry_hook_id_that_differs_from_the_trigger_fails(self):
        res = self.run_f(*good_fetch_back(), reg=registry(("5", 99, "bland_post_call", "fetch_back")))
        self.assertEqual(self.rows(res), [("F0", 1)])
        self.assertIn("lists hook 99", res[0].detail)

    def test_other_triggers_are_not_checked(self):
        """A scenario the registry does not list is not a webhook scenario."""
        self.assertEqual(self.run_f(trigger(), slack_text(2, "x"), scenario_id="77"), [])
        self.assertEqual(self.run_f(trigger(), slack_text(2, "x"), reg=ab.Webhooks()), [])

    def test_push_4_a_registered_webhook_scenario_must_keep_its_webhook_trigger(self):
        """Changing the trigger type used to make every F row vanish: check_f returned nothing for a non-webhook trigger."""
        res = self.run_f(trigger(), *good_fetch_back()[1:])
        self.assertEqual([(f.rule, f.status, f.module_id) for f in res], [("F0", ab.FAIL, 1)])
        self.assertIn("not a gateway:CustomWebHook trigger", res[0].detail)
        res = ab.check_f(blueprint("S", scenario_id="5"), ab.Allowlist(), FETCH_REG, None, None)
        self.assertEqual([(f.rule, f.status, f.module_id) for f in res], [("F0", ab.FAIL, "-")])
        res = self.run_f(*good_fetch_back())
        self.assertEqual([(f.rule, f.status) for f in res], [("F2", ab.PASS)])

    def test_the_registry_loader_validates_every_entry(self):
        def load(entries):
            with tempfile.TemporaryDirectory() as tmp:
                path = os.path.join(tmp, "webhooks.json")
                with open(path, "w", encoding="utf-8") as fh:
                    json.dump({"scenarios": entries}, fh)
                return ab.load_webhooks(path, required=True)
        ok = {"scenario_id": "5", "hook_id": 7, "caller": "bland_post_call", "protection": "fetch_back", "reason": "Called after each call",
              "lookup_label": "Campaign Launcher"}
        self.assertEqual(load([ok]).entries["5"].hook_id, 7)
        self.assertEqual(load([ok]).entries["5"].lookup_label, "Campaign Launcher")
        no_label = {k: v for k, v in ok.items() if k != "lookup_label"}
        key_entry = {**no_label, "caller": "bland_pathway_node", "protection": "api_key"}
        self.assertEqual(load([key_entry]).entries["5"].lookup_label, "")
        for bad in ({**ok, "lookup_label": ""}, no_label, {**ok, "lookup_label": "it's"}, {**ok, "lookup_label": "{x}"}, {**key_entry, "lookup_label": "X"},{**ok, "scenario_id": "x"}, {**ok, "hook_id": "7"}, {**ok, "hook_id": True}, {**ok, "caller": "someone"},
                    {**ok, "protection": "filter"}, {**ok, "reason": ""},
                    {**ok, "protection": "api_key"},  # a post-call webhook cannot send a header
                    ):
            with self.assertRaises(ab.InputError, msg=bad):
                load([bad])
        with self.assertRaises(ab.InputError):
            load([ok, ok])
        with self.assertRaises(ab.InputError):
            load("nope")
        self.assertEqual(ab.load_webhooks(os.path.join(FIX, "does-not-exist.json")).entries, {})
        with self.assertRaises(ab.InputError):
            ab.load_webhooks(os.path.join(FIX, "does-not-exist.json"), required=True)
        keyed = {**no_label, "caller": "bland_pathway_node", "protection": "api_key"}
        self.assertEqual(load([keyed]).entries["5"].protection, "api_key")

    def test_the_real_registry_matches_the_four_webhook_scenarios(self):
        reg = ab.load_webhooks(ab.DEFAULT_WEBHOOKS, required=True)
        self.assertEqual({k: (v.hook_id, v.caller, v.protection) for k, v in reg.entries.items()}, {
            "3943741": (1773988, "bland_pathway_node", "api_key"),
            "4218934": (1923792, "bland_post_call", "fetch_back"),
            "4226754": (1927751, "bland_post_call", "fetch_back"),
            "3975156": (1801156, "bland_post_call", "fetch_back"),
            "6832527": (3000983, "make_http", "api_key"),  # the Logger, deployed 2026-10-29
            "6840588": (3003631, "stripe_verifier", "api_key"),  # the F-H9 Stripe listener, hook 2026-10-30
            "6847022": (3007146, "bland_post_call", "fetch_back"),  # Batch Call Reconciliation (F-31.2), hook 2026-10-31
        })

    # --- F1: the hook has an API key --------------------------------------------------------

    def f1(self, hooks, allow=None):
        return self.run_f(webhook(), slack_text(2, "x"), reg=KEY_REG, hooks=hooks, allow=allow)

    def test_f1_without_hook_data_fails_unconfirmed_and_names_the_missing_scope(self):
        """R6: no proof that a key exists must never read as a pass, and a FAIL is what stops a fresh pull passing the audit."""
        for hooks in (None, ab.HookInfo(note="GET /hooks returned 403")):
            res = self.f1(hooks)
            self.assertEqual([(f.status, f.rule, f.module_id) for f in res], [(ab.FAIL, "F1", 1)])
            self.assertIn("UNCONFIRMED", res[0].detail)
            self.assertIn("hook auth state unknown, read token needs Webhooks: View", res[0].detail)

    def test_f1_a_hook_with_no_api_key_fails_and_one_key_passes(self):
        res = self.f1(hook_info(h1={"id": 1, "apikey_count": 0, "scenario_ids": [5]}))
        self.assertEqual([(f.status, f.module_id) for f in res], [(ab.FAIL, 1)])
        self.assertIn("no API key configured", res[0].detail)
        res = self.f1(hook_info(h1={"id": 1, "apikey_count": 2, "scenario_ids": [5]}))
        self.assertEqual([f.status for f in res], [ab.PASS])
        self.assertIn("requires 2 API key", res[0].detail)

    def test_f1_unknown_key_state_or_a_hook_missing_from_the_list_fails_unconfirmed(self):
        res = self.f1(hook_info(h1={"id": 1, "apikey_count": None}))
        self.assertEqual([f.status for f in res], [ab.FAIL])
        self.assertIn("UNCONFIRMED", res[0].detail)
        self.assertIn("hook auth state unknown", res[0].detail)
        res = self.f1(hook_info(h2={"id": 2, "apikey_count": 1}))
        self.assertEqual([f.status for f in res], [ab.FAIL])
        self.assertIn("UNCONFIRMED", res[0].detail)

    def test_f1_a_hook_that_serves_another_scenario_fails(self):
        res = self.f1(hook_info(h1={"id": 1, "apikey_count": 1, "scenario_ids": [77]}))
        self.assertEqual([f.status for f in res], [ab.FAIL])
        self.assertIn("serves scenarios [77]", res[0].detail)

    def test_f1_cannot_be_allowlisted(self):
        """R6: decision 1 has no exception, so no allowlist entry can turn an F1 FAIL into INFO."""
        with self.assertRaises(ab.InputError):
            with tempfile.TemporaryDirectory() as tmp:
                path = os.path.join(tmp, "allowlist.json")
                with open(path, "w", encoding="utf-8") as fh:
                    json.dump({"entries": [{"check": "F1", "scenario": "5", "module": "1", "reason": "Public form, no caller can send a key"}]}, fh)
                ab.load_allowlist(path)
        res = self.f1(hook_info(h1={"id": 1, "apikey_count": 0}), allow=ab.Allowlist([{"check": "F1", "scenario": "5", "module": "1",
                                                                                         "reason": "Public form, no caller can send a key"}]))
        self.assertEqual([(f.status, f.allowlisted) for f in res], [(ab.FAIL, False)])

    def test_f1_does_not_run_the_fetch_back_rules(self):
        res = self.run_f(webhook(), write_ledger(2, note="{{1.anything}}"), reg=KEY_REG, hooks=hook_info(h1={"id": 1, "apikey_count": 1}))
        self.assertEqual([(f.rule, f.status) for f in res], [("F1", ab.PASS)])

    # --- F2: fetch-back --------------------------------------------------------------------------

    def test_f2_a_verified_fetch_back_flow_passes(self):
        res = self.run_f(*good_fetch_back())
        self.assertEqual([(f.rule, f.status) for f in res], [("F2", ab.PASS)])

    def test_f2a_a_missing_call_details_module_fails_on_the_first_module_after_the_trigger(self):
        res = self.run_f(webhook(), call_lookup(2, formula="{External Call ID} = '{{1.call_id}}'"), found(write_ledger(3), 2))
        self.assertIn(("F2a", 2), self.rows(res))
        self.assertIn("No Bland call-details module", [f for f in res if f.rule == "F2a"][0].detail)

    def test_f2a_the_call_details_module_must_be_fed_exactly_the_call_id(self):
        for value in ("{{trim(1.call_id)}}", "x{{1.call_id}}", "{{1.id}}", "{{1.call_id}}{{1.to}}", "abc", "{{2.call_id}}"):
            res = self.run_f(webhook(), fetch_call(2, value), call_lookup(3), found(reconcile(4, **{F_COST: "{{2.price}}"}), 3))
            self.assertEqual(self.rows(res), [("F2a", 2)], value)

    def test_f2a_the_call_details_module_reads_no_other_request_field(self):
        flow = [webhook(), fetch_call(2), call_lookup(3), found(reconcile(4, **{F_COST: "{{2.price}}"}), 3)]
        flow[1] = filt(flow[1], [[{"a": "{{1.status}}", "b": "completed", "o": "text:equal"}]])
        res = self.run_f(*flow)
        self.assertEqual(self.rows(res), [("F2a", 2)])
        self.assertIn("status", res[0].detail)

    def test_f2a_a_module_that_reads_the_request_before_call_details_fails(self):
        res = self.run_f(webhook(), call_lookup(2, formula="{External Call ID} = '{{1.call_id}}'"), fetch_call(3), found(write_ledger(4), 2))
        self.assertIn(("F2c", 2), self.rows(res))
        self.assertIn("before call-details module 3", [f for f in res if f.module_id == 2 and f.rule == "F2c"][0].detail)

    def test_f2a_call_details_inside_a_route_is_not_on_the_main_flow(self):
        res = self.run_f(webhook(), router(2, [fetch_call(3), call_lookup(4), found(write_ledger(5), 4)], [slack_text(6, "x")]))
        self.assertIn(("F2a", 3), self.rows(res))
        self.assertIn("must be on the main flow", [f for f in res if f.module_id == 3][0].detail)

    def test_f2b_a_write_with_no_lookup_fails_on_that_module(self):
        res = self.run_f(webhook(), fetch_call(2), write_ledger(3, note="{{2.call_id}}"))
        self.assertEqual(self.rows(res), [("F2b", 3)])

    def test_f2b_a_lookup_without_a_found_filter_does_not_gate(self):
        res = self.run_f(webhook(), fetch_call(2), call_lookup(3), write_ledger(4, note="{{2.call_id}}"))
        self.assertEqual(self.rows(res), [("F2b", 4)])
        self.assertTrue(any("has no found filter on this module" in f.detail for f in res))
        # A filter that is not about the lookup, or one OR group without it, does not count.
        for flt in ([[{"a": "{{2.status}}", "o": "exist"}]],
                    [[{"a": "{{3.id}}", "o": "exist"}], [{"a": "{{2.status}}", "b": "x", "o": "text:equal"}]],
                    [[{"a": "{{3.id}}", "b": "x", "o": "text:equal"}]]):
            res = self.run_f(webhook(), fetch_call(2), call_lookup(3), filt(write_ledger(4, note="{{2.call_id}}"), flt))
            self.assertEqual(self.rows(res), [("F2b", 4)], flt)

    def test_f2b_only_the_exact_exist_filter_on_the_lookup_gates(self):
        """R4: a count filter, an extra condition, an OR group or a wrapped reference all let a non-match through."""
        for flt in ([[{"a": "{{3.__IMTLENGTH__}}", "b": "0", "o": "number:greater"}]],
                    [[{"a": "{{3.id}}", "o": "exist"}, {"a": "{{2.status}}", "b": "x", "o": "text:equal"}]],
                    [[{"a": "{{3.id}}", "o": "exist"}], [{"a": "{{2.status}}", "b": "x", "o": "text:equal"}]],
                    [[{"a": '{{ifempty(3.id; "x")}}', "o": "exist"}]],
                    [[{"a": "{{3.name}}", "o": "exist"}]],
                    [[{"a": "{{3.id}}", "o": "notexist"}]]):
            res = self.run_f(webhook(), fetch_call(2), call_lookup(3), filt(write_ledger(4, note="{{2.call_id}}"), flt))
            self.assertEqual(self.rows(res), [("F2b", 4)], flt)

    def test_f2b_the_lookup_must_be_the_pinned_form_on_the_ledger(self):
        """R4: the formula is exactly {External Call ID} = '{{<call-details>.call_id}}' on System Logs."""
        for lk in (call_lookup(3, table="tbl5jVTyUQq7buodU"),                      # Voice AI Ledger, created by this scenario
                   call_lookup(3, formula="{External Call ID} = 'fixed'"),
                   call_lookup(3, formula="{External Call ID} = '{{2.to}}'"),
                   call_lookup(3, table=LEAD),                                      # Applicants is not a ledger row
                   call_lookup(3, module="airtable:ActionGetRecord")):
            res = self.run_f(webhook(), fetch_call(2), lk, found(reconcile(4, **{F_COST: "{{2.price}}"}, note="{{2.call_id}}"), 3))
            self.assertIn(("F2b", 4), self.rows(res), lk["mapper"])
            self.assertNotIn("F2", [f.rule for f in res if f.status == ab.PASS], lk["mapper"])

    def test_f2b_formulas_that_can_match_any_record_are_not_the_pinned_lookup(self):
        """R4 probes: each of these used to PASS."""
        for formula in ("OR({External Call ID}='{{2.call_id}}', TRUE())",
                        "{External Call ID} != '{{2.call_id}}'",
                        "{External Call ID} = {{2.call_id}}",                       # unquoted (E8)
                        "{External ID} = '{{2.call_id}}'",                          # a field System Logs does not have
                        "AND({External Call ID} = '{{2.call_id}}', TRUE()) OR (TRUE())",
                        "AND({External Call ID} = '{{2.call_id}}', TRUE()) OR TRUE(), FALSE())",
                        "AND({External Call ID} = '{{2.call_id}}', {Note} = '{{2.from}}')",   # another reference in the rest
                        "AND({External Call ID} = '{{2.call_id}}',)",
                        "AND(TRUE(), {External Call ID} = '{{2.call_id}}')",
                        "OR({External Call ID} = '{{2.call_id}}', {External Call ID} = 'x')",
                        "{External Call ID} = '{{1.call_id}}'",                     # the request call ID
                        "SEARCH('{{2.call_id}}', {Notes})"):
            res = self.run_f(webhook(), fetch_call(2), call_lookup(3, formula=formula), found(reconcile(4, **{F_COST: "{{2.price}}"}, note="{{2.call_id}}"), 3))
            self.assertIn(("F2b", 4), self.rows(res), formula)

    def test_f2b_a_lookup_may_and_in_literal_clauses(self):
        for formula in ("{External Call ID} = '{{2.call_id}}'",
                        "{External Call ID}='{{ 2.call_id }}'",
                        "AND({External Call ID} = '{{2.call_id}}', {Scenario name} = 'S')",
                        "AND({External Call ID} = '{{2.call_id}}', {Scenario name} = 'S', {Voice AI cost} = BLANK())",
                        "AND({External Call ID} = '{{2.call_id}}', OR({Scenario name} = 'a)', {Scenario name} = 'b'))"):
            flow = [webhook(), fetch_call(2), call_lookup(3, formula=formula), found(reconcile(4, **{F_COST: "{{2.price}}"}, note="{{2.call_id}}"), 3)]
            res = self.run_f(*flow)
            self.assertEqual(self.rows(res), [], formula)   # F2a to F2c accept every one of them
            # F2d wants the unreconciled clause too, so only the formula that has it passes outright.
            verdict = [("F2", ab.PASS)] if "BLANK()" in formula and "= 'S'" in formula else [("F2d", ab.FAIL)]
            self.assertEqual([(f.rule, f.status) for f in res], verdict, formula)

    def test_f2c_a_lookup_keyed_on_the_request_call_id_fails(self):
        """R4: the lookup reads {{call-details.call_id}}, never the request, so a padded ID cannot inject into the formula."""
        flow = [webhook(), fetch_call(2), call_lookup(3, formula="{External Call ID} = '{{1.call_id}}'"),
                found(reconcile(4, **{F_COST: "{{2.price}}"}, note="{{2.call_id}}"), 3)]
        res = self.run_f(*flow)
        self.assertIn(("F2b", 3), self.rows(res))
        self.assertIn(("F2c", 3), self.rows(res))
        flow[2] = call_lookup(3, formula="AND({External Call ID} = '{{2.call_id}}', {Phone} = '{{1.to}}')")
        res = self.run_f(*flow)
        self.assertEqual(self.rows(res), [("F2b", 3), ("F2b", 4), ("F2c", 3)])
        self.assertIn("to", [f for f in res if f.rule == "F2c"][0].detail)

    def test_f2b_a_get_by_id_does_not_gate(self):
        """Decision 2 asks for a ledger row the system created, so a record fetched by an ID from the call is not a gate."""
        get = {"id": 3, "module": "airtable:ActionGetRecord", "mapper": {"table": LEAD, "id": "{{2.metadata.lead_id}}"}}
        res = self.run_f(webhook(), fetch_call(2), get, write_ledger(4, note="{{2.call_id}}"))
        self.assertEqual(self.rows(res), [("F2b", 4)])

    def test_f2b_a_lookup_handler_that_resumes_or_a_fetch_handler_that_resumes_fails(self):
        """R3 probes: both used to PASS."""
        flow = [webhook(), with_handler(fetch_call(2), directive(30, "Resume")), call_lookup(3), found(reconcile(4, **{F_COST: "{{2.price}}"}, note="{{2.call_id}}"), 3)]
        res = self.run_f(*flow)
        self.assertEqual(self.rows(res), [("F2a", 2)])
        self.assertIn("Resume", res[0].detail)
        flow = [webhook(), fetch_call(2), with_handler(call_lookup(3), directive(30, "Resume")), found(reconcile(4, **{F_COST: "{{2.price}}"}, note="{{2.call_id}}"), 3)]
        res = self.run_f(*flow)
        self.assertEqual(self.rows(res), [("F2b", 3), ("F2b", 4)])
        self.assertTrue(any("ends in Resume" in f.detail for f in res))
        for kind in ("Break", "Ignore"):
            flow = [webhook(), with_handler(fetch_call(2), directive(30, kind)), with_handler(call_lookup(3), directive(31, kind)),
                    found(reconcile(4, **{F_COST: "{{2.price}}"}, note="{{2.call_id}}"), 3)]
            self.assertEqual([(f.rule, f.status) for f in self.run_f(*flow)], [("F2", ab.PASS)], kind)

    def test_f2_a_resume_anywhere_in_a_handler_router_fails(self):
        handler = [router(40, [write_ledger(20, note="x"), directive(21, "Break")], [slack_text(22, "y"), directive(23, "Resume")])]
        flow = [webhook(), with_handler(fetch_call(2), *handler), call_lookup(3), found(reconcile(4, **{F_COST: "{{2.price}}"}, note="{{2.call_id}}"), 3)]
        self.assertEqual(self.rows(self.run_f(*flow)), [("F2a", 2)])

    def test_f2b_a_gate_covers_modules_after_it_including_routes_but_not_before(self):
        early = write_ledger(9, note="x")
        flow = [webhook(), fetch_call(2), early, call_lookup(3),
                found(router(4, [write_ledger(5, note="a")], [write_ledger(6, note="b")]), 3)]
        res = self.run_f(*flow)
        self.assertEqual(self.rows(res), [("F2b", 9)])
        # A gate inside one route covers that route only.
        flow = [webhook(), fetch_call(2), router(4, [call_lookup(3), found(write_ledger(5, note="a"), 3)], [write_ledger(6, note="b")])]
        self.assertEqual(self.rows(self.run_f(*flow)), [("F2b", 6)])

    def test_f2b_reads_are_not_writes(self):
        flow = [webhook(), fetch_call(2), {"id": 3, "module": "airtable:ActionSearchRecords", "mapper": {"table": LEAD, "formula": "1"}},
                {"id": 4, "module": "util:FunctionSleep", "mapper": {"duration": "5"}}]
        self.assertEqual([(f.rule, f.status) for f in self.run_f(*flow)], [("F2", ab.PASS)])

    def test_f2b_slack_email_sms_and_llm_modules_are_writes_too(self):
        for mt in ("slack:CreateMessage", "google-email:sendAnEmail", "twilio:SendSMS", "openai-gpt-3:CreateCompletion", "bland:sendACall"):
            flow = [webhook(), fetch_call(2), {"id": 3, "module": mt, "mapper": {}}]
            self.assertEqual(self.rows(self.run_f(*flow)), [("F2b", 3)], mt)

    def test_f2b_error_handlers_of_the_call_details_module_and_the_lookup_are_exempt_from_the_gate(self):
        handler = [write_ledger(20, note="{{var.scenario.executionId}}"), slack_text(21, "scenario Reconcile"), directive(22)]
        flow = [webhook(), with_handler(fetch_call(2), *handler),
                with_handler(call_lookup(3), write_ledger(30, note="{{2.call_id}}"), slack_text(31, "call {{2.call_id}}"), directive(32)),
                found(reconcile(4, **{F_COST: "{{2.price}}"}, note="{{2.call_id}}"), 3)]
        self.assertEqual([(f.rule, f.status) for f in self.run_f(*flow)], [("F2", ab.PASS)])

    def test_f2c_the_fetch_handler_may_not_read_the_request_at_all(self):
        """R1 probe: a handler that wrote {{1.call_id}} to the ledger and to Slack used to PASS. The text is free text from an
        unauthenticated request, so an attacker could put a link or a mention into the ops channel."""
        handler = [write_ledger(20, note="{{1.call_id}}"), slack_text(21, "forged: {{1.call_id}}"), directive(22)]
        flow = [webhook(), with_handler(fetch_call(2), *handler), call_lookup(3), found(reconcile(4, **{F_COST: "{{2.price}}"}, note="{{2.call_id}}"), 3)]
        res = self.run_f(*flow)
        self.assertEqual(self.rows(res), [("F2c", 20), ("F2c", 21)])
        self.assertIn("in an error handler", res[0].detail)
        self.assertIn("var.scenario.executionId", res[0].detail)
        # Any other request field in the handler is a read too.
        handler[0] = write_ledger(20, note="{{1.call_id}} {{1.price}}")
        res = self.run_f(webhook(), with_handler(fetch_call(2), *handler), call_lookup(3), found(reconcile(4, **{F_COST: "{{2.price}}"}, note="{{2.call_id}}"), 3))
        self.assertIn("price", [f for f in res if f.module_id == 20][0].detail)

    def test_f2c_a_lookup_handler_reads_the_call_details_output_not_the_request(self):
        handler = [write_ledger(30, note="{{1.call_id}}"), slack_text(31, "call {{1.call_id}}"), directive(32)]
        flow = [webhook(), fetch_call(2), with_handler(call_lookup(3), *handler), found(reconcile(4, **{F_COST: "{{2.price}}"}, note="{{2.call_id}}"), 3)]
        self.assertEqual(self.rows(self.run_f(*flow)), [("F2c", 30), ("F2c", 31)])
        handler = [write_ledger(30, note="{{2.call_id}}"), slack_text(31, "call {{2.call_id}}"), directive(32)]
        flow = [webhook(), fetch_call(2), with_handler(call_lookup(3), *handler), found(reconcile(4, **{F_COST: "{{2.price}}"}, note="{{2.call_id}}"), 3)]
        self.assertEqual([(f.rule, f.status) for f in self.run_f(*flow)], [("F2", ab.PASS)])

    def test_f2b_a_handler_built_as_a_router_is_still_the_exempt_handler(self):
        """R7 probe: a router inside the fetch or lookup handler used to give F2b and F2c false FAILs."""
        for owner_is_fetch in (True, False):
            inner = router(40, [write_ledger(20, note="{{var.scenario.executionId}}"), slack_text(21, "x"), directive(22)],
                           [slack_text(23, "y"), directive(24)])
            if owner_is_fetch:
                flow = [webhook(), with_handler(fetch_call(2), inner), call_lookup(3), found(reconcile(4, **{F_COST: "{{2.price}}"}, note="{{2.call_id}}"), 3)]
            else:
                flow = [webhook(), fetch_call(2), with_handler(call_lookup(3), inner), found(reconcile(4, **{F_COST: "{{2.price}}"}, note="{{2.call_id}}"), 3)]
            self.assertEqual([(f.rule, f.status) for f in self.run_f(*flow)], [("F2", ab.PASS)], owner_is_fetch)

    def test_f2b_a_router_handler_of_an_ungated_effect_module_is_covered_by_that_modules_row(self):
        """R7: the Interview Room (B) shape, where the handler of the OpenAI module is a router. One row on the owner, none on the router."""
        inner = router(40, [write_ledger(20, note="x"), slack_text(21, "x"), directive(22)])
        flow = [webhook(), fetch_call(2), with_handler({"id": 5, "module": "openai-gpt-3:CreateCompletion", "mapper": {}}, inner)]
        self.assertEqual(self.rows(self.run_f(*flow)), [("F2b", 5)])
        # Where the owner is a read, its handler gets the row.
        search = {"id": 5, "module": "airtable:ActionSearchRecords", "mapper": {"table": LEAD, "formula": "1"}}
        self.assertEqual(self.rows(self.run_f(webhook(), fetch_call(2), with_handler(search, inner))), [("F2b", 5)])

    def test_f2b_an_error_handler_of_an_ungated_module_is_one_row_on_that_module(self):
        search = {"id": 3, "module": "airtable:ActionSearchRecords", "mapper": {"table": LEAD, "formula": "1"}}
        flow = [webhook(), fetch_call(2), with_handler(search, write_ledger(30, note="x"), slack_text(31, "y"), directive(32))]
        res = self.run_f(*flow)
        self.assertEqual(self.rows(res), [("F2b", 3)])
        self.assertIn("[30, 31]", res[0].detail)

    def test_f2c_any_other_request_field_fails_on_the_module_that_reads_it(self):
        flow = good_fetch_back()
        flow[3] = found(reconcile(4, **{F_COST: "{{2.price}}"}, note="{{2.call_id}}", price="{{1.price}}", len="{{1.call_length}}"), 3)
        res = self.run_f(*flow)
        self.assertEqual(self.rows(res), [("F2c", 4)])
        self.assertIn("call_length, price", res[0].detail)
        # The call ID outside the call-details module and the lookup is a request read too.
        flow[3] = found(reconcile(4, **{F_COST: "{{2.price}}"}, note="{{1.call_id}}"), 3)
        self.assertEqual(self.rows(self.run_f(*flow)), [("F2c", 4)])

    def test_f2c_filters_and_parameters_count_as_reads(self):
        flow = good_fetch_back()
        flow.append(filt({"id": 5, "module": "util:FunctionSleep", "mapper": {"duration": "1"}}, [[{"a": "{{1.status}}", "b": "ok", "o": "text:equal"}]]))
        self.assertEqual(self.rows(self.run_f(*flow)), [("F2c", 5)])

    def test_f2c_a_bare_reference_may_resolve_to_the_request_so_it_fails(self):
        """R10 probe: a write mapping {{summary}} after a valid gate used to PASS (E2 alone, and E2 can be allowlisted)."""
        flow = good_fetch_back()
        flow[3] = found(reconcile(4, **{F_COST: "{{2.price}}"}, note="{{summary}}"), 3)
        res = self.run_f(*flow)
        self.assertEqual(self.rows(res), [("F2c", 4)])
        self.assertIn("summary", res[0].detail)
        self.assertIn("call-details module 2", res[0].detail)
        # A bare word inside an expression, and one in a filter, count too. Keywords and var.* do not.
        flow[3] = found(reconcile(4, **{F_COST: "{{2.price}}"}, note='{{if(completed; "a"; "b")}}'), 3)
        self.assertEqual(self.rows(self.run_f(*flow)), [("F2c", 4)])
        flow[3] = found(reconcile(4, **{F_COST: "{{2.price}}"}, note="{{var.scenario.executionId}} {{now}} {{2.call_id}} {{formatDate(now; \"YYYY\")}}"), 3)
        self.assertEqual([(f.rule, f.status) for f in self.run_f(*flow)], [("F2", ab.PASS)])
        # E2 cannot be allowlisted away: the F2c row is a separate rule that no allowlist entry reaches.
        allow = ab.Allowlist([{"check": "E2", "scenario": "5", "module": "4", "match": "summary", "reason": "Intended, resolves to the call"}])
        flow[3] = found(reconcile(4, **{F_COST: "{{2.price}}"}, note="{{summary}}"), 3)
        self.assertEqual(self.rows(self.run_f(*flow, allow=allow)), [("F2c", 4)])

    def test_f2c_an_aggregator_fed_by_the_webhook_reads_the_request(self):
        """R10 probe: parameters.feeder == the trigger used to PASS."""
        flow = good_fetch_back() + [{"id": 5, "module": "builtin:BasicAggregator", "parameters": {"feeder": 1}},
                                    found(write_ledger(6, note="{{5.array}}"), 3)]
        res = self.run_f(*flow)
        self.assertEqual(self.rows(res), [("F2c", 5)])
        self.assertIn("parameters.feeder", res[0].detail)
        flow[4]["parameters"]["feeder"] = 2   # fed by the call-details module instead
        self.assertEqual([(f.rule, f.status) for f in self.run_f(*flow)], [("F2", ab.PASS)])

    def test_f2_a_route_module_reading_the_request_is_found_at_any_depth(self):
        flow = [webhook(), fetch_call(2), call_lookup(3), found(router(4, [write_ledger(5, note="{{1.price}}")], [slack_text(6, "x")]), 3)]
        self.assertEqual(self.rows(self.run_f(*flow)), [("F2c", 5)])

    def test_f2_the_fix_for_a_row_closes_it_and_leaves_the_others(self):
        before = self.run_f(webhook(), fetch_call(2), write_ledger(3, note="{{1.price}}"))
        self.assertEqual(self.rows(before), [("F2b", 3), ("F2c", 3)])
        after = self.run_f(webhook(), fetch_call(2), call_lookup(4), found(reconcile(3, lookup=4, **{F_COST: "{{2.price}}"}, note="{{2.price}}"), 4))
        self.assertEqual([(f.rule, f.status) for f in after], [("F2", ab.PASS)])

    def test_f2_rows_cannot_be_allowlisted(self):
        allow = ab.Allowlist([{"check": "F1", "scenario": "5", "module": "3", "reason": "Not allowed for F2"}])
        res = self.run_f(webhook(), fetch_call(2), write_ledger(3, note="x"), allow=allow)
        self.assertEqual(self.rows(res), [("F2b", 3)])
        with self.assertRaises(ab.InputError):
            with tempfile.TemporaryDirectory() as tmp:
                path = os.path.join(tmp, "allowlist.json")
                with open(path, "w", encoding="utf-8") as fh:
                    json.dump({"entries": [{"check": "F2", "scenario": "5", "module": "3", "reason": "Because I said so"}]}, fh)
                ab.load_allowlist(path)

    def test_out_of_scope_scenarios_are_skipped_by_audit(self):
        labels = ab.Labels(True, {"9": {"name": "Off", "expected_label": None, "out_of_scope": True, "note": "disabled"}})
        b = blueprint("Off", webhook(), slack_text(2, "{{Video}}"), scenario_id="9")
        res = ab.audit([b], labels, schema(), True, None, link_map(), ab.Allowlist(), ab.Webhooks(), None, [])
        self.assertEqual([f for f in res.findings if f.check in "DEF"], [])

    def test_the_audit_reports_f_findings_and_exits_nonzero_when_a_webhook_is_unregistered(self):
        labels = ab.Labels(True, {})
        b = blueprint("S", *good_fetch_back(), scenario_id="5", sequential=True)
        res = ab.audit([b], labels, schema(), False, None, link_map(), ab.Allowlist(), ab.Webhooks(), None, [])
        self.assertEqual([(f.rule, f.status) for f in res.findings if f.check == "F"], [("F0", ab.FAIL)])
        res = ab.audit([b], labels, schema(), False, None, link_map(), ab.Allowlist(), FETCH_REG, None, [])
        self.assertEqual([(f.rule, f.status) for f in res.findings if f.check == "F"], [("F2", ab.PASS)])


class CheckF2dTests(unittest.TestCase):
    """F2d (decided 2026-10-28, tightened after the fixer pass): a fetch-back scenario must not be replayable or
    run early. Every module that writes, sends or spends waits for (a) a completed fetched call and (b) a ledger
    row that is not yet reconciled. The reconciliation is an update of the looked-up row, the first effect after
    both gates, with a Break handler, and the scenario processes one execution at a time. The Bland call-details
    output fields are `status` ("completed") and `completed` (boolean), docs.bland.ai/api-v1/get/calls-id."""

    PIN = "{External Call ID} = '{{2.call_id}}'"
    LBL = "{Scenario name} = 'S'"

    def run_f(self, *flow, links=None, allow=None, sequential=True, reg=FETCH_REG):
        return ab.check_f(blueprint("S", *flow, scenario_id="5", sequential=sequential), allow or ab.Allowlist(), reg, None, links)

    def rows(self, res):
        """F2a to F2c rows."""
        return sorted({(f.rule, f.module_id) for f in res if f.status == ab.FAIL and f.rule != "F2d"})

    def d_rows(self, res):
        return sorted({(f.rule, f.module_id) for f in res if f.status == ab.FAIL and f.rule == "F2d"})

    def flow(self, lookup=None, write=None):
        return [webhook(), fetch_call(2), lookup or call_lookup(3),
                found(write or reconcile(4, note="{{2.call_id}}", **{F_COST: "{{2.price}}"}), 3)]

    def lookup_with(self, *args):
        """A lookup whose formula is the call ID pin plus these top-level arguments."""
        return call_lookup(3, formula="AND(" + ", ".join((self.PIN,) + args) + ")")

    def test_the_verified_flow_passes_with_and_without_the_field_map(self):
        for links in (None, link_map()):
            res = self.run_f(*good_fetch_back(), links=links)
            self.assertEqual([(f.rule, f.status) for f in res], [("F2", ab.PASS)])
            self.assertIn("F2d", res[0].detail)

    # --- (a) completion ----------------------------------------------------------------------

    def test_a_write_with_no_completion_filter_fails_on_that_module(self):
        res = self.run_f(*self.flow(lookup=call_lookup(3, done=False)))
        self.assertEqual(self.d_rows(res), [("F2d", 4)])
        self.assertEqual(self.rows(res), [])
        self.assertIn("{{2.status}}", res[0].detail)
        self.assertIn("completed", res[0].detail)

    def test_the_accepted_completion_filters(self):
        for flt in ([[{"a": "{{2.status}}", "b": "completed", "o": "text:equal"}]],
                    [[{"a": "{{2.status}}", "b": "Completed", "o": "text:equal:ci"}]],
                    [[{"a": "{{ 2.status }}", "b": " completed ", "o": "text:equal"}]],
                    # other conditions in the same AND group only narrow it
                    [[{"a": "{{2.status}}", "b": "completed", "o": "text:equal"}, {"a": "{{2.price}}", "o": "exist"}]]):
            res = self.run_f(*self.flow(lookup=filt(call_lookup(3, done=False), flt)))
            self.assertEqual([(f.rule, f.status) for f in res], [("F2", ab.PASS)], flt)

    def test_filters_that_do_not_require_a_completed_call_do_not_count(self):
        for flt in ([[{"a": "{{2.status}}", "b": "completed", "o": "text:equal"}], [{"a": "{{2.price}}", "o": "exist"}]],   # an OR group skips it
                    [[{"a": "{{2.status}}", "b": "failed", "o": "text:notequal"}]],
                    [[{"a": "{{2.status}}", "b": "complete", "o": "text:equal"}]],
                    [[{"a": "{{2.status}}", "b": "comp", "o": "text:contain"}]],
                    [[{"a": "{{2.status}}", "b": "{{2.price}}", "o": "text:equal"}]],
                    [[{"a": "{{2.completed}}", "b": "false", "o": "boolean:equal"}]],
                    [[{"a": "{{2.completed}}", "b": "true", "o": "boolean:notequal"}]],
                    [[{"a": "{{2.completed}}", "o": "exist"}]],
                    [[{"a": '{{ifempty(2.status; "completed")}}', "b": "completed", "o": "text:equal"}]],
                    [[{"a": "{{2.call_length}}", "b": "completed", "o": "text:equal"}]],
                    [[{"a": "{{3.status}}", "b": "completed", "o": "text:equal"}]],       # another module's field
                    [[{"a": "{{1.status}}", "b": "completed", "o": "text:equal"}]]):     # the request, not the fetched call
            res = self.run_f(*self.flow(lookup=filt(call_lookup(3, done=False), flt)))
            self.assertIn(("F2d", 4), self.d_rows(res), flt)

    def test_m1_ended_statuses_widen_the_gate_only_where_registered(self):
        """F-31.2 (M1, 2026-10-31): Batch Call Reconciliation acts on calls nobody answered, which Bland reports as no-answer,
        busy, failed or canceled. Its registry entry lists those, so one OR group per listed status counts. Every group must
        require a listed status, and without the entry only completed counts."""
        ended = ("completed", "no-answer", "busy", "failed", "canceled")
        reg = ab.Webhooks({"5": ab.WebhookEntry("5", 1, "bland_post_call", "fetch_back", "Called after each call", "S", ended)})
        groups = [[{"a": "{{2.status}}", "b": s, "o": "text:equal"}] for s in ended]
        res = self.run_f(*self.flow(lookup=filt(call_lookup(3, done=False), groups)), reg=reg)
        self.assertEqual([(f.rule, f.status) for f in res], [("F2", ab.PASS)])
        res = self.run_f(*self.flow(lookup=filt(call_lookup(3, done=False), groups)))
        self.assertIn(("F2d", 4), self.d_rows(res))  # the default registry entry keeps completed only
        for bad in (groups + [[{"a": "{{2.price}}", "o": "exist"}]],                       # a group with no status test
                    groups + [[{"a": "{{2.status}}", "b": "in-progress", "o": "text:equal"}]],
                    [[{"a": "{{2.status}}", "b": "queued", "o": "text:equal"}]]):
            res = self.run_f(*self.flow(lookup=filt(call_lookup(3, done=False), bad)), reg=reg)
            self.assertIn(("F2d", 4), self.d_rows(res), bad)

    def test_m1_ended_statuses_registry_validation(self):
        def load(e):
            with tempfile.TemporaryDirectory() as tmp:
                path = os.path.join(tmp, "webhooks.json")
                with open(path, "w", encoding="utf-8") as fh:
                    json.dump({"scenarios": [e]}, fh)
                return ab.load_webhooks(path, required=True)
        ok = {"scenario_id": "5", "hook_id": 7, "caller": "bland_post_call", "protection": "fetch_back", "reason": "Called after each call",
              "lookup_label": "Batch Outbound Caller"}
        self.assertEqual(load(ok).entries["5"].ended_statuses, ("completed",))
        self.assertEqual(load({**ok, "ended_statuses": ["completed", "no-answer"]}).entries["5"].ended_statuses, ("completed", "no-answer"))
        for bad in (["no-answer"], ["completed", "in-progress"], ["completed", "completed"], [], "completed", ["completed", 1]):
            with self.assertRaises(ab.InputError, msg=bad):
                load({**ok, "ended_statuses": bad})
        key_entry = {k: v for k, v in ok.items() if k != "lookup_label"}
        with self.assertRaises(ab.InputError):
            load({**key_entry, "caller": "bland_pathway_node", "protection": "api_key", "ended_statuses": ["completed"]})

    def test_f2d_3_the_boolean_completed_flag_is_not_a_completion_gate(self):
        """Bland sets completed true on calls that failed or were not answered, so a failed call with price 0 passed the gate."""
        flt = [[{"a": "{{2.completed}}", "b": "true", "o": "boolean:equal"}]]
        res = self.run_f(*self.flow(lookup=filt(call_lookup(3, done=False), flt)))
        self.assertIn(("F2d", 4), self.d_rows(res))
        self.assertIn("does not count", res[0].detail)

    def test_a_filter_on_the_call_details_module_itself_is_not_a_gate(self):
        fetch = filt(fetch_call(2), done_filter())
        res = self.run_f(webhook(), fetch, call_lookup(3, done=False), found(reconcile(4, **{F_COST: "{{2.price}}"}), 3))
        self.assertIn(("F2d", 4), self.d_rows(res))

    def test_a_completion_filter_after_the_write_does_not_cover_it(self):
        late = filt(write_ledger(9, note="x"), done_filter())
        res = self.run_f(webhook(), fetch_call(2), call_lookup(3), found(reconcile(4, **{F_COST: "{{2.price}}"}), 3), late)
        self.assertEqual(self.d_rows(res), [])   # 3 gates everything after it, the late filter adds nothing
        res = self.run_f(webhook(), fetch_call(2), call_lookup(3, done=False), found(reconcile(4, **{F_COST: "{{2.price}}"}), 3), late)
        self.assertEqual(self.d_rows(res), [("F2d", 4)])   # the update is ahead of the late filter, the write behind it is covered

    def test_a_completion_gate_in_one_route_covers_that_route_only(self):
        lk = call_lookup(3, done=False)
        flow = [webhook(), fetch_call(2), lk, found(reconcile(7, **{F_COST: "{{2.price}}"}), 3),
                router(4, [filt(write_ledger(5, note="a"), done_filter())], [write_ledger(6, note="b")])]
        rows = self.d_rows(self.run_f(*flow))
        self.assertIn(("F2d", 6), rows)
        self.assertNotIn(("F2d", 5), rows)

    def test_a_filter_before_the_call_details_module_is_not_a_completion_gate(self):
        res = self.run_f(webhook(), filt({"id": 9, "module": "util:FunctionSleep", "mapper": {"duration": "1"}}, done_filter()),
                         fetch_call(2), call_lookup(3, done=False), found(reconcile(4, **{F_COST: "{{2.price}}"}), 3))
        self.assertIn(("F2d", 4), self.d_rows(res))

    def test_the_handler_of_an_ungated_module_is_one_row_on_that_module(self):
        handler = [write_ledger(30, note="x"), slack_text(31, "y"), directive(32)]
        owner = with_handler({"id": 5, "module": "openai-gpt-3:CreateCompletion", "mapper": {}}, *handler)
        upd = reconcile(7, **{F_COST: "{{2.price}}"})
        res = self.run_f(webhook(), fetch_call(2), call_lookup(3, done=False), found(upd, 3), owner)
        self.assertEqual(self.d_rows(res), [("F2d", 5), ("F2d", 7)])
        res = self.run_f(webhook(), fetch_call(2), call_lookup(3), found(upd, 3), owner)
        self.assertEqual(self.d_rows(res), [])

    def test_the_error_handlers_of_the_fetch_and_the_lookup_stay_exempt(self):
        handler = [write_ledger(20, note="{{var.scenario.executionId}}"), slack_text(21, "x"), directive(22)]
        flow = [webhook(), with_handler(fetch_call(2), *handler), with_handler(call_lookup(3), *handler[:1], slack_text(31, "y"), directive(32)),
                found(reconcile(4, **{F_COST: "{{2.price}}"}), 3)]
        self.assertEqual([(f.rule, f.status) for f in self.run_f(*flow)], [("F2", ab.PASS)])

    # --- (b) unreconciled --------------------------------------------------------------------

    def test_a_lookup_without_an_unreconciled_clause_fails_on_the_lookup(self):
        for formula in (self.lookup_with(self.LBL), self.lookup_with(self.LBL, "{Note} = 'x'")):
            res = self.run_f(*self.flow(lookup=formula))
            self.assertEqual(self.d_rows(res), [("F2d", 3)])
            self.assertEqual(self.rows(res), [])
            self.assertIn("unreconciled", res[0].detail)
            self.assertIn("already reconciled", res[0].detail)

    def test_the_accepted_blank_tests(self):
        for test in ("{Voice AI cost} = BLANK()", "{Voice AI cost}=BLANK()", "BLANK() = {Voice AI cost}", "{Voice AI cost} = ''",
                     '{Voice AI cost} = ""', "NOT({Voice AI cost})", "LEN({Voice AI cost}) = 0", "not( {Voice AI cost} )",
                     "LEN({Voice AI cost}&'') = 0", 'LEN( {Voice AI cost} & "" )=0'):
            res = self.run_f(*self.flow(lookup=self.lookup_with("{Note} = 'x, y'", self.LBL, test)))
            self.assertEqual([(f.rule, f.status) for f in res], [("F2", ab.PASS)], test)

    def test_blank_tests_that_restrict_nothing_do_not_count(self):
        for test in ("OR({Voice AI cost} = BLANK(), TRUE())", "{Voice AI cost} != BLANK()", "{Voice AI cost} = BLANK() OR TRUE()",
                     "{Voice AI cost} = 'BLANK()'", "NOT({Voice AI cost}) = FALSE()", "{Voice AI cost} = 0", "{External Call ID} = BLANK()",
                     "IF({Voice AI cost} = BLANK(), TRUE(), TRUE())", "{Voice AI cost}", "LEN({Voice AI cost}&'') > 0"):
            res = self.run_f(*self.flow(lookup=self.lookup_with(self.LBL, test)))
            self.assertEqual(self.d_rows(res), [("F2d", 3)], test)

    def test_the_blank_field_must_be_one_the_scenario_fills_in(self):
        """With the field map: a field the reconciliation update does not set is blank forever, so the clause
        excludes nothing. A field System Logs does not have is an Airtable error."""
        links = link_map()
        res = self.run_f(*self.flow(lookup=self.lookup_with(self.LBL, "{Applicant Link} = BLANK()")), links=links)
        self.assertEqual(self.d_rows(res), [("F2d", 3)])
        self.assertIn("does not set {Applicant Link}", res[0].detail)
        res = self.run_f(*self.flow(lookup=self.lookup_with(self.LBL, "{Reconciled} = BLANK()")), links=links)
        self.assertEqual(self.d_rows(res), [("F2d", 3)])
        self.assertIn("{Reconciled} is not a System Logs field", res[0].detail)
        # The update fills in Voice AI cost, so that field passes.
        res = self.run_f(*self.flow(), links=links)
        self.assertEqual([(f.rule, f.status) for f in res], [("F2", ab.PASS)])
        # An empty value is not a write.
        res = self.run_f(*self.flow(write=reconcile(4, **{F_COST: ""})), links=links)
        self.assertEqual(self.d_rows(res), [("F2d", 3)])
        self.assertIn("does not set {Voice AI cost}", res[0].detail)

    def test_the_pin_field_cannot_be_the_unreconciled_field(self):
        res = self.run_f(*self.flow(lookup=self.lookup_with(self.LBL, "{External Call ID} = BLANK()")), links=link_map())
        self.assertEqual(self.d_rows(res), [("F2d", 3)])
        self.assertIn("is the call ID pin itself", res[0].detail)

    def test_an_unreconciled_filter_after_the_lookup_is_the_other_accepted_form(self):
        sleep = lambda mid: {"id": mid, "module": "util:FunctionSleep", "mapper": {"duration": "1"}}   # noqa: E731
        plain = self.lookup_with(self.LBL)
        empty = [[{"a": "{{3.`Voice AI cost`}}", "o": "notexist"}]]
        write = reconcile(4, **{F_COST: "{{2.price}}"})
        # The filter covers the writes after it. The found filter on the module right after the lookup stays exactly one condition.
        flow = [webhook(), fetch_call(2), plain, found(sleep(5), 3), filt(sleep(6), empty), write]
        for links in (None, link_map()):
            self.assertEqual([(f.rule, f.status) for f in self.run_f(*flow, links=links)], [("F2", ab.PASS)])
        # An update ahead of the filter is not covered, and the row sits on that update.
        early = reconcile(9, **{F_COST: "{{2.price}}"})
        res = self.run_f(webhook(), fetch_call(2), plain, found(early, 3), filt(sleep(6), empty), write_ledger(4, note="x"))
        self.assertEqual(self.d_rows(res), [("F2d", 9)])
        self.assertIn("unreconciled", res[0].detail)
        # Wrong operator, wrong module or a function around the reference do not count, and then the lookup gets its row.
        for bad_filter in ([[{"a": "{{3.`Voice AI cost`}}", "o": "exist"}]],
                           [[{"a": "{{2.`Voice AI cost`}}", "o": "notexist"}]],
                           [[{"a": '{{ifempty(3.`Voice AI cost`; "x")}}', "o": "notexist"}]],
                           [[{"a": "{{3.`Voice AI cost`}}", "o": "notexist"}], [{"a": "{{2.status}}", "o": "exist"}]]):
            res = self.run_f(webhook(), fetch_call(2), plain, found(sleep(5), 3), filt(sleep(6), bad_filter), write)
            self.assertEqual(self.d_rows(res), [("F2d", 3)], bad_filter)

    def test_a_gate_in_a_route_covers_that_route_only_for_unreconciled_too(self):
        lk = self.lookup_with(self.LBL)
        empty = [[{"a": "{{3.`Voice AI cost`}}", "o": "notexist"}]]
        flow = [webhook(), fetch_call(2), lk, found(reconcile(7, **{F_COST: "{{2.price}}"}), 3),
                router(4, [filt(write_ledger(5, note="a"), empty)], [write_ledger(6, note="b")])]
        rows = self.d_rows(self.run_f(*flow))
        self.assertIn(("F2d", 6), rows)
        self.assertNotIn(("F2d", 5), rows)

    # --- the pieces together -----------------------------------------------------------------

    def test_a_write_with_neither_gate_gets_one_row_that_names_both(self):
        sleep = {"id": 5, "module": "util:FunctionSleep", "mapper": {"duration": "1"}}
        lk = call_lookup(3, formula="AND(" + self.PIN + ", " + self.LBL + ")", done=False)
        res = self.run_f(webhook(), fetch_call(2), lk, found(sleep, 3), filt(reconcile(4, **{F_COST: "{{2.price}}"}),
                                                                           [[{"a": "{{3.`Voice AI cost`}}", "o": "notexist"}]]))
        # the unreconciled filter is fine here, the completion gate is missing: one row on the update, none elsewhere
        self.assertEqual(self.d_rows(res), [("F2d", 4)])

    def test_a_lookup_that_is_not_pinned_gets_only_its_f2b_row(self):
        res = self.run_f(webhook(), fetch_call(2), call_lookup(3, formula="OR({External Call ID}='{{2.call_id}}', TRUE())", done=False),
                         found(write_ledger(4, note="{{2.call_id}}"), 3))
        self.assertIn(("F2b", 4), self.rows(res))
        self.assertNotIn(("F2d", 3), self.d_rows(res))   # F2b says the lookup is wrong, F2d adds nothing for a lookup that gates nothing

    def test_no_call_details_module_means_no_f2d_rows(self):
        res = self.run_f(webhook(), write_ledger(3, note="x"), sequential=False)
        self.assertEqual(self.d_rows(res), [])
        self.assertEqual([f.rule for f in res if f.status == ab.FAIL and f.rule == "F2a"], ["F2a"])

    def test_f2d_rows_cannot_be_allowlisted(self):
        for rule in ("F2d", "F2", "F"):
            with self.assertRaises(ab.InputError):
                with tempfile.TemporaryDirectory() as tmp:
                    path = os.path.join(tmp, "allowlist.json")
                    with open(path, "w", encoding="utf-8") as fh:
                        json.dump({"entries": [{"check": rule, "scenario": "5", "module": "4", "reason": "Because I said so"}]}, fh)
                    ab.load_allowlist(path)
        allow = ab.Allowlist([{"check": "E2", "scenario": "5", "module": "4", "match": "x", "reason": "Intended behaviour here"}])
        res = self.run_f(*self.flow(lookup=call_lookup(3, done=False)), allow=allow)
        self.assertEqual(self.d_rows(res), [("F2d", 4)])

    def test_the_real_ledger_field_names_are_known_to_the_field_map(self):
        links = ab.load_links(ab.DEFAULT_LINKS)
        self.assertTrue(links.has_field(ab.LEDGER_TABLE, "Voice AI cost"))
        self.assertTrue(links.has_field(ab.LEDGER_TABLE, ab.LOOKUP_FIELD))
        self.assertTrue(links.has_field(ab.LEDGER_TABLE, ab.LABEL_FIELD_NAME))

    def test_the_report_text_describes_f2d(self):
        self.assertIn("F2d", ab.SECTION_INTRO["F"])
        self.assertIn("completed", ab.SECTION_INTRO["F"])
        self.assertIn("Sequential", ab.SECTION_INTRO["F"])

    # --- F2d-1: the reconciliation must really touch the row the lookup found ----------------------

    def reconciled_by(self, writer, links=None, tail=()):
        return self.run_f(webhook(), fetch_call(2), call_lookup(3), found(writer, 3), *tail, links=links or link_map())

    def test_f2d_1_the_reference_update_passes_and_every_fake_reconciliation_fails(self):
        cost = {F_COST: "{{2.price}}"}
        self.assertEqual([(f.rule, f.status) for f in self.reconciled_by(reconcile(4, **cost))], [("F2", ab.PASS)])
        cases = {
            "a create of a new row": write_ledger(4, **cost),
            "an update of a literal record": reconcile(4, **cost) | {"mapper": {"table": LEDGER, "id": "recABCDEFGHIJKLMN", "record": cost}},
            "an update of another module's record": reconcile(4, lookup=2, **cost),
            "an update of the lookup id with text around it": reconcile(4, **cost) | {"mapper": {"table": LEDGER, "id": "x{{3.id}}", "record": cost}},
            "an update of the wrong table": reconcile(4, **cost) | {"mapper": {"table": LEAD, "id": "{{3.id}}", "record": cost}},
        }
        for name, writer in cases.items():
            res = self.reconciled_by(writer)
            self.assertEqual(self.d_rows(res), [("F2d", 3)], name)
            self.assertRegex(res[0].detail, r"leaves it blank|leaves the looked-up row blank|writes, sends or spends before the reconciliation update", name)

    def test_f2d_1_an_update_on_a_route_that_may_not_run_does_not_count(self):
        cost = {F_COST: "{{2.price}}"}
        never = [[{"a": "{{2.status}}", "b": "never", "o": "text:equal"}]]
        spend = {"id": 7, "module": "openai-gpt-3:CreateCompletion", "mapper": {}}
        r = router(5, [filt(reconcile(6, **cost), never)], [spend])
        res = self.run_f(webhook(), fetch_call(2), call_lookup(3), found(r, 3), links=link_map())
        self.assertEqual(self.d_rows(res), [("F2d", 3)])
        self.assertIn("router 5 sits between", res[0].detail)

    def test_f2d_1_an_update_after_other_effects_does_not_count(self):
        cost = {F_COST: "{{2.price}}"}
        spend = {"id": 7, "module": "openai-gpt-3:CreateCompletion", "mapper": {}}
        late = with_handler(reconcile(8, handler=False, **cost), directive(9, "Ignore"))
        res = self.run_f(webhook(), fetch_call(2), call_lookup(3), found(spend, 3), late, links=link_map())
        self.assertEqual(self.d_rows(res), [("F2d", 3)])
        self.assertIn("module 7 writes, sends or spends before the reconciliation update", res[0].detail)

    def test_f2d_1_the_update_must_fail_loudly_with_a_break_handler(self):
        cost = {F_COST: "{{2.price}}"}
        for name, writer in {
            "no handler": reconcile(4, handler=False, **cost),
            "ignore": with_handler(reconcile(4, handler=False, **cost), slack_text(30, "x"), directive(31, "Ignore")),
            "resume": with_handler(reconcile(4, handler=False, **cost), slack_text(30, "x"), directive(31, "Resume")),
        }.items():
            res = self.reconciled_by(writer)
            self.assertEqual(self.d_rows(res), [("F2d", 3)], name)
            self.assertIn("ends in Break", res[0].detail, name)

    def test_f2d_1_a_filter_between_the_gates_and_the_update_that_is_not_a_gate_fails(self):
        cost = {F_COST: "{{2.price}}"}
        sleep = lambda mid: {"id": mid, "module": "util:FunctionSleep", "mapper": {"duration": "1"}}   # noqa: E731
        other = [[{"a": "{{2.price}}", "o": "exist"}]]
        res = self.run_f(webhook(), fetch_call(2), call_lookup(3), found(sleep(5), 3), filt(reconcile(4, **cost), other), links=link_map())
        self.assertEqual(self.d_rows(res), [("F2d", 3)])
        self.assertIn("carries a filter that is not one of the gates", res[0].detail)

    def test_f2d_1_the_verified_flow_may_keep_searches_and_sleeps_before_the_update(self):
        cost = {F_COST: "{{2.price}}"}
        sleep = {"id": 5, "module": "util:FunctionSleep", "mapper": {"duration": "2"}}
        res = self.run_f(webhook(), fetch_call(2), call_lookup(3), found(sleep, 3), reconcile(4, **cost), write_ledger(6, note="x"), links=link_map())
        self.assertEqual([(f.rule, f.status) for f in res], [("F2", ab.PASS)])

    # --- F2d-2: no concurrent replays --------------------------------------------------------------

    def test_f2d_2_a_fetch_back_scenario_must_process_one_execution_at_a_time(self):
        res = self.run_f(*good_fetch_back(), sequential=False)
        self.assertEqual(self.d_rows(res), [("F2d", 1)])
        self.assertIn("Sequential processing is off", res[0].detail)
        self.assertIn("make_push cannot change", res[0].detail)
        for meta in ({}, {"scenario": {}}, {"scenario": {"sequential": False}}, {"scenario": {"sequential": "true"}}):
            b = blueprint("S", *good_fetch_back(), scenario_id="5")
            b.bp["metadata"] = meta
            res = ab.check_f(b, ab.Allowlist(), FETCH_REG, None, None)
            self.assertEqual(self.d_rows(res), [("F2d", 1)], meta)
        res = self.run_f(*good_fetch_back(), sequential=True)
        self.assertEqual([(f.rule, f.status) for f in res], [("F2", ab.PASS)])

    def test_f2d_2_the_sequential_row_cannot_be_allowlisted(self):
        allow = ab.Allowlist([{"check": "E2", "scenario": "5", "module": "1", "match": "x", "reason": "Intended behaviour here"}])
        res = self.run_f(*good_fetch_back(), sequential=False, allow=allow)
        self.assertEqual(self.d_rows(res), [("F2d", 1)])

    # --- F2d-3: a recorded 0 is not blank, and a failed call is not completed ----------------------

    def numeric_links(self):
        links = link_map()
        links.numeric_fields = {LEDGER: ["Voice AI cost"]}
        return links

    def test_f2d_3_a_number_field_needs_the_length_test_because_airtable_reads_zero_as_blank(self):
        links = self.numeric_links()
        for test in ("{Voice AI cost} = BLANK()", "NOT({Voice AI cost})", "{Voice AI cost} = ''", "LEN({Voice AI cost}) = 0", "BLANK() = {Voice AI cost}"):
            res = self.run_f(*self.flow(lookup=self.lookup_with(self.LBL, test)), links=links)
            self.assertEqual(self.d_rows(res), [("F2d", 3)], test)
            self.assertIn("reads 0 as blank", res[0].detail, test)
        res = self.run_f(*self.flow(lookup=self.lookup_with(self.LBL, "LEN({Voice AI cost}&'') = 0")), links=links)
        self.assertEqual([(f.rule, f.status) for f in res], [("F2", ab.PASS)])

    def test_f2d_3_the_notexist_filter_form_is_not_accepted_on_a_number_field(self):
        links = self.numeric_links()
        sleep = lambda mid: {"id": mid, "module": "util:FunctionSleep", "mapper": {"duration": "1"}}   # noqa: E731
        empty = [[{"a": "{{3.`Voice AI cost`}}", "o": "notexist"}]]
        flow = [webhook(), fetch_call(2), self.lookup_with(self.LBL), found(sleep(5), 3), filt(sleep(6), empty), reconcile(4, **{F_COST: "{{2.price}}"})]
        res = self.run_f(*flow, links=links)
        self.assertEqual(self.d_rows(res), [("F2d", 3)])
        self.assertIn("reads 0 as blank", res[0].detail)

    def test_f2d_3_a_text_marker_may_use_the_plain_blank_tests(self):
        """Applicant Link is not a number field, so the plain test is fine when the update sets it."""
        links = self.numeric_links()
        marker = reconcile(4, **{ab.LEAD_LINK_FIELD: ["{{2.call_id}}"]})
        res = self.run_f(*self.flow(lookup=self.lookup_with(self.LBL, "{Applicant Link} = BLANK()"), write=marker), links=links)
        self.assertEqual([(f.rule, f.status) for f in res], [("F2", ab.PASS)])

    def test_the_real_voice_ai_cost_field_is_recorded_as_a_number_field(self):
        links = ab.load_links(ab.DEFAULT_LINKS)
        self.assertIn("Voice AI cost", links.numeric_fields.get(ab.LEDGER_TABLE, []))

    # --- F2d-4: exactly the one row of the calling scenario ----------------------------------------

    def test_f2d_4_the_lookup_returns_one_record(self):
        for mr in ("10", 10, "", None, "2"):
            res = self.run_f(*self.flow(lookup=call_lookup(3, max_records=mr)))
            self.assertEqual(self.d_rows(res), [("F2d", 3)], mr)
            self.assertIn("maxRecords", res[0].detail)
        for mr in ("1", 1):
            res = self.run_f(*self.flow(lookup=call_lookup(3, max_records=mr)))
            self.assertEqual([(f.rule, f.status) for f in res], [("F2", ab.PASS)], mr)

    def test_f2d_4_the_lookup_pins_the_row_kind_of_the_calling_scenario(self):
        for formula in ("AND(" + self.PIN + ", {Voice AI cost} = BLANK())",                                            # no row kind
                        "AND(" + self.PIN + ", {Scenario name} = 'Other', {Voice AI cost} = BLANK())",                 # another scenario's rows
                        "AND(" + self.PIN + ", OR({Scenario name} = 'S', TRUE()), {Voice AI cost} = BLANK())",         # nested in an OR
                        "AND(" + self.PIN + ", {Scenario name} != 'S', {Voice AI cost} = BLANK())",
                        "AND(" + self.PIN + ", {Scenario name} = 'SS', {Voice AI cost} = BLANK())"):
            res = self.run_f(*self.flow(lookup=call_lookup(3, formula=formula)))
            self.assertEqual(self.d_rows(res), [("F2d", 3)], formula)
            self.assertIn("pin the row kind", res[0].detail, formula)
        for formula in ("AND(" + self.PIN + ', {Scenario name} = "S", {Voice AI cost} = BLANK())',
                        "AND( " + self.PIN + ",{Scenario  name}  =  'S' , {Voice AI cost} = BLANK() )"):
            res = self.run_f(*self.flow(lookup=call_lookup(3, formula=formula)))
            self.assertEqual([(f.rule, f.status) for f in res], [("F2", ab.PASS)], formula)

    def test_f2d_4_the_registry_names_the_label_and_a_missing_one_fails(self):
        reg = ab.Webhooks({"5": ab.WebhookEntry("5", 1, "bland_post_call", "fetch_back", "A sentence of reason", "")})
        res = self.run_f(*good_fetch_back(), reg=reg)
        self.assertEqual(self.d_rows(res), [("F2d", 3)])
        self.assertIn("no lookup_label", res[0].detail)
        other = registry(("5", 1, "bland_post_call", "fetch_back"))
        other.entries["5"].lookup_label = "Other"
        res = self.run_f(*good_fetch_back(), reg=other)
        self.assertIn("{Scenario name} = 'Other'", res[0].detail)

    def test_f2d_4_the_real_registry_labels_are_ledger_label_options(self):
        reg = ab.load_webhooks(ab.DEFAULT_WEBHOOKS, required=True)
        options = set(ab.load_schema(os.path.join(ROOT, "audit", "airtable_ledger_schema.json")).label_options)
        for sid, e in reg.entries.items():
            if e.protection == "fetch_back":
                self.assertIn(e.lookup_label, options, sid)
        self.assertEqual({sid: e.lookup_label for sid, e in reg.entries.items() if e.protection == "fetch_back"},
                         {"4218934": "Campaign Launcher", "4226754": "Email leads to Instant email and call (VIP Clients)",
                          "3975156": "The Interview Room (A)", "6847022": "Batch Outbound Caller"})


class HookInfoTests(unittest.TestCase):
    def load(self, manifest):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "manifest.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(manifest, fh)
            return ab.load_hooks_info(path)

    def test_hooks_come_from_the_manifest_and_null_or_absent_means_unknown(self):
        info = self.load({"hooks": [{"id": 4, "apikey_count": 1}]})
        self.assertTrue(info.available)
        self.assertEqual(info.by_id[4]["apikey_count"], 1)
        for manifest in ({"hooks": None, "hooks_note": "403 note"}, {"scenarios": []}):
            info = self.load(manifest)
            self.assertFalse(info.available)
        self.assertEqual(self.load({"hooks": None, "hooks_note": "403 note"}).note, "403 note")
        self.assertFalse(ab.load_hooks_info(None).available)
        self.assertFalse(ab.load_hooks_info(os.path.join(FIX, "nope.json")).available)


class CheckDAllowlistTests(unittest.TestCase):
    """audit/secret_allowlist.json turns a pinned Make webhook URL into INFO while the hook it targets passes F2."""

    URL = "https://hook." + "us2.make.com/" + "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"

    def send_call(self, mid=7, webhook_url=None):
        return {"id": mid, "module": "bland:sendACall", "mapper": {"task": "hi", "webhook": webhook_url or self.URL}}

    ENTRY = {"scenario_id": "5", "module_id": 7, "pattern_type": "make_webhook_url",
             "reason": "Points at the fetch-back hook", "requires_fetch_back_hook": "6",
             "token_sha256": hashlib.sha256(b"a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6").hexdigest()}

    def audit(self, allow, receiver_flow, partial=False):
        sender = blueprint("Sender", trigger(), self.send_call(), scenario_id="5")
        receiver = blueprint("Receiver", *receiver_flow, scenario_id="6", sequential=True)
        labels = ab.Labels(True, {})
        reg = registry(("6", 1, "bland_post_call", "fetch_back"))
        return ab.audit([sender, receiver], labels, schema(), False, None, link_map(), ab.Allowlist(), reg, None, allow, partial=partial)

    def d_rows(self, res):
        return [(f.status, f.module_id, f.allowlisted) for f in res.findings if f.check == "D"]

    def test_an_unlisted_url_is_a_fail(self):
        res = self.audit([], good_fetch_back())
        self.assertEqual(self.d_rows(res), [(ab.FAIL, 7, False)])
        self.assertNotIn("a1b2c3d4", " ".join(f.detail for f in res.findings))

    def test_a_pinned_url_is_info_while_the_target_passes_f2(self):
        res = self.audit([self.ENTRY], good_fetch_back())
        self.assertEqual(self.d_rows(res), [(ab.INFO, 7, True)])
        detail = [f.detail for f in res.findings if f.check == "D"][0]
        self.assertIn("allowlisted: Points at the fetch-back hook", detail)
        self.assertNotIn("a1b2c3d4", detail)
        self.assertEqual(res.unused_secret_allowlist, [])

    def test_the_allowance_becomes_a_fail_when_the_target_does_not_pass_f2(self):
        res = self.audit([self.ENTRY], [webhook(), write_ledger(2, note="{{1.price}}")])
        self.assertEqual(self.d_rows(res), [(ab.FAIL, 7, False)])
        detail = [f.detail for f in res.findings if f.check == "D"][0]
        self.assertIn("Scenario 6 does not pass check F2", detail)

    def test_a_target_that_is_not_a_fetch_back_webhook_scenario_fails(self):
        res = self.audit([{**self.ENTRY, "requires_fetch_back_hook": "99"}], good_fetch_back())
        self.assertEqual(self.d_rows(res), [(ab.FAIL, 7, False)])
        self.assertIn("not an audited fetch_back webhook scenario", [f.detail for f in res.findings if f.check == "D"][0])

    def test_a_single_scenario_run_reports_info_and_does_not_evaluate_the_target(self):
        res = self.audit([self.ENTRY], [webhook(), write_ledger(2, note="{{1.price}}")], partial=True)
        self.assertEqual(self.d_rows(res), [(ab.INFO, 7, True)])
        self.assertIn("not evaluated in a single-scenario run", [f.detail for f in res.findings if f.check == "D"][0])

    def test_an_entry_excuses_one_url_in_the_named_module_only(self):
        sender = blueprint("Sender", trigger(), self.send_call(7), self.send_call(8), self.send_call(9, "https://hook." + "us2.make.com/" + "z" * 8 + "y1b2c3d4e5f6g7h8i9"), scenario_id="5")
        res = ab.audit([sender, blueprint("Receiver", *good_fetch_back(), scenario_id="6", sequential=True)], ab.Labels(True, {}), schema(), False, None,
                       link_map(), ab.Allowlist(), registry(("6", 1, "bland_post_call", "fetch_back")), None, [self.ENTRY])
        self.assertEqual(sorted(self.d_rows(res)), [(ab.FAIL, 8, False), (ab.FAIL, 9, False), (ab.INFO, 7, True)])

    def test_other_pattern_types_and_locations_are_never_excused(self):
        key = "sk" + "_live_" + "A1b2C3d4E5f6G7h8J9k0L1m2"
        sender = blueprint("Sender", trigger(), {"id": 7, "module": "bland:sendACall", "mapper": {"webhook": self.URL, "task": key}}, scenario_id="5")
        res = ab.audit([sender, blueprint("Receiver", *good_fetch_back(), scenario_id="6", sequential=True)], ab.Labels(True, {}), schema(), False, None,
                       link_map(), ab.Allowlist(), registry(("6", 1, "bland_post_call", "fetch_back")), None, [self.ENTRY])
        self.assertEqual(sorted(self.d_rows(res)), [(ab.FAIL, 7, False), (ab.INFO, 7, True)])
        # The URL in the task text, or in another module type, is not the pinned field.
        other = blueprint("Sender", trigger(), {"id": 7, "module": "slack:CreateMessage", "mapper": {"webhook": self.URL}}, scenario_id="5")
        res = ab.audit([other, blueprint("Receiver", *good_fetch_back(), scenario_id="6", sequential=True)], ab.Labels(True, {}), schema(), False, None,
                       link_map(), ab.Allowlist(), registry(("6", 1, "bland_post_call", "fetch_back")), None, [self.ENTRY])
        self.assertEqual(self.d_rows(res), [(ab.FAIL, 7, False)])
        self.assertEqual(len(res.unused_secret_allowlist), 1)

    def test_an_entry_that_matches_nothing_is_reported_as_unused(self):
        sender = blueprint("Sender", trigger(), {"id": 7, "module": "bland:sendACall", "mapper": {"webhook": ""}}, scenario_id="5")
        res = ab.audit([sender], ab.Labels(True, {}), schema(), False, None, link_map(), ab.Allowlist(), ab.Webhooks(), None, [self.ENTRY])
        self.assertEqual([e["module_id"] for e in res.unused_secret_allowlist], [7])
        self.assertIn("Secret allowlist entry matched nothing", ab.render_summary(res, "x"))

    def test_the_real_allowlist_names_four_send_call_modules(self):
        import secret_scan
        entries = secret_scan.load_secret_allowlist()
        self.assertEqual([(e["scenario_id"], e["module_id"], e["requires_fetch_back_hook"]) for e in entries],
                         [("3961751", 7, "4218934"), ("3975140", 2, "3975156"), ("3920821", 103, "4226754"),
                          ("3953105", 32, "6847022")])  # X-41.7, X-41.10, X-46 moved 3 to Create a Call 32


class CheckE8Tests(unittest.TestCase):
    """sem-R2: an Airtable formula that names a missing field makes Airtable reject the filter."""

    def search(self, formula, table=LEAD, mid=2, **kw):
        return {"id": mid, "module": "airtable:ActionSearchRecords", "mapper": {"table": table, "formula": formula}, **kw}

    def test_a_field_the_table_does_not_have_fails_with_the_closest_name(self):
        res = run_e(trigger(), self.search("AND({Name} = 'x', {Phone Number} != '')"))
        fails = rule(res, "E8", ab.FAIL)
        self.assertEqual(len(fails), 1)
        self.assertEqual(fails[0].module_id, 2)
        self.assertIn("{Phone Number}", fails[0].detail)
        self.assertIn("Applicants", fails[0].detail)
        self.assertIn("Closest fields: Phone", fails[0].detail)

    def test_trigger_formulas_in_parameters_are_checked_too(self):
        watch = {"id": 1, "module": "airtable:TriggerWatchRecords", "parameters": {"table": LEAD, "formula": "{Mock Status} = 'Ready'"}}
        res = run_e(watch, slack_text(2, "x"))
        self.assertEqual([f.module_id for f in rule(res, "E8", ab.FAIL)], [1])
        self.assertIn("parameters.formula", rule(res, "E8", ab.FAIL)[0].detail)

    def test_real_fields_field_ids_and_quoted_values_pass(self):
        for formula in ("{Name} = '{{1.x}}'", '{Name} = "{{1.x}}"', "{" + F_NAME + "} = 'a'", "AND({Phone} = '{{1.phone}}', {Status} != '')",
                        "{Status} = '{not a field}'", "{Name} = '{{formatDate(now; \"YYYY\")}}'", "{Name} = 'it\\'s {fine}'", ""):
            with self.subTest(formula=formula):
                self.assertEqual(rule(run_e(trigger(), self.search(formula)), "E8"), [], formula)

    def test_an_unquoted_mapping_fails_unless_the_field_is_numeric(self):
        res = run_e(trigger(), self.search("{Name} = {{1.call_id}}"))
        fails = rule(res, "E8", ab.FAIL)
        self.assertEqual(len(fails), 1)
        self.assertIn("outside quotes", fails[0].detail)
        numeric = ab.AirtableMap(tables=link_map().tables, pii_fields={}, numeric_fields={LEAD: ["Name"]})
        b = blueprint("S", trigger(), self.search("{Name} = {{1.call_id}}"))
        self.assertEqual(rule(ab.check_e(b, numeric, ab.Allowlist()), "E8"), [])

    def test_unknown_tables_and_other_modules_are_not_checked(self):
        self.assertEqual(rule(run_e(trigger(), self.search("{Whatever} = 'x'", table="tblUNKNOWN0000000")), "E8"), [])
        other = {"id": 2, "module": "slack:CreateMessage", "mapper": {"table": LEAD, "formula": "{Nope} = 'x'"}}
        self.assertEqual(rule(run_e(trigger(), other), "E8"), [])

    def test_the_live_failures_are_caught_on_the_repo_map(self):
        links = ab.load_links(ab.DEFAULT_LINKS, required=True)
        system_logs = "tblf73Cdii3CsLKfL"
        bad = {"id": 3, "module": "airtable:ActionSearchRecords", "mapper": {"table": system_logs, "formula": "{External ID} = {{1.call_id}}"}}
        good = {"id": 3, "module": "airtable:ActionSearchRecords", "mapper": {"table": system_logs, "formula": "{External Call ID} = '{{1.call_id}}'"}}
        self.assertEqual(len(rule(ab.check_e(blueprint("S", webhook(), bad), links, ab.Allowlist()), "E8", ab.FAIL)), 2)
        self.assertEqual(rule(ab.check_e(blueprint("S", webhook(), good), links, ab.Allowlist()), "E8"), [])
        room = {"id": 1, "module": "airtable:TriggerWatchRecords",
                "parameters": {"table": LEAD, "formula": "AND({Mock Interview Status} = 'Ready to Call', {Phone Number} != '')"}}
        self.assertEqual(len(rule(ab.check_e(blueprint("S", room, slack_text(2, "x")), links, ab.Allowlist()), "E8", ab.FAIL)), 1)

    def test_allowlist_pins_an_e8_entry_to_the_text_it_excuses(self):
        allow = ab.Allowlist([{"check": "E8", "scenario": "7", "module": "2", "match": "{Legacy}", "reason": "Field arrives with the next sync"}])
        b = blueprint("S", trigger(), self.search("{Legacy} = 'x'"), scenario_id="7")
        res = rule(ab.check_e(b, link_map(), allow), "E8")
        self.assertEqual([f.status for f in res], [ab.INFO])
        b = blueprint("S", trigger(), self.search("AND({Legacy} = 'x', {Other} = 'y')"), scenario_id="7")
        res = rule(ab.check_e(b, link_map(), allow), "E8")
        self.assertEqual(sorted(f.status for f in res), [ab.FAIL, ab.INFO])


class AllowlistAndLinksTests(unittest.TestCase):
    """safety-R5 and safety-R10."""

    REC = "rec" + "A1b2C3d4E5f6G7"

    def load(self, *entries):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "allowlist.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"entries": list(entries)}, fh)
            return ab.load_allowlist(path)

    def good(self, **kw):
        e = {"check": "E4", "scenario": "1", "module": 2, "record_id": self.REC, "reason": "Configuration singleton by design"}
        e.update(kw)
        return e

    def test_an_e4_entry_without_a_record_id_is_refused(self):
        for rid in (None, "", "  ", "rec1", 5):
            e = self.good()
            e["record_id"] = rid
            with self.assertRaises(ab.InputError, msg=rid):
                self.load(e)
        e = self.good()
        del e["record_id"]
        with self.assertRaises(ab.InputError):
            self.load(e)

    def test_unknown_rule_ids_are_refused(self):
        for check in ("E9", "E0", "A1", "E", "e4", "F1", "F2", "X-41"):
            with self.assertRaises(ab.InputError, msg=check):
                self.load(self.good(check=check))
        for check in ("E1", "E2", "E3", "E5", "E6", "E7", "E8"):
            e = {"check": check, "scenario": "1", "module": 2, "reason": "Verified by hand on 2026-10-28", "match": "{{1.x}}"}
            self.assertEqual(self.load(e).entries[0]["check"], check)

    def test_per_reference_rules_must_pin_a_match_text(self):
        for check in ab.ALLOW_NEEDS_MATCH:
            with self.assertRaises(ab.InputError, msg=check):
                self.load({"check": check, "scenario": "1", "module": 2, "reason": "Verified by hand"})
            with self.assertRaises(ab.InputError, msg=check):
                self.load({"check": check, "scenario": "1", "module": 2, "reason": "Verified by hand", "match": "  "})

    def test_a_placeholder_reason_is_refused(self):
        for reason in (".", "x", "ok", "12345678", "  ", "..........", "a b"):
            with self.assertRaises(ab.InputError, msg=reason):
                self.load(self.good(reason=reason))

    def test_a_record_id_on_a_non_e4_entry_is_refused(self):
        with self.assertRaises(ab.InputError):
            self.load({"check": "E5", "scenario": "1", "module": 2, "record_id": self.REC, "reason": "Verified by hand"})

    def test_an_e6_entry_hides_only_the_field_it_names(self):
        allow = ab.Allowlist([{"check": "E6", "scenario": "5", "module": "3", "match": "{{2.Name}}", "reason": "Internal channel, reviewed"}])
        search = at_search(2, LEAD, fields=("id", "Name", "Phone"))
        b = blueprint("S", trigger(), search, slack_text(3, "{{2.Name}} {{2.Phone}}"), scenario_id="5")
        res = rule(ab.check_e(b, link_map(), allow), "E6")
        self.assertEqual(sorted(f.status for f in res), [ab.FAIL, ab.INFO])
        self.assertIn("{{2.Phone}}", [f for f in res if f.status == ab.FAIL][0].detail)

    def test_unused_entries_are_reported_for_audited_scenarios_only(self):
        allow = ab.Allowlist([
            {"check": "E4", "scenario": "5", "module": "2", "record_id": self.REC, "reason": "Singleton by design"},
            {"check": "E4", "scenario": "5", "module": "9", "record_id": self.REC, "reason": "Singleton by design"},
            {"check": "E4", "scenario": "6", "module": "2", "record_id": self.REC, "reason": "Singleton by design"}])
        b = blueprint("S", trigger(), at_get(2, CONFIG, self.REC), scenario_id="5")
        res = ab.audit([b], ab.Labels(True, {}), schema(), True, None, link_map(), allow)
        self.assertEqual([(e["scenario"], e["module"]) for e in res.unused_allowlist], [("5", "9")])

    def test_summary_counts_allowlisted_rows_apart_from_skips(self):
        allow = ab.Allowlist([{"check": "E4", "scenario": "5", "module": "2", "record_id": self.REC, "reason": "Singleton by design"},
                              {"check": "E4", "scenario": "5", "module": "7", "record_id": self.REC, "reason": "Singleton by design"}])
        skip = {"id": 3, "module": "bland:getCallDetails", "mapper": {}}
        b = blueprint("S", trigger(), at_get(2, CONFIG, self.REC), skip, slack_text(4, "{{3.x}}"), scenario_id="5")
        res = ab.audit([b], ab.Labels(True, {}), schema(), True, None, link_map(), allow)
        text = ab.render_summary(res, "note")
        self.assertIn("Allowlisted (shown as INFO): E 1", text)
        self.assertIn("Allowlist entry matched nothing: E4 scenario 5 module 7", text)
        self.assertGreaterEqual(res.count("E", ab.INFO), 2)   # the allowlisted row and the interface skip

    def write_links(self, doc):
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        path = os.path.join(tmp, "links.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh)
        return path

    def test_a_malformed_links_map_is_an_input_error_not_a_traceback(self):
        ok = {"name": "T", "fields": {"fldA": "A"}, "links": {"fldA": {"name": "A", "target": "tblB"}}}
        bad_docs = (
            {"tables": {"tblA": ["x"]}},
            {"tables": {"tblA": {"name": "T", "fields": ["a"]}}},
            {"tables": {"tblA": {"name": "T"}}},
            {"tables": {"tblA": {"fields": {}}}},
            {"tables": {"tblA": {"name": "T", "fields": {}, "links": ["x"]}}},
            {"tables": {"tblA": {"name": "T", "fields": {}, "links": {"fldA": "tblB"}}}},
            {"tables": {"tblA": {"name": "T", "fields": {}, "links": {"fldA": {"name": "A"}}}}},
            {"tables": {"tblA": ok}, "pii_fields": ["Name"]},
            {"tables": {"tblA": ok}, "pii_fields": {"tblA": "Name"}},
            {"tables": {"tblA": ok}, "non_airtable_pii": {"google-email:x": [1]}},
            {"tables": {"tblA": ok}, "numeric_fields": []},
        )
        for doc in bad_docs:
            path = self.write_links(doc)
            with self.assertRaises(ab.InputError, msg=doc):
                ab.load_links(path)
            code, _out, err = run_main("--dir", BP_DIR, "--labels", LABELS_OK, "--schema", SCHEMA, "--links", path, "--no-report")
            self.assertEqual(code, 2)
            self.assertNotIn("Traceback", err)
        good = ab.load_links(self.write_links({"tables": {"tblA": ok}}))
        self.assertEqual(good.link_target("tblA", "fldA"), "tblB")

    def test_the_repo_links_and_allowlist_still_load(self):
        links = ab.load_links(ab.DEFAULT_LINKS, required=True)
        self.assertIn("Phone", links.tables[LEAD]["fields"].values())
        allow = ab.load_allowlist(ab.DEFAULT_ALLOWLIST)
        self.assertTrue(all(e["check"] == "E4" and e["record_id"] for e in allow.entries))


class CheckEFOutputTests(unittest.TestCase):
    def bp_dir(self, tmp, flow):
        with open(os.path.join(tmp, "b.json"), "w", encoding="utf-8") as fh:
            json.dump({"name": "Batch Outbound Caller", "metadata": {}, "flow": flow}, fh)

    def test_e_and_f_fails_set_exit_code_and_fill_the_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.bp_dir(tmp, [webhook(), slack_text(2, "{{Video}}")])
            code, out, _ = run_main("--dir", tmp, "--labels", LABELS_OK, "--schema", SCHEMA, "--reports-dir", tmp,
                                    "--report-date", "2026-10-28", "--allowlist", os.path.join(tmp, "none.json"))
            self.assertEqual(code, 1)
            self.assertRegex(out, r"E  Mapping integrity\s+FAIL 1")
            self.assertRegex(out, r"F  Webhook authentication\s+FAIL 1")
            with open(os.path.join(tmp, "2026-10-28.md"), encoding="utf-8") as fh:
                report = fh.read()
            self.assertIn("## E. Mapping integrity", report)
            self.assertIn("## F. Webhook authentication", report)
            self.assertIn("E2 Bare reference", report)
            self.assertIn("| E. Mapping integrity |", report)
            self.assertNotIn(";", report)
            self.assertNotIn("—", report)

    def test_clean_blueprint_has_no_e_or_f_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.bp_dir(tmp, [trigger(), slack_text(2, "{{1.id}}")])
            _code, out, _ = run_main("--dir", tmp, "--labels", LABELS_OK, "--schema", SCHEMA, "--no-report")
            self.assertRegex(out, r"E  Mapping integrity\s+FAIL 0")
            self.assertRegex(out, r"F  Webhook authentication\s+FAIL 0")

    def test_check_list_has_titles_and_intros_for_every_check(self):
        self.assertEqual(ab.CHECKS, "ABCDEFLMPRS")
        for c in ab.CHECKS:
            self.assertIn(c, ab.CHECK_TITLES)
            self.assertIn(c, ab.SECTION_INTRO)


if __name__ == "__main__":
    unittest.main()
