"""Activation-blocker rules (decided 2026-10-29): F3 duplicate delivery on api_key webhooks (X-43), E9 conflicting router
routes (X-44) and E10 the Voice AI Ledger cost contract (X-45). Synthetic fixtures shaped like the live modules they
were measured on (Pending Call 3943741, The Interview Room (B) Grader 3975156, both reconciliation triggers). No network.
"""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import audit_blueprints as ab  # noqa: E402
import make_push  # noqa: E402

LEDGER = ab.LEDGER_TABLE
LEAD = ab.LEAD_TABLE
VOICE = ab.VOICE_LEDGER_TABLE
LABEL = "Automating 'Pending Call' Clients"
OK = "{Execution Status} = 'Success'"
PIN = f"AND({{External Call ID}} = '{{{{1.id}}}}', {{Scenario name}} = \"{LABEL}\", {OK})"
MOCK_STATUS = "fldYSv9WR2uwFZxVa"


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------


def bp(*flow, sid="3943741", sequential=True, name="Pending Call"):
    meta = {"scenario": {"sequential": sequential}}
    return ab.Blueprint(name=name, scenario_id=sid, source="test", bp={"name": name, "flow": list(flow), "metadata": meta})


def hook(mid=1, hid=1773988):
    return {"id": mid, "module": "gateway:CustomWebHook", "parameters": {"hook": hid}}


def details(mid=5, feed="{{1.id}}"):
    return {"id": mid, "module": "bland:getCallDetails", "mapper": {"call_id": feed}}


def search(mid, table, formula, *handler):
    m = {"id": mid, "module": "airtable:ActionSearchRecords", "mapper": {"table": table, "formula": formula}}
    if handler:
        m["onerror"] = list(handler)
    return m


def agg(mid, feeder):
    return {"id": mid, "module": "builtin:BasicAggregator", "parameters": {"feeder": feeder}, "mapper": {"id": f"{{{{{feeder}.id}}}}"}}


def filt(m, conditions):
    m = dict(m)
    m["filter"] = {"name": "f", "conditions": conditions}
    return m


def empty_test(aid):
    return [[{"a": f"{{{{first(map({aid}.array; \"id\"))}}}}", "o": "notexist"}]]


def openai(mid):
    return {"id": mid, "module": "openai-gpt-3:CreateCompletion", "mapper": {"model": "x"}}


def email(mid):
    return {"id": mid, "module": "google-email:sendAnEmail", "mapper": {"to": "{{7.Email}}"}}


def sms(mid):
    return {"id": mid, "module": "twilio:SendSMS", "mapper": {"to": "{{1.phone}}"}}


def status(mid):
    return {"id": mid, "module": "airtable:ActionUpdateRecords", "mapper": {"table": LEAD, "id": "{{7.id}}", "record": {ab.STATUS_FIELD: "{{1.status}}"}}}


def marker(mid, call="{{1.id}}", label=LABEL, outcome="Success"):
    return {"id": mid, "module": "airtable:ActionCreateRecord",
            "mapper": {"table": LEDGER, "record": {ab.LABEL_FIELD: label, ab.CALL_ID_FIELD: call, ab.OUTCOME_FIELD: outcome}}}


def router(mid, *routes, fallback=None):
    m = {"id": mid, "module": "builtin:BasicRouter", "routes": [{"flow": list(r)} for r in routes]}
    if fallback is not None:
        m["parameters"] = {"else": fallback}
    return m


def directive(mid, kind="Break"):
    return {"id": mid, "module": "builtin:" + kind}


def gate(sid=40, aid=41, formula=PIN, handler=("Break",)):
    """The duplicate lookup, its aggregator. The empty filter goes on the next module."""
    return [search(sid, LEDGER, formula, *[directive(90 + i, k) for i, k in enumerate(handler)]), agg(aid, sid)]


def registry(protection="api_key", caller="bland_pathway_node", sid="3943741", hid=1773988):
    e = ab.WebhookEntry(sid, hid, caller, protection, "registered for the test", "Campaign Launcher" if protection == "fetch_back" else "")
    return ab.Webhooks({sid: e})


def hooks(hid=1773988, sid="3943741"):
    return ab.HookInfo(True, {hid: {"id": hid, "apikey_count": 1, "scenario_ids": [int(sid)]}})


def f3(b, label=LABEL, reg=None):
    rows = ab.check_f(b, ab.Allowlist(), reg or registry(), hooks(), None, label)
    return [r for r in rows if r.rule == "F3"]


def e_rows(b, rule):
    return [r for r in ab.check_e(b, ab.load_links(ab.DEFAULT_LINKS), ab.Allowlist()) if r.rule == rule]


# ---------------------------------------------------------------------------
# F3 duplicate delivery (X-43)
# ---------------------------------------------------------------------------


class F3Tests(unittest.TestCase):
    def ungated(self):
        """Live Pending Call shape: call details, lead search, then OpenAI, the Status write, SMS and email."""
        return bp(hook(), details(), search(7, LEAD, "{Phone} = '{{1.phone}}'"), openai(13), marker(125),
                  router(135, [status(8), sms(11), email(12)], [email(14)]))

    def gated(self, *after, flow_tail=None):
        tail = flow_tail if flow_tail is not None else [filt(openai(13), empty_test(41)), marker(125),
                                                        router(135, [status(8), sms(11), email(12)], [email(14)])]
        return bp(hook(), details(), *gate(), *tail, *after)

    def test_ungated_scenario_fails_on_the_first_state_changing_module(self):
        rows = f3(self.ungated())
        self.assertEqual([(r.status, r.module_id) for r in rows], [("FAIL", 13)])
        self.assertIn("8 (lead Status write)", rows[0].detail)
        self.assertIn("11 (client send)", rows[0].detail)
        self.assertIn('{Scenario name} = "Automating \'Pending Call\' Clients"', rows[0].detail)

    def test_complete_gate_passes(self):
        rows = f3(self.gated())
        self.assertEqual([(r.status, r.module_id) for r in rows], [("PASS", 40)])

    def test_call_details_output_is_an_accepted_call_id(self):
        formula = f"AND({OK}, {{Scenario name}} = \"{LABEL}\", {{External Call ID}} = '{{{{5.call_id}}}}')"
        tail = [filt(openai(13), empty_test(41)), marker(125, call="{{5.call_id}}"), status(8)]
        rows = f3(bp(hook(), details(), *gate(formula=formula), *tail))
        self.assertEqual([r.status for r in rows], ["PASS"])

    def test_label_with_a_quote_in_single_quotes_is_not_a_pin(self):
        formula = f"AND({{External Call ID}} = '{{{{1.id}}}}', {{Scenario name}} = '{LABEL}', {OK})"
        rows = f3(bp(hook(), details(), *gate(formula=formula), filt(openai(13), empty_test(41)), marker(125)))
        self.assertEqual(sorted((r.status, r.module_id) for r in rows), [("FAIL", 13), ("FAIL", 40)])

    def test_extra_clause_or_missing_label_is_not_a_pin(self):
        for formula in (f"{{External Call ID}} = '{{{{1.id}}}}'",
                        f"AND({{External Call ID}} = '{{{{1.id}}}}', {{Scenario name}} = \"{LABEL}\")",
                        f"AND({{External Call ID}} = '{{{{1.id}}}}', {{Scenario name}} = \"{LABEL}\", {{Execution Status}} = 'Error')",
                        f"AND({{External Call ID}} = '{{{{1.id}}}}', {{Scenario name}} = \"{LABEL}\", {OK}, {{Phone}} = '1')",
                        f"AND({{External Call ID}} = '{{{{1.phone}}}}', {{Scenario name}} = \"{LABEL}\", {OK})"):
            with self.subTest(formula=formula):
                rows = f3(bp(hook(), details(), *gate(formula=formula), filt(openai(13), empty_test(41)), marker(125)))
                self.assertIn(("FAIL", 13), [(r.status, r.module_id) for r in rows])

    def test_text_aggregator_does_not_gate(self):
        """Reviewer finding: only an array aggregator has .array. A text aggregator makes length(.array) always 0."""
        lookup, a = gate()
        a = dict(a, module="builtin:TextAggregator")
        rows = f3(bp(hook(), details(), lookup, a, filt(openai(13), empty_test(41)), marker(125)))
        self.assertEqual(sorted((r.status, r.module_id) for r in rows), [("FAIL", 13), ("FAIL", 40)])
        self.assertIn("builtin:BasicAggregator", [r for r in rows if r.module_id == 40][0].detail)

    def test_error_row_is_not_a_marker(self):
        """Reviewer finding: the lookup only finds Success rows, so an Error row marks nothing processed."""
        rows = f3(bp(hook(), details(), *gate(), filt(openai(13), empty_test(41)), marker(125, outcome="Error")))
        self.assertEqual([(r.status, r.module_id) for r in rows], [("FAIL", 13)])
        self.assertIn("no Shadow Ledger create", rows[0].detail)

    def test_length_zero_is_not_an_empty_test(self):
        """Measured 2026-10-30: a search that finds nothing can still emit one empty bundle, so length(<agg>.array) is 1."""
        old = [[{"a": "{{length(41.array)}}", "b": "0", "o": "number:equal"}]]
        rows = f3(bp(hook(), details(), *gate(), filt(openai(13), old), marker(125)))
        self.assertIn(("FAIL", 13), [(r.status, r.module_id) for r in rows])
        self.assertIn("does not exist", " ".join(r.detail for r in rows))

    def test_lookup_handler_must_break(self):
        for kind in ("Ignore", "Resume"):
            with self.subTest(kind=kind):
                rows = f3(bp(hook(), details(), *gate(handler=(kind,)), filt(openai(13), empty_test(41)), marker(125)))
                self.assertEqual(sorted((r.status, r.module_id) for r in rows), [("FAIL", 13), ("FAIL", 40)])

    def test_lookup_without_aggregator_does_not_gate(self):
        rows = f3(bp(hook(), details(), gate()[0], filt(openai(13), [[{"a": "{{40.id}}", "o": "notexist"}]]), marker(125)))
        self.assertEqual(sorted((r.status, r.module_id) for r in rows), [("FAIL", 13), ("FAIL", 40)])

    def test_empty_filter_with_a_second_or_group_does_not_gate(self):
        loose = empty_test(41) + [[{"a": "{{1.status}}", "b": "VIP", "o": "text:equal"}]]
        rows = f3(bp(hook(), details(), *gate(), filt(openai(13), loose), marker(125)))
        self.assertEqual(sorted((r.status, r.module_id) for r in rows), [("FAIL", 13), ("FAIL", 13)])

    def test_gate_on_one_router_route_covers_that_route_only(self):
        tail = [router(50, [filt(marker(125), empty_test(41)), openai(13)], [email(14)])]
        rows = f3(bp(hook(), details(), *gate(), *tail))
        self.assertEqual([(r.status, r.module_id) for r in rows], [("FAIL", 14)])

    def test_no_marker_row_means_the_lookup_never_finds_a_first_delivery(self):
        rows = f3(bp(hook(), details(), *gate(), filt(openai(13), empty_test(41)), status(8)))
        self.assertEqual([(r.status, r.module_id) for r in rows], [("FAIL", 13)])
        self.assertIn("no Shadow Ledger create", rows[0].detail)

    def test_marker_before_the_gate_does_not_count(self):
        rows = f3(bp(hook(), details(), marker(125), *gate(), filt(openai(13), empty_test(41))))
        self.assertEqual([(r.status, r.module_id) for r in rows], [("FAIL", 13)])

    def test_marker_behind_a_filter_the_effect_does_not_pass_does_not_count(self):
        late = filt(marker(125), [[{"a": "{{1.status}}", "b": "VIP", "o": "text:equal"}]])
        rows = f3(bp(hook(), details(), *gate(), filt(openai(13), empty_test(41)), late))
        self.assertEqual([(r.status, r.module_id) for r in rows], [("FAIL", 13)])

    def test_marker_with_another_label_does_not_count(self):
        rows = f3(bp(hook(), details(), *gate(), filt(openai(13), empty_test(41)), marker(125, label="Campaign Launcher")))
        self.assertEqual([(r.status, r.module_id) for r in rows], [("FAIL", 13)])

    def test_sequential_processing_off_fails_on_the_trigger(self):
        b = self.gated()
        b.bp["metadata"]["scenario"]["sequential"] = False
        self.assertEqual([(r.status, r.module_id) for r in f3(b)], [("FAIL", 1)])

    def test_no_label_is_a_fail_and_none_skips(self):
        self.assertEqual([(r.status, r.module_id) for r in f3(self.gated(), label="")], [("FAIL", 1)])
        self.assertEqual(f3(self.gated(), label=None), [])

    def test_logger_and_fetch_back_scenarios_get_no_f3_rows(self):
        self.assertEqual(f3(self.ungated(), reg=registry(caller="make_http")), [])
        self.assertEqual(f3(self.ungated(), reg=registry(protection="fetch_back", caller="bland_post_call")), [])

    def test_ledger_and_slack_writes_are_not_state_changing(self):
        b = bp(hook(), details(), marker(125), {"id": 9, "module": "slack:CreateMessage", "mapper": {"text": "x"}})
        rows = f3(b)
        self.assertEqual([r.status for r in rows], ["PASS"])
        self.assertIn("no state-changing module", rows[0].detail)

    def test_effects_in_error_handlers_are_out_of_scope(self):
        b = bp(hook(), details(), dict(details(6), onerror=[sms(70), directive(71)]))
        self.assertEqual([r.status for r in f3(b)], ["PASS"])

    def test_audit_passes_the_confirmed_label(self):
        labels = ab.Labels(True, {"3943741": {"name": "Pending Call", "expected_label": LABEL}})
        res = ab.audit([self.ungated()], labels, ab.Schema([LABEL], []), True, links=ab.AirtableMap(), allowlist=ab.Allowlist(),
                       webhooks=registry(), hooks=hooks(), partial=True, secret_allowlist=[])
        self.assertEqual([(f.status, f.module_id) for f in res.findings if f.rule == "F3"], [("FAIL", 13)])
        res = ab.audit([self.gated()], labels, ab.Schema([LABEL], []), True, links=ab.AirtableMap(), allowlist=ab.Allowlist(),
                       webhooks=registry(), hooks=hooks(), partial=True, secret_allowlist=[])
        self.assertEqual([f.status for f in res.findings if f.rule == "F3"], ["PASS"])


# ---------------------------------------------------------------------------
# E9 conflicting routes (X-44)
# ---------------------------------------------------------------------------


def update(mid, field=MOCK_STATUS, value="Completed", rid="{{14.id}}"):
    return {"id": mid, "module": "airtable:ActionUpdateRecords", "mapper": {"table": LEAD, "id": rid, "record": {field: value}}}


def cond(a, b, o):
    c = {"a": a, "o": o}
    if b is not None:
        c["b"] = b
    return [[c]]


class E9Tests(unittest.TestCase):
    def rows(self, *routes, fallback=None):
        b = bp(hook(), router(5, *routes, fallback=fallback), sid="3975156", name="Grader")
        return e_rows(b, "E9")

    def test_grader_router_5_fails(self):
        completed = filt({"id": 2, "module": "openai-gpt-3:CreateCompletion", "mapper": {}}, cond("{{60.completed}}", "true", "boolean:equal"))
        rows = self.rows([completed, update(4)], [update(7, value="No Answer")])
        self.assertEqual([(r.status, r.module_id) for r in rows], [("FAIL", 5)])
        self.assertIn("route 2 has no filter and is not the fallback", rows[0].detail)
        self.assertIn("Mock Interview Status", rows[0].detail)

    def test_catch_all_as_fallback_passes(self):
        completed = filt(update(4), cond("{{60.status}}", "completed", "text:equal"))
        self.assertEqual(self.rows([completed], [update(7, value="No Answer")], fallback=1), [])

    def test_exclusive_filters_pass(self):
        pairs = [
            (cond("{{60.status}}", "completed", "text:equal"), cond("{{60.status}}", "completed", "text:notequal")),
            (cond("{{1.status}}", "VIP", "text:equal:ci"), cond("{{1.status}}", "Nurture", "text:equal:ci")),
            (cond("{{60.completed}}", "true", "boolean:equal"), cond("{{60.completed}}", "false", "boolean:equal")),
            (cond("{{3.id}}", None, "exist"), cond("{{3.id}}", None, "notexist")),
            (cond("{{2.score}}", "5", "number:greater"), cond("{{2.score}}", "5", "number:lessorequal")),
        ]
        for f1, f2 in pairs:
            with self.subTest(f1=f1):
                self.assertEqual(self.rows([filt(update(4), f1)], [filt(update(7, value="No Answer"), f2)]), [])

    def test_overlapping_filters_fail(self):
        pairs = [
            (cond("{{2.score}}", "5", "number:greater"), cond("{{2.score}}", "3", "number:greater")),
            (cond("{{1.status}}", "vip", "text:equal:ci"), cond("{{1.status}}", "VIP", "text:equal")),
            (cond("{{1.status}}", "VIP", "text:equal"), cond("{{2.score}}", "5", "number:greater")),
        ]
        for f1, f2 in pairs:
            with self.subTest(f1=f1):
                rows = self.rows([filt(update(4), f1)], [filt(update(7, value="No Answer"), f2)])
                self.assertEqual([(r.status, r.module_id) for r in rows], [("FAIL", 5)])

    def test_filter_later_in_the_route_counts(self):
        f1, f2 = cond("{{60.status}}", "completed", "text:equal"), cond("{{60.status}}", "completed", "text:notequal")
        other = {"id": 30, "module": "util:SetVariable2", "mapper": {}}
        self.assertEqual(self.rows([filt(other, f1), update(4)], [other | {"id": 31}, filt(update(7), f2)]), [])

    def test_or_group_that_escapes_the_exclusion_fails(self):
        f1 = cond("{{60.status}}", "completed", "text:equal") + cond("{{1.x}}", "y", "text:equal")
        f2 = cond("{{60.status}}", "completed", "text:notequal")
        self.assertEqual(len(self.rows([filt(update(4), f1)], [filt(update(7), f2)])), 1)

    def test_different_fields_or_creates_pass(self):
        self.assertEqual(self.rows([update(4)], [update(7, field="fldZ6rJvQ6TUpaNr1")]), [])
        create = {"id": 7, "module": "airtable:ActionCreateRecord", "mapper": {"table": LEAD, "record": {MOCK_STATUS: "x"}}}
        self.assertEqual(self.rows([update(4)], [create]), [])

    def test_status_by_name_and_by_id_is_the_same_field(self):
        rows = self.rows([update(4, field=ab.STATUS_FIELD, value="VIP")], [update(7, field="Status", value="Nurture")])
        self.assertEqual([r.status for r in rows], ["FAIL"])

    def test_nested_router_conflict_is_reported_on_the_inner_router(self):
        inner = router(6, [update(4)], [update(7)])
        b = bp(hook(), router(5, [inner], [{"id": 9, "module": "slack:CreateMessage", "mapper": {}}]), sid="3975156")
        self.assertEqual([r.module_id for r in e_rows(b, "E9")], [6])

    def test_writes_in_error_handlers_are_ignored(self):
        h = dict(update(4), onerror=[update(70), directive(71)])
        self.assertEqual(self.rows([h], [{"id": 9, "module": "slack:CreateMessage", "mapper": {}}]), [])


# ---------------------------------------------------------------------------
# E10 Voice AI Ledger cost contract (X-45)
# ---------------------------------------------------------------------------

GOOD_LENGTH = "{{round(20.call_length * 60)}}"
GOOD_RATE = "{{if(round(20.call_length * 60) > 0; 20.price * 60 / round(20.call_length * 60); 0)}}"


def voice(mid=4, **record):
    rec = {"fldr9IGcf4xCdeisR": "{{20.call_id}}"}
    rec.update(record)
    return {"id": mid, "module": "airtable:ActionCreateRecord", "mapper": {"table": VOICE, "record": rec}}


class F3StripeListenerTests(unittest.TestCase):
    """The F-H9 listener (caller stripe_verifier): the delivery is the Stripe event ID, and lead writes are gated effects."""

    def reg(self):
        e = ab.WebhookEntry("6900000", 1773988, ab.STRIPE_CALLER, "api_key", "registered for the test", "")
        return ab.Webhooks({"6900000": e})

    def rows(self, *flow):
        b = bp(hook(), *flow, sid="6900000", name="Stripe Payment Listener")
        res = ab.check_f(b, ab.Allowlist(), self.reg(), ab.HookInfo(True, {1773988: {"id": 1773988, "apikey_count": 1, "scenario_ids": [6900000]}}),
                         ab.load_links(ab.DEFAULT_LINKS), "Stripe Payment Listener")
        return [r for r in res if r.rule == "F3"]

    def update(self, mid, table):
        return {"id": mid, "module": "airtable:ActionUpdateRecords", "mapper": {"table": table, "id": "{{7.id}}",
                                                                                "record": {"fldCesYm5l1GrwSmF": "1"}}}

    def test_ungated_lead_write_fails_by_table_id_or_name(self):
        for table in (LEAD, "Applicants"):
            with self.subTest(table=table):
                self.assertEqual([(r.status, r.module_id) for r in self.rows(self.update(8, table))], [("FAIL", 8)])

    def test_gate_on_the_event_id_passes(self):
        pin = "AND({External Call ID} = '{{1.event_id}}', {Scenario name} = 'Stripe Payment Listener', {Execution Status} = 'Success')"
        mk = {"id": 5, "module": "airtable:ActionCreateRecord", "mapper": {"table": LEDGER, "record": {
            ab.LABEL_FIELD: "Stripe Payment Listener", ab.CALL_ID_FIELD: "{{1.event_id}}", ab.OUTCOME_FIELD: "Success"}}}
        r = self.rows(*gate(formula=pin), filt(mk, empty_test(41)), self.update(8, LEAD))
        self.assertEqual([r_.status for r_ in r], ["PASS"])

    def test_a_call_id_gate_does_not_count_for_the_listener(self):
        pin = "AND({External Call ID} = '{{1.call_id}}', {Scenario name} = 'Stripe Payment Listener', {Execution Status} = 'Success')"
        r = self.rows(*gate(formula=pin), filt(self.update(8, LEAD), empty_test(41)))
        self.assertIn("FAIL", [r_.status for r_ in r])


class E7ExistComplementTests(unittest.TestCase):
    def test_exist_and_notexist_on_one_operand_are_complements(self):
        f1 = {"filter": {"conditions": [[{"a": "{{first(map(113.array; \"id\"))}}", "o": "notexist"}]]}}
        f2 = {"filter": {"conditions": [[{"a": "{{first(map(113.array; \"id\"))}}", "o": "exist"}]]}}
        self.assertTrue(ab._are_complements(f1, f2))
        f3 = {"filter": {"conditions": [[{"a": "{{first(map(114.array; \"id\"))}}", "o": "exist"}]]}}
        self.assertFalse(ab._are_complements(f1, f3))


class E10Tests(unittest.TestCase):
    def rows(self, *flow):
        return e_rows(bp(hook(), details(20, "{{1.call_id}}"), *flow, sid="4226754"), "E10")

    def test_campaign_shape_maps_only_the_call_id(self):
        rows = self.rows(voice())
        self.assertEqual([(r.status, r.module_id) for r in rows], [("FAIL", 4)])
        self.assertIn("Call_Length is not mapped", rows[0].detail)
        self.assertIn("Rate per minute is not mapped", rows[0].detail)

    def test_vip_shape_maps_price_as_the_rate(self):
        rows = self.rows(voice(fldHVPuUWQArLCeMW="{{20.price}}", fldRjBE7U8tq8zAzo="{{20.call_length}}"))
        self.assertEqual(len(rows), 1)
        self.assertIn("whole seconds", rows[0].detail)
        self.assertIn("not the price", rows[0].detail)

    def test_pending_call_shape_sends_text(self):
        rows = self.rows(voice(fldHVPuUWQArLCeMW="{{20.price}} / {{20.call_length}}", fldRjBE7U8tq8zAzo="{{20.call_length}}"))
        self.assertIn("text around", rows[0].detail)

    def test_contract_mapping_passes(self):
        self.assertEqual(self.rows(voice(fldHVPuUWQArLCeMW=GOOD_RATE, fldRjBE7U8tq8zAzo=GOOD_LENGTH)), [])

    def test_field_names_are_accepted_as_keys(self):
        self.assertEqual(self.rows(voice(**{"Rate per minute": GOOD_RATE, "Call_Length": GOOD_LENGTH})), [])

    def test_unguarded_division_fails(self):
        rate = "{{20.price * 60 / round(20.call_length * 60)}}"
        rows = self.rows(voice(fldHVPuUWQArLCeMW=rate, fldRjBE7U8tq8zAzo=GOOD_LENGTH))
        self.assertIn("divides by zero", rows[0].detail)

    def test_minutes_based_rate_with_unrounded_seconds_fails(self):
        rows = self.rows(voice(fldHVPuUWQArLCeMW="{{if(20.call_length = 0; 0; 20.price / 20.call_length)}}",
                               fldRjBE7U8tq8zAzo="{{20.call_length * 60}}"))
        self.assertIn("whole seconds", rows[0].detail)

    def test_rate_per_minute_with_rounded_seconds_is_off_and_fails(self):
        rows = self.rows(voice(fldHVPuUWQArLCeMW="{{if(20.call_length = 0; 0; 20.price / 20.call_length)}}", fldRjBE7U8tq8zAzo=GOOD_LENGTH))
        self.assertIn("not the price", rows[0].detail)

    def test_ceil_seconds_with_a_compensating_rate_fails(self):
        """Reviewer finding: Total Cost right, duration wrong. ceil seconds with the matching rate keeps the cost exact."""
        length = "{{ceil(20.call_length * 60)}}"
        rate = "{{if(ceil(20.call_length * 60) > 0; 20.price * 60 / ceil(20.call_length * 60); 0)}}"
        rows = self.rows(voice(fldHVPuUWQArLCeMW=rate, fldRjBE7U8tq8zAzo=length))
        self.assertEqual(len(rows), 1)
        self.assertIn("not the call's length in seconds", rows[0].detail)
        self.assertNotIn("not the price", rows[0].detail)

    def test_reference_to_another_module_fails(self):
        rows = self.rows(voice(fldHVPuUWQArLCeMW="{{3.rate}}", fldRjBE7U8tq8zAzo=GOOD_LENGTH))
        self.assertIn("must read only the call-details module", rows[0].detail)

    def test_no_call_details_module_fails(self):
        b = bp(hook(), voice(fldHVPuUWQArLCeMW=GOOD_RATE, fldRjBE7U8tq8zAzo=GOOD_LENGTH), sid="4226754")
        self.assertIn("no Bland call-details module", e_rows(b, "E10")[0].detail)

    def test_unsupported_expression_fails_closed(self):
        rows = self.rows(voice(fldHVPuUWQArLCeMW="{{parseNumber(20.price)}}", fldRjBE7U8tq8zAzo=GOOD_LENGTH))
        self.assertIn("cannot be verified", rows[0].detail)

    def test_other_tables_are_out_of_scope(self):
        self.assertEqual(self.rows({"id": 4, "module": "airtable:ActionCreateRecord", "mapper": {"table": LEDGER, "record": {}}}), [])

    def test_evaluator_is_lazy_and_handles_ifempty(self):
        env = {(20, "call_length"): 0.0, (20, "price"): 0.5}
        node = ab._ExprParser("if(20.call_length > 0; 20.price / 20.call_length; ifempty(20.price; 1))").parse()
        self.assertEqual(ab._expr_eval(node, env), 0.5)
        self.assertEqual(ab._expr_eval(ab._ExprParser("round(2.5) + floor(1.9) + ceil(1.1) + max(1; 3) - min(4; 2)").parse(), {}), 7.0)


# ---------------------------------------------------------------------------
# make_push: fix IDs map to the new rules' checks
# ---------------------------------------------------------------------------


class FixCheckTests(unittest.TestCase):
    def test_blocker_fix_ids(self):
        self.assertEqual(make_push.fix_checks("X-43"), ("F",))
        self.assertEqual(make_push.fix_checks("X-44"), ("E",))
        self.assertEqual(make_push.fix_checks("X-45"), ("E",))


if __name__ == "__main__":
    unittest.main()


class E11EmptyLinkTests(unittest.TestCase):
    """Measured 2026-10-30, Market Watchdog 24: Applicant Link [""] got 422 Value "" is not a valid record ID."""
    def row(self, value):
        m = marker(30)
        m["mapper"]["record"]["fldx9nJ4XmlQx1frF"] = value
        return e_rows(bp(hook(), m), "E11")

    def test_empty_value_in_a_link_fails(self):
        for v in ([""], ["  "], ["{{1.id}}", ""]):
            with self.subTest(v=v):
                self.assertEqual([(r.status, r.module_id) for r in self.row(v)], [("FAIL", 30)])

    def test_mapped_or_absent_link_passes(self):
        for v in (["{{7.id}}"], "{{7.id}}"):
            with self.subTest(v=v):
                self.assertEqual(self.row(v), [])
        self.assertEqual(e_rows(bp(hook(), marker(30)), "E11"), [])
