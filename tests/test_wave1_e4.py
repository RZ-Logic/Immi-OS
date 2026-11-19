"""Wave 1 rules from the 2026-10-31 bug sweep: E26 an empty search bundle reaches an effect (campaign L8a) and S9 the
Stripe customer email gate (guardrail M6). E27 (padded Bland setting) was withdrawn: " Amelia " is the exact name of a
Bland voice. Synthetic fixtures shaped like the live modules (Campaign Launcher 3961751, The Interview Room (B) Grader 3975156, Financial Guardrail (AR)
3975479). No network.
"""

import copy
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import audit_blueprints as ab  # noqa: E402

LEAD = ab.LEAD_TABLE
LEDGER = ab.LEDGER_TABLE
CAMPAIGN = "tbl0IzlSUYDdZIcxZ"
LINKS = ab.load_links(ab.DEFAULT_LINKS, required=True)


def bp(*flow, sid="1", name="S"):
    return ab.Blueprint(name=name, scenario_id=sid, source="test", bp={"name": name, "flow": list(flow), "metadata": {}})


def e_rows(b, code, status=None):
    return [f for f in ab.check_e(b, LINKS, ab.Allowlist()) if f.rule == code and (status is None or f.status == status)]


def s9_rows(b, status=None):
    return [f for f in ab.check_s(b) if "S9" in f.detail and (status is None or f.status == status)]


def filt(m, conditions, name="f"):
    m = dict(m)
    m["filter"] = {"name": name, "conditions": conditions}
    return m


def cond(a, op, b=None):
    c = {"a": a, "o": op}
    if b is not None:
        c["b"] = b
    return [[c]]


def router(mid, *routes, fallback=None):
    r = {"id": mid, "module": "builtin:BasicRouter", "routes": [{"flow": list(x)} for x in routes]}
    if fallback is not None:
        r["parameters"] = {"else": fallback}
    return r


def handler(owner, directive="builtin:Break"):
    return [{"id": owner * 100, "module": "http:MakeRequest", "mapper": {"url": "x"}}, {"id": owner * 100 + 1, "module": directive}]


# ---------------------------------------------------------------------------
# E26, empty search bundle
# ---------------------------------------------------------------------------


def watch(mid=2):
    return {"id": mid, "module": "airtable:TriggerWatchRecords", "parameters": {"table": CAMPAIGN}}


def get_campaign(mid=4):
    return {"id": mid, "module": "airtable:ActionGetRecord", "mapper": {"table": CAMPAIGN, "id": "{{2.id}}"}}


def lead_search(mid=3, max_records="50"):
    mp = {"table": LEAD, "formula": "{Status} != 'Disqualified'"}
    if max_records is not None:
        mp["maxRecords"] = max_records
    return {"id": mid, "module": "airtable:ActionSearchRecords", "mapper": mp, "onerror": handler(mid)}


def gmail(mid, to="{{3.Email}}"):
    return {"id": mid, "module": "google-email:sendAnEmail", "mapper": {"to": [to], "subject": "x", "html": "x"}}


def update(mid, rid="{{3.id}}"):
    return {"id": mid, "module": "airtable:ActionUpdateRecords", "mapper": {"table": LEAD, "id": rid, "record": {"fldX": "Sent"}}}


def ledger(mid, text="x"):
    return {"id": mid, "module": "airtable:ActionCreateRecord",
            "mapper": {"table": LEDGER, "record": {"fldgzlLkRAwc6KGoh": "Error", ab.AI_RESPONSE_FIELD: text}}}


def slack(mid, text="x"):
    return {"id": mid, "module": "slack:CreateMessage", "mapper": {"text": text}}


def campaign_router(gate=None, route0=None, route1=None):
    """Campaign Launcher router 6: route 0 North America (9 behind starts with +1), route 1 International (8 behind not
    starts with +1, then 11 and 14)."""
    r0 = route0 if route0 is not None else [filt(gmail(9), cond("{{3.Phone}}", "text:startwith", "+1"), "North America")]
    r1 = route1 if route1 is not None else [filt(gmail(8), cond("{{3.Phone}}", "text:notstartwith", "+1"), "International"),
                                            update(11), ledger(14)]
    r = router(6, r0, r1)
    if gate is not None:
        r["filter"] = {"name": "Lead found", "conditions": gate}
    return r


def campaign(*after, search=None):
    return bp(watch(), get_campaign(), search or lead_search(), *after, sid="3961751", name="Campaign Launcher")


class E26EmptySearchTests(unittest.TestCase):
    def test_live_campaign_shape_fails_on_the_router(self):
        """L8a: route 1's not-starts-with +1 is true on the empty bundle, so Gmail 8, update 11 and ledger 14 run."""
        fail = e_rows(campaign(campaign_router()), "E26", ab.FAIL)
        self.assertEqual([f.module_id for f in fail], [6])
        self.assertIn("Search 3 can return several records", fail[0].detail)
        self.assertIn("{{3.id}} exists on this module", fail[0].detail)

    def test_detail_names_no_effect_module(self):
        """critic 1B.3: compare_audits keys FAIL rows on the full text, so a push that adds an effect must not reword it."""
        d1 = e_rows(campaign(campaign_router()), "E26", ab.FAIL)[0].detail
        extra = campaign_router(route1=[filt(gmail(8), cond("{{3.Phone}}", "text:notstartwith", "+1")), update(11), ledger(14),
                                        slack(87), ledger(88)])
        d2 = e_rows(campaign(extra), "E26", ab.FAIL)[0].detail
        self.assertEqual(d1, d2)
        for mid in ("8", "11", "14"):
            self.assertNotIn(f" {mid},", d1)
            self.assertNotIn(f"[{mid}", d1)

    def test_exists_gate_on_the_router_passes(self):
        """The X-41.15 fix: {{3.id}} exists on the link into router 6."""
        self.assertEqual(e_rows(campaign(campaign_router(gate=cond("{{3.id}}", "exist"))), "E26"), [])

    def test_gate_on_each_route_passes(self):
        r1 = [filt(gmail(8), [[{"a": "{{3.Phone}}", "b": "+1", "o": "text:notstartwith"}, {"a": "{{3.id}}", "o": "exist"}]]),
              update(11), ledger(14)]
        self.assertEqual(e_rows(campaign(campaign_router(route1=r1)), "E26"), [])

    def test_starts_with_route_is_already_gated(self):
        """Route 0 alone (starts with +1, a text:pattern call behind it) never runs on the empty bundle."""
        r0 = [filt(gmail(9), cond("{{3.Phone}}", "text:startwith", "+1")),
              router(54, [filt({"id": 7, "module": "bland:sendACall", "mapper": {"phone_number": "{{3.Phone}}"}},
                               cond("{{3.Phone}}", "text:pattern", "^\\+1[0-9]{10}$"))], [ledger(55), slack(58)], fallback=1)]
        b = campaign(router(6, r0, [{"id": 99, "module": "util:SetVariable2"}]))
        self.assertEqual(e_rows(b, "E26"), [])

    def test_max_records_one_is_out_of_scope(self):
        """Pending Call 121 and Batch Outbound Caller 2 (maxRecords 1) stay with F2b, F3, A and E11."""
        self.assertEqual(e_rows(campaign(campaign_router(), search=lead_search(max_records="1")), "E26"), [])
        self.assertEqual(e_rows(campaign(campaign_router(), search=lead_search(max_records=" 1 ")), "E26"), [])

    def test_missing_or_mapped_max_records_counts_as_many(self):
        self.assertEqual([f.module_id for f in e_rows(campaign(campaign_router(), search=lead_search(max_records=None)), "E26")], [6])
        self.assertEqual([f.module_id for f in e_rows(campaign(campaign_router(), search=lead_search(max_records="{{4.Cap}}")), "E26")], [6])

    def test_grader_shape_fails_on_router_5(self):
        """3975156: search 14 (maxRecords 10) feeds router 5, whose route 0 Claude call filters on another module."""
        search = {"id": 14, "module": "airtable:ActionSearchRecords", "mapper": {"table": LEAD, "maxRecords": "10",
                                                                                  "formula": "RECORD_ID() = 'x'"}}
        claude = filt({"id": 82, "module": "anthropic-claude:createAMessage", "mapper": {}},
                      cond("{{60.completed}}", "boolean:equal", "true"))
        r5 = router(5, [claude, update(4, "{{14.id}}")], [update(7, "{{14.id}}")], fallback=1)
        b = bp({"id": 1, "module": "gateway:CustomWebHook"}, router(24, [search, r5], [ledger(22)]), sid="3975156")
        self.assertEqual([f.module_id for f in e_rows(b, "E26", ab.FAIL)], [5])
        fixed = copy.deepcopy(b)
        fixed.bp["flow"][1]["routes"][0]["flow"][1]["filter"] = {"name": "Lead found (X-41.17)", "conditions": cond("{{14.id}}", "exist")}
        self.assertEqual(e_rows(fixed, "E26"), [])

    def test_number_operator_on_the_search_does_not_gate(self):
        """Documented false positive: a number or date test is unknown on the empty bundle (fix: use exists)."""
        b = campaign(campaign_router(gate=cond("{{3.Score}}", "number:greater", "0")))
        self.assertEqual([f.module_id for f in e_rows(b, "E26")], [6])

    def test_function_around_the_reference_does_not_gate(self):
        b = campaign(campaign_router(gate=cond("{{trim(3.id)}}", "exist")))
        self.assertEqual([f.module_id for f in e_rows(b, "E26")], [6])

    def test_condition_on_another_module_does_not_gate(self):
        b = campaign(campaign_router(gate=cond("{{4.id}}", "exist")))
        self.assertEqual([f.module_id for f in e_rows(b, "E26")], [6])

    def test_or_group_without_a_gate_does_not_gate(self):
        b = campaign(campaign_router(gate=[[{"a": "{{3.id}}", "o": "exist"}], [{"a": "{{4.id}}", "o": "exist"}]]))
        self.assertEqual([f.module_id for f in e_rows(b, "E26")], [6])

    def test_not_exist_and_matching_pattern_do_not_gate(self):
        self.assertEqual(len(e_rows(campaign(campaign_router(gate=cond("{{3.id}}", "notexist"))), "E26")), 1)
        self.assertEqual(len(e_rows(campaign(campaign_router(gate=cond("{{3.Phone}}", "text:pattern", "^.*$"))), "E26")), 1)

    def test_text_operators_read_on_empty_text(self):
        for op, lit, gates in (("text:equal", "x", True), ("text:equal", "", False), ("text:contain", "@", True),
                               ("text:notequal", "", True), ("text:notequal", "x", False), ("text:endwith:ci", "A", True),
                               ("text:pattern", "^\\+1", True), ("text:pattern:ci", "[a-z]", True), ("text:notpattern", "x", False),
                               ("text:equal", "{{4.x}}", False)):
            b = campaign(campaign_router(gate=cond("{{3.Phone}}", op, lit)))
            self.assertEqual(e_rows(b, "E26") == [], gates, (op, lit))

    def test_aggregator_after_the_search_is_out_of_scope(self):
        agg = {"id": 70, "module": "builtin:BasicAggregator", "parameters": {"feeder": 3}, "mapper": {"id": "{{3.id}}"}}
        self.assertEqual(e_rows(campaign(agg, gmail(8, "x")), "E26"), [])

    def test_effects_only_in_error_routes_do_not_count(self):
        """Search 3's own Logger handler is in an error route."""
        self.assertEqual(e_rows(campaign({"id": 6, "module": "util:SetVariable2"}), "E26"), [])

    def test_effect_before_the_search_does_not_count(self):
        b = bp(watch(), gmail(8, "x"), lead_search())
        self.assertEqual(e_rows(b, "E26"), [])

    def test_row_on_the_effect_when_it_follows_the_search(self):
        self.assertEqual([f.module_id for f in e_rows(campaign(gmail(8)), "E26")], [8])
        self.assertEqual(e_rows(campaign(filt(gmail(8), cond("{{3.id}}", "exist"))), "E26"), [])

    def test_one_row_per_search(self):
        b = campaign(campaign_router(), gmail(30))
        self.assertEqual([f.module_id for f in e_rows(b, "E26")], [6])

    def test_reads_after_the_search_are_not_effects(self):
        b = campaign({"id": 8, "module": "airtable:ActionGetRecord", "mapper": {"table": LEAD, "id": "{{3.id}}"}})
        self.assertEqual(e_rows(b, "E26"), [])


# ---------------------------------------------------------------------------
# S9, Stripe customer email gate
# ---------------------------------------------------------------------------

PATTERN = "^[^@ ]+@[^@ ]+[.][^@ ]+$"
EMAIL_GATE = cond("{{1.Email}}", "text:pattern", PATTERN)


def search_customers(mid=10, email="{{1.Email}}"):
    return {"id": mid, "module": "stripe:searchCustomers", "mapper": {"email": email, "limit": "1"}}


def customer_post(mid=85, body="email={{encodeURL(1.Email)}}&name={{encodeURL(1.Name)}}&metadata[airtable_record_id]={{1.id}}",
                  url="/v1/customers{{if(10.id; \"/\"; \"\")}}{{10.id}}", method="POST", key="immios-fh1-customer-{{1.id}}-x"):
    headers = [{"key": "Content-Type", "value": "application/x-www-form-urlencoded"}]
    if key is not None:
        headers.append({"key": "Idempotency-Key", "value": key})
    return {"id": mid, "module": "stripe:makeAnApiCall", "mapper": {"url": url, "method": method, "headers": headers, "body": body}}


def lock(mid=3):
    return filt({"id": mid, "module": "airtable:ActionUpdateRecords",
                 "mapper": {"table": LEAD, "id": "{{1.id}}", "record": {ab.STATUS_FIELD: "LOCKED - Payment Required"}}},
                cond("{{1.`Payment Status`}}", "text:notequal", "Paid in Full"))


def guardrail(*route0, fallback_route=None):
    """Financial Guardrail router 2: route 0 locks (3) then the Stripe leg, route 1 is the fallback ledger and Slack."""
    fb = fallback_route if fallback_route is not None else [ledger(43), slack(46)]
    trig = {"id": 1, "module": "airtable:TriggerWatchRecords"}
    return ab.Blueprint(name="Financial Guardrail (AR)", scenario_id="3975479", source="test",
                        bp={"name": "x", "flow": [trig, router(2, [lock(), *route0], fb, fallback=1)], "metadata": {}})


def m6_gate(*stripe_leg, gate=EMAIL_GATE, fallback_route=None):
    """The M6 candidate: router 89 after lock 3, route 0 the Stripe leg with the gate on its first module, route 1 (the
    fallback) the Error ledger row 90 and Slack alert 93."""
    leg = [copy.deepcopy(x) for x in stripe_leg]
    leg[0] = filt(leg[0], gate, "Email looks valid")
    fb = fallback_route if fallback_route is not None else [filt(ledger(90), [], "Email missing or invalid"), slack(93)]
    return guardrail(router(89, leg, fb, fallback=1))


class S9EmailGateTests(unittest.TestCase):
    def test_live_shape_fails_on_search_and_customer_post(self):
        fail = s9_rows(guardrail(search_customers(), customer_post()), ab.FAIL)
        self.assertEqual([f.module_id for f in fail], [10, 85])
        for f in fail:
            self.assertIn("S9 sends {{1.Email}} to Stripe with no format test", f.detail)

    def test_m6_candidate_passes(self):
        b = m6_gate(search_customers(), customer_post())
        self.assertEqual(s9_rows(b, ab.FAIL), [])
        self.assertEqual([f.module_id for f in s9_rows(b, ab.PASS)], [10])
        self.assertEqual([f for f in ab.check_s(b) if f.status == ab.FAIL], [])

    def test_gate_on_a_plain_module_fails_untraced(self):
        b = guardrail(filt(search_customers(), EMAIL_GATE), customer_post())
        fail = s9_rows(b, ab.FAIL)
        self.assertEqual([f.module_id for f in fail], [10, 85])
        self.assertIn("drops the lead with no trace", fail[0].detail)

    def test_gate_without_a_traced_fallback_fails(self):
        no_slack = m6_gate(search_customers(), customer_post(), fallback_route=[ledger(90)])
        self.assertIn("no trace", s9_rows(no_slack, ab.FAIL)[0].detail)
        no_fb = m6_gate(search_customers(), customer_post())
        no_fb.bp["flow"][1]["routes"][0]["flow"][1]["parameters"] = {}
        self.assertEqual(len(s9_rows(no_fb, ab.FAIL)), 2)
        filtered_fb = m6_gate(search_customers(), customer_post(),
                              fallback_route=[filt(ledger(90), EMAIL_GATE), slack(93)])
        self.assertEqual(len(s9_rows(filtered_fb, ab.FAIL)), 2)

    def test_gate_on_the_fallback_route_itself_fails(self):
        b = guardrail(router(89, [ledger(90), slack(93)], [filt(search_customers(), EMAIL_GATE), customer_post()], fallback=1))
        self.assertEqual(len(s9_rows(b, ab.FAIL)), 2)

    def test_gate_on_a_later_route_module_fails(self):
        b = guardrail(router(89, [{"id": 88, "module": "util:SetVariable2"}, filt(search_customers(), EMAIL_GATE), customer_post()],
                             [ledger(90), slack(93)], fallback=1))
        self.assertEqual(len(s9_rows(b, ab.FAIL)), 2)

    def test_encode_url_is_unwrapped(self):
        b = guardrail(customer_post(body="email={{ encodeURL( 1.Email ) }}&name=x"))
        self.assertIn("{{1.Email}}", s9_rows(b, ab.FAIL)[0].detail)
        self.assertEqual(s9_rows(m6_gate(customer_post(body="email={{encodeURL(1.Email)}}")), ab.FAIL), [])

    def test_case_insensitive_pattern_operator_passes(self):
        b = m6_gate(search_customers(), customer_post(), gate=cond("{{1.Email}}", "text:pattern:ci", PATTERN))
        self.assertEqual(s9_rows(b, ab.FAIL), [])

    def test_weak_gates_do_not_count(self):
        for gate in (cond("{{1.Email}}", "text:pattern", "^.+$"),           # no @
                     cond("{{1.Email}}", "text:pattern", "{{4.pattern}}"),  # mapped
                     cond("{{1.Email}}", "text:contain", "@"),              # not a pattern
                     cond("{{1.Email}}", "exist"),
                     cond("{{1.Other}}", "text:pattern", PATTERN),          # another mapping
                     [EMAIL_GATE[0], [{"a": "{{1.id}}", "o": "exist"}]]):   # one OR group is open
            b = m6_gate(search_customers(), customer_post(), gate=gate)
            self.assertEqual(len(s9_rows(b, ab.FAIL)), 2, gate)

    def test_out_of_scope_calls(self):
        """GET /v1/customers, an invoice POST with an email pair and a module that sends a literal email are not checked."""
        self.assertEqual(s9_rows(guardrail(customer_post(method="GET", key=None))), [])
        inv = customer_post(url="/v1/invoices", body="email={{1.Email}}&customer={{84.body.id}}&metadata[airtable_record_id]={{1.id}}"
                                                     "&metadata[milestone]=x")
        self.assertEqual(s9_rows(guardrail(inv)), [])
        self.assertEqual(s9_rows(guardrail(search_customers(email="ops@example.invalid"))), [])

    def test_s9_joins_other_s_rules_on_one_row(self):
        """S1 to S8 are unchanged: a POST with a bad key and no gate reports both."""
        fail = [f for f in ab.check_s(guardrail(customer_post(key=None))) if f.module_id == 85]
        self.assertEqual(len(fail), 1)
        self.assertIn("S1 the Idempotency-Key header is empty", fail[0].detail)
        self.assertIn("S9 sends", fail[0].detail)

    def test_error_route_is_out_of_scope(self):
        owner = {"id": 5, "module": "http:MakeRequest", "mapper": {}, "onerror": [search_customers()]}
        self.assertEqual(s9_rows(guardrail(owner)), [])


# ---------------------------------------------------------------------------
# The committed snapshots
# ---------------------------------------------------------------------------


class Wave1E4SnapshotTests(unittest.TestCase):
    """The full audit on blueprints/ (manifest mode, every input from the repo) raises exactly these FAIL rows for the three
    rules, as the critic's Wave 1 table names them."""

    EXPECTED = {"E26": set(), "S9": set()}  # X-41.15, X-41.17 and F-H1.4 (2026-10-31) closed every row

    def test_live_fail_rows(self):
        manifest = os.path.join(ROOT, "blueprints", "manifest.json")
        if not os.path.exists(manifest):
            self.skipTest("no committed snapshots")
        args = ab.build_parser().parse_args(["--no-report"])
        blueprints, coverage = ab.load_manifest_mode(args.blueprints, manifest)
        res = ab.audit(blueprints, ab.load_labels(args.labels), ab.load_schema(args.schema), True, coverage,
                       ab.load_links(args.links), ab.load_allowlist(args.allowlist), ab.load_webhooks(args.webhooks),
                       ab.load_hooks_info(manifest), ab.secret_scan.load_secret_allowlist(args.secret_allowlist),
                       status_designs=ab.load_status_designs(args.status_allow))
        ids = {b.name: str(b.scenario_id) for b in blueprints}
        got = {k: set() for k in self.EXPECTED}
        for f in res.findings:
            if f.status != ab.FAIL:
                continue
            for code in ("S9",) if f.check == "S" else (f.rule,):
                if code in got and (f.rule == code or f.detail.startswith(code + " ") or ("; " + code + " ") in f.detail):
                    got[code].add((ids[f.scenario], f.module_id))
                    if f.check == "E":
                        self.assertNotIn(";", f.detail)
                        self.assertNotIn("—", f.detail)
        self.assertEqual(got, self.EXPECTED)


if __name__ == "__main__":
    unittest.main()
