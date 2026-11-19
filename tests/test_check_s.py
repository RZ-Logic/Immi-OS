"""Check S, Stripe money calls (F-H1, F-H2, F-H9-prep, decided 2026-10-30). Synthetic fixtures shaped like the live
Financial Guardrail (AR) modules (createPaymentIntent 9, email 6) and the F-H1 invoice flow. No network."""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import audit_blueprints as ab  # noqa: E402
import make_push  # noqa: E402

GOOD_KEY = "immios-fh1-invoice-{{1.id}}-{{round(3.`Balance Due` * 100)}}"
GOOD_BODY = ("customer={{10.id}}&collection_method=send_invoice&metadata[airtable_record_id]={{1.id}}"
             "&metadata[milestone]=submission")


def bp(*flow):
    return ab.Blueprint(name="Financial Guardrail (AR)", scenario_id="3975479", source="test",
                        bp={"name": "x", "flow": [{"id": 1, "module": "airtable:TriggerWatchRecords"}, *flow], "metadata": {}})


def pi(mid=9, key="", meta=None):
    return {"id": mid, "module": "stripe:createPaymentIntent",
            "mapper": {"amount": "{{3.`Balance Due` * 100}}", "idempotency_key": key,
                       "metadata": meta if meta is not None else [{"key": "", "value": ""}]}}


def call(mid, url="/v1/invoices", method="POST", key=GOOD_KEY, body=GOOD_BODY):
    headers = [{"key": "Content-Type", "value": "application/x-www-form-urlencoded"}]
    if key is not None:
        headers.append({"key": "Idempotency-Key", "value": key})
    return {"id": mid, "module": "stripe:makeAnApiCall", "mapper": {"url": url, "method": method, "headers": headers, "body": body}}


def email(mid=6, link="{{9.charges.url}}"):
    return {"id": mid, "module": "google-email:sendAnEmail", "mapper": {"contents": [{"text": f"Pay here: {link}."}]}}


def rows(*flow):
    return [(f.status, f.module_id, f.detail) for f in ab.check_s(bp(*flow))]


class CheckSTests(unittest.TestCase):
    def test_live_shape_fails_on_the_payment_intent_and_the_email(self):
        r = rows(pi(), email())
        self.assertEqual([(s, m) for s, m, _ in r], [("FAIL", 9), ("FAIL", 6)])
        self.assertIn("S1 the idempotency key is empty", r[0][2])
        self.assertIn("airtable_record_id", r[0][2])
        self.assertIn("milestone", r[0][2])
        self.assertIn("S3", r[1][2])

    def test_payment_intent_with_key_and_metadata_passes(self):
        meta = [{"key": "airtable_record_id", "value": "{{1.id}}"}, {"key": "milestone", "value": "submission"}]
        self.assertEqual([(s, m) for s, m, _ in rows(pi(key=GOOD_KEY, meta=meta))], [("PASS", 9)])

    def test_invoice_flow_passes(self):
        r = rows(call(59), call(62, "/v1/invoiceitems", body="customer={{10.id}}&invoice={{59.body.id}}&amount=100"),
                 call(65, "/v1/invoices/{{59.body.id}}/finalize", body="auto_advance=false"),
                 email(link="{{65.body.hosted_invoice_url}}"))
        self.assertEqual([(s, m) for s, m, _ in r], [("PASS", 59), ("PASS", 62), ("PASS", 65)])

    def test_keys_that_change_per_run_or_miss_the_record_fail(self):
        for key, why in (("{{var.scenario.executionId}}-{{1.id}}", "changes on every run"),
                         ("inv-{{now}}-{{1.id}}", "changes on every run"),
                         ("inv-{{3.`Balance Due`}}", "record ID mapping"),
                         ("fixed-key", "fixed text"),
                         ("", "is empty"),
                         (None, "is empty")):
            with self.subTest(key=key):
                r = rows(call(59, key=key))
                self.assertEqual(r[0][0], "FAIL")
                self.assertIn(why, r[0][2])

    def test_invoice_create_without_lead_metadata_fails_but_an_item_does_not_need_it(self):
        r = rows(call(59, body="customer={{10.id}}"), call(62, "/v1/invoiceitems", body="customer={{10.id}}&amount=100"))
        self.assertEqual([(s, m) for s, m, _ in r], [("FAIL", 59), ("PASS", 62)])
        self.assertIn("S2", r[0][2])

    def test_record_id_metadata_must_be_a_bare_id_mapping(self):
        body = "customer={{10.id}}&metadata[airtable_record_id]={{1.Email}}&metadata[milestone]=submission"
        self.assertIn("airtable_record_id", rows(call(59, body=body))[0][2])

    def test_native_create_modules_without_a_key_field_fail(self):
        for t in ("stripe:createInvoice", "stripe:createInvoiceItem", "stripe:finalizeInvoice", "stripe:createRefund"):
            with self.subTest(t=t):
                r = rows({"id": 30, "module": t, "mapper": {}})
                self.assertEqual(r[0][0], "FAIL")
                self.assertIn("no idempotency key field", r[0][2])

    def test_reads_are_out_of_scope(self):
        self.assertEqual(rows(call(70, "/v1/invoices/search", method="GET", key=None, body="")), [])
        # A search sends the email to Stripe, so it needs the S9 format gate (bug sweep M6), but S1 to S8 leave it alone.
        r = rows({"id": 10, "module": "stripe:searchCustomers", "mapper": {"email": "{{1.Email}}"}})
        self.assertEqual([x[0] for x in r], ["FAIL"])
        self.assertTrue(r[0][2].startswith("S9 sends {{1.Email}} to Stripe with no format test"), r)

    def test_charges_reference_counts_only_for_a_stripe_module(self):
        self.assertEqual(rows({"id": 9, "module": "http:MakeRequest", "mapper": {}}, email()), [])

    def test_single_brace_key_fails(self):
        r = rows(call(59, key="immios-fh1-invoice-{{1.id}}-{round(3.`Balance Due` * 100)}"))
        self.assertEqual(r[0][0], "FAIL")
        self.assertIn("outside a {{ }} mapping", r[0][2])

    def test_header_name_is_case_insensitive(self):
        m = call(59, key=None)
        m["mapper"]["headers"].append({"key": "idempotency-key", "value": GOOD_KEY})
        self.assertEqual(rows(m)[0][0], "PASS")

    def test_fix_ids_map_to_check_s(self):
        for fix in ("F-H1", "F-H2", "F-H9-prep"):
            self.assertEqual(make_push.fix_checks(fix), ("S",))




class SiblingRouteTests(unittest.TestCase):
    """S6: Make keeps running sibling routes after a Break, so Stripe calls on sibling routes cannot depend on each other."""

    def router(self, void_filter, create_filter, fallback=None):
        void = call(74, "/v1/invoices/{{70.body.data[1].id}}/void", body="", key="immios-fh1-void-{{1.id}}-{{70.body.data[1].id}}")
        create = call(60)
        if void_filter:
            void["filter"] = {"name": "f", "conditions": void_filter}
        if create_filter:
            create["filter"] = {"name": "f", "conditions": create_filter}
        r = {"id": 73, "module": "builtin:BasicRouter", "routes": [{"flow": [void]}, {"flow": [create, email(6, "{{60.body.id}}")]}]}
        if fallback is not None:
            r["parameters"] = {"else": fallback}
        return r

    def s6(self, router):
        return [(st, m) for st, m, d in rows(router) if d.startswith("S6") or "S6 " in d]

    HAS = [[{"a": "{{length(70.body.data)}}", "b": "0", "o": "number:greater"}]]
    NONE = [[{"a": "{{length(70.body.data)}}", "b": "0", "o": "number:equal"}]]

    def test_void_beside_an_unfiltered_create_fails(self):
        self.assertEqual(self.s6(self.router(self.HAS, None)), [("FAIL", 73)])

    def test_mutually_filtered_routes_pass(self):
        self.assertEqual(self.s6(self.router(self.HAS, self.NONE)), [])

    def test_create_on_the_fallback_route_passes(self):
        self.assertEqual(self.s6(self.router(self.HAS, None, fallback=1)), [])

    def test_void_inline_before_the_create_has_no_router_row(self):
        void = call(74, "/v1/invoices/{{70.body.data[1].id}}/void", body="", key="immios-fh1-void-{{1.id}}-{{70.body.data[1].id}}")
        self.assertEqual([r for r in rows(call(60), void) if "S6" in r[2]], [])


class VersionPinTests(unittest.TestCase):
    """S7: paid_out_of_band (removed in Stripe API 2025-03-31.basil) is read only from a call pinned before basil."""

    def get(self, mid, version=None):
        headers = [{"key": "Stripe-Version", "value": version}] if version else []
        return {"id": mid, "module": "stripe:makeAnApiCall", "mapper": {"url": "/v1/invoices/{{4.body.data.object.id}}",
                                                                        "method": "GET", "headers": headers, "body": ""}}

    def reader(self, src):
        return {"id": 7, "module": "airtable:ActionSearchRecords", "mapper": {"formula": "x"}, "filter": {"name": "f", "conditions": [[
            {"a": "{{" + str(src) + ".body.paid_out_of_band}}", "b": "false", "o": "text:equal"}]]}}

    def s7(self, *flow):
        return [(st, m) for st, m, d in rows(*flow) if "S7" in d]

    def test_pinned_to_acacia_passes(self):
        self.assertEqual(self.s7(self.get(180, "2025-02-24.acacia"), self.reader(180)), [])

    def test_unpinned_or_basil_or_later_fails(self):
        for v in (None, "2025-03-31.basil", "2026-01-28.clover"):
            with self.subTest(v=v):
                self.assertEqual(self.s7(self.get(180, v), self.reader(180)), [("FAIL", 7)])

    def test_reading_it_from_the_event_fails(self):
        ev = {"id": 4, "module": "stripe:makeAnApiCall", "mapper": {"url": "/v1/events/{{1.event_id}}", "method": "GET", "headers": []}}
        r = self.reader(4)
        r["filter"]["conditions"][0][0]["a"] = "{{4.body.data.object.paid_out_of_band}}"
        self.assertEqual(self.s7(ev, r), [("FAIL", 7)])


class CustomerSourceTests(unittest.TestCase):
    """S8: Make's Stripe search emits an empty bundle when it finds nothing, so a POST never takes its customer from it."""

    def search(self):
        return {"id": 10, "module": "stripe:searchCustomers", "mapper": {"email": "{{1.Email}}", "limit": "1"}}

    def test_customer_straight_from_the_search_fails(self):
        r = rows(self.search(), call(60, body="customer={{10.id}}&metadata[airtable_record_id]={{1.id}}&metadata[milestone]=x"))
        self.assertEqual([(st, m) for st, m, d in r if "S8" in d], [("FAIL", 60)])

    def test_native_payment_intent_from_the_search_fails(self):
        p = pi(key=GOOD_KEY, meta=[{"key": "airtable_record_id", "value": "{{1.id}}"}, {"key": "milestone", "value": "x"}])
        p["mapper"]["customer"] = "{{10.id}}"
        self.assertEqual([(st, m) for st, m, d in rows(self.search(), p) if "S8" in d], [("FAIL", 9)])

    def test_customer_from_the_update_or_create_call_passes(self):
        cust = call(84, "/v1/customers{{if(10.id; \"/\"; \"\")}}{{10.id}}", body="email={{encodeURL(1.Email)}}",
                    key="immios-fh1-customer-{{1.id}}-x")
        inv = call(60, body="customer={{84.body.id}}&metadata[airtable_record_id]={{1.id}}&metadata[milestone]=x")
        self.assertEqual([d for _st, _m, d in rows(self.search(), cust, inv) if "S8" in d], [])

LOCKED = "LOCKED - Payment Required"
RELEASED = "Payment Verified - Ready"


def status_write(mid, value, conditions=None):
    m = {"id": mid, "module": "airtable:ActionUpdateRecords",
         "mapper": {"table": ab.LEAD_TABLE, "id": "{{1.id}}", "record": {ab.STATUS_FIELD: value}}}
    if conditions is not None:
        m["filter"] = {"name": "f", "conditions": conditions}
    return m


def ar(lock_cond, release_cond):
    """Financial Guardrail router 2: route 0 locks (3), route 1 releases (4), route 2 is the fallback."""
    router = {"id": 2, "module": "builtin:BasicRouter", "parameters": {"else": 2},
              "routes": [{"flow": [status_write(3, LOCKED, lock_cond)]}, {"flow": [status_write(4, RELEASED, release_cond)]},
                         {"flow": [{"id": 43, "module": "airtable:ActionCreateRecord", "mapper": {"table": ab.LEDGER_TABLE}}]}]}
    return router


BAL_GT0 = {"a": "{{1.`Balance Due`}}", "b": "0", "o": "number:greater"}
BAL_LE0 = {"a": "{{1.`Balance Due`}}", "b": "0", "o": "number:lessorequal"}
FEE_GT0 = {"a": "{{1.Fee}}", "b": "0", "o": "number:greater"}
READY = {"a": "{{1.`Payment Status`}}", "b": "Paid in Full", "o": "text:notequal"}
PAID = {"a": "{{1.`Payment Status`}}", "b": "Paid in Full", "o": "text:equal"}


class PaymentGateTests(unittest.TestCase):
    def gate_rows(self, router):
        return [(s, m, d) for s, m, d in rows(router) if d.startswith(("S4", "S5"))]

    def test_live_shape_fails_s5_on_the_lock_and_s4_on_the_release(self):
        r = self.gate_rows(ar([[BAL_GT0]], [[BAL_LE0, FEE_GT0]]))
        self.assertEqual([(s, m, d[:2]) for s, m, d in r], [("FAIL", 3, "S5"), ("FAIL", 4, "S4")])

    def test_l3_filters_pass(self):
        r = self.gate_rows(ar([[BAL_GT0, READY]], [[BAL_LE0, FEE_GT0, PAID]]))
        self.assertEqual([(s, m) for s, m, _ in r], [("PASS", 3), ("PASS", 4)])

    def test_an_or_group_without_the_condition_does_not_count(self):
        r = self.gate_rows(ar([[BAL_GT0, READY]], [[BAL_LE0, FEE_GT0, PAID], [BAL_LE0]]))
        self.assertEqual(r[1][:2], ("FAIL", 4))

    def test_not_equal_another_value_or_another_module_does_not_count(self):
        for cond in ({**PAID, "o": "text:notequal"}, {**PAID, "b": "Partial"}, {**PAID, "a": "{{1.Status}}"},
                     {**PAID, "a": "{{1.`Payment Status`}} "}, {**PAID, "b": "paid in full"}, {**PAID, "b": "Paid in Full "},
                     {**PAID, "a": "{{7.`Payment Status`}}"}):
            with self.subTest(cond=cond):
                r = self.gate_rows(ar([[BAL_GT0, READY]], [[BAL_LE0, FEE_GT0, cond]]))
                self.assertEqual(r[1][:2], ("FAIL", 4))

    def test_lock_gate_with_wrong_case_or_space_fails(self):
        for b in ("paid in full", "Paid in Full "):
            with self.subTest(b=b):
                r = self.gate_rows(ar([[BAL_GT0, {**READY, "b": b}]], [[BAL_LE0, FEE_GT0, PAID]]))
                self.assertEqual(r[0][:2], ("FAIL", 3))

    def test_lock_gate_on_status_does_not_count(self):
        status_ready = {"a": "{{1.Status}}", "b": "Ready for Submission", "o": "text:equal"}
        r = self.gate_rows(ar([[BAL_GT0, status_ready]], [[BAL_LE0, FEE_GT0, PAID]]))
        self.assertEqual(r[0][:2], ("FAIL", 3))

    def test_case_insensitive_equal_counts(self):
        r = self.gate_rows(ar([[BAL_GT0, {**READY, "o": "text:notequal:ci"}]], [[BAL_LE0, FEE_GT0, {**PAID, "o": "text:equal:ci"}]]))
        self.assertEqual([s for s, _m, _d in r], ["PASS", "PASS"])


class FilterOnlyExceptionTests(unittest.TestCase):
    def blueprint(self, lock_cond, release_cond):
        return {"name": "AR", "flow": [{"id": 1, "module": "airtable:TriggerWatchRecords"}, ar(lock_cond, release_cond)],
                "metadata": {}}

    def check(self, fix, live, cand):
        diff = make_push.diff_modules(live, cand)
        return make_push.check_status_writes(fix, cand, diff, None, live)

    def test_f_h9_may_change_only_the_filter_of_a_status_write(self):
        live = self.blueprint([[BAL_GT0]], [[BAL_LE0, FEE_GT0]])
        cand = self.blueprint([[BAL_GT0, READY]], [[BAL_LE0, FEE_GT0, PAID]])
        self.assertEqual(self.check("F-H9", live, cand), [3, 4])

    def test_f_h9_may_not_change_the_status_value_or_anything_else(self):
        live = self.blueprint([[BAL_GT0]], [[BAL_LE0, FEE_GT0]])
        for name, edit in {
            "value": lambda m: m["mapper"]["record"].update({ab.STATUS_FIELD: "Submitted"}),
            "table": lambda m: m["mapper"].update(id="{{2.id}}"),
            "handler": lambda m: m.update(onerror=[{"id": 90, "module": "builtin:Ignore"}]),
            "version": lambda m: m.update(version=2),
        }.items():
            with self.subTest(name=name):
                cand = self.blueprint([[BAL_GT0, READY]], [[BAL_LE0, FEE_GT0, PAID]])
                edit(cand["flow"][1]["routes"][1]["flow"][0])
                with self.assertRaises(make_push.Abort) as cm:
                    self.check("F-H9", live, cand)
                self.assertIn("only the filter", str(cm.exception))

    def test_f_h9_may_not_add_or_move_a_status_write(self):
        live = self.blueprint([[BAL_GT0]], [[BAL_LE0, FEE_GT0]])
        cand = self.blueprint([[BAL_GT0]], [[BAL_LE0, FEE_GT0]])
        cand["flow"][1]["routes"][2]["flow"].append(status_write(70, RELEASED))
        with self.assertRaises(make_push.Abort):
            self.check("F-H9", live, cand)
        cand = self.blueprint([[BAL_GT0]], [[BAL_LE0, FEE_GT0]])
        routes = cand["flow"][1]["routes"]
        routes[0]["flow"], routes[1]["flow"] = routes[1]["flow"], routes[0]["flow"]
        with self.assertRaises(make_push.Abort):
            self.check("F-H9", live, cand)

    def test_other_fix_ids_still_may_not_touch_a_status_write(self):
        live = self.blueprint([[BAL_GT0]], [[BAL_LE0, FEE_GT0]])
        cand = self.blueprint([[BAL_GT0, READY]], [[BAL_LE0, FEE_GT0]])
        for fix in ("F-H1", "F-H9-prep", "X-41"):
            with self.subTest(fix=fix):
                with self.assertRaises(make_push.Abort) as cm:
                    self.check(fix, live, cand)
                self.assertIn("only X-31 and F-31", str(cm.exception))

    def test_f_h9_maps_to_check_s(self):
        self.assertEqual(make_push.fix_checks("F-H9"), ("S",))

if __name__ == "__main__":
    unittest.main()
