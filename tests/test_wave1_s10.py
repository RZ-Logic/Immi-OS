"""Check S rule S10 (bug sweep L4, 2026-10-31): the AR lock write must not set Payment Status to a fixed Partial or
Unpaid. Also the F-H1.5 value-only exception to hard rule 1 (approved by Rizwan 2026-10-31) in make_push: a push may
change only the Payment Status value of an existing lead Status write. Synthetic fixtures shaped like Financial
Guardrail (AR) 3975479 modules 1, 2, 3 and 4, plus a snapshot test on the committed blueprints. No network."""

import copy
import glob
import json
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import audit_blueprints as ab  # noqa: E402
import make_push  # noqa: E402

LINKS = ab.load_links(ab.DEFAULT_LINKS, required=True)
PAYMENT_STATUS = "fldqpWCzawUrtO5YA"
AMOUNT_PAID = "fldCesYm5l1GrwSmF"
LOCKED = "LOCKED - Payment Required"
RELEASED = "Payment Verified - Ready"
DERIVED = '{{if(ifempty(1.`Amount Paid`; 0) > 0; "Partial"; "Unpaid")}}'
HAS_BALANCE = [[{"a": "{{1.`Balance Due`}}", "b": "0", "o": "number:greater"},
                {"a": "{{1.`Payment Status`}}", "b": "Paid in Full", "o": "text:notequal"}]]
PAID = [[{"a": "{{1.`Balance Due`}}", "b": "0", "o": "number:lessorequal"},
         {"a": "{{1.`Payment Status`}}", "b": "Paid in Full", "o": "text:equal"}]]
AR_ID = "3975479"


def lead_write(mid, status, payment, module="airtable:ActionUpdateRecords", conditions=None, table=ab.LEAD_TABLE,
               extra=None):
    rec = {ab.STATUS_FIELD: status}
    if payment is not None:
        rec[PAYMENT_STATUS] = payment
    rec.update(extra or {})
    m = {"id": mid, "module": module, "version": 2,
         "mapper": {"id": "{{1.id}}", "base": "appdQ4ThUSMpdVK21", "table": table, "record": rec,
                    "typecast": False, "useColumnId": False},
         "onerror": [{"id": 20 + mid, "module": "builtin:Break", "mapper": {"count": "3", "retry": True}}]}
    if conditions is not None:
        m["filter"] = {"name": "f", "conditions": conditions}
    return m


def ar(lock_payment="Partial", lock=None):
    """Financial Guardrail router 2: route 0 locks (3), route 1 releases (4), route 2 is the fallback."""
    return {"id": 2, "module": "builtin:BasicRouter", "version": 1, "parameters": {"else": 2},
            "routes": [{"flow": [lock or lead_write(3, LOCKED, lock_payment, conditions=HAS_BALANCE)]},
                       {"flow": [lead_write(4, RELEASED, "Paid in Full", conditions=PAID)]},
                       {"flow": [{"id": 43, "module": "airtable:ActionCreateRecord", "mapper": {"table": ab.LEDGER_TABLE}}]}]}


def raw(*flow):
    return {"name": "Financial Guardrail (AR)",
            "flow": [{"id": 1, "module": "airtable:TriggerWatchRecords", "version": 3,
                      "parameters": {"table": ab.LEAD_TABLE}}, *flow], "metadata": {}}


def s10_rows(*flow, links=None):
    b = ab.Blueprint(name="Financial Guardrail (AR)", scenario_id=AR_ID, source="test", bp=raw(*flow))
    return [(f.status, f.module_id, f.detail) for f in ab.check_s(b, links) if "S10 " in f.detail]


class S10RuleTests(unittest.TestCase):
    def test_live_shape_fails_on_the_lock(self):
        r = s10_rows(ar())
        self.assertEqual([(s, m) for s, m, _ in r], [("FAIL", 3)])
        self.assertTrue(r[0][2].startswith("S10 writes Payment Status as the fixed value Partial"))
        self.assertIn("an unpaid lead shows as partly paid", r[0][2])
        self.assertIn("{{1.`Amount Paid`}}", r[0][2])
        self.assertNotIn(";", r[0][2])  # report prose carries no semicolons, the IML lives in CLAUDE.md
        self.assertNotIn("—", r[0][2])

    def test_derived_value_passes(self):
        self.assertEqual(s10_rows(ar(DERIVED)), [])

    def test_lock_keeps_its_s5_pass_row(self):
        b = ab.Blueprint(name="AR", scenario_id=AR_ID, source="test", bp=raw(ar(DERIVED)))
        self.assertIn(("PASS", 3), [(f.status, f.module_id) for f in ab.check_s(b) if f.detail.startswith("S5")])

    def test_fixed_unpaid_fails_too(self):
        r = s10_rows(ar("Unpaid"))
        self.assertEqual([(s, m) for s, m, _ in r], [("FAIL", 3)])
        self.assertIn("a partly paid lead shows as unpaid", r[0][2])

    def test_case_space_and_select_object_forms_fail(self):
        for value in (" partial ", "PARTIAL", {"name": "Partial"}, ["Unpaid"]):
            with self.subTest(value=value):
                self.assertEqual([(s, m) for s, m, _ in s10_rows(ar(value))], [("FAIL", 3)])

    def test_paid_in_full_literal_is_left_to_s4(self):
        self.assertEqual(s10_rows(ar("Paid in Full")), [])

    def test_no_payment_status_in_the_record_passes(self):
        self.assertEqual(s10_rows(ar(None)), [])

    def test_writing_amount_paid_in_the_same_record_passes(self):
        lock = lead_write(3, LOCKED, "Unpaid", conditions=HAS_BALANCE, extra={AMOUNT_PAID: "0"})
        self.assertEqual(s10_rows(ar(lock=lock)), [])
        lock = lead_write(3, LOCKED, "Unpaid", conditions=HAS_BALANCE, extra={AMOUNT_PAID: ""})
        self.assertEqual([(s, m) for s, m, _ in s10_rows(ar(lock=lock))], [("FAIL", 3)])

    def test_create_is_exempt(self):
        create = lead_write(5, "New", "Partial", module="airtable:ActionCreateRecord")
        self.assertEqual(s10_rows(create), [])

    def test_upsert_counts(self):
        upsert = lead_write(5, LOCKED, "Partial", module="airtable:ActionUpsertRecord")
        self.assertEqual([(s, m) for s, m, _ in s10_rows(upsert)], [("FAIL", 5)])

    def test_other_table_is_exempt(self):
        self.assertEqual(s10_rows(lead_write(5, LOCKED, "Partial", table="tblOther000000001")), [])

    def test_error_route_is_exempt(self):
        owner = {"id": 9, "module": "stripe:makeAnApiCall", "mapper": {"url": "/v1/customers", "method": "GET"},
                 "onerror": [lead_write(5, LOCKED, "Partial")]}
        self.assertEqual(s10_rows(owner), [])

    def test_field_and_table_by_name_resolve(self):
        by_name = lead_write(5, LOCKED, None, extra={"Payment Status": "Partial"})
        self.assertEqual([(s, m) for s, m, _ in s10_rows(by_name)], [("FAIL", 5)])
        table_name = LINKS.tables[ab.LEAD_TABLE]["name"]
        named = lead_write(5, LOCKED, "Partial", table=table_name)
        self.assertEqual(s10_rows(named), [])  # without the map the table name is unknown
        self.assertEqual([(s, m) for s, m, _ in s10_rows(named, links=LINKS)], [("FAIL", 5)])
        paid_by_name = lead_write(5, LOCKED, "Partial", extra={"amount paid": "{{1.`Amount Paid`}}"})
        self.assertEqual(s10_rows(paid_by_name), [])

    def test_names_the_trigger_module(self):
        b = raw(ar())
        b["flow"][0]["id"] = 7
        blue = ab.Blueprint(name="AR", scenario_id=AR_ID, source="test", bp=b)
        detail = next(f.detail for f in ab.check_s(blue) if "S10 " in f.detail)
        self.assertIn("{{7.`Amount Paid`}}", detail)


def _full_audit(replace=None):
    """The audit the command line runs on the committed snapshots, with optional blueprint replacements by scenario ID."""
    args = ab.build_parser().parse_args([])
    manifest = os.path.join(args.blueprints, "manifest.json")
    blueprints, coverage = ab.load_manifest_mode(args.blueprints, manifest)
    for b in blueprints:
        if replace and str(b.scenario_id) in replace:
            b.bp = replace[str(b.scenario_id)]
    res = ab.audit(blueprints, ab.load_labels(args.labels), ab.load_schema(args.schema), True, coverage,
                   ab.load_links(args.links), ab.load_allowlist(args.allowlist), ab.load_webhooks(args.webhooks),
                   ab.load_hooks_info(manifest), None, status_designs=ab.load_status_designs(args.status_allow),
                   schedule=ab.load_schedule_info(manifest))
    sid = {b.name: str(b.scenario_id) for b in blueprints}
    return res, sid


def _live_ar() -> dict:
    path = glob.glob(os.path.join(ROOT, "blueprints", f"*__{AR_ID}.json"))[0]
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _lock(bp: dict) -> dict:
    return next(m for m, _e, _c in ab.walk(bp["flow"]) if m.get("id") == 3)


class S10SnapshotTests(unittest.TestCase):
    def test_live_rows(self):
        if not glob.glob(os.path.join(ROOT, "blueprints", "*__*.json")):
            self.skipTest("no committed snapshots")
        res, sid = _full_audit()
        got = {(sid.get(f.scenario), f.module_id) for f in res.findings
               if f.check == "S" and f.status == ab.FAIL and "S10 " in f.detail}
        self.assertEqual(got, set())  # F-H1.5 (2026-10-31, Guardrail v16) closed module 3

    def test_f_h1_5_live_passes_and_the_old_literal_fails_again(self):
        """Live v16 carries the derived value. Putting the literal Partial back reopens S10 on 3 and nothing else."""
        if not glob.glob(os.path.join(ROOT, "blueprints", f"*__{AR_ID}.json")):
            self.skipTest("no committed snapshot")
        live = _live_ar()
        self.assertEqual(_lock(live)["mapper"]["record"][PAYMENT_STATUS], DERIVED)
        old = copy.deepcopy(live)
        _lock(old)["mapper"]["record"][PAYMENT_STATUS] = "Partial"
        now, _ = _full_audit()
        back, _ = _full_audit({AR_ID: old})
        key = lambda f: (f.check, f.scenario, str(f.module_id), f.status, f.detail)  # noqa: E731
        reopened = {key(f) for f in back.findings if f.status in (ab.FAIL, ab.REVIEW, ab.UNCONFIRMED)} \
            - {key(f) for f in now.findings}
        self.assertEqual({(k[0], k[2], k[3]) for k in reopened}, {("S", "3", ab.FAIL)})


class ValueOnlyExceptionTests(unittest.TestCase):
    """The F-H1.5 value-only exception (approved by Rizwan 2026-10-31): only Payment Status's value may change."""

    def check(self, fix, live, cand, links=None):
        return make_push.check_status_writes(fix, cand, make_push.diff_modules(live, cand), links, live)

    def cand(self, edit=None, value=DERIVED):
        c = raw(ar(value))
        if edit:
            edit(c, c["flow"][1]["routes"][0]["flow"][0])
        return c

    def test_payment_status_value_change_passes(self):
        for fix in ("F-H1.5", "F-H1.5.1"):
            with self.subTest(fix=fix):
                self.assertEqual(self.check(fix, raw(ar()), self.cand()), [3])

    def test_anything_else_aborts(self):
        cases = {
            "status value": lambda c, m: m["mapper"]["record"].update({ab.STATUS_FIELD: "Disqualified"}),
            "other field added": lambda c, m: m["mapper"]["record"].update({AMOUNT_PAID: "0"}),
            "payment status dropped": lambda c, m: m["mapper"]["record"].pop(PAYMENT_STATUS),
            "payment status by name": lambda c, m: m["mapper"]["record"].update(
                {"Payment Status": m["mapper"]["record"].pop(PAYMENT_STATUS)}),
            "filter": lambda c, m: m.update(filter=None),
            "typecast": lambda c, m: m["mapper"].update(typecast=True),
            "record id": lambda c, m: m["mapper"].update(id="{{2.id}}"),
            "handler": lambda c, m: m.update(onerror=[{"id": 90, "module": "builtin:Ignore"}]),
            "version": lambda c, m: m.update(version=3),
            "moved": lambda c, m: c["flow"][1]["routes"][2]["flow"].insert(0, c["flow"][1]["routes"][0]["flow"].pop(0)),
        }
        for name, edit in cases.items():
            with self.subTest(name=name):
                with self.assertRaises(make_push.Abort) as cm:
                    self.check("F-H1.5", raw(ar()), self.cand(edit))
                self.assertIn("may change only the value of " + PAYMENT_STATUS, str(cm.exception))

    def test_no_value_change_on_a_touched_status_write_aborts(self):
        c = self.cand(lambda c, m: m.update(onerror=[{"id": 90, "module": "builtin:Ignore"}]), value="Partial")
        with self.assertRaises(make_push.Abort):
            self.check("F-H1.5", raw(ar()), c)

    def test_adding_a_status_write_aborts(self):
        c = self.cand()
        c["flow"][1]["routes"][2]["flow"].append(lead_write(70, LOCKED, "Unpaid"))
        with self.assertRaises(make_push.Abort):
            self.check("F-H1.5", raw(ar()), c)

    def test_other_fix_ids_may_not(self):
        for fix in ("F-H1", "F-H1.4", "F-H1.50", "F-H1.6", "F-H9", "X-41.7", "X-18"):
            with self.subTest(fix=fix):
                with self.assertRaises(make_push.Abort):
                    self.check(fix, raw(ar()), self.cand())

    def test_f_h1_5_maps_to_check_s(self):
        self.assertEqual(make_push.fix_checks("F-H1.5"), ("S",))
        self.assertEqual(make_push.STATUS_VALUE_FIXES, {"F-H1.5": (PAYMENT_STATUS,)})

    def test_live_guardrail_candidate_touches_only_module_3(self):
        """The pushed v16 against v15 (rebuilt from v16 with the literal Partial): only module 3 differs, and only F-H1.5
        may make that change."""
        if not glob.glob(os.path.join(ROOT, "blueprints", f"*__{AR_ID}.json")):
            self.skipTest("no committed snapshot")
        cand = _live_ar()
        live = copy.deepcopy(cand)
        _lock(live)["mapper"]["record"][PAYMENT_STATUS] = "Partial"
        diff = make_push.diff_modules(live, cand)
        self.assertEqual((sorted(diff.added), sorted(diff.changed), sorted(diff.removed)), ([], [3], []))
        self.assertEqual(self.check("F-H1.5", live, cand, LINKS), [3])
        with self.assertRaises(make_push.Abort):
            self.check("F-H1.4", live, cand, LINKS)


if __name__ == "__main__":
    unittest.main()
