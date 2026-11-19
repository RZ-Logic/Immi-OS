"""Wave 1 rules from the 2026-10-31 bug sweep: B1 (a Logger call's lead_record_id sends a whole Airtable link list, bug sweep
L3, closed by F-E5.4 with {{first(<link>)}}, which the Logger payload contract now accepts) and E11 clause (a) (a mapped
item in an Airtable record list that is not a record ID can be empty, bug sweep L2). Synthetic fixtures shaped like the live
modules, plus a snapshot of the rows on the committed blueprints. No network.
"""

import copy
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import audit_blueprints as ab  # noqa: E402
import secret_scan  # noqa: E402

LEAD = ab.LEAD_TABLE
LEDGER = ab.LEDGER_TABLE
FILES = "tblSFR7Sg8uh8noO2"
LINK = ab.LEAD_LINK_FIELD  # System Logs: Applicant Link (multipleRecordLinks to Applicants)
VAR = "var.team.IMMIOS_LOGGER_URL"
CONN = 4242
SPEC = ab.LoggerSpec("900", 77, VAR, CONN, "The shared Logger, a sentence")
LINKS = ab.load_links(ab.DEFAULT_LINKS, required=True)
FIXED_LINK = "{{remove(add(emptyarray; ifempty(first(5.`Related Applicant`); emptystring)); emptystring)}}"


def bp(*flow, sid="1"):
    return ab.Blueprint(name="S", scenario_id=sid, source="test", bp={"name": "S", "flow": list(flow), "metadata": {}})


def trigger(mid=1):
    return {"id": mid, "module": "google-email:triggerWatchNewEmails", "parameters": {"limit": 1}}


def search(mid, table=FILES):
    return {"id": mid, "module": "airtable:ActionSearchRecords", "mapper": {"table": table, "formula": "{Client Email} = 'x'",
                                                                           "maxRecords": "1"}}


def ext(mid):
    return {"id": mid, "module": "google-email:sendAnEmail", "mapper": {}}


def call(mid, owner, lead=None):
    body = {"label": "S", "outcome": "Error", "module_id": str(owner), "module_name": "Send",
            "error_type": "{{%s.error.type}}" % owner, "error_message": "{{%s.error.message}}" % owner,
            "execution_id": "{{var.scenario.executionId}}"}
    if lead is not None:
        body["lead_record_id"] = lead
    return {"id": mid, "module": "http:MakeRequest", "version": 4,
            "parameters": {"authenticationType": "apiKeyConnection", "apiKeyAccount": CONN},
            "mapper": {"url": "{{%s}}" % VAR, "method": "post", "headers": [], "queryParameters": [], "contentType": "urlEncoded",
                       "urlEncodedBodyContent": [{"name": k, "value": v} for k, v in body.items()], "parseResponse": False,
                       "stopOnHttpError": False, "allowRedirects": False}}


def handled(m, *handler):
    m = dict(m)
    m["onerror"] = list(handler)
    return m


def brk(mid=21):
    return {"id": mid, "module": "builtin:Break"}


def ledger(mid, **record):
    return {"id": mid, "module": "airtable:ActionCreateRecord", "mapper": {"table": LEDGER, "record": dict(record)}}


def b_rows(lead, source=None, spec=SPEC, links=LINKS):
    """check B on [trigger, source search 3, email 4 with handler [logger call 20, Break]]."""
    src = source if source is not None else search(3)
    return ab.check_b(bp(trigger(), src, handled(ext(4), call(20, 4, lead), brk())), spec, links=links)


def b1(rows):
    return [f for f in rows if f.rule == "B1"]


def owner(rows):
    return next(f for f in rows if f.module_id == 4)


def e11(b, status=ab.FAIL):
    return [f for f in ab.check_e(b, LINKS, ab.Allowlist()) if f.rule == "E11" and f.status == status]


class B1LinkListTests(unittest.TestCase):
    """B1: a Logger call whose lead_record_id is one bare reference to an Airtable link field FAILs on the call."""

    def test_whole_link_list_fails_on_the_call(self):
        # Support Bot shape: Files search 5, Logger lead_record_id {{5.`Related Applicant`}}.
        rows = b_rows("{{3.`Related Applicant`}}")
        got = b1(rows)
        self.assertEqual([(f.check, f.status, f.module_id) for f in got], [("B", ab.FAIL, 20)])
        self.assertTrue(got[0].detail.startswith("B1 lead_record_id: logger call 20 sends {{3.`Related Applicant`}}"))
        self.assertIn("{{first(3.`Related Applicant`)}}", got[0].detail)
        self.assertNotIn(";", got[0].detail)
        # The owner row keeps passing the bare link on purpose: the push changes the call only.
        self.assertEqual(owner(rows).status, ab.PASS, owner(rows).detail)

    def test_system_logs_applicant_link_fails(self):
        # Recon Campaign / Recon VIP shape: a System Logs search, {{3.`Applicant Link`}}.
        rows = b_rows("{{3.`Applicant Link`}}", search(3, LEDGER))
        self.assertEqual([f.module_id for f in b1(rows)], [20])

    def test_first_of_the_link_passes(self):
        for src, field in ((search(3), "Related Applicant"), (search(3, LEDGER), "Applicant Link")):
            rows = b_rows("{{first(3.`%s`)}}" % field, src)
            self.assertEqual(b1(rows), [])
            self.assertEqual(owner(rows).status, ab.PASS, owner(rows).detail)
        rows = b_rows("{{first( 3.`Related Applicant` )}}")
        self.assertEqual(owner(rows).status, ab.PASS, owner(rows).detail)

    def test_record_id_is_not_b1(self):
        rows = b_rows("{{3.id}}", search(3, LEAD))
        self.assertEqual(b1(rows), [])
        self.assertEqual(owner(rows).status, ab.PASS, owner(rows).detail)

    def test_non_link_field_is_not_b1_and_stays_an_owner_fail(self):
        # A lookup, rollup or text field is not in the link map, so it is the contract FAIL on the owner, not B1.
        rows = b_rows("{{3.`Client Email`}}")
        self.assertEqual(b1(rows), [])
        self.assertEqual(owner(rows).status, ab.FAIL)
        self.assertIn("not an Applicants record ID", owner(rows).detail)

    def test_no_lead_record_id_or_no_logger_registry_is_not_b1(self):
        self.assertEqual(b1(b_rows(None)), [])
        self.assertEqual(b1(b_rows("{{3.`Related Applicant`}}", spec=None)), [])

    def test_text_around_the_link_is_not_b1(self):
        rows = b_rows("x {{3.`Related Applicant`}}")
        self.assertEqual(b1(rows), [])
        self.assertIn("lead_record_id that is not one mapped reference", owner(rows).detail)

    def test_without_the_link_map_nothing_is_known_to_be_a_list(self):
        self.assertEqual(b1(b_rows("{{3.`Related Applicant`}}", links=ab.AirtableMap())), [])

    def test_call_in_a_nested_handler_router_is_found(self):
        r = {"id": 30, "module": "builtin:BasicRouter", "routes": [{"flow": [call(20, 4, "{{3.`Related Applicant`}}"), brk()]}]}
        rows = ab.check_b(bp(trigger(), search(3), handled(ext(4), r)), SPEC, links=LINKS)
        self.assertEqual([f.module_id for f in b1(rows)], [20])


class FirstOfContractTests(unittest.TestCase):
    """The Logger payload contract accepts lead_record_id {{first(<Applicants link>)}} and nothing looser (F-E5.4)."""

    def test_first_of_a_record_id_fails(self):
        row = owner(b_rows("{{first(3.id)}}", search(3, LEAD)))
        self.assertEqual(row.status, ab.FAIL)
        self.assertIn("first() belongs on a link field only", row.detail)

    def test_first_of_a_non_link_field_fails(self):
        row = owner(b_rows("{{first(3.`Client Email`)}}"))
        self.assertEqual(row.status, ab.FAIL)
        self.assertIn("lead_record_id {{first(3.`Client Email`)}}, but lead_record_id is not an Applicants record ID", row.detail)

    def test_first_of_a_link_to_another_table_fails(self):
        row = owner(b_rows("{{first(3.`Voice AI Ledger`)}}", search(3, LEDGER)))
        self.assertEqual(row.status, ab.FAIL)
        self.assertIn("not an Applicants record ID", row.detail)

    def test_first_of_a_link_not_in_scope_fails(self):
        rows = ab.check_b(bp(trigger(), handled(ext(4), call(20, 4, "{{first(5.`Related Applicant`)}}"), brk()), search(5)),
                          SPEC, links=LINKS)
        self.assertIn("not in scope", owner(rows).detail)
        self.assertEqual(owner(rows).status, ab.FAIL)

    def test_first_with_more_arguments_or_text_fails(self):
        for v in ("{{first(3.`Related Applicant`; 2)}}", "{{first(3.`Related Applicant`)}} x", "{{last(3.`Related Applicant`)}}",
                  "{{first(first(3.`Related Applicant`))}}"):
            row = owner(b_rows(v))
            self.assertEqual(row.status, ab.FAIL, v)
            self.assertIn("lead_record_id that is not one mapped reference", row.detail, v)

    def test_first_is_lead_record_id_only(self):
        c = call(20, 4)
        c["mapper"]["urlEncodedBodyContent"].append({"name": "call_id", "value": "{{first(3.call_id)}}"})
        rows = ab.check_b(bp(trigger(), {"id": 3, "module": "bland:sendACall", "mapper": {}}, handled(ext(4), c, brk())), SPEC,
                          links=LINKS)
        self.assertIn("sends call_id that is not one mapped reference", owner(rows).detail)


class E11MappedListItemTests(unittest.TestCase):
    """E11 clause (a): a record list item that maps anything but a record ID FAILs, main flow, routes and error routes."""

    def test_first_of_a_link_in_a_list_fails(self):
        # Support Bot 18 shape.
        got = e11(bp(trigger(), search(5), ledger(18, **{LINK: ["{{first(5.`Related Applicant`)}}"]})))
        self.assertEqual([f.module_id for f in got], [18])
        self.assertTrue(got[0].detail.startswith(f"E11 (a) record field(s) {LINK}"))
        self.assertIn("5.`Related Applicant`", got[0].detail)
        self.assertNotIn(";", got[0].detail)

    def test_fixed_single_string_form_passes(self):
        self.assertEqual(e11(bp(trigger(), search(5), ledger(18, **{LINK: FIXED_LINK}))), [])

    def test_record_ids_and_literals_pass(self):
        for v in (["{{5.id}}"], ["{{5.id}}", "{{6.id}}"], ["recABCDEFGHIJKLMN"], ["{{var.scenario.executionId}}"], []):
            self.assertEqual(e11(bp(trigger(), search(5), search(6), ledger(18, **{LINK: v}))), [], v)

    def test_any_non_id_field_in_a_list_fails(self):
        for v in (["{{5.`Related Applicant`}}"], ["{{5.id}}", "{{6.Name}}"], ["{{ifempty(5.Status; \"x\")}}"]):
            got = e11(bp(trigger(), search(5), search(6), ledger(18, **{"fldMULTI": v})))
            self.assertEqual([f.module_id for f in got], [18], v)

    def test_update_and_error_route_writes_count(self):
        upd = {"id": 19, "module": "airtable:ActionUpdateRecords",
               "mapper": {"table": LEDGER, "id": "{{5.id}}", "record": {LINK: ["{{5.`Applicant Link`}}"]}}}
        self.assertEqual([f.module_id for f in e11(bp(trigger(), search(5, LEDGER), upd))], [19])
        err = handled(ext(4), ledger(30, **{LINK: ["{{5.`Related Applicant`}}"]}), brk())
        self.assertEqual([f.module_id for f in e11(bp(trigger(), search(5), err))], [30])

    def test_literal_empty_clause_unchanged(self):
        # The original clause keeps its scope: outside error routes only, and its own row.
        got = e11(bp(trigger(), ledger(18, **{LINK: [""]})))
        self.assertEqual(len(got), 1)
        self.assertTrue(got[0].detail.startswith("E11 record field(s)"))
        self.assertEqual(e11(bp(trigger(), handled(ext(4), ledger(30, **{LINK: [""]}), brk()))), [])
        both = e11(bp(trigger(), search(5), ledger(18, **{LINK: ["", "{{5.Name}}"]})))
        self.assertEqual(len(both), 2)

    def test_not_allowlistable(self):
        self.assertNotIn("E11", ab.ALLOW_RULES)
        self.assertNotIn("B1", ab.ALLOW_RULES)


def _full_audit():
    p = ab.build_parser().parse_args([])
    man = os.path.join(ROOT, "blueprints", "manifest.json")
    bps, cov = ab.load_manifest_mode(os.path.join(ROOT, "blueprints"), man)
    return ab.audit(bps, ab.load_labels(p.labels), ab.load_schema(p.schema), True, cov, ab.load_links(p.links),
                    ab.load_allowlist(p.allowlist), ab.load_webhooks(p.webhooks), ab.load_hooks_info(man),
                    secret_scan.load_secret_allowlist(p.secret_allowlist), status_designs=ab.load_status_designs(p.status_allow),
                    schedule=ab.load_schedule_info(man))


class SnapshotTests(unittest.TestCase):
    """The rows on the committed pull (2026-10-31), exactly. A fix push removes rows here (update the sets with the pull)."""

    B1_EXPECTED: set = set()  # F-E5.4 (2026-10-31) closed Support Bot 122-139, Recon Campaign 30 and Recon VIP 31, 32
    E11A_EXPECTED = set()  # X-41.16 (2026-10-31, Support Bot v30) closed 3954492 module 18

    @classmethod
    def setUpClass(cls):
        if not os.path.exists(os.path.join(ROOT, "blueprints", "manifest.json")):
            raise unittest.SkipTest("no committed snapshots")
        cls.res = _full_audit()
        cls.sid = {ab._scenario_label(b): str(b.scenario_id) for b in cls.res.blueprints}

    def rows(self, pred):
        return {(self.sid[f.scenario], f.module_id) for f in self.res.findings if f.status == ab.FAIL and pred(f)}

    def test_b1_rows(self):
        self.assertEqual(self.rows(lambda f: f.rule == "B1"), self.B1_EXPECTED)
        for f in self.res.findings:
            if f.rule == "B1":
                self.assertEqual(f.check, "B")
                self.assertNotIn(";", f.detail)

    def test_e11_clause_a_rows(self):
        self.assertEqual(self.rows(lambda f: f.rule == "E11" and f.detail.startswith("E11 (a)")), self.E11A_EXPECTED)
        self.assertEqual(self.rows(lambda f: f.rule == "E11"), self.E11A_EXPECTED)

    def test_designed_fixes_close_the_rows(self):
        """The F-E5.4 and X-41 candidates from the design pass both rules and raise no other FAIL on their scenario."""
        by_sid = {str(b.scenario_id): b for b in self.res.blueprints}
        before = {(f.check, f.rule, str(f.module_id), f.detail) for f in self.res.findings if f.status == ab.FAIL}
        cands = {}
        for sid, mids in (("3954492", (122, 123, 125, 126, 127, 128, 136, 139)), ("4218934", (30,)), ("4226754", (31, 32))):
            b = copy.deepcopy(by_sid[sid])
            for m, _e, _c in ab.walk(b.bp["flow"]):
                if m.get("id") in mids:
                    for it in m["mapper"]["urlEncodedBodyContent"]:
                        if it["name"] == "lead_record_id" and not it["value"].startswith("{{first("):
                            it["value"] = "{{first(%s)}}" % ab._single_expression(it["value"])
            cands[sid] = b
        for m, _e, _c in ab.walk(cands["3954492"].bp["flow"]):
            if m.get("id") == 18:
                m["mapper"]["record"][LINK] = FIXED_LINK
        p = ab.build_parser().parse_args([])
        man = os.path.join(ROOT, "blueprints", "manifest.json")
        bps = [cands.get(str(b.scenario_id), b) for b in self.res.blueprints]
        res = ab.audit(bps, ab.load_labels(p.labels), ab.load_schema(p.schema), True, [], ab.load_links(p.links),
                       ab.load_allowlist(p.allowlist), ab.load_webhooks(p.webhooks), ab.load_hooks_info(man),
                       secret_scan.load_secret_allowlist(p.secret_allowlist), status_designs=ab.load_status_designs(p.status_allow),
                       schedule=ab.load_schedule_info(man))
        after = {(f.check, f.rule, str(f.module_id), f.detail) for f in res.findings if f.status == ab.FAIL}
        self.assertEqual(after - before, set())
        self.assertEqual([f for f in res.findings if f.rule == "B1" or (f.rule == "E11" and f.status == ab.FAIL)], [])


if __name__ == "__main__":
    unittest.main()
