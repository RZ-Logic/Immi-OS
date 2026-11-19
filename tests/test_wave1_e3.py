"""Wave 1 audit rules E24 and E25 from the 2026-10-31 bug sweep (check E, not allowlistable).

E24 (M7, X-41.13): an Ignore handler may not end a path that still holds independent work (Market Watchdog).
E25 (L9, X-41.14): one owner for voice cost, only a fetch_back reconciliation writes Voice AI Ledger rows or System Logs
Voice AI cost (Pending Call). Synthetic fixtures shaped like the live modules, plus the committed snapshots. No network.
"""

import glob
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import audit_blueprints as ab  # noqa: E402

LINKS = ab.load_links(ab.DEFAULT_LINKS, required=True)
INTEL = "tblRsgfa1CtxpMgOo"
CAMPAIGN = "tbl0IzlSUYDdZIcxZ"
LEDGER = ab.LEDGER_TABLE
VOICE = ab.VOICE_LEDGER_TABLE
COST = ab.VOICE_COST_FIELD


def bp(*flow, sid="1"):
    return ab.Blueprint(name="S", scenario_id=sid, source="test", bp={"name": "S", "flow": list(flow), "metadata": {}})


def rows(b, code, status=None, webhooks=None):
    return [f for f in ab.check_e(b, LINKS, ab.Allowlist(), None, webhooks)
            if f.rule == code and (status is None or f.status == status)]


def ids(b, code, webhooks=None):
    return sorted(f.module_id for f in rows(b, code, ab.FAIL, webhooks))


def rss(mid=1):
    return {"id": mid, "module": "rss:TriggerNewArticle", "parameters": {"maxResults": 5}}


def logger_call(mid):
    return {"id": mid, "module": "http:MakeRequest", "version": 4, "mapper": {"url": "{{var.team.IMMIOS_LOGGER_URL}}"}}


def handled(m, directive="Ignore", logger_id=None):
    m = dict(m)
    lid = logger_id or m["id"] + 100
    m["onerror"] = [logger_call(lid), {"id": lid + 100, "module": f"builtin:{directive}"}]
    return m


def create(mid, table, record=None):
    return {"id": mid, "module": "airtable:ActionCreateRecord", "mapper": {"table": table, "record": record or {"fldA": "{{1.title}}"}}}


def update(mid, table, record=None, rid="{{1.id}}"):
    return {"id": mid, "module": "airtable:ActionUpdateRecords",
            "mapper": {"table": table, "id": rid, "record": record or {"fldA": "x"}}}


def search(mid, table, formula="{Name} = 'x'"):
    return {"id": mid, "module": "airtable:ActionSearchRecords", "mapper": {"table": table, "formula": formula}}


def email(mid, body="{{1.title}}"):
    return {"id": mid, "module": "google-email:sendAnEmail", "mapper": {"to": ["x@example.com"], "subject": "s", "content": body}}


def upload(mid):
    return {"id": mid, "module": "google-drive:uploadAFile", "mapper": {"data": "{{6.data}}", "fileName": "{{6.fileName}}"}}


def ledger_row(mid, record=None):
    return create(mid, LEDGER, record or {ab.LABEL_FIELD: "Market Watchdog", ab.OUTCOME_FIELD: "Success"})


def bland(mid):
    return {"id": mid, "module": "bland:sendACall", "mapper": {"phone_number": "{{1.phone}}"}}


def router(mid, *routes):
    return {"id": mid, "module": "builtin:BasicRouter", "routes": [{"flow": list(r)} for r in routes]}


def registry(sid, protection):
    return ab.Webhooks(entries={sid: ab.WebhookEntry(sid, 1, "bland_post_call" if protection == "fetch_back" else "bland_pathway_node",
                                                     protection, "test")})


# ---------------------------------------------------------------------------
# E24 Ignore drops independent work (M7)
# ---------------------------------------------------------------------------


class E24IgnoreTests(unittest.TestCase):
    def test_watchdog_route_create_then_unrelated_email_fails(self):
        """Live route 0 shape: Intel create 12 (Ignore), Campaign create 27, email 15, System Logs 16, none reads 12."""
        b = bp(rss(), router(9, [handled(create(12, INTEL)), handled(create(27, CAMPAIGN)), handled(email(15)), handled(ledger_row(16))]))
        self.assertEqual(ids(b, "E24"), [12, 15, 27])
        detail = rows(b, "E24", ab.FAIL)[0].detail
        self.assertTrue(detail.startswith("E24 Ignore on 12 ends this path when 12 fails, so modules 27, 15, 16 never run"))
        self.assertIn("Use Resume", detail)
        self.assertNotIn(";", detail)
        self.assertNotIn("—", detail)

    def test_single_lost_module_reads_singular(self):
        b = bp(rss(), handled(create(14, INTEL)), handled(ledger_row(24)))
        self.assertIn("so module 24 never runs, and it does not read the output of 14", rows(b, "E24", ab.FAIL)[0].detail)

    def test_resume_passes(self):
        """The designed fix: the Ignore becomes a Resume under a new ID."""
        b = bp(rss(), handled(create(12, INTEL), "Resume"), handled(create(27, CAMPAIGN), "Resume"), handled(email(15), "Resume"),
               handled(ledger_row(16)))
        self.assertEqual(rows(b, "E24"), [])

    def test_break_passes(self):
        self.assertEqual(rows(bp(rss(), handled(create(12, INTEL), "Break"), email(15)), "E24"), [])

    def test_later_module_that_reads_the_output_passes(self):
        b = bp(rss(), handled(create(12, INTEL)), email(15, "Saved {{12.id}}"))
        self.assertEqual(rows(b, "E24"), [])

    def test_transitive_dependence_passes(self):
        """15 maps 27, which maps 12, so both depend on 12."""
        b = bp(rss(), handled(create(12, INTEL)), create(27, CAMPAIGN, {"fldIntel": ["{{12.id}}"]}), email(15, "{{27.id}}"))
        self.assertEqual(rows(b, "E24"), [])

    def test_dependence_in_filter_or_parameters_passes(self):
        filtered = dict(email(15, "x"))
        filtered["filter"] = {"name": "f", "conditions": [[{"a": "{{12.id}}", "o": "exist"}]]}
        self.assertEqual(rows(bp(rss(), handled(create(12, INTEL)), filtered), "E24"), [])
        params = {"id": 15, "module": "google-email:sendAnEmail", "parameters": {"account": "{{12.id}}"}, "mapper": {}}
        self.assertEqual(rows(bp(rss(), handled(create(12, INTEL)), params), "E24"), [])

    def test_aggregator_fed_by_the_module_depends_on_it(self):
        agg = {"id": 30, "module": "builtin:BasicAggregator", "parameters": {"feeder": 12}, "mapper": {"id": "x"}}
        b = bp(rss(), handled(create(12, INTEL)), agg, email(15, "{{30.array}}"))
        self.assertEqual(rows(b, "E24"), [])

    def test_later_search_on_the_same_table_passes(self):
        """A search may find the record the create made, so it depends on it, and so does what maps the search."""
        b = bp(rss(), handled(create(12, INTEL)), search(20, INTEL), email(15, "{{20.Title}}"))
        self.assertEqual(rows(b, "E24"), [])

    def test_search_on_another_table_does_not_create_dependence(self):
        b = bp(rss(), handled(create(12, INTEL)), search(20, CAMPAIGN), email(15, "{{20.Name}}"))
        self.assertEqual(ids(b, "E24"), [12])

    def test_update_with_ignore_is_out_of_scope(self):
        """Batch Outbound Caller 2 sets Calling (update, Ignore) before it dials: a lock step, not independent work."""
        b = bp(rss(), handled(update(2, ab.LEAD_TABLE, {ab.STATUS_FIELD: "Calling"})), bland(3))
        self.assertEqual(rows(b, "E24"), [])

    def test_send_followed_by_other_effect_is_out_of_scope(self):
        """Campaign Launcher 9: the email (Ignore) ahead of the call. Skipping the call after a failed send is a business choice."""
        b = bp(rss(), handled(email(9)), bland(7))
        self.assertEqual(rows(b, "E24"), [])

    def test_send_whose_only_later_module_is_a_ledger_create_fails(self):
        """Watchdog 15: a failed alert email drops the System Logs Success row (clause ii)."""
        self.assertEqual(ids(bp(rss(), handled(email(15)), handled(ledger_row(16))), "E24"), [15])

    def test_ignore_on_the_last_module_passes(self):
        """Critic 1B.2, Signed Contracts push 1: the upload with Ignore goes last on the flow, after ledger row 10."""
        b = bp(rss(), search(7, ab.LEAD_TABLE), handled(update(9, "tblSFR7Sg8uh8noO2"), "Break"),
               handled(ledger_row(10, {ab.LEAD_LINK_FIELD: ["{{7.id}}"]}), "Break"), handled(upload(40), logger_id=41))
        self.assertEqual(rows(b, "E24"), [])

    def test_upload_before_the_ledger_row_fails(self):
        """The shape the critic rejected: upload 39 (Ignore) ahead of ledger row 10, which maps only {{7.id}}."""
        b = bp(rss(), search(7, ab.LEAD_TABLE), handled(upload(39)), handled(ledger_row(10, {ab.LEAD_LINK_FIELD: ["{{7.id}}"]}), "Break"))
        self.assertEqual(ids(b, "E24"), [39])

    def test_last_on_its_route_passes_while_sibling_routes_hold_work(self):
        """Ignore drops the bundle from its own route only, so sibling routes are not lost work."""
        b = bp(rss(), router(9, [handled(email(15)), handled(ledger_row(16))], [handled(ledger_row(23))], [handled(create(14, INTEL))]))
        self.assertEqual(ids(b, "E24"), [15])

    def test_modules_in_a_later_router_count(self):
        b = bp(rss(), handled(create(12, INTEL)), router(9, [email(15)], [ledger_row(16)]))
        f = rows(b, "E24", ab.FAIL)
        self.assertEqual([x.module_id for x in f], [12])
        self.assertIn("modules 15, 16 never run", f[0].detail)

    def test_internal_modules_are_not_lost_work(self):
        setvar = {"id": 40, "module": "util:SetVariable2", "mapper": {"name": "x", "value": "{{1.title}}"}}
        self.assertEqual(rows(bp(rss(), handled(create(12, INTEL)), setvar), "E24"), [])

    def test_error_route_modules_are_out_of_scope(self):
        """A module inside an error route is judged by check B, and the handler's own modules are not later work."""
        owner = dict(create(12, INTEL))
        owner["onerror"] = [handled(email(60)), handled(ledger_row(61)), {"id": 62, "module": "builtin:Break"}]
        self.assertEqual(rows(bp(rss(), owner), "E24"), [])

    def test_trigger_is_out_of_scope(self):
        self.assertEqual(rows(bp(handled(rss()), email(15)), "E24"), [])


# ---------------------------------------------------------------------------
# E25 one owner for voice cost (L9)
# ---------------------------------------------------------------------------


class E25VoiceCostOwnerTests(unittest.TestCase):
    API = registry("1", "api_key")
    FETCH = registry("1", "fetch_back")

    def test_voice_ledger_create_in_api_key_scenario_fails(self):
        """Pending Call 76."""
        b = bp(rss(), create(76, VOICE, {ab.VOICE_CALL_LENGTH: "{{round(5.call_length * 60)}}"}))
        f = rows(b, "E25", ab.FAIL, self.API)
        self.assertEqual([x.module_id for x in f], [76])
        self.assertTrue(f[0].detail.startswith("E25 Module 76 creates a Voice AI Ledger row, but voice cost belongs to the "
                                               "post-call reconciliation"))
        self.assertNotIn(";", f[0].detail)
        self.assertNotIn("—", f[0].detail)

    def test_system_logs_voice_cost_by_id_name_or_literal_zero_fails(self):
        """Pending Call 81, 83 and 136 map {{76.`Total Cost`}}. A field keyed by name and a literal 0 count too."""
        b = bp(rss(), ledger_row(81, {COST: "{{76.`Total Cost`}}"}), ledger_row(83, {" Voice AI Cost ": "0"}),
               update(84, LEDGER, {f" {COST}": 0}))
        self.assertEqual(ids(b, "E25", self.API), [81, 83, 84])
        self.assertIn("writes Voice AI cost on a System Logs row", rows(b, "E25", ab.FAIL, self.API)[0].detail)

    def test_fixed_shape_passes(self):
        """The designed fix: 76 removed, 81, 83 and 136 without Voice AI cost and the Voice AI Ledger link."""
        b = bp(rss(), ledger_row(81, {ab.LABEL_FIELD: "x", ab.CALL_ID_FIELD: "{{3.id}}"}), ledger_row(83))
        self.assertEqual(rows(b, "E25", webhooks=self.API), [])

    def test_fetch_back_scenario_owns_the_cost(self):
        b = bp(rss(), update(3, LEDGER, {COST: "{{2.price}}"}), create(4, VOICE))
        self.assertEqual(rows(b, "E25", webhooks=self.FETCH), [])

    def test_unregistered_scenario_fails(self):
        """A scheduled scenario (no webhook entry) is not a reconciliation either."""
        b = bp(rss(), create(4, VOICE), sid="2")
        self.assertEqual(ids(b, "E25", self.FETCH), [4])

    def test_no_registry_says_nothing(self):
        b = bp(rss(), create(76, VOICE), ledger_row(81, {COST: "1"}))
        self.assertEqual(rows(b, "E25"), [])
        self.assertEqual(rows(b, "E25", webhooks=ab.Webhooks()), [])

    def test_error_route_write_fails(self):
        owner = dict(email(15))
        owner["onerror"] = [ledger_row(60, {COST: "0"}), {"id": 61, "module": "builtin:Ignore"}]
        self.assertEqual(ids(bp(rss(), owner), "E25", self.API), [60])

    def test_voice_ledger_update_and_reads_pass(self):
        b = bp(rss(), update(5, VOICE), search(6, VOICE), search(7, LEDGER, "{Voice AI cost} = BLANK()"))
        self.assertEqual(rows(b, "E25", webhooks=self.API), [])

    def test_table_by_name_resolves(self):
        b = bp(rss(), create(76, "Voice AI Ledger"), create(81, "System Logs", {"Voice AI cost": "{{5.price}}"}))
        self.assertEqual(ids(b, "E25", self.API), [76, 81])

    def test_other_tables_pass(self):
        b = bp(rss(), create(9, CAMPAIGN, {COST: "1"}))
        self.assertEqual(rows(b, "E25", webhooks=self.API), [])


# ---------------------------------------------------------------------------
# The committed snapshots, full audit
# ---------------------------------------------------------------------------


class SnapshotTests(unittest.TestCase):
    EXPECTED: set = set()  # X-41.13 and X-41.14 (2026-10-31) closed every row

    def test_full_audit_fails_exactly_the_swept_modules(self):
        if not glob.glob(os.path.join(ROOT, "blueprints", "*__*.json")):
            self.skipTest("no committed snapshots")
        args = ab.build_parser().parse_args([])
        manifest = os.path.join(args.blueprints, "manifest.json")
        blueprints, coverage = ab.load_manifest_mode(args.blueprints, manifest)
        res = ab.audit(blueprints, ab.load_labels(args.labels), ab.load_schema(args.schema), True, coverage,
                       ab.load_links(args.links), ab.load_allowlist(args.allowlist), ab.load_webhooks(args.webhooks),
                       ab.load_hooks_info(manifest), ab.secret_scan.load_secret_allowlist(args.secret_allowlist),
                       status_designs=ab.load_status_designs(args.status_allow), schedule=ab.load_schedule_info(manifest))
        sid = {ab._scenario_label(b): str(b.scenario_id) for b in blueprints}
        got = {(f.rule, sid.get(f.scenario), f.module_id) for f in res.findings if f.rule in ("E24", "E25")}
        self.assertTrue(all(f.status == ab.FAIL for f in res.findings if f.rule in ("E24", "E25")))
        self.assertEqual(got, self.EXPECTED)


if __name__ == "__main__":
    unittest.main()
