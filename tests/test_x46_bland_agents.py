"""X-46 (2026-11-01): the Bland call rules read Send a Call and Create a Call the same (E14, E17, E18 and F3), and check E28
FAILs a Bland call to a pathway migrated to a v2 agent (audit/bland_agents.json), a Create a Call without a registered
agent_id, and an agent_version that is not exactly production. E1 checks a reference to a Bland call against its pinned
outputs. Synthetic fixtures shaped like Batch Outbound Caller 3953105 (module 3 at v17, the new Create a Call 32). The
webhook URL is fake. No network.
"""

import glob
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import audit_blueprints as ab  # noqa: E402

LEAD = ab.LEAD_TABLE
LINKS = ab.load_links(ab.DEFAULT_LINKS, required=True)
PATHWAY = "9080fb12-984b-43c8-b78a-8ed72e3369c0"   # Immigration Screener pathway, migrated by X-46
AGENT = "738cdfc6-ca81-4c9a-88e3-82fe87f6502b"     # the Immigration Screener agent
VIP_PATHWAY = "4340209a-8f9d-40a1-927d-332351fbc99a"  # VIP intake 3920821, not migrated
CONN = 99999999  # a synthetic bland2 connection ID
FAKE_HOOK = "https://hook." + "us2.make.com/" + "FAKE" * 8  # built in parts, so the repo secret scan stays clean
REGISTRY = ab.BlandAgents(
    pathways={PATHWAY: {"pathway_id": PATHWAY, "agent_id": AGENT, "name": "Immigration Screener", "reason": "test entry"}},
    agents={AGENT: {"pathway_id": PATHWAY, "agent_id": AGENT, "name": "Immigration Screener", "reason": "test entry"}})


def bp(*flow, sid="3953105"):
    return ab.Blueprint(name="S", scenario_id=sid, source="test", bp={"name": "S", "flow": list(flow), "metadata": {}})


def rows(b, code, status=None, registry=REGISTRY):
    return [f for f in ab.check_e(b, LINKS, ab.Allowlist(), bland_agents=registry)
            if f.rule == code and (status is None or f.status == status)]


def search(mid=1, formula="{Status} = 'Pending Call'"):
    return {"id": mid, "module": "airtable:ActionSearchRecords", "mapper": {"table": LEAD, "formula": formula}}


def lead_update(mid=2):
    return {"id": mid, "module": "airtable:ActionUpdateRecords",
            "mapper": {"table": LEAD, "id": "{{1.id}}", "record": {ab.STATUS_FIELD: "Calling"}}}


def send_call(mid=3, **mapper):
    """Batch module 3 at v17: Send a Call on the Immigration Screener pathway with the pinned post-call webhook."""
    mp = {"phone_number": "{{1.Phone}}", "task": "x", "pathway_id": PATHWAY, "webhook": FAKE_HOOK}
    mp.update(mapper)
    return {"id": mid, "module": "bland:sendACall", "version": 1, "mapper": {k: v for k, v in mp.items() if v is not None}}


def create_call(mid=32, **mapper):
    """The X-46 target: Create a Call on the registered agent, production pin."""
    mp = {"phone_number": "{{1.Phone}}", "task": "x", "agent_id": AGENT, "agent_version": "production",
          "request_data": '{"name": "{{1.Name}}"}', "webhook": FAKE_HOOK}
    mp.update(mapper)
    return {"id": mid, "module": "bland:createACall", "version": 1, "parameters": {"__IMTCONN__": CONN},
            "mapper": {k: v for k, v in mp.items() if v is not None}}


def batch(call):
    return bp(search(), lead_update(), call)


# ---------------------------------------------------------------------------
# Create a Call counts as a Bland call everywhere Send a Call does
# ---------------------------------------------------------------------------


class BlandCallsTests(unittest.TestCase):
    def test_both_types_are_bland_calls(self):
        self.assertEqual(set(ab.BLAND_CALLS), {"bland:sendACall", "bland:createACall"})
        self.assertFalse(hasattr(ab, "BLAND_CALL"))

    def test_e14_gates_create_a_call_like_send_a_call(self):
        """Batch shape: search 1 on Status only, update 2 sets Calling, the call dials {{1.Phone}}. The row sits on 1."""
        for call in (send_call(3), create_call(32)):
            fail = rows(batch(call), "E14", ab.FAIL)
            self.assertEqual([f.module_id for f in fail], [1], call["module"])
            self.assertIn(f"Bland {call['id']} dials {{{{1.Phone}}}}", fail[0].detail)
        gated = bp(search(formula="AND({Status} = 'Pending Call', REGEX_MATCH({Phone}, '^[+][1-9][0-9]{7,14}$'))"),
                   lead_update(), create_call(32))
        self.assertEqual(rows(gated, "E14"), [])

    def test_e17_needs_the_post_call_webhook_on_create_a_call(self):
        for call in (send_call(3, webhook=None), create_call(32, webhook=None)):
            fail = rows(batch(call), "E17", ab.FAIL)
            self.assertEqual([f.module_id for f in fail], [call["id"]], call["module"])
        self.assertEqual(rows(batch(create_call(32)), "E17"), [])

    def test_e18_reads_create_a_call_as_a_client_send(self):
        self.assertTrue(ab._is_client_send(create_call()))
        self.assertTrue(ab._is_client_send(send_call()))
        for call in (send_call(3), create_call(32)):
            b = bp(search(formula="{Phone} != ''"), lead_update(), call)
            fail = rows(b, "E18", ab.FAIL)
            self.assertEqual([f.module_id for f in fail], [1], call["module"])  # the search can return a Disqualified lead
        self.assertEqual(rows(batch(create_call(32)), "E18"), [])  # {Status} = 'Pending Call' excludes both

    def test_f3_counts_create_a_call_as_a_paid_client_call(self):
        for call in (send_call(), create_call()):
            self.assertEqual(ab._f3_kind(call, ab._DEFAULT_LEAD), "client call (paid)", call["module"])

    def test_error_route_calls_are_out_of_scope_for_e14_and_e17_but_not_e28(self):
        """A Bland call in a handler still dials, so E28 judges it. E14 and E17 keep their error route exemption."""
        owner = dict(search(5, "{Name} = 'x'"))
        owner["onerror"] = [create_call(40, agent_id=None, webhook=None)]
        b = bp(owner)
        for code in ("E14", "E17"):
            self.assertEqual(rows(b, code), [], code)
        self.assertEqual([f.module_id for f in rows(b, "E28", ab.FAIL)], [40])
        owner["onerror"] = [send_call(41)]
        self.assertEqual([f.module_id for f in rows(bp(owner), "E28", ab.FAIL)], [41])  # the migrated pathway in a handler


# ---------------------------------------------------------------------------
# E28 Bland call to a migrated pathway
# ---------------------------------------------------------------------------


class E28MustFailTests(unittest.TestCase):
    def test_batch_module_3_at_v17_fails(self):
        """The must-fail case of the X-46 push: Send a Call 3 still dials the migrated Immigration Screener pathway."""
        fail = rows(batch(send_call(3)), "E28", ab.FAIL)
        self.assertEqual([f.module_id for f in fail], [3])
        self.assertIn(f"dials pathway {PATHWAY}", fail[0].detail)
        self.assertIn(AGENT, fail[0].detail)
        self.assertIn("agent_version production", fail[0].detail)

    def test_pathway_match_ignores_case_and_whitespace(self):
        fail = rows(batch(send_call(3, pathway_id=f" {PATHWAY.upper()} ")), "E28", ab.FAIL)
        self.assertEqual([f.module_id for f in fail], [3])

    def test_create_a_call_with_the_migrated_pathway_fails(self):
        fail = rows(batch(create_call(32, agent_id=None, agent_version=None, pathway_id=PATHWAY)), "E28", ab.FAIL)
        self.assertEqual(len(fail), 2)  # the pathway row and the no agent row
        self.assertTrue(any("dials pathway" in f.detail for f in fail))
        self.assertTrue(any("sets no agent_id and dials by pathway_id only" in f.detail for f in fail))

    def test_create_a_call_with_no_agent_id_fails(self):
        """Module 32 as pulled today: added in the UI, never configured, so its mapper and parameters are empty."""
        unconfigured = {"id": 32, "module": "bland:createACall", "version": 1, "parameters": {}, "mapper": {}}
        for call in (create_call(32, agent_id=None), create_call(32, agent_id=""), create_call(32, agent_id="   "),
                     create_call(32, agent_id=[]), create_call(32, agent_id={})):
            fail = rows(batch(call), "E28", ab.FAIL)
            self.assertEqual([f.module_id for f in fail], [32], call)
            self.assertIn("sets no agent_id", fail[0].detail)
        for call in (unconfigured, {"id": 32, "module": "bland:createACall", "version": 1}):
            fail = rows(batch(call), "E28", ab.FAIL)
            self.assertEqual([f.module_id for f in fail], [32, 32], call)
            self.assertIn("sets no agent_id and dials nothing", fail[0].detail)
            self.assertIn("has no connection (parameters.__IMTCONN__)", fail[1].detail)

    def test_create_a_call_by_persona_only_fails(self):
        fail = rows(batch(create_call(32, agent_id=None, persona_id="11111111-2222-3333-4444-555555555555")), "E28", ab.FAIL)
        self.assertEqual([f.module_id for f in fail], [32])
        self.assertIn("dials by persona_id only", fail[0].detail)

    def test_create_a_call_on_another_pathway_and_no_agent_fails(self):
        fail = rows(batch(create_call(32, agent_id=None, pathway_id=VIP_PATHWAY)), "E28", ab.FAIL)
        self.assertEqual([f.module_id for f in fail], [32])
        self.assertIn("dials by pathway_id only", fail[0].detail)

    def test_unknown_agent_id_fails(self):
        other = "00000000-1111-2222-3333-444444444444"
        fail = rows(batch(create_call(32, agent_id=other)), "E28", ab.FAIL)
        self.assertEqual([f.module_id for f in fail], [32])
        self.assertIn(f"dials agent {other}, which is not in audit/bland_agents.json", fail[0].detail)

    def test_mapped_agent_id_fails(self):
        fail = rows(batch(create_call(32, agent_id="{{1.Agent}}")), "E28", ab.FAIL)
        self.assertEqual([f.module_id for f in fail], [32])
        self.assertIn("maps agent_id", fail[0].detail)

    def test_agent_version_not_exactly_production_fails(self):
        for ver in ("staging", "Production", " production", "production ", "{{1.version}}", "3", "", None):
            fail = rows(batch(create_call(32, agent_version=ver)), "E28", ab.FAIL)
            self.assertEqual([f.module_id for f in fail], [32], repr(ver))
            self.assertIn("not exactly production", fail[0].detail, repr(ver))
        fail = rows(batch(create_call(32, agent_version="staging")), "E28", ab.FAIL)
        self.assertIn('agent_version "staging"', fail[0].detail)
        fail = rows(batch(create_call(32, agent_version="production ")), "E28", ab.FAIL)
        self.assertIn('agent_version "production ", not exactly production', fail[0].detail)  # the quotes show the space
        fail = rows(batch(create_call(32, agent_version=None)), "E28", ab.FAIL)
        self.assertIn("agent_version nothing", fail[0].detail)

    def test_an_empty_registry_fails_every_create_a_call_and_misses_the_pathway(self):
        """Strictest for Create a Call and loosest for the migrated pathway, which is why the audit refuses a missing file."""
        fail = rows(batch(create_call(32)), "E28", ab.FAIL, registry=ab.BlandAgents())
        self.assertEqual([f.module_id for f in fail], [32])
        self.assertEqual(rows(batch(send_call(3)), "E28", registry=ab.BlandAgents()), [])

    def test_the_audit_refuses_a_missing_registry(self):
        with tempfile.TemporaryDirectory() as d:
            missing = os.path.join(d, "bland_agents.json")
            with mock.patch.object(ab, "DEFAULT_BLAND_AGENTS", missing):
                with self.assertRaises(ab.InputError):
                    ab.check_e(batch(send_call(3)), LINKS, ab.Allowlist())
            err = io.StringIO()
            with redirect_stdout(io.StringIO()), redirect_stderr(err):
                code = ab.main(["--no-report", "--bland-agents", missing])
            self.assertEqual(code, 2)
            self.assertIn("no Bland agent registry", err.getvalue())

    def test_agent_id_beside_a_pathway_or_persona_fails(self):
        """Make takes only one of pathway_id, persona_id and agent_id (spec 5.1), so a second one leaves the dial unknown."""
        for extra in ({"pathway_id": VIP_PATHWAY}, {"persona_id": "11111111-2222-3333-4444-555555555555"},
                      {"pathway_id": "{{1.pathway}}"}):
            fail = rows(batch(create_call(32, **extra)), "E28", ab.FAIL)
            self.assertEqual([f.module_id for f in fail], [32], extra)
            self.assertIn(f"sets agent_id and also {next(iter(extra))}", fail[0].detail)
        fail = rows(batch(create_call(32, pathway_id=VIP_PATHWAY, persona_id="x")), "E28", ab.FAIL)
        self.assertIn("also pathway_id and persona_id", fail[0].detail)
        self.assertEqual(rows(batch(create_call(32, pathway_id="", persona_id=None)), "E28"), [])  # empty is not set

    def test_send_a_call_with_an_agent_id_fails(self):
        """Send a Call has no agent_id field, so Make drops the value and the call dials by task or pathway."""
        fail = rows(batch(send_call(7, pathway_id=None, agent_id=AGENT, agent_version="production")), "E28", ab.FAIL)
        self.assertEqual([f.module_id for f in fail], [7])
        self.assertIn("Send a Call 7 sets agent_id, but the module has no agent_id field", fail[0].detail)
        self.assertEqual(rows(batch(send_call(7, pathway_id=None, agent_id="")), "E28"), [])

    def test_a_mapped_pathway_on_send_a_call_is_a_review(self):
        review = rows(batch(send_call(3, pathway_id="{{1.pathway}}")), "E28")
        self.assertEqual([(f.module_id, f.status) for f in review], [(3, ab.REVIEW)])
        self.assertIn("maps pathway_id {{1.pathway}}", review[0].detail)
        self.assertEqual(rows(batch(send_call(3, pathway_id="{{1.pathway}}")), "E28", registry=ab.BlandAgents()), [])

    def test_an_agent_id_that_is_not_a_string_fails_with_a_true_message(self):
        for agent, kind in (([AGENT], "list"), ({"id": AGENT}, "dict"), (7, "int")):
            fail = rows(batch(create_call(32, agent_id=agent)), "E28", ab.FAIL)
            self.assertEqual([f.module_id for f in fail], [32], agent)
            self.assertIn(f"sets agent_id to a {kind}, not a Bland agent UUID", fail[0].detail)
            self.assertNotIn("sets no agent_id", fail[0].detail)

    def test_an_agent_id_with_spaces_fails(self):
        for agent in (f" {AGENT}", f"{AGENT} ", f"{AGENT}\n"):
            fail = rows(batch(create_call(32, agent_id=agent)), "E28", ab.FAIL)
            self.assertEqual([f.module_id for f in fail], [32], repr(agent))
            self.assertIn("with spaces around it", fail[0].detail)

    def test_a_value_that_is_not_a_uuid_is_never_echoed(self):
        """A key pasted into agent_id or agent_version must not reach the console or the report."""
        pasted = "org_" + "FAKE" * 12  # key-shaped, built in parts
        fail = rows(batch(create_call(32, agent_id=pasted)), "E28", ab.FAIL)
        self.assertEqual([f.module_id for f in fail], [32])
        self.assertIn("a value that is not a Bland UUID", fail[0].detail)
        fail = rows(batch(create_call(32, agent_version=pasted)), "E28", ab.FAIL)
        self.assertIn("a value that is not production, staging or a version number", fail[0].detail)
        fail = rows(batch(create_call(32, agent_id=pasted + "{{1.x}}")), "E28", ab.FAIL)
        self.assertIn("maps agent_id a value that is not a Bland UUID", fail[0].detail)
        fail = rows(batch(send_call(3, pathway_id=pasted + "{{1.x}}")), "E28")
        for f in fail + rows(batch(create_call(32, agent_id=pasted)), "E28") + rows(batch(create_call(32, agent_version=pasted)), "E28"):
            self.assertNotIn("FAKEFAKE", f.detail)

    def test_create_a_call_with_no_connection_fails(self):
        for params in ({}, {"__IMTCONN__": None}, {"__IMTCONN__": ""}, None):
            call = create_call(32)
            if params is None:
                del call["parameters"]
            else:
                call["parameters"] = params
            fail = rows(batch(call), "E28", ab.FAIL)
            self.assertEqual([f.module_id for f in fail], [32], params)
            self.assertIn("has no connection", fail[0].detail)

    def test_e28_cannot_be_allowlisted(self):
        self.assertNotIn("E28", ab.ALLOW_RULES)
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "allowlist.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"entries": [{"check": "E28", "scenario": "3953105", "module": "32",
                                        "reason": "an attempt to excuse the agent rule"}]}, fh)
            with self.assertRaises(ab.InputError):
                ab.load_allowlist(path)


class E28PassTests(unittest.TestCase):
    def test_create_a_call_on_the_registered_agent_and_production_passes(self):
        self.assertEqual(rows(batch(create_call(32)), "E28"), [])
        self.assertEqual(rows(batch(create_call(32, agent_id=AGENT.upper())), "E28"), [])

    def test_send_a_call_by_task_passes(self):
        """Campaign Launcher 3961751 module 7 and The Interview Room (A) 3975140 module 2 dial by task, no pathway."""
        self.assertEqual(rows(batch(send_call(7, pathway_id=None)), "E28"), [])

    def test_send_a_call_on_an_unmigrated_pathway_passes(self):
        """VIP intake 3920821 module 10 dials pathway 4340209a, which is not in the registry."""
        self.assertEqual(rows(batch(send_call(10, pathway_id=VIP_PATHWAY)), "E28"), [])

    def test_check_e_reads_the_committed_registry_by_default(self):
        b = batch(create_call(32))
        self.assertEqual([f for f in ab.check_e(b, LINKS, ab.Allowlist()) if f.rule == "E28"], [])
        b = batch(send_call(3))
        self.assertEqual([f.module_id for f in ab.check_e(b, LINKS, ab.Allowlist()) if f.rule == "E28"], [3])


# ---------------------------------------------------------------------------
# The registry (audit/bland_agents.json)
# ---------------------------------------------------------------------------


class RegistryTests(unittest.TestCase):
    def write(self, d, data):
        path = os.path.join(d, "bland_agents.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        return path

    def entry(self, **kw):
        e = {"pathway_id": PATHWAY, "agent_id": AGENT, "name": "Immigration Screener", "reason": "X-46 migration test"}
        e.update(kw)
        return e

    def test_the_committed_registry_maps_the_screener(self):
        reg = ab.load_bland_agents(ab.DEFAULT_BLAND_AGENTS, required=True)
        self.assertEqual(reg.pathways[PATHWAY]["agent_id"], AGENT)
        self.assertEqual(reg.agents[AGENT]["name"], "Immigration Screener")

    def test_a_missing_file_is_refused_unless_optional(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "none.json")
            with self.assertRaises(ab.InputError):
                ab.load_bland_agents(path)
            self.assertEqual(ab.load_bland_agents(path, required=False).agents, {})

    def test_bad_entries_are_refused(self):
        bad = ({"agents": "x"}, {"agents": ["x"]}, {"agents": [self.entry(pathway_id="9080fb12")]},
               {"agents": [self.entry(agent_id=None)]}, {"agents": [self.entry(name="")]},
               {"agents": [self.entry(reason="x")]}, {"agents": [self.entry(), self.entry()]},
               {"agents": [self.entry(), self.entry(pathway_id=VIP_PATHWAY)]})
        with tempfile.TemporaryDirectory() as d:
            for data in bad:
                with self.assertRaises(ab.InputError, msg=data):
                    ab.load_bland_agents(self.write(d, data))

    def test_ids_are_stored_lowercase(self):
        with tempfile.TemporaryDirectory() as d:
            reg = ab.load_bland_agents(self.write(d, {"agents": [self.entry(agent_id=AGENT.upper())]}))
            self.assertIn(AGENT, reg.agents)

    def test_the_e_description_names_e28(self):
        self.assertIn("E28 (X-46)", ab.SECTION_INTRO["E"])
        self.assertIn("E28", ab.__doc__)


# ---------------------------------------------------------------------------
# E1 reads the pinned Bland call outputs
# ---------------------------------------------------------------------------


def ledger_create(mid=18, ref="{{32.call_id}}"):
    return {"id": mid, "module": "airtable:ActionCreateRecord", "mapper": {"table": "tblShadowLedgerFAKE", "record": {"fldX": ref}}}


def e1_rows(*flow):
    """E1 rows of the flow, leaving out the skip row for search 1 (an Airtable fixture with no interface)."""
    return [f for f in ab.check_e(bp(*flow), LINKS, ab.Allowlist(), bland_agents=REGISTRY)
            if f.rule == "E1" and not (f.status == ab.INFO and f.module_id == 1)]


class BlandOutputsTests(unittest.TestCase):
    def test_the_pinned_outputs(self):
        self.assertEqual(ab.BLAND_CALL_OUTPUTS, {"status", "message", "call_id"})

    def test_a_reference_to_a_real_output_passes_and_no_row_says_skipped(self):
        for call in (create_call(32), send_call(32)):
            for ref in ("{{32.call_id}}", "{{32.status}}", "{{32.message}}", "{{32.error.message}}"):
                found = e1_rows(search(), call, ledger_create(ref=ref))
                self.assertEqual(found, [], (call["module"], ref))

    def test_a_typo_in_a_bland_output_fails(self):
        """After X-46, Shadow Ledger 18 and Logger call 26 map {{32.call_id}}. A typo must FAIL, not pass as a skipped INFO."""
        found = e1_rows(search(), create_call(32), ledger_create(ref="{{32.callid}}"))
        self.assertEqual([(f.module_id, f.status) for f in found], [(18, ab.FAIL)])
        self.assertIn("does not output `callid`", found[0].detail)
        self.assertIn("call_id", found[0].detail)  # the closest output is named

    def test_an_interface_still_wins(self):
        call = create_call(32)
        call["metadata"] = {"interface": [{"name": "call_id"}, {"name": "batch_id"}]}
        found = e1_rows(search(), call, ledger_create(ref="{{32.batch_id}}"))
        self.assertEqual(found, [])


# ---------------------------------------------------------------------------
# The committed snapshots
# ---------------------------------------------------------------------------


class SnapshotE28Tests(unittest.TestCase):
    """E28 on blueprints/: only the unconfigured Create a Call 32 of Batch Outbound Caller may FAIL (the X-46 push closes
    it). A subset test, so the push and re-pull that remove the rows keep it green. A row anywhere else fails it, for
    example on Campaign Launcher 3961751, The Interview Room (A) 3975140 or VIP intake 3920821."""

    def test_e28_rows_on_live_snapshots(self):
        files = sorted(glob.glob(os.path.join(ROOT, "blueprints", "*__*.json")))
        if not files:
            self.skipTest("no committed snapshots")
        got = set()
        for path in files:
            b = ab._load_blueprint_file(path)
            for f in ab.check_e(b, LINKS, ab.Allowlist()):
                if f.rule == "E28" and f.status in (ab.FAIL, ab.REVIEW):
                    got.add((str(b.scenario_id), f.module_id, f.status))
                    self.assertNotIn(";", f.detail)
                    self.assertNotIn("\u2014", f.detail)
                    self.assertNotIn("hook.", f.detail)
        self.assertEqual(got - {("3953105", 32, ab.FAIL)}, set())


if __name__ == "__main__":
    unittest.main()
