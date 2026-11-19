"""X-46 tooling: the pinned post-call webhook in a Create a Call module (secret_scan), the secret allowlist pin on Batch
Outbound Caller module 32, and the X-46 push mapping and Bland agent registry guard (make_push). Every hook URL is
assembled at runtime from synthetic parts, so this file holds no literal the pre-commit hook would block. No network.
"""

import hashlib
import json
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.join(ROOT, "scripts"), os.path.join(ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import audit_blueprints  # noqa: E402
import make_push  # noqa: E402
import secret_scan  # noqa: E402
import test_make_push as tp  # noqa: E402  (helpers only, no test class is imported into this module)

HOOK_TAIL = "FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE"
HOOK_URL = "https://hook." + "us2.make.com/" + HOOK_TAIL
OTHER_URL = "https://hook." + "us2.make.com/" + "FAKEOTHERFAKEOTHERFAKEOTHERFAKE0"
HOOK_SHA = hashlib.sha256(HOOK_TAIL.encode()).hexdigest()
SID = "3953105"


def create_call(mid=32, url=HOOK_URL, **mapper):
    return {"id": mid, "module": "bland:createACall", "version": 1,
            "mapper": {"phone_number": "{{1.Phone}}", "task": "hello", "agent_id": "00000000-0000-4000-8000-000000000000",
                       "agent_version": "production", "webhook": url, **mapper}}


def blueprint(*flow):
    return {"name": "Synthetic", "flow": list(flow), "metadata": {}}


def entry(module_id=32, **kw):
    return {"scenario_id": SID, "module_id": module_id, "pattern_type": "make_webhook_url",
            "reason": "Create a Call webhook points at a fetch-back hook", "requires_fetch_back_hook": "6847022",
            "token_sha256": HOOK_SHA, **kw}


def split(bp, entries, sid=SID):
    return secret_scan.split_findings(bp, sid, secret_scan.parse_secret_allowlist({"entries": entries}))


def types(findings):
    return sorted(f["pattern_type"] for f in findings)


class CreateACallPinTests(unittest.TestCase):
    def test_both_bland_call_types_are_allowlistable_and_membership_is_exact(self):
        self.assertIsInstance(secret_scan.ALLOWLISTABLE_MODULE_TYPE, tuple)
        self.assertEqual(set(secret_scan.ALLOWLISTABLE_MODULE_TYPE), {"bland:sendACall", "bland:createACall"})
        # A tuple tests membership, so a type that is only a substring of an allowed type is not allowed.
        bp = blueprint({"id": 32, "module": "bland:send", "mapper": {"webhook": HOOK_URL}})
        blocking, allowed = split(bp, [entry()])
        self.assertEqual((types(blocking), allowed), (["make_webhook_url"], []))

    def test_a_pinned_webhook_in_create_a_call_is_allowed_when_the_hash_matches(self):
        blocking, allowed = split(blueprint(create_call()), [entry()])
        self.assertEqual(blocking, [])
        self.assertEqual([(a["module_id"], a["module_type"], a["requires_fetch_back_hook"], a["kind"]) for a in allowed],
                         [(32, "bland:createACall", "6847022", secret_scan.PINNED_KIND)])
        self.assertNotIn(HOOK_TAIL, json.dumps(allowed))

    def test_send_a_call_is_still_allowed(self):
        send = {"id": 3, "module": "bland:sendACall", "mapper": {"task": "hello", "webhook": HOOK_URL}}
        blocking, allowed = split(blueprint(send), [entry(module_id=3)])
        self.assertEqual((blocking, [(a["module_id"], a["module_type"]) for a in allowed]), ([], [(3, "bland:sendACall")]))

    def test_a_different_hash_blocks(self):
        blocking, allowed = split(blueprint(create_call(url=OTHER_URL)), [entry()])
        self.assertEqual((types(blocking), allowed), (["make_webhook_url"], []))
        blocking, allowed = split(blueprint(create_call()), [entry(token_sha256="0" * 64)])
        self.assertEqual((types(blocking), allowed), (["make_webhook_url"], []))

    def test_a_field_other_than_mapper_webhook_blocks(self):
        cases = {
            "task": blueprint({"id": 32, "module": "bland:createACall", "mapper": {"task": "go to " + HOOK_URL}}),
            "request_data": blueprint({"id": 32, "module": "bland:createACall",
                                       "mapper": {"request_data": json.dumps({"cb": HOOK_URL})}}),
            "parameters": blueprint({"id": 32, "module": "bland:createACall", "parameters": {"webhook": HOOK_URL}}),
            "nested in another mapper": blueprint({"id": 40, "module": "http:MakeRequest",
                                                   "mapper": {"body": create_call(32)}}),
        }
        for label, bp in cases.items():
            blocking, allowed = split(bp, [entry()])
            self.assertEqual((label, types(blocking), allowed), (label, ["make_webhook_url"], []))

    def test_a_second_url_in_the_same_module_still_blocks(self):
        blocking, allowed = split(blueprint(create_call(first_sentence="see " + HOOK_URL)), [entry()])
        self.assertEqual((types(blocking), len(allowed)), (["make_webhook_url"], 1))

    def test_the_pin_names_the_module_and_the_scenario(self):
        for label, entries, sid in (("module 3 pin", [entry(module_id=3)], SID), ("other scenario", [entry()], "9")):
            blocking, allowed = split(blueprint(create_call()), entries, sid)
            self.assertEqual((label, types(blocking), allowed), (label, ["make_webhook_url"], []))

    def test_check_d_labels_each_pinned_row_with_its_own_module_type(self):
        """The D row shows bland:createACall or bland:sendACall, never the text of the ALLOWLISTABLE_MODULE_TYPE tuple."""
        send = {"id": 3, "module": "bland:sendACall", "mapper": {"task": "hello", "webhook": HOOK_URL}}
        b = audit_blueprints.Blueprint(name="Synthetic", scenario_id=SID, source="test", bp=blueprint(send, create_call()))
        entries = secret_scan.parse_secret_allowlist({"entries": [entry(module_id=3), entry()]})
        for f2_state in (None, {"6847022": True}, {"6847022": False}):
            rows = audit_blueprints.check_d(b, entries, f2_state)
            self.assertEqual(sorted((f.module_id, f.module_type) for f in rows),
                             [(3, "bland:sendACall"), (32, "bland:createACall")], f2_state)
            for f in rows:
                self.assertNotIn(HOOK_TAIL, f.detail)
                self.assertNotIn("(", f.module_type)

    def test_the_repo_pin_moved_from_module_3_to_module_32(self):
        entries = secret_scan.load_secret_allowlist(secret_scan.DEFAULT_SECRET_ALLOWLIST)
        batch = [e for e in entries if e["scenario_id"] == SID]
        self.assertEqual([(e["module_id"], e["pattern_type"], e["requires_fetch_back_hook"]) for e in batch],
                         [(32, "make_webhook_url", "6847022")])
        self.assertIn("X-46", batch[0]["reason"])


class X46PushTests(unittest.TestCase):
    def test_fix_checks_maps_x46_to_b_and_e(self):
        self.assertEqual(make_push.FIX_CHECKS["X-46"], ("B", "E"))
        self.assertEqual(make_push.fix_checks("X-46"), ("B", "E"))

    def test_an_x46_target_outside_b_and_e_aborts(self):
        delta = make_push.AuditDelta(fails_before=1, fails_after=0, new_fails=[], closed=[], new_other=[])
        with self.assertRaises(make_push.Abort) as ctx:
            make_push.check_targets("X-46", [("A", "2")], delta, {2})
        self.assertIn("closes check B/E findings only", str(ctx.exception))


class BlandAgentRegistryGuardTests(tp.Base):
    """The Bland agent registry is an audit input (check E28), so the push refuses an uncommitted one."""

    def test_the_default_run_still_passes(self):
        code, output = self.run_main(tp.FakeMake(tp.live_blueprint()))
        self.assertEqual(code, make_push.EXIT_OK, output)

    def test_an_uncommitted_registry_aborts_before_any_request(self):
        fake = tp.FakeMake(tp.live_blueprint())
        code, output = self.run_main(
            fake, snapshot_state=lambda path: "it differs from the last commit" if os.path.basename(path) == "bland_agents.json" else None)
        self.assertEqual(code, make_push.EXIT_ABORT)
        self.assertIn("Bland agent registry", output)
        self.assertIn("not the committed version", output)
        self.assertEqual(fake.calls, [])

    def test_a_missing_registry_is_not_skipped(self):
        missing = os.path.join(self.tmp, "no_bland_agents.json")
        fake = tp.FakeMake(tp.live_blueprint())
        code, output = self.run_main(
            fake, extra=("--bland-agents", missing),
            snapshot_state=lambda path: "it is not tracked by git" if path == missing else None)
        self.assertEqual(code, make_push.EXIT_ABORT)
        self.assertIn("Bland agent registry", output)
        self.assertEqual(fake.calls, [])

    def test_an_invalid_registry_aborts_as_an_audit_input(self):
        bad = os.path.join(self.tmp, "bland_agents.json")
        with open(bad, "w", encoding="utf-8") as fh:
            json.dump({"agents": [{"pathway_id": "not-a-uuid"}]}, fh)
        fake = tp.FakeMake(tp.live_blueprint())
        code, output = self.run_main(fake, extra=("--bland-agents", bad))
        self.assertEqual(code, make_push.EXIT_ABORT)
        self.assertIn("audit inputs", output)
        self.assertEqual(fake.calls, [])


class E24TargetExemptionTests(unittest.TestCase):
    """An E24 FAIL on an unchanged Ignore owner may be declared when every module its row names as dropped is in --modules."""

    E24 = "E24 Ignore on 2 ends this path when 2 fails, so module 18 never runs, and it does not read the output of 2 (bug sweep M7)."

    def _delta(self, closed):
        fail = audit_blueprints.FAIL
        keys = {(k[0], k[1]) for k in closed}
        return make_push.AuditDelta(
            fails_before=len(closed), fails_after=0, new_fails=[], closed=sorted(closed), new_other=[],
            remaining_fails=set(), live_fails=keys, live_reviews=set(), remaining_reviews=set(),
            live_review_sigs={}, remaining_review_sigs=set())

    def test_e24_on_unchanged_owner_accepted_when_dropped_module_changes(self):
        fail = audit_blueprints.FAIL
        delta = self._delta([("E", "2", fail, self.E24), ("E", "18", fail, "E1 x")])
        make_push.check_targets("X-46", [("E", "2"), ("E", "18")], delta, {18})

    def test_e24_refused_when_dropped_module_not_in_modules(self):
        fail = audit_blueprints.FAIL
        delta = self._delta([("E", "2", fail, self.E24), ("E", "26", fail, "E1 x")])
        with self.assertRaises(make_push.Abort):
            make_push.check_targets("X-46", [("E", "2"), ("E", "26")], delta, {26})

    def test_other_e_row_on_owner_still_refused(self):
        fail = audit_blueprints.FAIL
        delta = self._delta([("E", "2", fail, self.E24), ("E", "2", fail, "E1 {{3.id}} points at module 3"),
                             ("E", "18", fail, "E1 x")])
        with self.assertRaises(make_push.Abort):
            make_push.check_targets("X-46", [("E", "2"), ("E", "18")], delta, {18})

    def test_dropped_ids_parsed(self):
        self.assertEqual(make_push._e24_dropped(self.E24), {18})
        self.assertEqual(make_push._e24_dropped("E24 Ignore on 5 ends this path when 5 fails, so modules 7, 9 and 12 never run, and none"), {7, 9, 12})
        self.assertEqual(make_push._e24_dropped("E1 module 18 never runs"), set())


if __name__ == "__main__":
    unittest.main()
