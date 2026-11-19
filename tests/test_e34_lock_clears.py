"""Check E34: the F-F10 lock clears the last run's Draft Doc Link and review note with {{erase}}. Synthetic fixtures."""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import audit_blueprints as ab  # noqa: E402

LINKS = ab.load_links(ab.DEFAULT_LINKS, required=True)
LEAD = ab.LEAD_TABLE
OWNER = "Module F Drafting Chain"
PIN = ab.FF10Pin("7000001", OWNER, 12330102)
DS, LINK, NOTE = "fld5BxjXujOOFzzoE", "fldPxDXPA1OSfbZsW", "fld4Qm3T5ys4E3qJM"


def trigger():
    return {"id": 1, "module": "airtable:TriggerWatchRecords", "version": 3, "mapper": {},
            "parameters": {"table": LEAD, "formula": "{Drafting Status} = 'Ready for AI Draft'", "maxRecords": 1,
                           "config": {"triggerField": "Drafting Modified"}}}


def lock(**extra):
    rec = {DS: "Drafting"}
    rec.update(extra)
    return {"id": 2, "module": "airtable:ActionUpdateRecords", "version": 3, "mapper": {"table": LEAD, "id": "{{1.id}}", "record": rec}}


def router():
    return {"id": 3, "module": "builtin:BasicRouter", "version": 1, "mapper": None,
            "routes": [{"flow": [lock()]}]}


def e34(*flow, name=OWNER, sid="7000001"):
    b = ab.Blueprint(name=name, scenario_id=sid, source="test", bp={"name": name, "flow": list(flow), "metadata": {}})
    return [f for f in ab.check_e(b, LINKS, ab.Allowlist(), bland_agents=ab.BlandAgents(), ff10=PIN) if f.rule == "E34"]


class E34Tests(unittest.TestCase):
    def test_lock_that_erases_both_passes(self):
        self.assertEqual(e34(trigger(), lock(**{LINK: "{{erase}}", NOTE: "{{erase}}"})), [])

    def test_names_work_like_ids(self):
        self.assertEqual(e34(trigger(), lock(**{"Draft Doc Link": "{{ erase }}", "drafting review note": "{{erase}}"})), [])

    def test_lock_without_erase_fails_naming_both(self):
        rows = e34(trigger(), lock())
        self.assertEqual([r.module_id for r in rows], [2])
        self.assertIn("Draft Doc Link", rows[0].detail)
        self.assertIn("Drafting Review Note", rows[0].detail)

    def test_empty_value_does_not_clear(self):
        rows = e34(trigger(), lock(**{LINK: "", NOTE: "{{emptystring}}"}))
        self.assertEqual(len(rows), 1)

    def test_one_missing_fails(self):
        rows = e34(trigger(), lock(**{LINK: "{{erase}}"}))
        self.assertEqual(len(rows), 1)
        self.assertNotIn("Draft Doc Link", rows[0].detail.split("does not clear")[1].split("with")[0])

    def test_no_lock_before_the_router_fails_on_the_trigger(self):
        rows = e34(trigger(), router())
        self.assertEqual([r.module_id for r in rows], [1])

    def test_erase_is_no_bare_reference(self):
        b = ab.Blueprint(name=OWNER, scenario_id="7000001", source="test",
                         bp={"name": OWNER, "flow": [trigger(), lock(**{LINK: "{{erase}}", NOTE: "{{erase}}"})], "metadata": {}})
        self.assertEqual([f for f in ab.check_e(b, LINKS, ab.Allowlist(), bland_agents=ab.BlandAgents(), ff10=PIN) if f.rule == "E2"], [])

    def test_other_scenarios_are_out_of_scope(self):
        self.assertEqual(e34(trigger(), lock(), name="Another", sid="5"), [])


if __name__ == "__main__":
    unittest.main()
