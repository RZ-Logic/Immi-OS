"""Check E33: a link field written as text needs metadata.expect typing it as an array (measured 2026-11-15, F-F10 run
bbfed59f on 7049689, 422 Value is not an array of record IDs). Synthetic fixtures only."""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import audit_blueprints as ab  # noqa: E402

LINKS = ab.load_links(ab.DEFAULT_LINKS, required=True)
LEDGER = ab.LEDGER_TABLE
LINK = "fldx9nJ4XmlQx1frF"  # System Logs Applicant Link -> Applicants
NOTE = "fld7oKusxba5RuIZR"  # System Logs AI response, not a link


def create(value, expect=None, mid=5, key=LINK):
    m = {"id": mid, "module": "airtable:ActionCreateRecord", "version": 3,
         "mapper": {"table": LEDGER, "record": {ab.LABEL_FIELD: "Market Watchdog", key: value}}}
    if expect is not None:
        m["metadata"] = {"expect": expect}
    return m


def typed(kind="array"):
    return [{"name": "record", "spec": [{"name": LINK, "type": kind, "label": "Applicant Link"}]}]


def e33(*flow):
    b = ab.Blueprint(name="Synthetic", scenario_id="9000001", source="test", bp={"name": "Synthetic", "flow": list(flow), "metadata": {}})
    return [f for f in ab.check_e(b, LINKS, ab.Allowlist(), bland_agents=ab.BlandAgents(), ff10=ab.FF10Pin(None, "Module F Drafting Chain", 12330102))
            if f.rule == "E33"]


class E33Tests(unittest.TestCase):
    def test_text_without_expect_fails(self):
        rows = e33(create("{{1.id}}"))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].status, ab.FAIL)
        self.assertIn("Applicant Link", rows[0].detail)

    def test_text_with_array_expect_passes(self):
        self.assertEqual(e33(create("{{1.id}}", expect=typed())), [])

    def test_expect_of_another_type_does_not_cover_it(self):
        self.assertEqual(len(e33(create("{{1.id}}", expect=typed("text")))), 1)

    def test_list_form_passes(self):
        self.assertEqual(e33(create(["{{1.id}}"])), [])

    def test_array_expression_passes(self):
        v = "{{remove(add(emptyarray; ifempty(first(5.`Related Applicant`); emptystring)); emptystring)}}"
        self.assertEqual(e33(create(v)), [])
        self.assertEqual(e33(create("{{ map(3.array; \"id\") }}")), [])

    def test_text_in_a_non_link_field_passes(self):
        self.assertEqual(e33(create("{{1.id}}", key=NOTE)), [])

    def test_error_routes_count(self):
        owner = {"id": 2, "module": "http:MakeRequest", "version": 4, "mapper": {}, "onerror": [create("{{1.id}}", mid=9)]}
        rows = e33(owner)
        self.assertEqual([r.module_id for r in rows], [9])
        self.assertIn("error route", rows[0].detail)

    def test_update_fails_too(self):
        m = create("{{1.id}}")
        m["module"] = "airtable:ActionUpdateRecords"
        m["mapper"]["id"] = "{{4.id}}"
        self.assertEqual(len(e33(m)), 1)


if __name__ == "__main__":
    unittest.main()
