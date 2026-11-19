"""X-17.1 IRPA and IRPR provision index (scripts/law_index.py). Synthetic Justice Laws XML fixtures in
tests/fixtures/law/, plus invariants on the committed snapshot in law/. No network."""

import hashlib
import json
import os
import re
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import law_index as li  # noqa: E402

FIX = os.path.join(ROOT, "tests", "fixtures", "law")
LAW = os.path.join(ROOT, "law")
MIGRATION = os.path.join(ROOT, "supabase", "migrations", "20261102000001_law_index.sql")


def read(name):
    with open(os.path.join(FIX, name), "rb") as f:
        return f.read()


def parse(name):
    inst, rows = li.parse(read(name))
    return inst, {r["key"]: r for r in rows}, rows


def migration_key_pattern():
    with open(MIGRATION, encoding="utf-8") as f:
        sql = f.read()
    m = re.search(r"CHECK \(key ~ '([^']+)'\)", sql)
    return re.compile(m.group(1)), sql


class TestParse(unittest.TestCase):
    def setUp(self):
        self.inst, self.by_key, self.rows = parse("mini_act.xml")

    def test_instrument_row(self):
        self.assertEqual(self.inst["instrument"], "IRPA")
        self.assertEqual(self.inst["current_to"], "2026-09-30")
        self.assertEqual(self.inst["source_sha256"], hashlib.sha256(read("mini_act.xml")).hexdigest())
        self.assertEqual(self.inst["related_or_not_in_force"], ["2008, c. 3, s. 6"])

    def test_nested_keys_and_levels(self):
        expect = {"IRPA 30": "section", "IRPA 30(1)": "subsection", "IRPA 30(1)(a)": "paragraph",
                  "IRPA 30(1)(b)(i)": "subparagraph", "IRPA 30(1)(b)(i)(A)": "clause", "IRPA 30(1.1)": "subsection"}
        for key, level in expect.items():
            self.assertEqual(self.by_key[key]["level"], level, key)
        self.assertEqual(self.by_key["IRPA 30(1)(b)(i)"]["parent_key"], "IRPA 30(1)(b)")
        self.assertIsNone(self.by_key["IRPA 30"]["parent_key"])
        self.assertEqual(self.by_key["IRPA 30(1.1)"]["lims_id"], "2700")
        self.assertEqual(self.by_key["IRPA 30(1.1)"]["lims_fid"], "27")

    def test_own_text_whitespace_and_marginal_notes(self):
        self.assertEqual(self.by_key["IRPA 30(1)"]["own_text"], "A foreign national may not work or study unless")
        self.assertEqual(self.by_key["IRPA 30(1)"]["marginal_note"], "Work and study")
        self.assertEqual(self.by_key["IRPA 30(1.1)"]["marginal_note"], "Authorization")
        self.assertEqual(self.by_key["IRPA 30"]["own_text"], "")

    def test_heading_path_resets_on_higher_level(self):
        self.assertEqual(self.by_key["IRPA 1"]["heading_path"], "Short Title")
        self.assertEqual(self.by_key["IRPA 30"]["heading_path"], "PART 1 Entry > DIVISION 1 Requirements")
        self.assertEqual(self.by_key["IRPA 2"]["heading_path"], "PART 1 Entry > DIVISION 2 Interpretation")
        self.assertEqual(self.by_key["IRPA 189"]["heading_path"], "PART 5 Transitional Provisions")

    def test_repealed_section_and_paragraph(self):
        self.assertEqual(self.by_key["IRPA 11.1"]["status"], "repealed")
        self.assertEqual(self.by_key["IRPA 30(1)(c)"]["status"], "repealed")
        self.assertEqual(self.by_key["IRPA 30(1)(a)"]["status"], "in_force")

    def test_footnote_ref_label_and_footnote_text_dropped(self):
        r = self.by_key["IRPA 189"]
        self.assertEqual(r["label"], "189")
        self.assertNotIn("Note", r["own_text"])

    def test_amendment_ranges_expand_and_are_amending(self):
        for sec in ("204", "205", "227.1", "228", "229"):
            self.assertEqual(self.by_key[f"IRPA {sec}"]["status"], "amending", sec)
            self.assertEqual(self.by_key[f"IRPA {sec}"]["own_text"], "[Amendments]")
        self.assertNotIn("IRPA 227.2", self.by_key)

    def test_definitions_stay_in_section_text(self):
        self.assertNotIn("IRPA 2(a)", self.by_key)
        self.assertIn("fee means a charge for (a) examinations.", self.by_key["IRPA 2"]["own_text"])

    def test_related_or_not_in_force_not_indexed(self):
        self.assertNotIn("IRPA 6", self.by_key)

    def test_history_notes_excluded_from_hash(self):
        changed = read("mini_act.xml").replace(b"2012, c. 17, s. 1</HistoricalNoteSubItem>",
                                               b"2019, c. 9, s. 4</HistoricalNoteSubItem>")
        _, rows = li.parse(changed)
        self.assertEqual({r["key"]: r["text_sha256"] for r in rows},
                         {k: r["text_sha256"] for k, r in self.by_key.items()})

    def test_text_change_moves_unit_and_ancestors_only(self):
        changed = read("mini_act.xml").replace(b"as a student, or", b"as a student or worker, or")
        _, rows = li.parse(changed)
        new = {r["key"]: r["text_sha256"] for r in rows}
        moved = sorted(k for k in new if new[k] != self.by_key[k]["text_sha256"])
        self.assertEqual(moved, ["IRPA 30", "IRPA 30(1)", "IRPA 30(1)(b)", "IRPA 30(1)(b)(i)", "IRPA 30(1)(b)(i)(A)"])

    def test_hash_matches_xml_rendering(self):
        """The row-based rendering (the one law.provision_text uses) equals the XML tree rendering."""
        import xml.etree.ElementTree as ET
        root = ET.fromstring(read("mini_act.xml"))
        sec30 = [s for s in root.iter("Section") if li._text_of(s.find("Label")) == "30"][0]
        self.assertEqual(self.by_key["IRPA 30"]["text_sha256"], hashlib.sha256(li._render(sec30).encode()).hexdigest())

    def test_section_prefix_does_not_swallow_decimal_section(self):
        _, by_key, rows = parse("mini_regs.xml")
        i = [r["key"] for r in rows].index("IRPR 216")
        text = li.render_rows(rows, i)
        self.assertNotIn("minor child", text)
        self.assertTrue(text.startswith("216 (1) An officer shall issue"))
        self.assertEqual(by_key["IRPR 216.1"]["heading_path"], "PART 12 Students > DIVISION 3 Issuance of Study Permits")

    def test_ranged_and_typo_labels(self):
        _, by_key, _ = parse("mini_regs.xml")
        for key in ("IRPR 216(1)(c)", "IRPR 216(1)(d)", "IRPR 216(1)(e)", "IRPR 216(2)", "IRPR 216(3)"):
            self.assertEqual(by_key[key]["status"], "repealed", key)
        self.assertEqual(by_key["IRPR 216(4)(a)"]["own_text"], "the fee is paid.")
        self.assertEqual(by_key["IRPR 216(4)(a)"]["label"], "(a)")
        for bad in (b"<Label>(i) to (iv)</Label>", b"<Label>(e) to (c)</Label>", b"<Label>(4) or (5)</Label>"):
            with self.assertRaises(li.LawIndexError):
                li.parse(read("mini_regs.xml").replace(b"<Label>(c) to (e)</Label>", bad))

    def test_regulation_instrument_number(self):
        inst, _, _ = parse("mini_regs.xml")
        self.assertEqual((inst["instrument"], inst["consolidated_number"]), ("IRPR", "SOR-2002-227"))

    def test_fail_closed(self):
        bad = read("mini_act.xml").replace(b"<Label>11.1</Label>", b"<Label>30</Label>")
        with self.assertRaises(li.LawIndexError):
            li.parse(bad)
        with self.assertRaises(li.LawIndexError):
            li.parse(read("mini_act.xml").replace(b"I-2.5</ConsolidatedNumber>", b"C-29</ConsolidatedNumber>"))
        with self.assertRaises(li.LawIndexError):
            li.parse(read("mini_act.xml").replace(b"<Label>11.1</Label>", b"<Label>Schedule</Label>"))
        with self.assertRaises(li.LawIndexError):
            li.parse(read("mini_act.xml").replace(b"<Label>(1.1)</Label>", b""))

    def test_keys_match_migration_check(self):
        pattern, _ = migration_key_pattern()
        for key in self.by_key:
            self.assertRegex(key, pattern)


class TestDiffAndSql(unittest.TestCase):
    def test_diff(self):
        _, old = li.parse(read("mini_act.xml"))
        _, new = li.parse(read("mini_act.xml").replace(b"authorized; or", b"authorized in writing; or")
                          .replace(b"<Label>11.1</Label>", b"<Label>11.2</Label>"))
        d = li.diff(old, new)
        self.assertEqual(d["added"], ["IRPA 11.2"])
        self.assertEqual(d["removed"], ["IRPA 11.1"])
        self.assertIn("IRPA 30(1)(a)", d["changed"])
        self.assertNotIn("IRPA 30(1.1)", d["changed"])

    def test_sql_one_transaction_escaped_and_never_deletes(self):
        inst, rows = li.parse(read("mini_regs.xml"))
        sql = li.to_sql({"instruments": [inst]}, {"IRPR": rows})
        self.assertTrue(sql.startswith("BEGIN;\n") and sql.endswith("COMMIT;\n"))
        self.assertIn("foreign national''s", sql)
        self.assertNotIn("DELETE", sql.upper())
        self.assertIn("SET status = 'absent', ord = NULL", sql)
        self.assertEqual(sql.count("INSERT INTO law.provisions"), len(rows))

    def test_sql_gate_runs_inside_the_transaction(self):
        inst, rows = li.parse(read("mini_regs.xml"))
        sql = li.to_sql({"instruments": [inst]}, {"IRPR": rows})
        gate = sql.index("DO $gate$")
        self.assertLess(sql.rindex("UPDATE law.provisions SET status = 'absent'"), gate)
        self.assertTrue(sql[gate:].endswith("$gate$;\nCOMMIT;\n"))
        self.assertIn(f"IF n <> {len(rows)} THEN RAISE EXCEPTION", sql)
        self.assertIn(f"source_sha256 = '{inst['source_sha256']}'", sql)
        self.assertIn("IS DISTINCT FROM p.text_sha256", sql)
        self.assertIn("live units sit under an absent parent", sql)
        # Deferred checks run before the gate, so --check (which ends in ROLLBACK) fails when COMMIT would.
        # Measured in review 2026-11-02: without this a duplicate ord or a missing parent passed --check.
        sc = sql.index("SET CONSTRAINTS ALL IMMEDIATE;\n")
        self.assertLess(sql.rindex("UPDATE law.provisions SET status = 'absent'"), sc)
        self.assertLess(sc, gate)


class TestCommittedSnapshot(unittest.TestCase):
    """law/ is the canonical index. These hold on every reload."""

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(LAW, "manifest.json"), encoding="utf-8") as f:
            cls.manifest = json.load(f)
        cls.rows = {i["instrument"]: li.load_jsonl(os.path.join(LAW, i["instrument"] + ".jsonl"))
                    for i in cls.manifest["instruments"]}

    def test_manifest_matches_rows(self):
        self.assertEqual([i["instrument"] for i in self.manifest["instruments"]], ["IRPA", "IRPR"])
        for i in self.manifest["instruments"]:
            rows = self.rows[i["instrument"]]
            self.assertEqual(i["units"], len(rows))
            self.assertEqual(i["sections"], sum(r["level"] == "section" for r in rows))
            self.assertRegex(i["source_sha256"], r"^[0-9a-f]{64}$")

    def test_keys_unique_valid_and_ordered(self):
        pattern, _ = migration_key_pattern()
        for inst, rows in self.rows.items():
            keys = [r["key"] for r in rows]
            self.assertEqual(len(keys), len(set(keys)), inst)
            self.assertEqual([r["ord"] for r in rows], list(range(1, len(rows) + 1)), inst)
            for r in rows:
                self.assertRegex(r["key"], pattern)
                self.assertIn(r["status"], li.STATUSES)
                self.assertEqual(r["parent_key"] is None, r["level"] == "section", r["key"])

    def test_parents_precede_children(self):
        for rows in self.rows.values():
            seen = set()
            for r in rows:
                if r["parent_key"]:
                    self.assertIn(r["parent_key"], seen, r["key"])
                seen.add(r["key"])

    def test_hashes_recompute_from_rows(self):
        for rows in self.rows.values():
            for i, r in enumerate(rows):
                self.assertEqual(hashlib.sha256(li.render_rows(rows, i).encode("utf-8")).hexdigest(),
                                 r["text_sha256"], r["key"])

    def test_known_provisions(self):
        by_key = {r["key"]: r for rows in self.rows.values() for r in rows}
        for key in ("IRPR 216(1)(b)", "IRPR 179", "IRPR 200(1)", "IRPA 3(1)(a)", "IRPA 30(1.1)", "IRPA 11(1)"):
            self.assertEqual(by_key[key]["status"], "in_force", key)
        self.assertEqual(by_key["IRPR 216"]["heading_path"], "PART 12 Students > DIVISION 3 Issuance of Study Permits")
        self.assertEqual(by_key["IRPA 11.1"]["status"], "repealed")
        self.assertEqual(by_key["IRPA 212"]["status"], "amending")


class TestMigration(unittest.TestCase):
    def test_rls_and_no_api_grants(self):
        _, sql = migration_key_pattern()
        self.assertIn("ALTER TABLE law.instruments ENABLE ROW LEVEL SECURITY;", sql)
        self.assertIn("ALTER TABLE law.provisions ENABLE ROW LEVEL SECURITY;", sql)
        self.assertIn("REVOKE ALL ON law.instruments, law.provisions FROM PUBLIC, anon, authenticated;", sql)
        self.assertIn("REVOKE ALL ON FUNCTION law.provision_text(TEXT) FROM PUBLIC, anon, authenticated;", sql)
        self.assertNotRegex(sql, r"(?i)\bGRANT\b")
        self.assertNotRegex(sql, r"(?i)CREATE POLICY")

    def test_every_function_revokes_public_execute(self):
        # A per-schema ALTER DEFAULT PRIVILEGES cannot revoke the global PUBLIC EXECUTE, so each function must.
        _, sql = migration_key_pattern()
        funcs = re.findall(r"(?i)CREATE (?:OR REPLACE )?FUNCTION (law\.\w+)\(([^)]*)\)", sql)
        self.assertTrue(funcs)
        for name, args in funcs:
            sig = name + "(" + ", ".join(a.split()[-1] for a in args.split(",") if a.strip()) + ")"
            self.assertIn(f"REVOKE ALL ON FUNCTION {sig} FROM PUBLIC, anon, authenticated;", sql)
        code = re.sub(r"--[^\n]*", "", sql).upper()
        self.assertNotIn("SECURITY DEFINER", code)
        self.assertNotIn("ALTER DEFAULT PRIVILEGES", code)

    def test_reload_safe_ord_and_absent_rendering(self):
        # Measured on PGlite 2026-11-02: with a NOT NULL, non-deferrable UNIQUE (instrument, ord) any reload that
        # adds or removes a unit mid-instrument fails, and an absent sub-unit kept rendering inside its parent.
        _, sql = migration_key_pattern()
        self.assertRegex(sql, r"\n  ord\s+INTEGER,")
        self.assertIn("CHECK ((status = 'absent') = (ord IS NULL))", sql)
        self.assertIn("UNIQUE (instrument, ord) DEFERRABLE INITIALLY DEFERRED", sql)
        self.assertIn("WHERE p.status <> 'absent'", sql)
        # An absent key returns NULL, not the text of live sub-units (review 2026-11-02).
        self.assertIn("AND EXISTS (SELECT 1 FROM law.provisions k WHERE k.key = p_key AND k.status <> 'absent')", sql)

    def test_status_values_match_loader(self):
        _, sql = migration_key_pattern()
        for s in li.STATUSES + ("absent",):
            self.assertIn(f"'{s}'", sql)


if __name__ == "__main__":
    unittest.main()
