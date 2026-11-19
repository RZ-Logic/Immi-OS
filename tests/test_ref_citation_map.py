"""X-17.2 citation mapping and drafting gate (ref/document_types.json, ref/citation_map.json, migration
20261102000003). Invariants on the committed files against the migration, the loader and law/. No network, no
database. The gate's behaviour is rehearsed on Postgres, see specs/X-17.2-citation-map.md."""

import json
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REF = os.path.join(ROOT, "ref")
LAW = os.path.join(ROOT, "law")
MIGRATION = os.path.join(ROOT, "supabase", "migrations", "20261102000003_ref_citation_map.sql")
LOADER = os.path.join(ROOT, "scripts", "law_load", "load.mjs")

DOC_COLS = ["code", "display_name", "restricted_to_visa_code", "active", "sort_order", "min_words", "max_words"]
MAP_COLS = ["document_type", "visa_code", "provision_key", "purpose", "origin", "reviewed_by_licence", "reviewed_on",
            "reviewed_text_sha256", "reviewed_row_sha256", "sort_order"]
REVIEW = ("reviewed_by_licence", "reviewed_on", "reviewed_text_sha256", "reviewed_row_sha256")


def load(name):
    with open(os.path.join(REF, f"{name}.json"), encoding="utf-8") as f:
        return json.load(f)[name]


def law():
    out = {}
    for inst in ("IRPA", "IRPR"):
        with open(os.path.join(LAW, f"{inst}.jsonl"), encoding="utf-8") as f:
            for line in f:
                r = json.loads(line)
                out[r["key"]] = r
    return out


def text(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def loader_cols(loader, table):
    m = re.search(r'\{ table: "' + table + r'",[^{}]*?cols: \[([^\]]*)\]', loader)
    return re.findall(r'"(\w+)"', m.group(1))


def row_sha256(r):
    """Python twin of ref.citation_row_sha256: pair, key and purpose joined by newlines."""
    import hashlib
    raw = chr(10).join((r["document_type"], r["visa_code"], r["provision_key"], r["purpose"]))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def pairs():
    """Every (document_type, visa_code) the catalogue defines, IRB matters excluded."""
    visas = load("visa_types")
    out = []
    for d in load("document_types"):
        for v in visas:
            if v["licence_class_required"] == "RCIC-IRB":
                continue
            if d["restricted_to_visa_code"] in (None, v["code"]):
                out.append((d["code"], v["code"]))
    return out


class TestDocumentTypes(unittest.TestCase):
    def test_decided_types(self):
        d = {x["code"]: x for x in load("document_types")}
        self.assertEqual(sorted(d), ["LOE", "STUDY-PLAN", "SUBMISSION-LETTER"])
        self.assertEqual(d["STUDY-PLAN"]["restricted_to_visa_code"], "TR-STUDY")
        self.assertIsNone(d["SUBMISSION-LETTER"]["restricted_to_visa_code"])
        self.assertIsNone(d["LOE"]["restricted_to_visa_code"])
        self.assertTrue(all(x["active"] for x in d.values()))
        codes = {v["code"] for v in load("visa_types")}
        for x in d.values():
            self.assertTrue(x["restricted_to_visa_code"] is None or x["restricted_to_visa_code"] in codes)
            self.assertEqual(sorted(x), sorted(DOC_COLS))


class TestCitationMap(unittest.TestCase):
    def setUp(self):
        self.rows = load("citation_map")
        self.idx = law()

    def test_columns_match_loader_and_migration(self):
        loader = text(LOADER)
        self.assertEqual(loader_cols(loader, "document_types"), DOC_COLS)
        self.assertEqual(loader_cols(loader, "citation_map"), MAP_COLS)
        # min_words and max_words arrive with F-F13.1 (migration 20261103000004).
        sql = text(MIGRATION) + text(os.path.join(ROOT, "supabase", "migrations", "20261103000004_ff13_validator.sql"))
        for c in DOC_COLS + MAP_COLS:
            self.assertRegex(sql, rf"\n  (ADD COLUMN )?{c}\s")
        for r in self.rows:
            self.assertEqual(sorted(r), sorted(MAP_COLS))

    def test_loader_order_and_sync(self):
        loader = text(LOADER)
        order = re.findall(r'\{ table: "(\w+)", key: \[[^\]]*\], extra: "(\w+)"', loader)
        self.assertEqual(order, [("visa_types", "refuse"), ("document_types", "refuse"), ("document_sections", "delete"),
                                 ("citation_map", "delete"), ("prompts", "refuse"), ("prompt_bindings", "delete"),
                                 ("test_records", "refuse"), ("ircc_vocabulary", "refuse"), ("exemplar_tags", "delete"),
                                 ("exemplar_test_seeds", "refuse")])

    def test_every_key_in_force_and_unique(self):
        seen = set()
        for r in self.rows:
            k = (r["document_type"], r["visa_code"], r["provision_key"])
            self.assertNotIn(k, seen)
            seen.add(k)
            p = self.idx.get(r["provision_key"])
            self.assertIsNotNone(p, k)
            self.assertEqual(p["status"], "in_force", k)

    def test_no_parent_and_child_in_one_pair(self):
        # provision_text() of a key includes its sub-units, so mapping both injects the child's text twice.
        by_pair = {}
        for r in self.rows:
            by_pair.setdefault((r["document_type"], r["visa_code"]), []).append(r["provision_key"])
        for pair, keys in by_pair.items():
            for a in keys:
                for b in keys:
                    self.assertFalse(a != b and b.startswith(a + "("), f"{pair}: {a} and its sub-unit {b}")

    def test_pairs_valid_and_covered(self):
        valid = set(pairs())
        got = {(r["document_type"], r["visa_code"]) for r in self.rows}
        self.assertLessEqual(got, valid, got - valid)
        self.assertEqual(got, valid, f"pairs without a candidate row: {sorted(valid - got)}")
        # Never a row for an IRB matter (REF-CLAIM), never a study plan outside TR-STUDY.
        self.assertFalse(any(r["visa_code"] == "REF-CLAIM" for r in self.rows))
        self.assertFalse(any(r["document_type"] == "STUDY-PLAN" and r["visa_code"] != "TR-STUDY" for r in self.rows))

    def test_review_fields_together_and_well_formed(self):
        for r in self.rows:
            filled = [r[c] is not None for c in REVIEW]
            self.assertIn(filled, ([True] * 4, [False] * 4), r["provision_key"])
            self.assertIn(r["origin"], ("ai_candidate", "rcic"))
            if r["reviewed_by_licence"] is not None:
                self.assertRegex(r["reviewed_by_licence"], r"^R[0-9]{6}$")
                self.assertRegex(r["reviewed_text_sha256"], r"^[0-9a-f]{64}$")
                # The row hash must be the digest of this row, so a reworded purpose or a copied row is caught here
                # as well as by ref.citation_status.
                self.assertEqual(r["reviewed_row_sha256"], row_sha256(r), r["provision_key"])
                self.assertRegex(r["reviewed_on"], r"^\d{4}-\d{2}-\d{2}$")

    def test_no_review_without_a_named_rcic(self):
        # No reviewer is named yet (X-17.2 open item 17.1), so no row may claim a signature. Remove this test in
        # the commit that records the first real review.
        self.assertFalse(any(r["reviewed_by_licence"] for r in self.rows))
        self.assertTrue(all(r["origin"] == "ai_candidate" for r in self.rows))

    def test_purpose_plain_and_ordered(self):
        orders = {}
        for r in self.rows:
            p = r["purpose"]
            self.assertTrue(p.strip() and len(p) <= 200, r["provision_key"])
            self.assertNotRegex(p, "[;—–]", r["provision_key"])
            pair = (r["document_type"], r["visa_code"])
            self.assertNotIn(r["sort_order"], orders.setdefault(pair, set()), pair)
            orders[pair].add(r["sort_order"])
            self.assertGreater(r["sort_order"], 0)


class TestMigration(unittest.TestCase):
    def test_locked_down(self):
        s = text(MIGRATION)
        self.assertIn("ALTER TABLE ref.document_types ENABLE ROW LEVEL SECURITY;", s)
        self.assertIn("ALTER TABLE ref.citation_map ENABLE ROW LEVEL SECURITY;", s)
        self.assertIn("REVOKE ALL ON ref.document_types, ref.citation_map FROM PUBLIC, anon, authenticated;", s)
        funcs = re.findall(r"CREATE FUNCTION (ref\.\w+)\(([^)]*)\)", s)
        self.assertEqual(sorted(f for f, _ in funcs),
                         ["ref.citation_context", "ref.citation_row_sha256", "ref.citation_status", "ref.drafting_gate"])
        for name, args in funcs:
            sig = name + "(" + ", ".join(a.split()[-1] for a in args.split(",") if a.strip()) + ")"
            self.assertIn(f"REVOKE ALL ON FUNCTION {sig} FROM PUBLIC, anon, authenticated;", s)
        code = re.sub(r"--[^\n]*", "", s).upper()
        for bad in ("GRANT ", "CREATE POLICY", "SECURITY DEFINER", "ALTER DEFAULT PRIVILEGES", "INSERT INTO"):
            self.assertNotIn(bad, code)

    def test_gate_rules_present(self):
        s = text(MIGRATION)
        self.assertIn("(SELECT licence_class_required FROM v) = 'RCIC-IRB' THEN 'IRB matter, Module F does not draft'", s)
        self.assertIn("WHEN EXISTS (SELECT 1 FROM s WHERE state = 'not_in_force') THEN 'a mapped provision is not in force'", s)
        self.assertIn("WHEN NOT EXISTS (SELECT 1 FROM s WHERE state = 'current') THEN 'no current reviewed citation rows'", s)
        self.assertIn("WHEN m.reviewed_text_sha256 IS DISTINCT FROM p.text_sha256 THEN 'amended_since_review'", s)
        # The row binding is tested before the text, so a changed purpose never reads as current.
        self.assertLess(s.index("THEN 'changed_since_review'"), s.index("THEN 'amended_since_review'"))
        self.assertIn("p_document_type || chr(10) || p_visa_code || chr(10) || p_provision_key || chr(10) || p_purpose", s)
        self.assertIn("WHERE g.allowed", s)
        self.assertIn("CHECK (reviewed_by_licence ~ '^R[0-9]{6}$')", s)
        self.assertGreater(os.path.basename(MIGRATION), "20261102000002_ref_visa_types.sql")


if __name__ == "__main__":
    unittest.main()
