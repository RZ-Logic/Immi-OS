"""F-F13.2 required sections and IRCC vocabulary (migration 20261116000007, ref/document_sections.json,
ref/ircc_vocabulary.json, scripts/ircc_vocabulary.py, scripts/law_load). Static invariants on the committed files. No
network, no database. The behaviour is the PGlite suite scripts/law_load/ff13_2.test.mjs (node --test), see
specs/F-F13.2-sections-vocabulary.md."""

import difflib
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MIGRATIONS = os.path.join(ROOT, "supabase", "migrations")
MIGRATION = os.path.join(MIGRATIONS, "20261116000007_ff13_2_sections_vocabulary.sql")
PREVIOUS = os.path.join(MIGRATIONS, "20261115000006_ff10_drafting_context.sql")
LOADER = os.path.join(ROOT, "scripts", "law_load", "load.mjs")
SUITE = os.path.join(ROOT, "scripts", "law_load", "ff13_2.test.mjs")
GENERATOR = os.path.join(ROOT, "scripts", "ircc_vocabulary.py")
SECTIONS = os.path.join(ROOT, "ref", "document_sections.json")
VOCABULARY = os.path.join(ROOT, "ref", "ircc_vocabulary.json")
VISA_TYPES = os.path.join(ROOT, "ref", "visa_types.json")
PROMPTS = os.path.join(ROOT, "ref", "prompts.json")
SPEC = os.path.join(ROOT, "specs", "F-F13.2-sections-vocabulary.md")
VALIDATOR_DEF = re.compile(r"CREATE (?:OR REPLACE )?FUNCTION ff13\.validate_draft\(")


def text(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def code(sql):
    return re.sub(r"--[^\n]*", "", sql)


def function_text(sql, name):
    m = re.search(r"CREATE (?:OR REPLACE )?FUNCTION " + re.escape(name) + r"\(", sql)
    return sql[m.start():sql.index("\n$$;\n", m.start()) + 5]


class TestMigration(unittest.TestCase):
    def setUp(self):
        self.sql = text(MIGRATION)
        self.code = code(self.sql)

    def test_latest_validator_is_this_migration(self):
        # X-32 (20261116000008) restates this validator with its three changes, held by tests/test_x32_migration.py.
        defs = [f for f in sorted(os.listdir(MIGRATIONS)) if f.endswith(".sql") and VALIDATOR_DEF.search(text(os.path.join(MIGRATIONS, f)))]
        self.assertEqual(defs[-2:], [os.path.basename(MIGRATION), "20261116000008_x32_exemplars.sql"])

    def test_every_function_revokes_public_and_pins_search_path(self):
        funcs = re.findall(r"CREATE (?:OR REPLACE )?FUNCTION ((?:ff13|ref)\.\w+)\(([^)]*)\)", self.sql)
        self.assertEqual(sorted(f for f, _ in funcs), ["ff13._line_match", "ff13._lines", "ff13._vfold", "ff13._vkey", "ff13._vocab_patterns",
                                                       "ff13.validate_draft"])
        for name, args in funcs:
            types = [a.split()[-1] for a in args.split(",") if a.strip()]
            sig = name + "(" + ", ".join(types) + ")"
            self.assertRegex(self.sql, re.escape(f"REVOKE ALL ON FUNCTION {sig}") + r"\s+FROM PUBLIC, anon, authenticated;", sig)
        for b in re.split(r"CREATE (?:OR REPLACE )?FUNCTION ", self.code)[1:]:
            self.assertIn("SET search_path = pg_catalog, pg_temp" + chr(10), b.split("AS $$")[0], b[:40])
        # Only the validator is a definer here, and nothing is granted: ff13_make keeps its EXECUTE through the replace.
        self.assertEqual(self.code.count("SECURITY DEFINER"), 1)
        self.assertEqual(re.findall(r"GRANT [^;]+;", self.code), [])
        for bad in ("CREATE POLICY", "ALTER DEFAULT PRIVILEGES", "EXECUTE format", "EXECUTE '", "dblink", "COPY ", "PASSWORD", "CREATE ROLE"):
            self.assertNotIn(bad, self.code)
        for helper in ("_vfold", "_vkey", "_lines", "_line_match"):
            head = function_text(self.code, "ff13." + helper).split("AS $$")[0]
            self.assertIn("LANGUAGE sql\nIMMUTABLE\nSET search_path = pg_catalog, pg_temp\n", head, helper)
        # The pattern build reads ref.ircc_vocabulary, so it is STABLE, and the validator calls it rather than a copy.
        head = function_text(self.code, "ff13._vocab_patterns").split("AS $$")[0]
        self.assertIn("LANGUAGE sql\nSTABLE\nSET search_path = pg_catalog, pg_temp\n", head)
        self.assertIn("FROM ff13._vocab_patterns() p;", function_text(self.code, "ff13.validate_draft"))
        self.assertEqual(self.code.count("string_agg(x.re, "), 1)

    def test_tables_locked(self):
        for t in ("ref.document_sections", "ref.ircc_vocabulary"):
            self.assertIn(f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY;", self.code)
            self.assertIn(f"REVOKE ALL ON {t} FROM PUBLIC, anon, authenticated;", self.code)
        v = self.code[self.code.index("CREATE TABLE ref.ircc_vocabulary"):self.code.index("ALTER TABLE ref.ircc_vocabulary")]
        self.assertIn("REFERENCES ref.ircc_vocabulary(id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED", v)
        self.assertIn("CHECK ((status = 'former') = (replaced_by IS NOT NULL))", v)

    def test_table_columns_match_the_loader_and_the_files(self):
        loader = text(LOADER)
        for table, path in (("document_sections", SECTIONS), ("ircc_vocabulary", VOCABULARY)):
            m = re.search(r'\{ table: "' + table + r'", key: \[([^\]]*)\], extra: "(\w+)",\n    cols: \[([^\]]*)\] \}', loader)
            self.assertIsNotNone(m, table)
            cols = re.findall(r'"(\w+)"', m.group(3))
            t = self.code[self.code.index(f"CREATE TABLE ref.{table}"):]
            t = t[:t.index("\n);")]
            self.assertEqual(re.findall(r"\n  ([a-z_]+)\s", t), cols + ["loaded_at"], table)
            with open(path, encoding="utf-8") as f:
                rows = json.load(f)[table]
            for r in rows:
                self.assertEqual(sorted(r), sorted(cols), table)
        self.assertIn('{ table: "document_sections", key: ["document_type", "section"], extra: "delete",', loader)
        self.assertIn('{ table: "ircc_vocabulary", key: ["id"], extra: "refuse",', loader)
        self.assertIn('const REF_ARRAYS = new Set(["aliases", "variants", "ircc_aliases", "common_variants", "visa_codes", "source_urls", "addresses"]);', loader)
        self.assertIn('"ordinal"]);', loader)
        self.assertIn("for (const p of await sectionAndVocabularyProblems(client, opts)) problems.push(p);", loader)
        self.assertIn("ff13._vocab_patterns() p", loader)

    def test_validator_restated_with_every_attribute(self):
        old = function_text(text(PREVIOUS), "ff13.validate_draft")
        new = function_text(self.sql, "ff13.validate_draft")
        self.assertEqual(new.split("AS $$")[0], old.split("AS $$")[0])
        self.assertIn("c_version    CONSTANT TEXT := 'F-F13.2+F-F10';", new)

    def test_validator_changes_only_the_additions(self):
        old = function_text(text(PREVIOUS), "ff13.validate_draft").splitlines()
        new = function_text(self.sql, "ff13.validate_draft").splitlines()
        diff = list(difflib.unified_diff(old, new, lineterm="", n=0))
        removed = [l[1:] for l in diff if l.startswith("-") and not l.startswith("---")]
        self.assertEqual(removed, ["  c_version    CONSTANT TEXT := 'F-F13.1+F-F10';"])
        added = "\n".join(l[1:] for l in diff if l.startswith("+") and not l.startswith("+++"))
        for c in ("section_missing", "section_out_of_order", "section_empty"):
            self.assertRegex(added, r"v_hard := v_hard \|\| jsonb_build_object\('check', '" + c + "'")
        for c in ("vocabulary_former_name", "vocabulary_not_addressee", "vocabulary_program_mismatch", "vocabulary_unknown_office"):
            self.assertRegex(added, r"v_soft := v_soft \|\| jsonb_build_object\('check', '" + c + "'")
            self.assertNotRegex(added, r"v_hard := v_hard \|\| jsonb_build_object\('check', '" + c + "'")
        # Every new entry with matched text keeps it under 'text', which the ledger insert drops (jsonb_agg(e - 'text')).
        for m in re.finditer(r"jsonb_build_object\('check', '(?:section|vocabulary)_\w+'.*?\);", added, re.S):
            self.assertNotRegex(m.group(0), r"'(?:info|key)', substr\(v_draft", m.group(0)[:60])
        # The NO DRAFT exemption is one line only, and the new block sits inside the scan block (skipped on input_too_large).
        self.assertIn("ELSIF NOT (cardinality(v_lines) = 1 AND regexp_replace(v_lines[1]->>'line', '\\s+', ' ', 'g')\n"
                      "                   IN ('NO DRAFT PREPARED. The inputs contain text that reads as instructions.',\n"
                      "                       'NO DRAFT PREPARED. The case facts support none of the provided grounds.')) THEN", added)
        new_text = "\n".join(new)
        self.assertLess(new_text.index("-- F-F13.2: required sections"), new_text.index("    v_verdict := CASE WHEN cardinality(v_hard) > 0"))
        self.assertLess(new_text.index("IF NOT EXISTS (SELECT 1 FROM unnest(v_hard) e WHERE e->>'check' = 'input_too_large') THEN"),
                        new_text.index("-- F-F13.2: required sections"))

    def test_new_prose_has_no_em_dash_or_semicolon(self):
        old = set(text(PREVIOUS).splitlines())
        for line in self.sql.splitlines():
            if line.strip().startswith("--") and line not in old:
                self.assertNotIn("—", line)
                self.assertNotIn(";", line, line)

    def test_vfold_is_one_for_one(self):
        m = re.search(r"SELECT translate\(p_text, '([^']*)', '([^']*)'\)", self.sql)
        src, dst = m.group(1), m.group(2)
        self.assertEqual(len(src), len(dst))
        self.assertEqual(len(set(src)), len(src))
        self.assertTrue(all(c.isascii() and c.isalpha() for c in dst))
        for a, b in (("á", "a"), ("ã", "a"), ("é", "e"), ("ü", "u"), ("Ł", "L"), ("ỹ", "y")):
            self.assertEqual(dst[src.index(a)], b, a)


class TestFiles(unittest.TestCase):
    def test_sections_follow_the_registered_draft_prompt(self):
        with open(SECTIONS, encoding="utf-8") as f:
            rows = json.load(f)["document_sections"]
        self.assertEqual({r["document_type"] for r in rows}, {"SUBMISSION-LETTER"})
        rows.sort(key=lambda r: r["ordinal"])
        self.assertEqual([r["ordinal"] for r in rows], list(range(1, 11)))
        self.assertEqual([(r["section"], r["match_kind"], r["text"]) for r in rows], [
            ("Review line", "first_line", "Draft for review by RCIC {rcic}. Not for submission until the RCIC of record has reviewed and signed it."),
            ("Re line", "prefix", "Re:"), ("Salutation", "line", "Dear Officer,"), ("Introduction", "heading", "Introduction"),
            ("Background", "heading", "Background"), ("Legal framework", "heading", "Legal framework"), ("Submissions", "heading", "Submissions"),
            ("Conclusion", "heading", "Conclusion"), ("Closing", "line", "Respectfully submitted,"), ("RCIC signature", "last_line", "{rcic}")])
        with open(PROMPTS, encoding="utf-8") as f:
            prompts = json.load(f)["prompts"]
        draft = [p for p in prompts if p["stage"] == "drafting-chain.submission-letter-draft"]
        self.assertTrue(draft)
        for p in draft:
            system = p["template"]["system"]
            structure = system[system.index("Structure, in this order:"):]
            self.assertIn("First line, exactly: Draft for review by RCIC followed by rcic_of_record and a period, then the sentence: "
                          "Not for submission until the RCIC of record has reviewed and signed it.", structure)
            self.assertIn("A line starting Re:", structure)
            for line in ("The line: Dear Officer,", "The line: Respectfully submitted,", "Last line: rcic_of_record exactly as given."):
                self.assertIn(line, structure)
            positions = [structure.index(f"- {h}:") for h in ("Introduction", "Background", "Legal framework", "Submissions", "Conclusion")]
            self.assertEqual(positions, sorted(positions))
            self.assertIn("NO DRAFT PREPARED.", system)
        for r in rows:
            for t in [r["text"], *r["variants"], r["note"]]:
                self.assertNotIn("—", t)
                self.assertNotIn(";", t)
            # The form ff13._line_match compares (the table CHECK holds the same), so a variant can match a line.
            for t in [r["text"], *r["variants"]]:
                self.assertEqual(t, " ".join(t.split()), r["section"])
                self.assertTrue(t and t.isascii() and "_" not in t, r["section"])

    def test_vocabulary_rows(self):
        with open(VOCABULARY, encoding="utf-8") as f:
            rows = json.load(f)["ircc_vocabulary"]
        with open(VISA_TYPES, encoding="utf-8") as f:
            codes = {r["code"] for r in json.load(f)["visa_types"]}
        ids = {r["id"] for r in rows}
        self.assertEqual(len(ids), len(rows))
        covered = set()
        for r in rows:
            self.assertRegex(r["id"], r"^(office|prog|org)-[a-z0-9]+(-[a-z0-9]+)*$")
            self.assertIn(r["kind"], ("office", "program", "organization"))
            self.assertEqual(r["status"] == "former", r["replaced_by"] is not None, r["id"])
            self.assertTrue(r["successor_note"] is None or r["status"] == "former", r["id"])
            if r["replaced_by"]:
                target = next(x for x in rows if x["id"] == r["replaced_by"])
                self.assertEqual((target["status"], target["kind"]), ("current", r["kind"]), r["id"])
            self.assertLessEqual(set(r["visa_codes"]), codes, r["id"])
            self.assertTrue(r["source_urls"] and all(u.startswith("https://") for u in r["source_urls"]), r["id"])
            for a in r["ircc_aliases"] + r["common_variants"]:
                self.assertEqual(a, a.lower().strip(), r["id"])
            for t in (r["note"] or "", r["source_note"], r["canonical_name"], r["successor_note"] or ""):
                self.assertNotIn("—", t)
                self.assertNotIn(";", t)
            if r["kind"] == "program" and r["status"] == "current":
                covered |= set(r["visa_codes"])
        self.assertEqual(covered, codes)

    def test_generator_reproduces_the_committed_file(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "ircc_vocabulary.json")
            subprocess.run([sys.executable, "-I", GENERATOR, out], check=True, capture_output=True)
            with open(out, "rb") as a, open(VOCABULARY, "rb") as b:
                self.assertEqual(a.read(), b.read())

    def test_tracked_and_synthetic(self):
        for p in (MIGRATION, SUITE, GENERATOR, SECTIONS, VOCABULARY, SPEC):
            r = subprocess.run(["git", "check-ignore", "-q", os.path.relpath(p, ROOT)], cwd=ROOT)
            self.assertEqual(r.returncode, 1, f"{p} is git-ignored")
        s = text(SUITE)
        self.assertEqual(set(re.findall(r"rec[A-Za-z0-9]{14}", s)), {"recTESTff132abcd1"})
        self.assertIn('const NAME = "ZZ-TEST Amara Okafor";', s)


if __name__ == "__main__":
    unittest.main()
