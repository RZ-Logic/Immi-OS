"""F-F13.1 citation validator (migration 20261103000004, scripts/law_load/make_role.mjs). Static invariants on the
committed files. No network, no database. The validator's behaviour is the PGlite suite
scripts/law_load/ff13.test.mjs (node --test), see specs/F-F13.1-citation-validator.md. The body invariants read the
latest definition of ff13.validate_draft, since F-F10 replaces it in migration 20261115000006
(tests/test_ff10_drafting_context.py)."""

import json
import os
import re
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MIGRATION = os.path.join(ROOT, "supabase", "migrations", "20261103000004_ff13_validator.sql")
LOADER = os.path.join(ROOT, "scripts", "law_load", "load.mjs")
MAKE_ROLE = os.path.join(ROOT, "scripts", "law_load", "make_role.mjs")
SUITE = os.path.join(ROOT, "scripts", "law_load", "ff13.test.mjs")
PACKAGE = os.path.join(ROOT, "scripts", "law_load", "package.json")
VALIDATOR = "ff13.validate_draft(" + ", ".join(["TEXT"] * 16) + ")"


def text(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def code(sql):
    return re.sub(r"--[^\n]*", "", sql)


MIGRATIONS = os.path.join(ROOT, "supabase", "migrations")
VALIDATOR_DEF = re.compile(r"CREATE (?:OR REPLACE )?FUNCTION ff13\.validate_draft\(")


def latest_validator():
    """The comment-stripped text of the last migration that defines ff13.validate_draft, from that definition to its end."""
    last = None
    for f in sorted(os.listdir(MIGRATIONS)):
        if f.endswith(".sql") and VALIDATOR_DEF.search(text(os.path.join(MIGRATIONS, f))):
            last = os.path.join(MIGRATIONS, f)
    c = code(text(last))
    start = VALIDATOR_DEF.search(c).start()
    return c[start:c.index("\n$$;", start)]


class TestMigration(unittest.TestCase):
    def setUp(self):
        self.sql = text(MIGRATION)
        self.code = code(self.sql)

    def test_every_function_revokes_public_and_pins_search_path(self):
        funcs = re.findall(r"CREATE FUNCTION (ff13\.\w+)\(([^)]*)\)", self.sql)
        self.assertEqual(sorted(f for f, _ in funcs), ["ff13._dates", "ff13._fold", "ff13._hits", "ff13._month", "ff13._ymd",
                                                        "ff13.validate_draft", "ff13.validations_append_only"])
        for name, args in funcs:
            types = [a.split()[-1] for a in args.split(",") if a.strip()]
            sig = name + "(" + ", ".join(types) + ")"
            self.assertRegex(self.sql, re.escape(f"REVOKE ALL ON FUNCTION {sig}") + r"\s+FROM PUBLIC, anon, authenticated;", sig)
        bodies = re.split(r"CREATE FUNCTION ", self.code)[1:]
        # pg_temp listed last: with it left out Postgres searches it first, and a pg_temp domain could run code as the
        # definer's owner (review 2026-11-03).
        for b in bodies:
            self.assertIn("SET search_path = pg_catalog, pg_temp" + chr(10), b.split("AS $$")[0], b[:40])
        self.assertNotIn("search_path = ''", self.code)
        for f in ("law.provision_text(TEXT)", "ref.citation_row_sha256(TEXT, TEXT, TEXT, TEXT)", "ref.citation_status(TEXT, TEXT)",
                  "ref.drafting_gate(TEXT, TEXT)", "ref.citation_context(TEXT, TEXT)"):
            self.assertIn(f"ALTER FUNCTION {f} SET search_path = pg_catalog, pg_temp;", self.code)

    def test_grants_are_exactly_the_make_path(self):
        grants = re.findall(r"GRANT [^;]+;", self.code)
        self.assertEqual([re.sub(r"\s+", " ", g) for g in grants], [
            "GRANT USAGE ON SCHEMA ff13 TO ff13_make;",
            f"GRANT EXECUTE ON FUNCTION {VALIDATOR} TO ff13_make;"])
        self.assertEqual(self.code.count("SECURITY DEFINER"), 1)
        definer = self.code[self.code.index("CREATE FUNCTION ff13.validate_draft"):]
        self.assertLess(definer.index("SECURITY DEFINER"), definer.index("AS $$"))
        for bad in ("CREATE POLICY", "ALTER DEFAULT PRIVILEGES", "EXECUTE format", "EXECUTE '", "dblink", "COPY "):
            self.assertNotIn(bad, self.code)
        self.assertIn("CREATE ROLE ff13_make NOLOGIN NOINHERIT NOCREATEDB NOCREATEROLE NOREPLICATION CONNECTION LIMIT 5;", self.code)
        self.assertNotIn("PASSWORD", self.code)

    def test_ledger_append_only_and_locked(self):
        self.assertIn("BEFORE UPDATE OR DELETE ON ff13.validations", self.code)
        self.assertIn("BEFORE TRUNCATE ON ff13.validations", self.code)
        self.assertIn("ALTER TABLE ff13.validations ENABLE ALWAYS TRIGGER validations_append_only;", self.code)
        self.assertIn("ALTER TABLE ff13.validations ENABLE ALWAYS TRIGGER validations_no_truncate;", self.code)
        self.assertIn("ALTER TABLE ff13.validations ENABLE ROW LEVEL SECURITY;", self.code)
        self.assertIn("REVOKE ALL ON ff13.validations FROM PUBLIC, anon, authenticated;", self.code)
        self.assertIn("REVOKE ALL ON SCHEMA ff13 FROM PUBLIC;", self.code)

    def test_ledger_never_stores_matched_text(self):
        # Every element that reaches a ledger column drops 'text', and the table has no column for the draft, the
        # name, the facts or the exemplar terms.
        self.assertEqual(self.code.count("jsonb_agg(e - 'text')"), 2)
        table = self.code[self.code.index("CREATE TABLE ff13.validations"):self.code.index("CREATE INDEX validations_record_idx")]
        for col in ("draft ", "applicant", "facts", "exemplar", "review_note", "detail"):
            self.assertNotRegex(table, rf"\n  {col}", col)
        body = latest_validator()
        self.assertEqual(body.count("jsonb_agg(e - 'text')"), 2)
        inserts = re.findall(r"INSERT INTO ff13\.validations.*?RETURNING id INTO v_id;", body, re.S)
        self.assertEqual(len(inserts), 2)
        for insert in inserts:
            for arg in ("p_draft", "p_applicant_name", "p_case_facts", "p_exemplar_terms", "v_note", "v_detail"):
                self.assertNotIn(arg, insert)

    def test_errors_never_propagate_from_the_body(self):
        body = latest_validator()
        # query_canceled is not part of OTHERS, so a statement_timeout would escape without it.
        self.assertIn("EXCEPTION WHEN OTHERS OR query_canceled THEN", body)
        # The gate is read into scalars, so the code after the block never reads an unassigned record.
        self.assertNotIn("v_gate.", body)
        self.assertNotIn("v_gate      RECORD", body)
        self.assertIn("'validator_error'", body)
        # Every argument is TEXT, so no cast fails before the body runs.
        args = re.search(r"FUNCTION ff13\.validate_draft\(([^)]*)\)", body).group(1)
        self.assertEqual({a.split()[-1] for a in args.split(",")}, {"TEXT"})

    def test_decided_dispositions(self):
        hard = ["gate_refused", "fabricated_citation", "not_in_force", "unresolved_reference", "forbidden_content", "placeholder",
                "below_word_floor", "applicant_name_absent", "applicant_name_missing", "exemplar_leak", "stop_reason_not_end_turn",
                "airtable_record_id_malformed", "input_too_large", "draft_empty", "no_word_band", "too_many_matches",
                "unreadable_character", "mixed_script"]
        soft = ["unprovided_citation", "date_not_in_facts", "invalid_date", "ambiguous_date", "above_word_ceiling", "gate_flag",
                "stamps_missing", "stamps_malformed"]
        body = latest_validator()
        for c in hard:
            self.assertRegex(body, r"v_hard := v_hard \|\| jsonb_build_object\('check', '" + c + "'", c)
        for c in soft:
            self.assertRegex(body, r"v_soft := v_soft \|\| jsonb_build_object\('check', '" + c + "'", c)
        # Amended and changed since review are soft, from the citation_status state.
        self.assertIn("IF v_state IN ('amended_since_review', 'changed_since_review') THEN\n            v_soft := v_soft", body)


class TestFiles(unittest.TestCase):
    def test_word_bands(self):
        with open(os.path.join(ROOT, "ref", "document_types.json"), encoding="utf-8") as f:
            d = {r["code"]: r for r in json.load(f)["document_types"]}
        for r in d.values():
            self.assertIsInstance(r["min_words"], int)
            self.assertGreater(r["max_words"], r["min_words"])
            self.assertGreater(r["min_words"], 0)

    def test_loader_knows_the_make_path(self):
        loader = text(LOADER)
        self.assertIn('const SCHEMAS = ["law", "ref", "ff13"];', loader)
        self.assertIn('const MAKE_ROLE = "ff13_make";', loader)
        self.assertIn('"ff13.validations", "ff13.groundings", "ff13.selections"]', loader)

    def test_make_role_never_prints_the_password(self):
        s = code(text(MAKE_ROLE))
        for line in s.splitlines():
            if "console." in line:
                # The password variable (or the verifier v) is never interpolated or passed into a printed line. The
                # word "password" in a message is fine.
                self.assertNotRegex(line, r"\$\{\s*(?:password|v)\s*\}|[(,+]\s*(?:password|v)\s*[),+]", line)
        self.assertIn("PASSWORD '${v}'", s)
        self.assertIn("toClipboard(password)", s)
        self.assertNotIn("writeFileSync", s)

    def test_pglite_pinned_and_suite_tracked(self):
        with open(PACKAGE, encoding="utf-8") as f:
            pkg = json.load(f)
        self.assertEqual(pkg["devDependencies"], {"@electric-sql/pglite": "0.5.9"})
        for p in (SUITE, MAKE_ROLE, MIGRATION):
            r = subprocess.run(["git", "check-ignore", "-q", os.path.relpath(p, ROOT)], cwd=ROOT)
            self.assertEqual(r.returncode, 1, f"{p} is git-ignored")

    def test_suite_fixtures_are_synthetic(self):
        s = text(SUITE)
        self.assertIn('const NAME = "Testa Applicanta Zed";', s)
        self.assertEqual(set(re.findall(r"rec[A-Za-z0-9]{14}", s)), {"recTESTabcdefghi1"})


if __name__ == "__main__":
    unittest.main()
