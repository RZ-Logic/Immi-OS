"""F-F10 grounding and test path (migration 20261115000006, ref/test_records.json, scripts/law_load). Static invariants
on the committed files. No network, no database. The behaviour is the PGlite suite scripts/law_load/ff10.test.mjs
(node --test), see specs/F-F10-drafting-chain.md."""

import datetime
import difflib
import json
import os
import re
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MIGRATIONS = os.path.join(ROOT, "supabase", "migrations")
MIGRATION = os.path.join(MIGRATIONS, "20261115000006_ff10_drafting_context.sql")
OLD_VALIDATOR = os.path.join(MIGRATIONS, "20261103000004_ff13_validator.sql")
LOADER = os.path.join(ROOT, "scripts", "law_load", "load.mjs")
MAKE_ROLE = os.path.join(ROOT, "scripts", "law_load", "make_role.mjs")
SUITE = os.path.join(ROOT, "scripts", "law_load", "ff10.test.mjs")
TEST_RECORDS = os.path.join(ROOT, "ref", "test_records.json")
VALIDATOR = "ff13.validate_draft(" + ", ".join(["TEXT"] * 16) + ")"
DRAFTING_CONTEXT = "ff13.drafting_context(" + ", ".join(["TEXT"] * 5) + ")"


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

    def test_every_function_revokes_public_and_pins_search_path(self):
        funcs = re.findall(r"CREATE (?:OR REPLACE )?FUNCTION ((?:ff13|ref)\.\w+)\(([^)]*)\)", self.sql)
        self.assertEqual(sorted(f for f, _ in funcs), ["ff13._test_gate", "ff13.drafting_context", "ff13.groundings_append_only",
                                                       "ff13.validate_draft", "ref.test_records_retire_only"])
        for name, args in funcs:
            types = [a.split()[-1] for a in args.split(",") if a.strip()]
            sig = name + "(" + ", ".join(types) + ")"
            self.assertRegex(self.sql, re.escape(f"REVOKE ALL ON FUNCTION {sig}") + r"\s+FROM PUBLIC, anon, authenticated;", sig)
        for b in re.split(r"CREATE (?:OR REPLACE )?FUNCTION ", self.code)[1:]:
            self.assertIn("SET search_path = pg_catalog, pg_temp" + chr(10), b.split("AS $$")[0], b[:40])
        self.assertNotIn("search_path = ''", self.code)

    def test_grants_and_definers(self):
        grants = [re.sub(r"\s+", " ", g) for g in re.findall(r"GRANT [^;]+;", self.code)]
        self.assertEqual(grants, [f"GRANT EXECUTE ON FUNCTION {DRAFTING_CONTEXT} TO ff13_make;"])
        self.assertEqual(self.code.count("SECURITY DEFINER"), 2)
        for name in ("ff13.drafting_context", "ff13.validate_draft"):
            head = function_text(self.code, name).split("AS $$")[0]
            for attr in ("LANGUAGE plpgsql\nVOLATILE\nSECURITY DEFINER\nSET search_path = pg_catalog, pg_temp\n",):
                self.assertIn(attr, head, name)
        # Across every migration, exactly the Make functions are definers (X-32 adds the ranker as the third).
        definers = set()
        for f in sorted(os.listdir(MIGRATIONS)):
            if f.endswith(".sql"):
                c = code(text(os.path.join(MIGRATIONS, f)))
                for m in re.finditer(r"CREATE (?:OR REPLACE )?FUNCTION ([\w.]+)\(", c):
                    if "SECURITY DEFINER" in c[m.end():c.index("AS $$", m.end())]:
                        definers.add(m.group(1))
        self.assertEqual(definers, {"ff13.drafting_context", "ff13.validate_draft", "ff13.rank_exemplars"})
        for bad in ("CREATE POLICY", "ALTER DEFAULT PRIVILEGES", "EXECUTE format", "EXECUTE '", "dblink", "COPY ", "PASSWORD", "CREATE ROLE"):
            self.assertNotIn(bad, self.code)

    def test_drafting_context_signature(self):
        head = function_text(self.code, "ff13.drafting_context").split("AS $$")[0]
        args = re.search(r"ff13\.drafting_context\(([^)]*)\)", head).group(1)
        self.assertEqual([a.split() for a in args.split(",")], [["p_airtable_record_id", "TEXT"], ["p_make_execution_id", "TEXT"],
                                                                 ["p_visa_code", "TEXT"], ["p_document_type", "TEXT"], ["p_synthetic_flag", "TEXT"]])
        self.assertIn("RETURNS TABLE (allowed TEXT, reason TEXT, gate_mode TEXT, provision_keys TEXT, provisions TEXT, flags TEXT, grounding_id BIGINT)", head)
        body = function_text(self.code, "ff13.drafting_context")
        self.assertIn("v_flag       BOOLEAN := coalesce(btrim(lower(p_synthetic_flag)), '') = 'true';", body)
        self.assertIn("c_v1_document CONSTANT TEXT := 'SUBMISSION-LETTER';", body)
        self.assertIn("v_reason := 'document type not in F-F10 v1';", body)
        self.assertIn("v_reason := 'test marker mismatch';", body)
        self.assertIn("EXCEPTION WHEN OTHERS OR query_canceled THEN", body)
        self.assertIn("FROM ref.drafting_gate(p_visa_code, p_document_type) g;", body)
        self.assertIn("FROM ref.citation_context(p_visa_code, p_document_type) WITH ORDINALITY", body)
        # The header states the argument order Make maps.
        self.assertIn("--   2 p_make_execution_id    {{var.scenario.executionId}}", self.sql)

    def test_validator_restated_with_every_attribute(self):
        old = function_text(text(OLD_VALIDATOR), "ff13.validate_draft")
        new = function_text(self.sql, "ff13.validate_draft")
        old_head, new_head = old.split("AS $$")[0], new.split("AS $$")[0]
        self.assertEqual(new_head, old_head.replace("CREATE FUNCTION", "CREATE OR REPLACE FUNCTION", 1))
        self.assertIn("c_version    CONSTANT TEXT := 'F-F13.1+F-F10';", new)

    def test_validator_changes_only_the_test_mode_additions(self):
        old = function_text(text(OLD_VALIDATOR), "ff13.validate_draft").splitlines()
        new = function_text(self.sql, "ff13.validate_draft").splitlines()
        removed = [l[1:] for l in difflib.unified_diff(old, new, lineterm="", n=0) if l.startswith("-") and not l.startswith("---")]
        self.assertEqual(removed, [
            "CREATE FUNCTION ff13.validate_draft(",
            "  c_version    CONSTANT TEXT := 'F-F13.1';",
            "    SELECT g.allowed, g.reason, g.provision_keys, g.flags INTO v_gate_allowed, v_gate_reason, v_gate_keys, v_gate_flags",
            "      FROM ref.drafting_gate(coalesce(v_visa, ''), coalesce(v_doc, '')) g;",
            "                                  prompt_version, prompt_sha256, request_id, input_tokens, output_tokens)",
            "            v_mreq, v_mserv, v_stop, v_pver, v_psha, v_req, v_in_tok, v_out_tok)",
            "                                  draft_sha256, draft_chars, verdict, provided_keys, citations, hard_fails, soft_flags)",
            "            jsonb_build_array(v_hard[1]), '[]')"])
        added = [l[1:] for l in difflib.unified_diff(old, new, lineterm="", n=0) if l.startswith("+") and not l.startswith("+++")]
        # The production gate is the same statement, inside the mode branch.
        self.assertIn("      SELECT g.allowed, g.reason, g.provision_keys, g.flags INTO v_gate_allowed, v_gate_reason, v_gate_keys, v_gate_flags", added)
        self.assertIn("        FROM ref.drafting_gate(coalesce(v_visa, ''), coalesce(v_doc, '')) g;", added)
        joined = "\n".join(added)
        for c in ("test_mode", "test_mode_unreviewed_grounding"):
            self.assertRegex(joined, r"v_soft := v_soft \|\| jsonb_build_object\('check', '" + c + "'")
        self.assertRegex(joined, r"v_hard := v_hard \|\| jsonb_build_object\('check', 'test_mode_name_not_synthetic'\)")
        self.assertIn("v_state := 'provided_unreviewed';", joined)
        self.assertIn("'gate_mode', coalesce(v_mode, 'unknown'),", joined)
        self.assertIn("'F-F13 TEST MODE: ", joined)
        self.assertIn("jsonb_build_array(v_hard[1]), '[]', coalesce(v_mode, 'unknown'))", joined)
        # Test mode comes only from a grounding row with the same record and execution, never a time window.
        self.assertIn("FROM ff13.groundings g WHERE g.airtable_record_id = v_record AND g.make_execution_id = v_exec", joined)
        self.assertNotRegex(joined, r"interval|grounded_at")

    def test_tables_locked_and_append_only(self):
        for t, fn, row, trunc in (("ff13.groundings", "ff13.groundings_append_only", "groundings_append_only", "groundings_no_truncate"),
                                  ("ref.test_records", "ref.test_records_retire_only", "test_records_retire_only", "test_records_no_truncate")):
            self.assertIn(f"BEFORE UPDATE OR DELETE ON {t}\n  FOR EACH ROW EXECUTE FUNCTION {fn}();", self.code)
            self.assertIn(f"BEFORE TRUNCATE ON {t}\n  FOR EACH STATEMENT EXECUTE FUNCTION {fn}();", self.code)
            self.assertIn(f"ALTER TABLE {t} ENABLE ALWAYS TRIGGER {row};", self.code)
            self.assertIn(f"ALTER TABLE {t} ENABLE ALWAYS TRIGGER {trunc};", self.code)
            self.assertIn(f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY;", self.code)
            self.assertIn(f"REVOKE ALL ON {t} FROM PUBLIC, anon, authenticated;", self.code)

    def test_tables_hold_ids_codes_and_hashes_only(self):
        g = self.code[self.code.index("CREATE TABLE ff13.groundings"):self.code.index("CREATE INDEX groundings_record_exec_idx")]
        cols = re.findall(r"\n  ([a-z0-9_]+)\s", g)
        self.assertEqual(cols, ["id", "grounded_at", "airtable_record_id", "make_execution_id", "visa_code", "document_type", "gate_mode",
                                "allowed", "reason", "provision_keys", "provisions_sha256"])
        self.assertIn("CHECK (gate_mode IN ('production', 'test', 'unknown'))", g)
        t = self.code[self.code.index("CREATE TABLE ref.test_records"):self.code.index("CREATE FUNCTION ref.test_records_retire_only")]
        self.assertEqual(re.findall(r"\n  ([a-z0-9_]+)\s", t), ["airtable_record_id", "added_on", "expires_on", "retired_on", "loaded_at"])
        self.assertIn("CHECK (expires_on >= added_on AND expires_on <= added_on + 30)", t)
        self.assertNotRegex(t, r"\n  note")

    def test_ledger_gate_mode_column(self):
        self.assertIn("ALTER TABLE ff13.validations\n  ADD COLUMN gate_mode TEXT NOT NULL DEFAULT 'production' CHECK (gate_mode IN ('production', 'test', 'unknown'));", self.code)
        self.assertIn("ALTER TABLE ff13.validations ALTER COLUMN gate_mode DROP DEFAULT;", self.code)
        self.assertLess(self.code.index("ADD COLUMN gate_mode"), self.code.index("DROP DEFAULT"))

    def test_new_prose_has_no_em_dash_or_semicolon(self):
        # Comment lines this migration adds (the validator's own F-F13.1 comments are carried over unchanged). A Make
        # mapping quoted in a comment is code, so its {{ }} is left out.
        old = set(text(OLD_VALIDATOR).splitlines())
        for line in self.sql.splitlines():
            if line.strip().startswith("--") and line not in old:
                line = re.sub(r"\{\{.*?\}\}", "", line)
                self.assertNotIn("—", line)
                self.assertNotIn(";", line, line)


class TestFiles(unittest.TestCase):
    def test_test_records_file(self):
        with open(TEST_RECORDS, encoding="utf-8") as f:
            doc = json.load(f)
        self.assertIsInstance(doc["test_records"], list)
        seen = set()
        for r in doc["test_records"]:
            self.assertEqual(sorted(r), ["added_on", "airtable_record_id", "expires_on", "retired_on"])
            self.assertRegex(r["airtable_record_id"], r"^rec[A-Za-z0-9]{14}$")
            self.assertNotIn(r["airtable_record_id"], seen)
            seen.add(r["airtable_record_id"])
            added = datetime.date.fromisoformat(r["added_on"])
            expires = datetime.date.fromisoformat(r["expires_on"])
            self.assertTrue(added <= expires <= added + datetime.timedelta(days=30), r["airtable_record_id"])
            if r["retired_on"] is not None:
                self.assertGreaterEqual(datetime.date.fromisoformat(r["retired_on"]), added)
            self.assertNotIn(r["airtable_record_id"], ("recVERIFYunlisted", "recVERIFYlistedxx"))

    def test_loader_knows_the_f_f10_path(self):
        s = text(LOADER)
        self.assertIn('{ table: "test_records", key: ["airtable_record_id"], extra: "refuse", allowEmpty: true,\n'
                      '    cols: ["airtable_record_id", "added_on", "expires_on", "retired_on"] },', s)
        self.assertIn('const REF_DATES = new Set(["last_verified", "reviewed_on", "registered_on", "added_on", "expires_on", "retired_on"]);', s)
        self.assertRegex(s, r'const REF_NULLABLE = new Set\(\[[^\]]*"retired_on"\]\);')
        self.assertIn("(!list.length && !t.allowEmpty)", s)
        self.assertIn('export const DRAFTING_CONTEXT = "ff13.drafting_context(text,text,text,text,text)";', s)
        self.assertIn("export const MAKE_FUNCTIONS = [VALIDATOR, DRAFTING_CONTEXT, RANK_EXEMPLARS];", s)
        self.assertIn('"function ff13.drafting_context": [MAKE_ROLE]', s)
        self.assertIn('const want = ["usage on ff13", ...MAKE_FUNCTIONS];', s)
        self.assertIn('add("Make function definers", definers.length === MAKE_FUNCTIONS.length', s)
        self.assertIn('"ff13.validations", "ff13.groundings", "ff13.selections"]', s)
        # The Airtable read: the read-only token by the .env parser, never a database key, never given to the CLI, never printed.
        self.assertIn('const ENV_KEYS = ["SUPABASE_DB_URL", "SUPABASE_DB_PASSWORD", "SUPABASE_DB_CA"];', s)
        self.assertIn('const AIRTABLE_KEYS = ["AIRTABLE_PAT"];', s)
        self.assertIn("for (const k of [...ENV_KEYS, ...AIRTABLE_KEYS]) delete env[k];", s)
        self.assertIn('const SYNTHETIC_TEST_CASE = "fldsCjg7ftgursZvl";', s)
        self.assertIn("body = { fields: [SYNTHETIC_TEST_CASE], returnFieldsByFieldId: true", s)
        self.assertIn('/listRecords`, {\n        method: "POST"', s)
        for line in code(s).splitlines():
            if "console." in line or "add(" in line or "return [name" in line:
                self.assertNotRegex(line, r"\$\{\s*pat\s*\}|[(,+]\s*pat\s*[),+]", line)

    def test_airtable_field_pinned_in_the_link_map(self):
        with open(os.path.join(ROOT, "audit", "airtable_links.json"), encoding="utf-8") as f:
            links = json.load(f)
        self.assertEqual(links["tables"]["tblHk09sCKLcOJXr9"]["fields"]["fldsCjg7ftgursZvl"], "Synthetic Test Case")

    def test_make_role_probes_the_new_function(self):
        s = text(MAKE_ROLE)
        self.assertIn('const DRAFTING_CONTEXT = "ff13.drafting_context(text,text,text,text,text)";', s)
        self.assertIn('const DENIED = ["law.provisions", "ff13.validations", "ff13.groundings", "ff13.selections", "ref.test_records", "ref.exemplar_test_seeds",\n'
                      '  "ref.exemplar_tags"];', s)
        self.assertIn('const RANK_EXEMPLARS = "ff13.rank_exemplars(text,text,text,text,text,text)";', s)
        self.assertIn("ex.h && dc.h && rk.h && denied.length === DENIED.length", s)
        # The probe never calls a function that writes.
        self.assertNotRegex(code(s), r"SELECT \* FROM ff13\.")

    def test_suite_tracked_and_synthetic(self):
        for p in (SUITE, MIGRATION, TEST_RECORDS):
            r = subprocess.run(["git", "check-ignore", "-q", os.path.relpath(p, ROOT)], cwd=ROOT)
            self.assertEqual(r.returncode, 1, f"{p} is git-ignored")
        s = text(SUITE)
        for rec in set(re.findall(r"rec[A-Za-z0-9]{14}", s)):
            self.assertRegex(rec, r"^rec(?:TEST|VERIFY)", rec)
        self.assertIn('const NAME = "TEST Applicanta Zed";', s)


if __name__ == "__main__":
    unittest.main()
