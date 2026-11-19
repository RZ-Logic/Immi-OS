"""X-32 exemplar selection (migration 20261116000008, ref/exemplar_tags.json, ref/exemplar_test_seeds.json,
scripts/law_load). Static invariants on the committed files. No network, no database. The behaviour is the PGlite suite
scripts/law_load/x32.test.mjs (node --test), see specs/X-32-exemplars.md section 3."""

import difflib
import json
import os
import re
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MIGRATIONS = os.path.join(ROOT, "supabase", "migrations")
MIGRATION = os.path.join(MIGRATIONS, "20261116000008_x32_exemplars.sql")
PREVIOUS = os.path.join(MIGRATIONS, "20261116000007_ff13_2_sections_vocabulary.sql")
LOADER = os.path.join(ROOT, "scripts", "law_load", "load.mjs")
MAKE_ROLE = os.path.join(ROOT, "scripts", "law_load", "make_role.mjs")
SUITE = os.path.join(ROOT, "scripts", "law_load", "x32.test.mjs")
TAGS = os.path.join(ROOT, "ref", "exemplar_tags.json")
SEEDS = os.path.join(ROOT, "ref", "exemplar_test_seeds.json")
VALIDATOR_DEF = re.compile(r"CREATE (?:OR REPLACE )?FUNCTION ff13\.validate_draft\(")
RANK = "ff13.rank_exemplars(" + ", ".join(["TEXT"] * 6) + ")"


def text(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def code(sql):
    return re.sub(r"--[^\n]*", "", sql)


def function_text(sql, name):
    m = re.search(r"CREATE (?:OR REPLACE )?FUNCTION " + re.escape(name) + r"\(", sql)
    return sql[m.start():sql.index("\n$$;\n", m.start()) + 5]


def columns(sql, table):
    t = sql[sql.index(f"CREATE TABLE {table} ("):]
    t = t[:t.index("\n);")]
    return re.findall(r"\n  ([a-z_]+)\s", t)


class TestMigration(unittest.TestCase):
    def setUp(self):
        self.sql = text(MIGRATION)
        self.code = code(self.sql)

    def test_latest_validator_is_this_migration(self):
        last = [f for f in sorted(os.listdir(MIGRATIONS)) if f.endswith(".sql") and VALIDATOR_DEF.search(text(os.path.join(MIGRATIONS, f)))][-1]
        self.assertEqual(last, os.path.basename(MIGRATION))

    def test_every_function_revokes_public_and_pins_search_path(self):
        funcs = re.findall(r"CREATE (?:OR REPLACE )?FUNCTION ((?:ff13|ref)\.\w+)\(([^)]*)\)", self.sql)
        self.assertEqual(sorted(f for f, _ in funcs), ["ff13.rank_exemplars", "ff13.selections_append_only", "ff13.validate_draft",
                                                       "ref.exemplar_test_seeds_retire_only"])
        for name, args in funcs:
            types = [a.split()[-1] for a in args.split(",") if a.strip()]
            sig = name + "(" + ", ".join(types) + ")"
            self.assertRegex(self.sql, re.escape(f"REVOKE ALL ON FUNCTION {sig}") + r"\s+FROM PUBLIC, anon, authenticated;", sig)
        for b in re.split(r"CREATE (?:OR REPLACE )?FUNCTION ", self.code)[1:]:
            self.assertIn("SET search_path = pg_catalog, pg_temp" + chr(10), b.split("AS $$")[0], b[:40])
        self.assertNotIn("search_path = ''", self.code)

    def test_grants_and_definers(self):
        grants = [re.sub(r"\s+", " ", g) for g in re.findall(r"GRANT [^;]+;", self.code)]
        self.assertEqual(grants, [f"GRANT EXECUTE ON FUNCTION {RANK} TO ff13_make;"])
        self.assertEqual(self.code.count("SECURITY DEFINER"), 2)
        for name in ("ff13.rank_exemplars", "ff13.validate_draft"):
            self.assertIn("LANGUAGE plpgsql\nVOLATILE\nSECURITY DEFINER\nSET search_path = pg_catalog, pg_temp\n",
                          function_text(self.code, name).split("AS $$")[0], name)
        # The revoke comes before the grant, so the grant is the one privilege left.
        self.assertLess(self.code.index(f"REVOKE ALL ON FUNCTION {RANK}"), self.code.index(f"GRANT EXECUTE ON FUNCTION {RANK}"))
        for bad in ("CREATE POLICY", "ALTER DEFAULT PRIVILEGES", "EXECUTE format", "EXECUTE '", "dblink", "COPY ", "PASSWORD", "CREATE ROLE"):
            self.assertNotIn(bad, self.code)

    def test_tables_locked_append_only_and_retire_only(self):
        for t, fn, row, trunc in (("ff13.selections", "ff13.selections_append_only", "selections_append_only", "selections_no_truncate"),
                                  ("ref.exemplar_test_seeds", "ref.exemplar_test_seeds_retire_only", "exemplar_test_seeds_retire_only",
                                   "exemplar_test_seeds_no_truncate")):
            self.assertIn(f"BEFORE UPDATE OR DELETE ON {t}\n  FOR EACH ROW EXECUTE FUNCTION {fn}();", self.code)
            self.assertIn(f"BEFORE TRUNCATE ON {t}\n  FOR EACH STATEMENT EXECUTE FUNCTION {fn}();", self.code)
            self.assertIn(f"ALTER TABLE {t} ENABLE ALWAYS TRIGGER {row};", self.code)
            self.assertIn(f"ALTER TABLE {t} ENABLE ALWAYS TRIGGER {trunc};", self.code)
        for t in ("ff13.selections", "ref.exemplar_test_seeds", "ref.exemplar_tags"):
            self.assertIn(f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY;", self.code)
            self.assertIn(f"REVOKE ALL ON {t} FROM PUBLIC, anon, authenticated;", self.code)

    def test_tables_hold_ids_codes_keys_counts_and_flags_only(self):
        self.assertEqual(columns(self.code, "ff13.selections"),
                         ["id", "selected_at", "airtable_record_id", "make_execution_id", "grounding_id", "gate_mode", "candidate_count",
                          "eligible_count", "exemplar_record_id", "exemplar_code", "score", "term_count", "weak_keys",
                          "supported_keys", "conflicts", "flags", "function_version"])   # supported_keys, conflicts: 2026-11-19
        self.assertEqual(columns(self.code, "ref.exemplar_test_seeds"), ["airtable_record_id", "exemplar_code", "added_on", "retired_on", "loaded_at"])
        sel = self.code[self.code.index("CREATE TABLE ff13.selections"):self.code.index("CREATE INDEX selections_record_exec_idx")]
        self.assertIn("exemplar_code       TEXT         CHECK (exemplar_code ~ '^(ZZ-TEST-)?EX-[A-Z]+(-[A-Z]+)*-[0-9]{3}$')", sel)
        self.assertIn("flags <@ '[", sel)
        self.assertIn("CHECK (exemplar_code IS NULL OR gate_mode = 'test' OR exemplar_code !~ '^ZZ-TEST-')", sel)
        seeds = self.code[self.code.index("CREATE TABLE ref.exemplar_test_seeds"):self.code.index("CREATE FUNCTION ref.exemplar_test_seeds_retire_only")]
        self.assertIn("CHECK (exemplar_code ~ '^ZZ-TEST-EX-[A-Z]+(-[A-Z]+)*-[0-9]{3}$')", seeds)
        tags = self.code[self.code.index("CREATE TABLE ref.exemplar_tags"):self.code.index("ALTER TABLE ref.exemplar_tags")]
        self.assertIn("CHECK (visa_code NOT IN ('REF-CLAIM', 'REF-RESETTLE', 'HC-PR'))", tags)
        self.assertIn("CHECK ((review_state = 'reviewed') = (reviewer_licence IS NOT NULL))", tags)

    def test_ranker_signature_and_rules(self):
        head = function_text(self.code, "ff13.rank_exemplars").split("AS $$")[0]
        args = re.search(r"ff13\.rank_exemplars\(([^)]*)\)", head).group(1)
        self.assertEqual([a.split() for a in args.split(",")], [["p_airtable_record_id", "TEXT"], ["p_make_execution_id", "TEXT"],
                                                                 ["p_visa_code", "TEXT"], ["p_document_type", "TEXT"], ["p_outline", "TEXT"],
                                                                 ["p_candidates", "TEXT"]])
        self.assertIn("RETURNS TABLE (exemplar_record_id TEXT, exemplar_code TEXT, score INTEGER, candidate_count INTEGER, eligible_count INTEGER,\n"
                      "               flags TEXT, selection_id BIGINT)", head)
        body = function_text(self.code, "ff13.rank_exemplars")
        for const in ("c_excluded_codes CONSTANT TEXT[] := ARRAY['REF-CLAIM', 'REF-RESETTLE', 'HC-PR'];", "c_no_pick        CONSTANT TEXT := 'none';",
                      "c_min_score      CONSTANT INTEGER := 0;", "c_max_candidates CONSTANT INTEGER := 100;",
                      "c_document       CONSTANT TEXT := 'SUBMISSION-LETTER';"):
            self.assertIn(const, body)
        # Test mode only from the grounding row of the same record and execution, the validator's rule, never a window.
        self.assertIn("FROM ff13.groundings g WHERE g.airtable_record_id = v_record AND g.make_execution_id = v_exec", body)
        self.assertIn("v_mode := CASE WHEN v_g_mode = 'test' AND EXISTS (SELECT 1 FROM ref.test_records t WHERE t.airtable_record_id = v_record)", body)
        self.assertNotRegex(body, r"interval|grounded_at|p_mode")
        self.assertIn("EXCEPTION WHEN OTHERS OR query_canceled THEN", body)
        self.assertIn("RETURN QUERY SELECT coalesce(v_pick_id, c_no_pick)", body)
        # Production refuses a listed ID whether retired or not, test mode needs it listed, not retired, with its code.
        self.assertIn("OR EXISTS (SELECT 1 FROM ref.exemplar_test_seeds s WHERE s.airtable_record_id = v_c_id[v_i]) THEN", body)
        self.assertIn("AND s.exemplar_code = v_c_code[v_i] AND s.retired_on IS NULL", body)
        # The outline is never stored: one INSERT per path, and neither names the outline or the candidates.
        inserts = re.findall(r"INSERT INTO ff13\.selections.*?;", body, re.S)
        self.assertEqual(len(inserts), 2)
        for i in inserts:
            for arg in ("p_outline", "p_candidates", "v_outline", "v_line", "v_c_tags"):
                self.assertNotRegex(i, r"\b" + arg + r"\b")

    def test_validator_restated_with_every_attribute(self):
        old = function_text(text(PREVIOUS), "ff13.validate_draft")
        new = function_text(self.sql, "ff13.validate_draft")
        self.assertEqual(new.split("AS $$")[0], old.split("AS $$")[0])
        self.assertIn("c_version    CONSTANT TEXT := 'F-F13.2+F-F10+X-32';", new)
        self.assertIn(f"REVOKE ALL ON FUNCTION ff13.validate_draft({', '.join(['TEXT'] * 16)})\n  FROM PUBLIC, anon, authenticated;", self.sql)

    def test_validator_changes_only_the_three_x32_rules(self):
        old = function_text(text(PREVIOUS), "ff13.validate_draft").splitlines()
        new = function_text(self.sql, "ff13.validate_draft").splitlines()
        diff = list(difflib.unified_diff(old, new, lineterm="", n=0))
        removed = [l[1:] for l in diff if l.startswith("-") and not l.startswith("---")]
        self.assertEqual(removed, ["  c_version    CONSTANT TEXT := 'F-F13.2+F-F10';", "        IF v_pos > 0 THEN",
                                   "          v_hard := v_hard || jsonb_build_object('check', 'exemplar_leak', 'info', 'term ' || v_i, 'offset', v_pos);",
                                   "            SELECT 'Soft flag', e, n + 100000 FROM unnest(v_soft) WITH ORDINALITY u(e, n)) x) lines;"])
        added = "\n".join(l[1:] for l in diff if l.startswith("+") and not l.startswith("+++"))
        for c in ("exemplar_terms_mismatch", "exemplar_terms_unexpected"):
            self.assertRegex(added, r"v_hard := v_hard \|\| jsonb_build_object\('check', '" + c + "'")
        self.assertRegex(added, r"v_soft := v_soft \|\| jsonb_build_object\('check', 'exemplar_term_in_facts'")
        self.assertNotRegex(added, r"v_hard := v_hard \|\| jsonb_build_object\('check', 'exemplar_term_in_facts'")
        # Every new rule is keyed on a selection row of the same record and execution.
        self.assertIn("FROM ff13.selections s WHERE s.airtable_record_id = v_record AND s.make_execution_id = v_exec", added)
        self.assertIn("IF v_sel_id IS NOT NULL THEN", added)
        self.assertIn("IF v_pos > 0 AND v_sel_id IS NOT NULL THEN", added)
        self.assertIn("SELECT 10000000, 'Exemplar used: ' || coalesce(v_sel_code, 'none') WHERE v_sel_id IS NOT NULL) lines;", added)
        # Without a selection the leak is the first case-blind occurrence, exactly as before.
        self.assertIn("v_leak := v_pos;", added)
        self.assertIn("v_hard := v_hard || jsonb_build_object('check', 'exemplar_leak', 'info', 'term ' || v_i, 'offset', v_leak);", added)
        # The facts are matched on their folded copy with the leak test's escaping, from each occurrence as the draft writes
        # it and with case kept (finding 2026-11-16: a case-blind match let the town Mission pass on a church mission), so
        # the facts test carries no 'i' flag while the draft side stays case-blind.
        new_text = "\n".join(new)
        escape = r"""regexp_replace(regexp_replace(v_term, '([\]\[.\\+*?^$(){}|])', '\\\1', 'g'), '\s+', '\\s+', 'g')"""
        self.assertEqual(new_text.count(escape), 2, escape)
        facts = re.search(r"regexp_instr\(normalize\(v_fscan, NFC\),\n(.*?)\), 0\) = 0 THEN", new_text, re.S)
        self.assertIsNotNone(facts)
        self.assertIn(escape.replace("v_term", "v_h.g[1]"), facts.group(1))
        self.assertNotIn("'i'", facts.group(1))
        self.assertIn("|| ')(?=$|[^[:alnum:]_])', 'i', 1) LOOP", new_text)
        # The term count uses the leak test's split and folding, so it equals the lines the leak test reads.
        self.assertEqual(new_text.count("regexp_split_to_table(v_terms, '\\r\\n|[\\n\\v\\f\\r\\u0085\\u2028\\u2029]')"), 2)
        self.assertIn("WHERE btrim(normalize(translate(ff13._fold(t), '_', ' '), NFC)) <> '';", new_text)
        # The ledger still drops matched text and keeps its two inserts.
        self.assertEqual(new_text.count("jsonb_agg(e - 'text')"), 2)

    def test_new_prose_has_no_em_dash_or_semicolon(self):
        old = set(text(PREVIOUS).splitlines())
        for line in self.sql.splitlines():
            if line.strip().startswith("--") and line not in old:
                line = re.sub(r"\{\{.*?\}\}", "", line)
                self.assertNotIn("—", line)
                self.assertNotIn(";", line, line)


class TestLoaderAndFiles(unittest.TestCase):
    def test_loader_knows_the_x32_tables_and_function(self):
        s = text(LOADER)
        self.assertIn('{ table: "exemplar_tags", key: ["tag", "visa_code"], extra: "delete",\n'
                      '    cols: ["tag", "visa_code", "addresses", "label", "review_state", "reviewer_licence", "reviewed_on"] },', s)
        self.assertIn('{ table: "exemplar_test_seeds", key: ["airtable_record_id"], extra: "refuse", allowEmpty: true,\n'
                      '    cols: ["airtable_record_id", "exemplar_code", "added_on", "retired_on"] },', s)
        self.assertIn('export const RANK_EXEMPLARS = "ff13.rank_exemplars(text,text,text,text,text,text)";', s)
        self.assertIn("export const MAKE_FUNCTIONS = [VALIDATOR, DRAFTING_CONTEXT, RANK_EXEMPLARS];", s)
        self.assertIn('"function ff13.rank_exemplars": [MAKE_ROLE]', s)
        self.assertIn("for (const p of await x32Problems(client)) problems.push(p);", s)
        self.assertIn("checks.push(await x32SeedCheck(client, airtable));", s)
        self.assertIn("for (const c of await x32Checks(client)) checks.push(c);", s)
        self.assertIn('guardTriggers(client, "ff13.selections", "ff13.selections_append_only()", "selections_append_only", "selections_no_truncate")', s)
        # The Airtable read of the TEST seeds: Status and Exemplar Code by field ID, POST, the token never printed.
        self.assertIn("fields: [fStatus, fCode]", s)
        self.assertIn("returnFieldsByFieldId: true", s)
        for line in code(s).splitlines():
            if "console." in line or "add(" in line or "return [name" in line:
                self.assertNotRegex(line, r"\$\{\s*pat\s*\}|[(,+]\s*pat\s*[),+]", line)
        m = re.search(r"\{ table: \"exemplar_tags\", key: \[[^\]]*\], extra: \"\w+\",\n    cols: \[([^\]]*)\] \}", s)
        self.assertEqual(re.findall(r'"(\w+)"', m.group(1)) + ["loaded_at"], columns(code(text(MIGRATION)), "ref.exemplar_tags"))

    def test_make_role_probes_the_ranker(self):
        s = text(MAKE_ROLE)
        self.assertIn('const RANK_EXEMPLARS = "ff13.rank_exemplars(text,text,text,text,text,text)";', s)
        self.assertIn("ex.h && dc.h && rk.h && denied.length === DENIED.length", s)
        for t in ("ff13.selections", "ref.exemplar_test_seeds", "ref.exemplar_tags"):
            self.assertIn(f'"{t}"', s[s.index("const DENIED"):s.index("];", s.index("const DENIED"))])
        self.assertNotRegex(code(s), r"SELECT \* FROM ff13\.")

    def test_seed_list_file_starts_empty_and_holds_no_harness_id(self):
        with open(SEEDS, encoding="utf-8") as f:
            doc = json.load(f)
        self.assertEqual(sorted(doc), ["exemplar_test_seeds", "source"])
        self.assertIsInstance(doc["exemplar_test_seeds"], list)
        for r in doc["exemplar_test_seeds"]:
            self.assertEqual(sorted(r), ["added_on", "airtable_record_id", "exemplar_code", "retired_on"])
            self.assertRegex(r["airtable_record_id"], r"^rec[A-Za-z0-9]{14}$")
            self.assertNotRegex(r["airtable_record_id"], r"^rec(?:X32ZZTEST|TEST|VERIFY)")
            self.assertRegex(r["exemplar_code"], r"^ZZ-TEST-EX-[A-Z]+(-[A-Z]+)*-[0-9]{3}$")
        for t in (doc["source"],):
            self.assertNotIn("—", t)
            self.assertNotIn(";", t)

    def test_tag_file_rows_fit_the_table(self):
        with open(TAGS, encoding="utf-8") as f:
            rows = json.load(f)["exemplar_tags"]
        for r in rows:
            self.assertEqual(sorted(r), ["addresses", "label", "review_state", "reviewed_on", "reviewer_licence", "tag", "visa_code"])
            self.assertNotIn(r["visa_code"], ("REF-CLAIM", "REF-RESETTLE", "HC-PR"))
            self.assertTrue(8 <= len(r["label"]) <= 120 and r["label"] == r["label"].strip(), r["tag"])
            self.assertEqual(len(set(r["addresses"])), len(r["addresses"]), r["tag"])
            for a in r["addresses"]:
                self.assertRegex(a, r"^(IRPA|IRPR) [^|]{1,40}$")
            self.assertEqual((r["review_state"], r["reviewer_licence"], r["reviewed_on"]), ("unreviewed", None, None))

    def test_suite_tracked_and_synthetic(self):
        for p in (SUITE, MIGRATION, SEEDS, TAGS):
            r = subprocess.run(["git", "check-ignore", "-q", os.path.relpath(p, ROOT)], cwd=ROOT)
            self.assertEqual(r.returncode, 1, f"{p} is git-ignored")
        s = text(SUITE)
        for rec in set(re.findall(r"rec[A-Za-z0-9]{14}", s)):
            self.assertRegex(rec, r"^rec(?:TESTx32|VERIFYx32)", rec)
        self.assertIn('const NAME = "ZZ-TEST Corwin Ashdale";', s)


if __name__ == "__main__":
    unittest.main()
