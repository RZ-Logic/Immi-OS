"""X-20.1 visa types (ref/visa_types.json, migration 20261102000002). Invariants on the committed file against the
migration and the committed law/ index. No network, no database."""

import datetime
import json
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REF = os.path.join(ROOT, "ref", "visa_types.json")
LAW = os.path.join(ROOT, "law")
MIGRATION = os.path.join(ROOT, "supabase", "migrations", "20261102000002_ref_visa_types.sql")
LOADER = os.path.join(ROOT, "scripts", "law_load", "load.mjs")
MIGRATION_DIR = "supabase/migrations"

# Decided by Rizwan 2026-11-02: X-20 option 1, all 17 active, Express Entry as 3 codes.
DECIDED = [
    "TR-VISIT", "TR-SUPER", "TR-STUDY", "TR-WP-EMP", "TR-WP-OPEN", "TR-PGWP",
    "PR-EE-CEC", "PR-EE-FSW", "PR-EE-FST", "PR-PNP-EE", "PR-PNP-BASE",
    "FAM-SPOUSE", "FAM-PGP", "FAM-OTHER",
    "REF-CLAIM", "REF-RESETTLE", "HC-PR",
]
COLS = ["code", "display_name", "category", "governing_provision", "ircc_url", "intake_status",
        "intake_note", "licence_class_required", "active", "aliases", "sort_order", "last_verified"]


def loader_cols(loader, table):
    """The cols list of one REF_TABLES entry in load.mjs."""
    m = re.search(r'\{ table: "' + table + r'",[^{}]*?cols: \[([^\]]*)\]', loader)
    return re.findall(r'"(\w+)"', m.group(1))


def rows():
    with open(REF, encoding="utf-8") as f:
        return json.load(f)["visa_types"]


def law():
    out = {}
    for inst in ("IRPA", "IRPR"):
        with open(os.path.join(LAW, f"{inst}.jsonl"), encoding="utf-8") as f:
            for line in f:
                r = json.loads(line)
                out[r["key"]] = r
    return out


def sql():
    with open(MIGRATION, encoding="utf-8") as f:
        return f.read()


def check_values(column):
    m = re.search(column + r"\s+TEXT\s+NOT NULL CHECK \(" + column + r" IN \(([^)]*)\)\)", re.sub(r"\s+", " ", sql()))
    return [v.strip().strip("'") for v in m.group(1).split(",")]


class TestRows(unittest.TestCase):
    def test_exactly_the_decided_codes_all_active(self):
        r = rows()
        self.assertEqual([x["code"] for x in sorted(r, key=lambda x: x["sort_order"])], DECIDED)
        self.assertTrue(all(x["active"] is True for x in r))

    def test_columns_match_loader_and_migration(self):
        with open(LOADER, encoding="utf-8") as f:
            loader = f.read()
        self.assertEqual(loader_cols(loader, "visa_types"), COLS)
        for c in COLS:
            self.assertRegex(sql(), rf"\n  {c}\s")
        for x in rows():
            self.assertEqual(sorted(x), sorted(COLS), x["code"])

    def test_code_pattern_and_enums_match_migration(self):
        pat = re.compile(re.search(r"CHECK \(code ~ '([^']+)'\)", sql()).group(1))
        cats, intake, lic = check_values("category"), check_values("intake_status"), check_values("licence_class_required")
        for x in rows():
            self.assertRegex(x["code"], pat)
            self.assertIn(x["category"], cats, x["code"])
            self.assertIn(x["intake_status"], intake, x["code"])
            self.assertIn(x["licence_class_required"], lic, x["code"])
            self.assertTrue(x["display_name"].strip(), x["code"])
            self.assertTrue(x["intake_note"] is None or x["intake_note"].strip(), x["code"])
        # A status the code alone would overstate carries a note (apply review 2026-11-02).
        by = {x["code"]: x for x in rows()}
        for c in ("FAM-PGP", "REF-RESETTLE", "TR-STUDY", "REF-CLAIM"):
            self.assertIsNotNone(by[c]["intake_note"], c)

    def test_governing_provision_is_an_in_force_law_key(self):
        idx = law()
        for x in rows():
            p = idx.get(x["governing_provision"])
            self.assertIsNotNone(p, f'{x["code"]}: {x["governing_provision"]} not in law/')
            self.assertEqual(p["status"], "in_force", x["code"])

    def test_urls_dates_and_order(self):
        today = datetime.date(2026, 11, 2)
        orders = [x["sort_order"] for x in rows()]
        self.assertEqual(len(set(orders)), len(orders))
        self.assertTrue(all(isinstance(o, int) and o > 0 for o in orders))
        for x in rows():
            self.assertTrue(x["ircc_url"].startswith("https://www.canada.ca/en/immigration-refugees-citizenship/"), x["code"])
            self.assertLessEqual(datetime.date.fromisoformat(x["last_verified"]), today, x["code"])

    def test_aliases_lowercase_trimmed_and_distinct(self):
        owner = {}
        for x in rows():
            self.assertIsInstance(x["aliases"], list)
            for a in x["aliases"]:
                self.assertEqual(a, a.strip().lower(), x["code"])
                self.assertTrue(a, x["code"])
                self.assertNotIn(a, owner, f'{a} on {owner.get(a)} and {x["code"]}')
                owner[a] = x["code"]
            self.assertEqual(len(x["aliases"]), len(set(x["aliases"])), x["code"])

    def test_known_facts(self):
        by = {x["code"]: x for x in rows()}
        # PGP intake paused since 2026-07-15 (IRCC notice, SECTION3_DECISIONS X-20).
        self.assertEqual(by["FAM-PGP"]["intake_status"], "Paused")
        # Refugee claims are heard by the IRB, so representation needs the RCIC-IRB class.
        self.assertEqual(by["REF-CLAIM"]["licence_class_required"], "RCIC-IRB")
        self.assertEqual(by["HC-PR"]["governing_provision"], "IRPA 25")
        self.assertEqual(by["TR-STUDY"]["governing_provision"], "IRPR 216")


class TestMigration(unittest.TestCase):
    def test_locked_down_like_law(self):
        s = sql()
        self.assertIn("REVOKE ALL ON SCHEMA ref FROM PUBLIC;", s)
        self.assertIn("REVOKE ALL ON SCHEMA ref FROM anon, authenticated;", s)
        self.assertIn("ALTER TABLE ref.visa_types ENABLE ROW LEVEL SECURITY;", s)
        self.assertIn("REVOKE ALL ON ref.visa_types FROM PUBLIC, anon, authenticated;", s)
        code = re.sub(r"--[^\n]*", "", s).upper()
        for bad in ("GRANT ", "CREATE POLICY", "SECURITY DEFINER", "ALTER DEFAULT PRIVILEGES", "CREATE FUNCTION", "INSERT INTO"):
            self.assertNotIn(bad, code)

    def test_fk_into_law_and_reload_safe_order(self):
        s = sql()
        self.assertIn("REFERENCES law.provisions(key) ON DELETE RESTRICT", s)
        self.assertIn("UNIQUE (sort_order) DEFERRABLE INITIALLY DEFERRED", s)
        self.assertNotRegex(s, r"sort_order\s+INTEGER\s+NOT NULL UNIQUE")
        # Runs after the law migration, whose table it references.
        self.assertGreater(os.path.basename(MIGRATION), "20261102000001_law_index.sql")

    def test_every_loaded_path_is_tracked(self):
        # The repo's .gitignore is a whitelist. A path it ignores passes the loader's git-clean guard while
        # uncommitted, so the loader would push working-tree data (measured 2026-11-02: ref/ was ignored).
        import subprocess
        with open(LOADER, encoding="utf-8") as f:
            loaded = re.findall(r'"([^"]+)"', re.search(r"const LOADED = \[([^\]]*)\]", f.read()).group(1))
        self.assertIn("ref", loaded)
        for p in loaded + [MIGRATION_DIR, os.path.relpath(MIGRATION, ROOT), "ref/visa_types.json", "law/IRPA.jsonl"]:
            r = subprocess.run(["git", "check-ignore", "-q", p], cwd=ROOT)
            self.assertEqual(r.returncode, 1, f"{p} is git-ignored")

    def test_loader_runs_ref_before_set_constraints(self):
        with open(LOADER, encoding="utf-8") as f:
            loader = f.read()
        body = loader[loader.index("await client.query(seed.head);"):]
        self.assertLess(body.index("await upsertRef(client, ref);"), body.index("await client.query(seed.tail);"))
        self.assertLess(body.index("await client.query(seed.tail);"), body.index("await refGate(client, ref);"))
        self.assertIn('"ref"', re.search(r"const LOADED = \[[^\]]*\]", loader).group(0))


if __name__ == "__main__":
    unittest.main()
