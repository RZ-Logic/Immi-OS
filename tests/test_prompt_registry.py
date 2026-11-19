"""X-36.1 prompts registry: scripts/prompt_registry.py, audit check R, the migration and the loader wiring. Synthetic
blueprints only, plus the committed snapshots for the every-module-is-bound test. No network, no database. The registry's
database behaviour is the PGlite suite scripts/law_load/prompts.test.mjs."""

import copy
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import audit_blueprints as ab  # noqa: E402
import prompt_registry as pr  # noqa: E402

MIGRATION = os.path.join(ROOT, "supabase", "migrations", "20261113000005_ref_prompts.sql")
LOADER = os.path.join(ROOT, "scripts", "law_load", "load.mjs")
PUSH = os.path.join(ROOT, "scripts", "make_push.py")

MAPPER = {"model": "claude-haiku-5-5", "max_tokens": 2048, "thinking": {"type": "adaptive"},
          "system": "You sort test emails. Return true or false.", "messages": [{"role": "user", "content": "{{1.text}}"}]}


def text(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def claude(mid, mapper=None):
    return {"id": mid, "module": pr.CLAUDE_MODULE, "version": 1, "mapper": copy.deepcopy(mapper or MAPPER)}


def blueprint(flow, sid="900001"):
    return ab.Blueprint(name="Synthetic", scenario_id=sid, source="synthetic", bp={"name": "Synthetic", "flow": flow})


class Files:
    """A temporary registry pair, written through the real writer so it is a valid file."""

    def __init__(self, versions, bindings):
        self.dir = tempfile.mkdtemp()
        self.prompts = os.path.join(self.dir, "prompts.json")
        self.bindings = os.path.join(self.dir, "prompt_bindings.json")
        with open(self.prompts, "w", encoding="utf-8") as f:
            json.dump({"prompts": versions}, f)
        with open(self.bindings, "w", encoding="utf-8") as f:
            json.dump({"prompt_bindings": bindings}, f)

    def close(self):
        shutil.rmtree(self.dir, ignore_errors=True)


def version(stage="test.sorter", v=1, mapper=None, **over):
    m = copy.deepcopy(mapper or MAPPER)
    row = {"stage": stage, "version": v, "description": "Sorts synthetic test emails.", "model": m["model"], "template": m,
           "template_sha256": pr.template_sha256(m), "registered_on": "2026-11-13"}
    row.update(over)
    return row


class TestCanonical(unittest.TestCase):
    def test_canonical_form_is_fixed(self):
        # Sorted keys, no whitespace, non-ASCII kept as is, the same string scripts/law_load/load.mjs canonicalJson builds.
        self.assertEqual(pr.canonical({"b": 1, "a": ["é", {"d": None, "c": True}]}), '{"a":["é",{"c":true,"d":null}],"b":1}')
        self.assertEqual(pr.template_sha256({"a": 1}), "015abd7f5cc57a2dd94b7590f04ad8084273905ee33ec5cebeae62276a97f862")

    def test_hash_covers_every_setting(self):
        base = pr.template_sha256(MAPPER)
        for key, value in (("model", "claude-opus-5-5"), ("max_tokens", 4096), ("system", MAPPER["system"] + " "),
                           ("thinking", {"type": "disabled"})):
            m = copy.deepcopy(MAPPER)
            m[key] = value
            self.assertNotEqual(pr.template_sha256(m), base, key)
        self.assertEqual(pr.template_sha256(dict(reversed(list(MAPPER.items())))), base, "key order does not matter")


class TestLoad(unittest.TestCase):
    def check_refused(self, versions, bindings, needle):
        f = Files(versions, bindings)
        try:
            with self.assertRaises(pr.RegistryError) as cm:
                pr.load(f.prompts, f.bindings)
            self.assertIn(needle, str(cm.exception))
        finally:
            f.close()

    def test_committed_registry_loads(self):
        reg = pr.load()
        self.assertGreaterEqual(len(reg.versions), 10)
        for (stage, v), row in reg.versions.items():
            self.assertEqual(row["template_sha256"], pr.template_sha256(row["template"]), pr.stamp(stage, v))
            # The run-time stamp fits the ff13 ledger's prompt_version shape.
            self.assertRegex(pr.stamp(stage, v), r"^[A-Za-z0-9._-]{1,60}@[0-9]{1,6}$")

    def test_refusals(self):
        b = [{"scenario_id": 900001, "module_id": 2, "stage": "test.sorter", "version": 1}]
        self.check_refused([version(stage="Test Sorter")], [], "stage must be")
        self.check_refused([version(), version()], b, "twice")
        self.check_refused([version(v=2)], [], "no gap")
        self.check_refused([version(template_sha256="0" * 64)], b, "template_sha256")
        self.check_refused([version(model="claude-opus-5-5")], b, "model must equal")
        self.check_refused([version(description="short")], b, "description")
        self.check_refused([version(registered_on="13/11/2026")], b, "registered_on")
        self.check_refused([{**version(), "extra": 1}], b, "exactly")
        self.check_refused([version()], [dict(b[0], version=2)], "not a registered version")
        self.check_refused([version()], b + b, "twice")
        self.check_refused([version()], [dict(b[0], module_id="2")], "positive integers")

    def test_one_template_is_one_version_of_its_stage(self):
        # ref.prompts holds UNIQUE (template_sha256, stage), so a repeated template must fail here, not at load time.
        b = [{"scenario_id": 900001, "module_id": 2, "stage": "test.sorter", "version": 1}]
        self.check_refused([version(), version(v=2, mapper=dict(MAPPER, system="Edited sorter.")), version(v=3)], b,
                           "has the template of test.sorter@1")

    def test_refuses_a_template_the_js_loader_would_hash_differently(self):
        b = [{"scenario_id": 900001, "module_id": 2, "stage": "test.sorter", "version": 1}]
        for bad in ({"max_tokens": 2048.0}, {"outputFormat": {"multipleOf": 1e-7}}, {"x": -0.0}, {"x": 2 ** 53},
                    {"outputFormat": {"\U0001F600": 1}}, {"system": "lone \ud800"}):
            m = dict(MAPPER, **bad)
            self.check_refused([version(mapper=m)], b, "could not reproduce its hash")
        for date in ("20261113", "2026-W46-5", "2026-11-13T00:00"):
            self.check_refused([version(registered_on=date)], b, "registered_on")
        ok = dict(MAPPER, outputFormat={"limit": 2 ** 53 - 1, "\u00e9": 1, "\uff41": 2, "z": [0, -5]})
        f = Files([version(mapper=ok)], b)
        try:
            pr.load(f.prompts, f.bindings)
        finally:
            f.close()


class TestCheckR(unittest.TestCase):
    def setUp(self):
        self.f = Files([version(), version(v=2, mapper=dict(MAPPER, system="Version two of the sorter."))],
                       [{"scenario_id": 900001, "module_id": 2, "stage": "test.sorter", "version": 1}])
        self.reg = pr.load(self.f.prompts, self.f.bindings)

    def tearDown(self):
        self.f.close()

    def rows(self, flow, sid="900001"):
        return [(f.status, f.module_id, f.rule) for f in ab.check_r(blueprint(flow, sid), self.reg)]

    def test_bound_and_matching_passes(self):
        self.assertEqual(self.rows([claude(2)]), [(ab.PASS, 2, "R")])

    def test_unbound_module_fails_r1(self):
        self.assertIn((ab.FAIL, 7, "R1"), self.rows([claude(2), claude(7)]))

    def test_drifted_template_fails_r2(self):
        drift = dict(MAPPER, system=MAPPER["system"] + " Be brief.")
        rows = ab.check_r(blueprint([claude(2, drift)]), self.reg)
        self.assertEqual([(f.status, f.rule) for f in rows], [(ab.FAIL, "R2")])
        self.assertIn("test.sorter@1", rows[0].detail)

    def test_module_bound_to_newer_version_needs_its_template(self):
        # The binding names version 1, so the version 2 template is drift until the binding moves.
        self.assertEqual(self.rows([claude(2, dict(MAPPER, system="Version two of the sorter."))]), [(ab.FAIL, 2, "R2")])

    def test_stale_binding_fails_r3(self):
        self.assertIn((ab.FAIL, 2, "R3"), self.rows([{"id": 2, "module": "util:SetVariable2", "mapper": {}}]))

    def test_error_route_and_router_modules_are_checked(self):
        router = {"id": 3, "module": "builtin:BasicRouter", "routes": [{"flow": [claude(9)]}]}
        owner = {"id": 4, "module": "http:MakeRequest", "mapper": {}, "onerror": [claude(10)]}
        rows = self.rows([claude(2), router, owner])
        self.assertIn((ab.FAIL, 9, "R1"), rows)
        self.assertIn((ab.FAIL, 10, "R1"), rows)

    def test_other_scenarios_bindings_are_ignored(self):
        self.assertEqual(self.rows([], sid="900002"), [])

    def test_every_live_claude_module_is_bound_and_matches(self):
        reg = pr.load()
        blueprints, _cov = ab.load_manifest_mode(os.path.join(ROOT, "blueprints"), os.path.join(ROOT, "blueprints", "manifest.json"))
        rows = [f for b in blueprints for f in ab.check_r(b, reg)]
        self.assertTrue(rows)
        self.assertEqual([f for f in rows if f.status == ab.FAIL], [])


class TestRegister(unittest.TestCase):
    def test_register_reuses_then_adds_a_version_and_never_edits_one(self):
        d = tempfile.mkdtemp()
        try:
            bps = os.path.join(d, "blueprints")
            os.makedirs(bps)
            snap = os.path.join(bps, "synthetic__900001.json")
            prompts, bindings = os.path.join(d, "prompts.json"), os.path.join(d, "prompt_bindings.json")
            with open(snap, "w", encoding="utf-8") as f:
                json.dump({"name": "Synthetic", "flow": [claude(2)]}, f)
            kw = dict(blueprints=bps, prompts_path=prompts, bindings_path=bindings, today="2026-11-13")
            self.assertIn("registered test.sorter@1", pr.register(900001, 2, "test.sorter", "Sorts synthetic test emails.", **kw))
            with open(prompts, encoding="utf-8") as f:
                v1 = json.load(f)["prompts"][0]
            self.assertIn("reused test.sorter@1", pr.register(900001, 2, "test.sorter", "Sorts synthetic test emails.", **kw))
            with open(snap, "w", encoding="utf-8") as f:
                json.dump({"name": "Synthetic", "flow": [claude(2, dict(MAPPER, system="Edited sorter."))]}, f)
            self.assertIn("registered test.sorter@2", pr.register(900001, 2, "test.sorter", "Sorts synthetic test emails.", **kw))
            reg = pr.load(prompts, bindings)
            self.assertEqual(reg.versions[("test.sorter", 1)], v1, "version 1 is untouched")
            self.assertEqual(reg.bindings[("900001", 2)], ("test.sorter", 2))
            with self.assertRaises(pr.RegistryError):
                pr.register(900001, 99, "test.sorter", "Sorts synthetic test emails.", **kw)
            # A revert binds back to version 1 instead of adding a third version with version 1's template.
            with open(snap, "w", encoding="utf-8") as f:
                json.dump({"name": "Synthetic", "flow": [claude(2)]}, f)
            self.assertIn("reused test.sorter@1", pr.register(900001, 2, "test.sorter", "Sorts synthetic test emails.", **kw))
            reg = pr.load(prompts, bindings)
            self.assertEqual(sorted(reg.versions), [("test.sorter", 1), ("test.sorter", 2)])
            self.assertEqual(reg.bindings[("900001", 2)], ("test.sorter", 1))
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_register_from_a_candidate(self):
        d = tempfile.mkdtemp()
        try:
            bps = os.path.join(d, "blueprints")
            os.makedirs(bps)
            snap = os.path.join(bps, "synthetic__900001.json")
            with open(snap, "w", encoding="utf-8") as f:
                json.dump({"name": "Synthetic", "flow": [claude(2)], "metadata": {}}, f)
            prompts, bindings = os.path.join(d, "prompts.json"), os.path.join(d, "prompt_bindings.json")
            kw = dict(blueprints=bps, prompts_path=prompts, bindings_path=bindings, today="2026-11-13")
            pr.register(900001, 2, "test.sorter", "Sorts synthetic test emails.", **kw)
            cand = os.path.join(d, "candidate.json")
            with open(cand, "w", encoding="utf-8") as f:
                json.dump({"name": "Synthetic", "flow": [claude(2, dict(MAPPER, system="Pushed sorter.")), claude(5)], "metadata": {}}, f)
            before = open(snap, encoding="utf-8").read()
            self.assertIn("registered test.sorter@2", pr.register(900001, 2, "test.sorter", "Sorts synthetic test emails.", candidate=cand, **kw))
            self.assertIn("registered test.added@1", pr.register(900001, 5, "test.added", "A module the push adds to the scenario.", candidate=cand, **kw))
            self.assertEqual(open(snap, encoding="utf-8").read(), before, "the snapshot is never written")
            with self.assertRaises(pr.RegistryError):
                pr.register(900001, 5, "test.added", "A module the push adds to the scenario.", **kw)   # not in the snapshot
            with self.assertRaises(pr.RegistryError):
                pr.register(900001, 2, "test.sorter", "Sorts synthetic test emails.", candidate=os.path.join(d, "missing.json"), **kw)
            with self.assertRaises(pr.RegistryError):
                pr.register(900099, 2, "test.sorter", "Sorts synthetic test emails.", candidate=cand, **kw)   # no such snapshot
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_a_refused_version_never_reaches_the_files(self):
        d = tempfile.mkdtemp()
        try:
            bps = os.path.join(d, "blueprints")
            os.makedirs(bps)
            snap = os.path.join(bps, "synthetic__900001.json")
            prompts, bindings = os.path.join(d, "prompts.json"), os.path.join(d, "prompt_bindings.json")
            kw = dict(blueprints=bps, prompts_path=prompts, bindings_path=bindings, today="2026-11-13")
            with open(snap, "w", encoding="utf-8") as f:
                json.dump({"name": "Synthetic", "flow": [claude(2)]}, f)
            pr.register(900001, 2, "test.sorter", "Sorts synthetic test emails.", **kw)
            saved = (open(prompts, encoding="utf-8").read(), open(bindings, encoding="utf-8").read())
            for bad in ({k: v for k, v in MAPPER.items() if k != "model"}, {}, dict(MAPPER, model=5), dict(MAPPER, max_tokens=2048.0)):
                with open(snap, "w", encoding="utf-8") as f:
                    json.dump({"name": "Synthetic", "flow": [claude(2, bad) if bad else {"id": 2, "module": pr.CLAUDE_MODULE, "mapper": {}}]}, f)
                with self.assertRaises(pr.RegistryError):
                    pr.register(900001, 2, "test.sorter", "Sorts synthetic test emails.", **kw)
                self.assertEqual((open(prompts, encoding="utf-8").read(), open(bindings, encoding="utf-8").read()), saved)
                pr.load(prompts, bindings)
        finally:
            shutil.rmtree(d, ignore_errors=True)


class TestHistory(unittest.TestCase):
    """A version is held to the commit that first registered it, in the working tree and in the index."""

    def git(self, *args):
        subprocess.run(["git", *args], cwd=self.d, check=True, capture_output=True)

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.git("init", "-q")
        self.git("config", "user.email", "test@example.test")
        self.git("config", "user.name", "Test")
        self.git("config", "core.hooksPath", "/dev/null")
        os.makedirs(os.path.join(self.d, "ref"))
        self.path = os.path.join(self.d, "ref", "prompts.json")

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def write(self, rows):
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump({"prompts": rows}, f)

    def test_history(self):
        self.write([version()])
        self.assertEqual(pr.history_problems(self.path), [], "untracked file passes")
        self.git("add", "ref/prompts.json")
        self.git("commit", "-q", "-m", "v1")
        self.assertEqual(pr.history_problems(self.path), [])
        edited = version(mapper=dict(MAPPER, system="Rewritten in place."))
        self.write([edited])
        self.assertTrue(any("differs from commit" in p for p in pr.history_problems(self.path)))
        self.git("add", "ref/prompts.json")
        self.assertTrue(any("differs from commit" in p for p in pr.history_problems(self.path, staged=True)))
        self.git("commit", "-q", "-m", "edited in place")
        self.assertTrue(any("differs from commit" in p for p in pr.history_problems(self.path)), "still refused once committed")
        self.write([version(), version(v=2, mapper=dict(MAPPER, system="Rewritten in place."))])
        self.assertEqual(pr.history_problems(self.path), [], "restoring v1 and adding v2 passes")
        self.write([])
        self.assertTrue(any("is gone" in p for p in pr.history_problems(self.path)))


class TestCheckRPull(unittest.TestCase):
    def test_binding_to_a_scenario_outside_the_pull_fails_r3_on_a_full_audit_only(self):
        f = Files([version()], [{"scenario_id": 900077, "module_id": 2, "stage": "test.sorter", "version": 1}])
        try:
            reg = pr.load(f.prompts, f.bindings)
            rows = ab.check_r_pull(reg, {"900001"})
            self.assertEqual([(r.status, r.module_id, r.rule) for r in rows], [(ab.FAIL, 2, "R3")])
            self.assertEqual(ab.check_r_pull(reg, {"900077"}), [])
            schema = ab.load_schema(os.path.join(ROOT, "audit", "airtable_ledger_schema.json"))
            res = ab.audit([blueprint([])], ab.Labels(confirmed=False, scenarios={}), schema, True, prompts=reg,
                           manifest_ids={"900001"}, partial=True)
            self.assertFalse([x for x in res.findings if x.check == "R" and x.rule == "R3"], "a partial audit skips the pull-wide R3")
        finally:
            f.close()


class TestWiring(unittest.TestCase):
    def test_migration_locked_down_and_immutable(self):
        s = re.sub(r"--[^\n]*", "", text(MIGRATION))
        self.assertIn("ALTER TABLE ref.prompts ENABLE ROW LEVEL SECURITY;", s)
        self.assertIn("ALTER TABLE ref.prompt_bindings ENABLE ROW LEVEL SECURITY;", s)
        self.assertIn("REVOKE ALL ON ref.prompts, ref.prompt_bindings FROM PUBLIC, anon, authenticated;", s)
        self.assertIn("REVOKE ALL ON FUNCTION ref.prompts_immutable() FROM PUBLIC, anon, authenticated;", s)
        self.assertIn("BEFORE UPDATE OR DELETE ON ref.prompts", s)
        self.assertIn("BEFORE TRUNCATE ON ref.prompts", s)
        self.assertIn("ALTER TABLE ref.prompts ENABLE ALWAYS TRIGGER prompts_immutable;", s)
        self.assertIn("ALTER TABLE ref.prompts ENABLE ALWAYS TRIGGER prompts_no_truncate;", s)
        self.assertIn("SET search_path = pg_catalog, pg_temp", s)
        self.assertIn("CHECK (model = template ->> 'model')", s)
        for bad in ("GRANT ", "SECURITY DEFINER", "CREATE POLICY", "search_path = ''"):
            self.assertNotIn(bad, s)

    def test_loader_tables_order_and_columns(self):
        loader = text(LOADER)
        tables = re.findall(r'\{ table: "(\w+)", key: \[[^\]]*\], extra: "(\w+)"(, insertOnly: true)?', loader)
        self.assertEqual([t[0] for t in tables], ["visa_types", "document_types", "document_sections", "citation_map", "prompts",
                                                  "prompt_bindings", "test_records", "ircc_vocabulary", "exemplar_tags", "exemplar_test_seeds"])
        self.assertEqual(tables[4], ("prompts", "refuse", ", insertOnly: true"))
        self.assertEqual(tables[5][:2], ("prompt_bindings", "delete"))
        sql = text(MIGRATION)
        for c in pr.PROMPT_COLS + pr.BINDING_COLS:
            self.assertRegex(sql, rf"\n  {c}\s")

    def test_make_push_treats_the_registry_as_an_audit_input(self):
        s = text(PUSH)
        self.assertIn('"X-36": ("R",)', s)
        self.assertIn('("prompts registry", args.prompts), ("prompt bindings", args.prompt_bindings)', s)
        self.assertIn("prompts = audit_blueprints.load_prompts(args.prompts, args.prompt_bindings)", s)
        self.assertIn("audit_blueprints.prompt_registry.history_problems(args.prompts)", s)

    def test_pre_commit_hook_runs_the_history_check(self):
        hook = text(os.path.join(ROOT, ".githooks", "pre-commit"))
        self.assertIn('git diff --cached --name-only -- ref/prompts.json', hook)
        self.assertIn('scripts/prompt_registry.py" check --staged', hook)

    def test_audit_requires_the_registry(self):
        with self.assertRaises(ab.InputError):
            ab.load_prompts(os.path.join(ROOT, "ref", "no_such_prompts.json"), os.path.join(ROOT, "ref", "prompt_bindings.json"))


if __name__ == "__main__":
    unittest.main()
