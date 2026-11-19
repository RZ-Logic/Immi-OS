"""F-F14 evaluation harness (scripts/ff14, eval/ff14). Static invariants on the committed files, then the harness's own
--check, which needs Node and no network or database. The behaviour is the suite scripts/ff14/ff14.test.mjs
(node --test, PGlite and a faked Claude), see specs/F-F14-evaluation-harness.md."""

import json
import os
import re
import shutil
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FF14 = os.path.join(ROOT, "scripts", "ff14")
GOLDEN = os.path.join(ROOT, "eval", "ff14", "golden", "v1")
CITATION_MAP = os.path.join(ROOT, "ref", "citation_map.json")
SOURCES = ["run.mjs", "db.mjs", "iml.mjs", "chain.mjs", "grade.mjs", "golden.mjs", "x32.mjs"]


def text(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def cases():
    return [json.loads(text(os.path.join(GOLDEN, f))) for f in sorted(os.listdir(GOLDEN)) if f.endswith(".json")]


class TestGoldenSet(unittest.TestCase):
    def test_synthetic_names_and_ids(self):
        ids, seqs = set(), set()
        for c in cases():
            self.assertTrue(c["inputs"]["name"].startswith("ZZ-TEST"), c["id"])
            self.assertTrue(c["inputs"]["rcic_of_record"].startswith("ZZ-TEST RCIC "), c["id"])
            self.assertNotIn(c["id"], ids)
            self.assertNotIn(c["record_seq"], seqs)
            ids.add(c["id"])
            seqs.add(c["record_seq"])

    def test_strata_and_negatives(self):
        paid = [c for c in cases() if c["kind"] != "control"]
        self.assertEqual(len(paid), 26)
        self.assertEqual(len({c["stratum"] for c in paid}), 16)
        self.assertNotIn("REF-CLAIM", {c["stratum"] for c in paid})
        self.assertGreaterEqual(len([c for c in paid if c["kind"] == "negative"]), 3)

    def test_keys_in_the_provided_set(self):
        rows = json.loads(text(CITATION_MAP))["citation_map"]
        pairs = {}
        for r in rows:
            if r["document_type"] == "SUBMISSION-LETTER":
                pairs.setdefault(r["visa_code"], set()).add(r["provision_key"])
        for c in cases():
            if c["kind"] == "control":
                continue
            keys = list(c["expected"]["controlling_keys"]) + list(c["expected"]["support"])
            for k in keys:
                self.assertIn(k, pairs[c["inputs"]["visa_code"]], f"{c['id']} {k}")

    def test_manifest_pins_the_set(self):
        manifest = json.loads(text(os.path.join(ROOT, "eval", "ff14", "golden", "manifest.json")))
        pin = manifest["versions"]["v1"]
        self.assertRegex(pin["digest"], r"^[0-9a-f]{64}$")
        self.assertEqual(pin["cases"], len(cases()))

    def test_traps_have_hand_checks_and_the_date_check_is_specific(self):
        by_id = {c["id"]: c for c in cases()}
        for cid in ["ff14-002", "ff14-009", "ff14-012", "ff14-022", "ff14-026"]:
            self.assertTrue(any(ch["type"] == "hand" and ch["text"] for ch in by_id[cid]["expected"]["checks"]), cid)
        for c in cases():
            self.assertNotIn("outline_risk_flags_nonempty", [ch["type"] for ch in c["expected"]["checks"]], c["id"])
        flag = [ch for ch in by_id["ff14-003"]["expected"]["checks"] if ch["type"] == "outline_risk_flags_contain"]
        self.assertEqual(len(flag), 1)
        self.assertIn("03/04/2025", flag[0]["any"])

    def test_no_secret_shapes(self):
        for c in cases():
            blob = json.dumps(c)
            self.assertNotRegex(blob, r"sk-ant-|sk_live_|xox[abp]-|pat[A-Za-z0-9]{14}\.")


class TestRunnerSource(unittest.TestCase):
    def test_no_commit_in_the_runner(self):
        for f in SOURCES:
            code = "\n".join(re.sub(r"//.*$", "", line) for line in text(os.path.join(FF14, f)).splitlines())
            self.assertNotRegex(code, r"\bCOMMIT\b", f)
            self.assertNotRegex(code, r"[\"'`]\s*(?:COMMIT|END)\b", f)

    def test_sdk_pinned_exactly(self):
        pkg = json.loads(text(os.path.join(FF14, "package.json")))
        self.assertRegex(pkg["dependencies"]["@anthropic-ai/sdk"], r"^[0-9]+\.[0-9]+\.[0-9]+$")
        self.assertEqual(set(pkg["dependencies"]), {"@anthropic-ai/sdk"})

    def test_no_fallbacks_or_sampling_sent(self):
        code = text(os.path.join(FF14, "iml.mjs"))
        self.assertNotIn("fallbacks:", code)
        self.assertNotIn("betas", code)
        self.assertIn('baseURL: "https://api.anthropic.com"', text(os.path.join(FF14, "run.mjs")))

    def test_runs_and_golden_are_tracked(self):
        """Run folders are committed (decision 2026-11-16, 771293a removed the ignore rule), and the @1 byte-for-byte
        guard of scripts/ff14/x32.test.mjs reads the committed full run 20261116T195149Z."""
        if not shutil.which("git"):
            self.skipTest("no git")
        ignored = subprocess.run(["git", "check-ignore", "-q", "eval/ff14/runs/x/run.json"], cwd=ROOT)
        self.assertEqual(ignored.returncode, 1)
        listed = subprocess.run(["git", "ls-files", "--error-unmatch", "eval/ff14/runs/20261116T195149Z/cases/ff14-001.json"],
                                cwd=ROOT, capture_output=True)
        self.assertEqual(listed.returncode, 0)
        tracked = subprocess.run(["git", "check-ignore", "-q", "eval/ff14/golden/v1/ff14-001.json"], cwd=ROOT)
        self.assertEqual(tracked.returncode, 1)


class TestHarnessCheck(unittest.TestCase):
    def test_check_is_clean(self):
        node = shutil.which("node")
        if not node or not os.path.isdir(os.path.join(FF14, "node_modules")) or not os.path.isdir(os.path.join(ROOT, "scripts", "law_load", "node_modules")):
            self.skipTest("Node or the pinned node_modules are not installed (npm ci in scripts/ff14 and scripts/law_load)")
        r = subprocess.run([node, os.path.join(FF14, "run.mjs"), "--check"], cwd=ROOT, capture_output=True, text=True, timeout=120)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("check: clean", r.stdout)


if __name__ == "__main__":
    unittest.main()
