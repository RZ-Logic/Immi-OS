"""X-32 synthetic TEST seeds (scripts/x32_seeds.py): the committed seeds lint clean against the skeleton rules and the tag
vocabulary, every rule fails on a one-line change, the digests and the overlay match, and the reference ranker follows
steps 4 to 7 of ff13.rank_exemplars (specs/X-32-exemplars.md section 3). Synthetic data only, no network.
"""

import copy
import json
import os
import re
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import x32_seeds as xs  # noqa: E402

SEEDS = xs.load_seeds()
VOCAB = xs.load_vocab()
GOLDEN = xs.golden_text()
BY_CODE = {s["code"]: s for s in SEEDS}


def lines_for(*pairs, status="TEST"):
    return "\n".join(xs.rank_key(rid, BY_CODE[code], status) for rid, code in pairs)


R1, R2, R3 = "recX32ZZTEST00001", "recX32ZZTEST00002", "recX32ZZTEST00003"


class TestSeeds(unittest.TestCase):
    def test_the_committed_seeds_lint_clean(self):
        self.assertEqual(xs.lint(), [])
        self.assertGreaterEqual(len(SEEDS), 3)
        self.assertTrue({"TR-VISIT", "TR-STUDY"} <= {s["visa_code"] for s in SEEDS})

    def test_digests_and_overlay_match(self):
        with open(xs.SEED_MANIFEST, encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)["seeds"], xs.manifest_rows())
        with open(xs.OVERLAY, encoding="utf-8") as fh:
            self.assertEqual(json.load(fh), xs.overlay(SEEDS, VOCAB))
        self.assertEqual(xs.main(["check"]), 0)

    def test_each_rule_fails(self):
        base = copy.deepcopy(SEEDS[0])
        base.pop("_file", None)

        def bad(**change):
            s = copy.deepcopy(base)
            for k, v in change.items():
                s[k] = v(s) if callable(v) else v
            return xs.seed_problems(s, VOCAB, GOLDEN)

        sk = base["skeleton_lines"]
        self.assertEqual(xs.seed_problems(base, VOCAB, GOLDEN), [])
        cases = {
            "code": dict(code="EX-TR-VISIT-001"),
            "excluded": dict(visa_code="HC-PR", code="ZZ-TEST-EX-HC-PR-001"),
            "doc": dict(document_code="LOE"),
            "source": dict(source_type="RCIC-written"),
            "tag": dict(tags=["no-such-tag"]),
            "first line": dict(skeleton_lines=["Draft for review."] + sk[1:]),
            "headings": dict(skeleton_lines=[x for x in sk if x != "Background"]),
            "ending": dict(skeleton_lines=sk[:-1]),
            "citation key": dict(skeleton_lines=sk[:5] + ["The officer applies IRPR 179(b) here."] + sk[5:]),
            "section number": dict(skeleton_lines=sk[:5] + ["Under section 179 the officer decides."] + sk[5:]),
            "paragraph ref": dict(skeleton_lines=sk[:5] + ["See 179(b) on this point."] + sk[5:]),
            "lower placeholder": dict(skeleton_lines=sk[:5] + ["The [applicant name] works here."] + sk[5:]),
            "less than": dict(skeleton_lines=sk[:5] + ["A value < 5 is low."] + sk[5:]),
            "em dash": dict(skeleton_lines=sk[:5] + ["A pause — here."] + sk[5:]),
            "blank line": dict(skeleton_lines=sk[:5] + [""] + sk[5:]),
            "term absent": dict(terms=base["terms"] + ["Nowhere Junction"]),
            "golden term": dict(terms=base["terms"] + ["Kumasi"],
                                skeleton_lines=sk[:5] + ["The applicant lives in Kumasi."] + sk[5:]),
            "shadow is a term": dict(shadow_terms=[base["terms"][0]]),
            "no terms": dict(terms=[]),
        }
        for what, change in cases.items():
            self.assertTrue(bad(**change), what)

    def test_vocabulary_rules(self):
        cmap = json.load(open(xs.CITATION_MAP, encoding="utf-8"))["citation_map"]
        codes = [v["code"] for v in json.load(open(xs.VISA_TYPES, encoding="utf-8"))["visa_types"]]
        self.assertEqual(xs.vocab_problems(VOCAB, cmap, codes), [])
        for change in ({"tag": "Bad Tag"}, {"visa_code": "REF-CLAIM"}, {"addresses": ["IRPR 999"]}, {"addresses": []},
                       {"review_state": "reviewed"}, {"reviewer_licence": "R000000"}):
            row = dict(VOCAB[0], **change)
            self.assertTrue(xs.vocab_problems([row], cmap, codes), change)
        self.assertTrue(xs.vocab_problems([VOCAB[0], VOCAB[0]], cmap, codes))


class TestReferenceRanker(unittest.TestCase):
    listed = {R1, R2, R3}

    def rank(self, lines, weak, visa="TR-VISIT", mode="test", listed=None):
        return xs.rank(lines, weak, visa, "SUBMISSION-LETTER", VOCAB, self.listed if listed is None else listed, mode)

    def test_scores_weak_keys_and_breaks_ties(self):
        lines = lines_for((R1, "ZZ-TEST-EX-TR-WP-EMP-001"), (R2, "ZZ-TEST-EX-TR-WP-EMP-002"))
        emp = dict(visa="TR-WP-EMP")
        self.assertEqual(self.rank(lines, ["IRPR 200(1)(c)(iii)"], **emp)["exemplar_code"], "ZZ-TEST-EX-TR-WP-EMP-002")
        self.assertEqual(self.rank(lines, ["IRPR 200(1)(c)(ii.1)"], **emp)["exemplar_code"], "ZZ-TEST-EX-TR-WP-EMP-001")
        tie = self.rank(lines, [], **emp)
        self.assertEqual((tie["exemplar_code"], tie["score"]), ("ZZ-TEST-EX-TR-WP-EMP-001", 0))   # score 0 still selects
        self.assertEqual(self.rank(lines, ["IRPR 200(1)(c)(ii.1)", "IRPR 205(a)"], **emp)["score"], 2)
        # The score counts keys, not tags: two TR-VISIT tags that both address IRPR 179(b) score 1.
        two = f"{R1}|ZZ-TEST-EX-TR-VISIT-001|TEST|TR-VISIT|SUBMISSION-LETTER|2|home-ties-thin, first-trip-abroad"
        self.assertEqual(self.rank(two, ["IRPR 179(b)"])["score"], 1)
        # A seed with no tag is still selected, at score 0.
        bare = self.rank(lines_for((R1, "ZZ-TEST-EX-TR-VISIT-001")), ["IRPR 179(b)"])
        self.assertEqual((bare["exemplar_code"], bare["score"]), ("ZZ-TEST-EX-TR-VISIT-001", 0))

    def test_conflicts_first(self):
        """Decided by Rizwan 2026-11-19: the fewest supported keys a seed's tags address (it leaves them out) wins first,
        then the score. ff14-018 (spouse in Canada, IRPR 124 supported) gets the in-Canada seed, not the lower code."""
        sp = lines_for((R1, "ZZ-TEST-EX-FAM-SPOUSE-001"), (R2, "ZZ-TEST-EX-FAM-SPOUSE-002"))
        inland = xs.rank(sp, [], "FAM-SPOUSE", "SUBMISSION-LETTER", VOCAB, self.listed, "test", strong_keys=["IRPR 124"])
        self.assertEqual((inland["exemplar_code"], inland["score"], inland["conflicts"]), ("ZZ-TEST-EX-FAM-SPOUSE-002", 0, 0))
        outland = xs.rank(sp, [], "FAM-SPOUSE", "SUBMISSION-LETTER", VOCAB, self.listed, "test", strong_keys=[])
        self.assertEqual(outland["exemplar_code"], "ZZ-TEST-EX-FAM-SPOUSE-001")   # no conflict either way, the code decides
        # Conflicts outrank a higher score: the seed that covers the weak 183(2) but leaves out the supported 179(b) loses.
        both = f"{R1}|ZZ-TEST-EX-TR-VISIT-001|TEST|TR-VISIT|SUBMISSION-LETTER|2|home-ties-thin, stay-funds-modest"
        bare = f"{R2}|ZZ-TEST-EX-TR-VISIT-002|TEST|TR-VISIT|SUBMISSION-LETTER|2|"
        got = xs.rank(both + "\n" + bare, ["IRPR 183(2)"], "TR-VISIT", "SUBMISSION-LETTER", VOCAB, self.listed, "test",
                      strong_keys=["IRPR 179(b)"])
        self.assertEqual((got["exemplar_code"], got["score"], got["conflicts"]), ("ZZ-TEST-EX-TR-VISIT-002", 0, 0))
        # Without the supported key, the higher score wins as before.
        old = xs.rank(both + "\n" + bare, ["IRPR 183(2)"], "TR-VISIT", "SUBMISSION-LETTER", VOCAB, self.listed, "test")
        self.assertEqual((old["exemplar_code"], old["score"], old["conflicts"]), ("ZZ-TEST-EX-TR-VISIT-001", 1, 0))

    def test_test_mode_needs_a_listed_test_seed(self):
        lines = lines_for((R1, "ZZ-TEST-EX-TR-VISIT-001"))
        self.assertEqual(self.rank(lines, [], listed=set())["exemplar_code"], "")
        active = lines_for((R1, "ZZ-TEST-EX-TR-VISIT-001"), status="Active")
        self.assertEqual(self.rank(active, [])["exemplar_code"], "")

    def test_production_refuses_any_test_mark_for_the_whole_run(self):
        prod = "\n".join([f"{R3}|EX-TR-VISIT-001|Active|TR-VISIT|SUBMISSION-LETTER|2|home-ties-thin",
                          lines_for((R1, "ZZ-TEST-EX-TR-VISIT-001"), status="Active")])
        got = self.rank(prod, [], mode="production", listed=set())
        self.assertEqual((got["exemplar_code"], "test_seed_in_production" in got["flags"]), ("", True))
        listed_id = f"{R3}|EX-TR-VISIT-001|Active|TR-VISIT|SUBMISSION-LETTER|2|home-ties-thin"
        self.assertEqual(self.rank(listed_id, [], mode="production", listed={R3})["exemplar_code"], "")
        # Production scores only reviewed vocabulary rows, so an unreviewed tag gives 0 and the row still selects.
        ok = self.rank(listed_id, ["IRPR 179(b)"], mode="production", listed=set())
        self.assertEqual((ok["exemplar_code"], ok["score"]), ("EX-TR-VISIT-001", 0))

    def test_empty_malformed_cross_cell_and_excluded(self):
        lines = "\n\n" + lines_for((R1, "ZZ-TEST-EX-TR-VISIT-001")) + "\nnot|a|row\n"
        got = self.rank(lines, [])
        self.assertEqual(got["exemplar_code"], "ZZ-TEST-EX-TR-VISIT-001")
        self.assertIn("candidate_malformed", got["flags"])
        cross = self.rank(lines_for((R2, "ZZ-TEST-EX-TR-STUDY-001")), [])
        self.assertEqual((cross["exemplar_code"], "cross_cell_candidate" in cross["flags"]), ("", True))
        self.assertIn("excluded_cell", self.rank("", [], visa="HC-PR")["flags"])
        self.assertEqual(self.rank("", [])["exemplar_code"], "")


class TestFindings20261116(unittest.TestCase):
    """The X-32 review findings of 2026-11-16 that live in the seeds, the reference ranker and the Airtable plan."""

    def base(self):
        s = copy.deepcopy(BY_CODE["ZZ-TEST-EX-TR-VISIT-001"])
        s.pop("_file", None)
        return s

    def test_every_seed_carries_the_test_mark_once_in_its_skeleton(self):
        for s in SEEDS:
            self.assertEqual(xs.skeleton(s).count(xs.MARKER), 1, s["code"])
            self.assertNotIn("ZZ-TEST", " ".join(s["terms"] + s["shadow_terms"]).upper())
        b = self.base()
        sk = b["skeleton_lines"]
        unmarked = [x.replace(xs.MARKER + " ", "") for x in sk]
        self.assertTrue(xs.seed_problems(dict(b, skeleton_lines=unmarked), VOCAB, GOLDEN))
        twice = sk[:5] + [sk[4] + " " + xs.MARKER] + sk[6:]
        self.assertTrue(xs.seed_problems(dict(b, skeleton_lines=twice), VOCAB, GOLDEN))
        self.assertTrue(xs.seed_problems(dict(b, terms=b["terms"] + ["ZZ-TEST Guild"],
                                              skeleton_lines=sk[:5] + ["The ZZ-TEST Guild hosts it."] + sk[5:]), VOCAB, GOLDEN))

    def test_seeds_model_compliant_letters(self):
        for s in SEEDS:
            words = len(xs.skeleton(s).replace(xs.MARKER, " ").split())
            self.assertGreaterEqual(words, xs.MIN_WORDS, s["code"])
        b = self.base()
        sk = b["skeleton_lines"]
        at = sk.index("Submissions")
        for bad in ("Nothing in the record suggests a purpose beyond the event.",
                    "Nothing in the file points to ties in Canada that compete with them.",
                    "The applicant would have no reason to secure leave rather than resign.",
                    "The applicant will certainly return."):
            self.assertTrue(xs.seed_problems(dict(b, skeleton_lines=sk[:at + 1] + [bad] + sk[at + 1:]), VOCAB, GOLDEN), bad)
        legal = sk.index("Legal framework")
        ungrounded = sk[:legal + 1] + [sk[legal + 1] + " The officer weighs the ties against any incentive to remain."] + sk[legal + 2:]
        self.assertTrue(any("no [CITATION]" in p for p in xs.seed_problems(dict(b, skeleton_lines=ungrounded), VOCAB, GOLDEN)))
        short = [x for i, x in enumerate(sk) if i < 6 or x in xs.HEADINGS or i >= len(sk) - 3 or "[CITATION]" in x]
        self.assertTrue(any("words" in p for p in xs.seed_problems(dict(b, skeleton_lines=short), VOCAB, GOLDEN)))

    def test_codes_are_validated_and_no_pick_is_never_empty(self):
        line = f"{R3}|EX-TR-VISIT-001|Active|TR-VISIT|SUBMISSION-LETTER|1|home-ties-thin"
        for code in ("EX-TR-VISIT-Okafor", "Okafor family, Moncton", "EX-TR-VISIT-OKAFOR-001", "EX-TR-STUDY-001", "EX-TR-VISIT-01"):
            got = xs.rank(line.replace("EX-TR-VISIT-001", code), [], "TR-VISIT", "SUBMISSION-LETTER", VOCAB, set(), "production")
            self.assertEqual((got["exemplar_code"], got["exemplar_record_id"]), ("", xs.NO_PICK), code)
            self.assertIn("candidate_malformed", got["flags"])
        self.assertEqual(xs.rank(line, [], "TR-VISIT", "SUBMISSION-LETTER", VOCAB, set(), "production")["exemplar_code"], "EX-TR-VISIT-001")
        self.assertTrue(xs.code_ok("ZZ-TEST-EX-TR-WP-EMP-007", "TR-WP-EMP"))
        self.assertFalse(xs.code_ok("EX-TR-WP-EMP-007", "TR-WP"))
        for got in (xs.rank("", [], "TR-VISIT", "SUBMISSION-LETTER", VOCAB, set()),
                    xs.rank("", [], "HC-PR", "SUBMISSION-LETTER", VOCAB, set()),
                    xs.rank(lines_for((R1, "ZZ-TEST-EX-TR-VISIT-001")), [], "TR-VISIT", "SUBMISSION-LETTER", VOCAB, set(), "production")):
            self.assertEqual(got["exemplar_record_id"], xs.NO_PICK)
        self.assertFalse(xs.NO_PICK.startswith("rec"))

    def test_terms_rule_gives_term_count_equal_to_the_validator_lines(self):
        """Python mirror of the PGlite test in scripts/ff14/x32.test.mjs (the validator's own split runs there)."""
        fold_empty = set(" _\u00a0\u1680\u202f\u205f\u3000") | {chr(c) for c in range(0x2000, 0x200b)}

        def validator_lines(text):
            parts = re.split("\r\n|[\n\u000b\f\r\u0085\u2028\u2029]", text)
            return sum(1 for p in parts if any(ch not in fold_empty for ch in p))

        for bad in ("Moncton\nwelding\n", "Velmora Valley\n \nHarrowgate Ceramics Guild", "a\rb", "a\u2028b", "a\n\u00a0\nb",
                    "\nMoncton", "a\n_\nb", "a\tb", ""):
            self.assertFalse(xs.terms_status_ok(bad), repr(bad))
        pieces = ["Moncton", "welding", "", " ", "\u00a0", "_", "\t", "\r", "\u2028", "a b", "\u200b", "x_y"]
        accepted = 0
        for a in pieces:
            for b in pieces:
                for text in (a, f"{a}\n{b}", f"{a}\n{b}\n", f"{a}\n\n{b}", f"\n{a}", f"{a}\r\n{b}"):
                    if xs.terms_status_ok(text):
                        accepted += 1
                        self.assertEqual(xs.term_count(text), validator_lines(text), repr(text))
        self.assertGreater(accepted, 20)

    def test_the_javascript_mirror_uses_the_same_classes_and_spacing(self):
        with open(os.path.join(ROOT, "scripts", "ff14", "x32.mjs"), encoding="utf-8") as fh:
            self.assertIn('skeleton: s.skeleton_lines.join("\\n\\n")', fh.read())
        self.test_the_javascript_mirror_uses_the_same_classes()

    def test_the_javascript_mirror_uses_the_same_classes(self):
        with open(os.path.join(ROOT, "scripts", "ff14", "x32.mjs"), encoding="utf-8") as fh:
            js = fh.read()

        def esc(text):
            return "".join(c if 32 <= ord(c) < 127 else {"\n": "\\n", "\t": "\\t", "\r": "\\r", "\f": "\\f"}.get(c, "\\u%04x" % ord(c))
                           for c in text)
        self.assertIn("/" + esc(xs.TERMS_BLANK_LINE_RE) + "/", js)
        self.assertIn("/" + esc(xs.TERMS_SEPARATOR_RE) + "/", js)
        self.assertIn(f'export const NO_PICK = "{xs.NO_PICK}";', js)


class TestFindingsPart2(unittest.TestCase):
    """The X-32 part 2 review findings of 2026-11-16 that live in the seeds, the vocabulary and the lint."""

    def base(self):
        s = copy.deepcopy(BY_CODE["ZZ-TEST-EX-FAM-OTHER-001"])
        s.pop("_file", None)
        return s

    def test_paragraphs_are_separated_by_one_blank_line(self):
        for s in SEEDS:
            text = xs.skeleton(s)
            self.assertEqual(text.split("\n\n"), s["skeleton_lines"], s["code"])
            self.assertNotIn("\n\n\n", text)
            self.assertEqual(text, text.strip())
        rows = xs.airtable_rows(SEEDS, "FIRM-01")
        self.assertEqual([r["fields"]["Skeleton"] for r in rows], [xs.skeleton(s) for s in sorted(SEEDS, key=lambda s: s["code"])])

    def test_trap_cases_pick_the_route_the_case_takes(self):
        """A tag addresses only keys its seed leaves out, so the weak key of a trap is the route the case does not take
        and the pick is the seed of the route it does take (finding: met-ground tags picked the other route)."""
        with open(xs.OVERLAY, encoding="utf-8") as fh:
            cases = json.load(fh)["cases"]
        want = {"ff14-006": "ZZ-TEST-EX-TR-WP-EMP-001", "ff14-007": "ZZ-TEST-EX-TR-WP-EMP-002",
                "ff14-008": "ZZ-TEST-EX-TR-WP-OPEN-001", "ff14-010": "ZZ-TEST-EX-TR-SUPER-001",
                "ff14-017": "ZZ-TEST-EX-FAM-SPOUSE-001", "ff14-020": "ZZ-TEST-EX-FAM-PGP-001",
                "ff14-021": "ZZ-TEST-EX-FAM-OTHER-001", "ff14-026": "ZZ-TEST-EX-TR-STUDY-002"}
        for case, code in want.items():
            self.assertEqual((cases[case]["pick"], cases[case]["score"] > 0), (code, True), case)
        # The picks argue the route the case takes: the LMIA letter for the LMIA cook, the exempt letter for the scientist,
        # the spousal open permit, a Canadian insurer, an outland spouse, a parent, an orphaned relative, no funds argument.
        lmia, exempt = (xs.skeleton(BY_CODE[c]) for c in ("ZZ-TEST-EX-TR-WP-EMP-001", "ZZ-TEST-EX-TR-WP-EMP-002"))
        self.assertIn("positive labour market impact assessment", lmia)
        self.assertNotIn("labour market impact assessment was issued", exempt)
        self.assertIn("spouse or common-law partner in Canada class", xs.skeleton(BY_CODE["ZZ-TEST-EX-TR-WP-OPEN-001"]))
        self.assertNotIn("youth mobility", xs.skeleton(BY_CODE["ZZ-TEST-EX-TR-WP-OPEN-001"]))
        self.assertIn("an insurance company in Canada", xs.skeleton(BY_CODE["ZZ-TEST-EX-TR-SUPER-001"]))
        self.assertNotIn("outside Canada", xs.skeleton(BY_CODE["ZZ-TEST-EX-TR-SUPER-001"]))
        self.assertNotIn("no closer relative", xs.skeleton(BY_CODE["ZZ-TEST-EX-FAM-OTHER-001"]))
        self.assertNotRegex(xs.skeleton(BY_CODE["ZZ-TEST-EX-TR-STUDY-002"]), r"(?i)\bfunds?\b|tuition|financial")
        # Every tag a seed carries is in the vocabulary of its code, and an untagged seed is allowed.
        self.assertTrue(any(not s["tags"] for s in SEEDS))

    def test_the_lint_refuses_each_part_2_defect(self):
        b = self.base()
        sk = b["skeleton_lines"]
        self.assertEqual(xs.seed_problems(b, VOCAB, GOLDEN), [])
        intro = sk.index("Background")
        subs = sk.index("Submissions") + 1
        legal = sk.index("Legal framework") + 1

        def at(i, line):
            return xs.seed_problems(dict(b, skeleton_lines=sk[:i] + [line] + sk[i:]), VOCAB, GOLDEN)

        for line in ("The file raises one point that calls for explanation: the earlier marriage.",
                     "Two points in the file call for explanation.",
                     "The letter sets out the facts, then the provisions, and then the submissions.",
                     "The letter also explains a gap in the study history."):
            self.assertTrue(at(intro, line), line)
        for line in ("Each fact refers to a document in the index of supporting documents.",
                     "The applicant and the family are not inadmissible on the documents in the application.",
                     "The applicant meets the requirements for permanent residence.",
                     "The applicant has worked there for [NUMBER] years.", "The applicant was [AGE] when the course began.",
                     "The assessment is less than five years old on the date of the application.",
                     "The experience since [YEAR] exceeds two years within that period.",
                     "The employment since [START DATE] is well within the period.",
                     "The application was made [NUMBER] days after the letter of completion.",
                     "The applicant asks for the permit length that program length supports under the public policy for graduates.",
                     "The applicant attends a boarding school in the town."):
            self.assertTrue(at(subs, line), line)
        # The law states periods in its own terms: Legal framework may say it, a fact paragraph may not.
        law = "The work must fall in the three years before the application [CITATION]."
        self.assertEqual(at(legal, law), [])
        self.assertTrue(at(subs, "The work fell within the three years before the application."))
        # A listed part of a term is allowed.
        self.assertEqual(xs.seed_problems(dict(b, shadow_terms=b["shadow_terms"] + ["boarding school"],
                                               skeleton_lines=sk[:subs] + ["The applicant attends a boarding school."] + sk[subs:]),
                                          VOCAB, GOLDEN), [])

    def test_pgwp_background_is_in_time_order(self):
        s = BY_CODE["ZZ-TEST-EX-TR-PGWP-001"]
        lines = s["skeleton_lines"]
        bg = " ".join(lines[lines.index("Background") + 1:lines.index("Legal framework")])
        marks = ["[ENTRY DATE]", "[START DATE]", "co-op placement", "off campus", "[COMPLETION DATE]", "[APPLICATION DATE]"]
        self.assertEqual([bg.index(m) for m in marks], sorted(bg.index(m) for m in marks), marks)


class TestAirtablePlan(unittest.TestCase):
    """specs/X-32-airtable-exemplars.json: review time and identity recorded by Airtable, every attested field tracked, the
    code and terms rules in Status (findings 2026-11-16)."""

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(ROOT, "specs", "X-32-airtable-exemplars.json"), encoding="utf-8") as fh:
            cls.plan = json.load(fh)
        cls.fields = {s["field"]["name"]: s["field"] for k, s in cls.plan.items() if k.endswith("_create_field")}
        cls.table = {f["name"]: f for f in cls.plan["step_1_create_table"]["fields"]}

    def test_status_is_the_generated_formula(self):
        f = self.fields["Status"]["options"]["formula"]
        self.assertEqual(f, xs.status_formula())
        for part in (xs.CODE_TEST_RE, xs.CODE_ACTIVE_RE, xs.airtable_pattern(xs.TERMS_BLANK_LINE_RE),
                     xs.airtable_pattern(xs.TERMS_SEPARATOR_RE), f'FIND("{xs.MARKER}", {{Skeleton}})',
                     '{RCIC Attested By} = "RCIC NOT YET NAMED"', "IS_AFTER({RCIC Reviewed At}, {Content Modified})",
                     '{Consent Reference} != ""'):
            self.assertIn(part, f)
        self.assertNotIn('NOT(FIND("\\n\\n"', f)   # the old blank-pair test, which let a trailing newline through

    def test_review_time_and_identity_are_recorded_by_airtable(self):
        self.assertNotIn("RCIC Reviewed At", self.table)   # no hand-typed date field
        at, by = self.fields["RCIC Reviewed At"], self.fields["RCIC Attested By"]
        self.assertEqual((at["type"], at["options"]["referencedFieldIds"]), ("lastModifiedTime", ["Review Attestation"]))
        self.assertEqual((by["type"], by["options"]["referencedFieldIds"]), ("lastModifiedBy", ["Review Attestation"]))

    def test_content_modified_tracks_every_attested_field_and_not_the_attestation(self):
        got = self.fields["Content Modified"]["options"]["referencedFieldIds"]
        self.assertEqual(got, list(xs.CONTENT_FIELDS))
        for name in ("Retired", "Consent Recorded", "Consent Reference", "Exemplar Code", "RCIC Reviewer", "Skeleton",
                     "Residual Quasi-Identifiers", "Source Type"):
            self.assertIn(name, got)
        self.assertNotIn("Review Attestation", got)
        self.assertTrue(set(got) <= set(self.table))

    def test_each_computed_field_names_only_fields_created_before_it(self):
        made = set(self.table)
        for key in sorted(k for k in self.plan if k.endswith("_create_field")):
            f = self.plan[key]["field"]
            refs = set(f.get("options", {}).get("referencedFieldIds", []))
            refs |= set(re.findall(r"\{([^{}]+)\}", f.get("options", {}).get("formula", ""))) - {"3"}
            self.assertTrue(refs <= made, (key, sorted(refs - made)))
            made.add(f["name"])


if __name__ == "__main__":
    unittest.main()
