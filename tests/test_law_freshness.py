"""X-37 law freshness check (scripts/law_freshness.py), on synthetic XML and pages, no network."""

import hashlib
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import law_freshness as lf  # noqa: E402

XML_URL = {inst: urls[0] for inst, urls in lf.SOURCES.items()}
PAGE_URL = {inst: urls[1] for inst, urls in lf.SOURCES.items()}


def xml(kind, current, amended, inner="2022-03-04"):
    # An inner element with its own, older lastAmendedDate, as in the IRPR file (measured 2026-11-19).
    return (f'<?xml version="1.0"?><{kind} lims:pit-date="{amended}" lims:lastAmendedDate="{amended}" '
            f'lims:current-date="{current}" xmlns:lims="http://justice.gc.ca/lims"><Identification>'
            f'<Section lims:lastAmendedDate="{inner}"/></Identification></{kind}>').encode()


def page(current, amended, word="Regulations are"):
    return (f"<div class='info'><p id='assentedDate'>{word} current to {current}  and <a href='#hist'>last amended</a> on "
            f"{amended}. <a href='PITIndex.html'>Previous Versions</a></p></div>").encode()


IRPA = xml("Statute", "2026-09-30", "2026-03-26")
IRPR = xml("Regulation", "2026-10-29", "2026-10-23")


def manifest(irpa=IRPA, irpr=IRPR):
    return {"instruments": [
        {"instrument": "IRPA", "current_to": "2026-09-30", "last_amended": "2026-03-26", "source_sha256": hashlib.sha256(irpa).hexdigest()},
        {"instrument": "IRPR", "current_to": "2026-10-29", "last_amended": "2026-10-23", "source_sha256": hashlib.sha256(irpr).hexdigest()}]}


def getter(irpa=IRPA, irpr=IRPR, irpa_page=None, irpr_page=None):
    served = {XML_URL["IRPA"]: irpa, XML_URL["IRPR"]: irpr,
              PAGE_URL["IRPA"]: irpa_page or page("2026-10-29", "2026-03-26", "Act"),
              PAGE_URL["IRPR"]: irpr_page or page("2026-10-29", "2026-10-23")}
    return lambda url: served[url]


class TestParsers(unittest.TestCase):
    def test_the_root_dates_win_over_inner_elements(self):
        self.assertEqual(lf.xml_dates(IRPR), {"current_to": "2026-10-29", "last_amended": "2026-10-23"})
        self.assertEqual(lf.xml_dates(IRPA), {"current_to": "2026-09-30", "last_amended": "2026-03-26"})

    def test_a_file_without_a_root_or_its_dates_is_an_error(self):
        with self.assertRaises(lf.FreshnessError):
            lf.xml_dates(b"<html>not the law</html>")
        with self.assertRaises(lf.FreshnessError):
            lf.xml_dates(b'<?xml version="1.0"?><Statute xml:lang="en"></Statute>')

    def test_the_page_line_reads_through_the_link(self):
        self.assertEqual(lf.page_dates(page("2026-10-29", "2026-10-23")), {"current_to": "2026-10-29", "last_amended": "2026-10-23"})
        self.assertEqual(lf.page_dates(page("2026-10-29", "2026-03-26", "Act")), {"current_to": "2026-10-29", "last_amended": "2026-03-26"})
        self.assertIsNone(lf.page_dates(b"<p>maintenance</p>"))


class TestCheck(unittest.TestCase):
    def test_pinned_files_are_current(self):
        res = lf.check(manifest(), {"rows": []}, get=getter())
        self.assertEqual(res["exit"], 0)
        self.assertTrue(all(r["xml"]["equals_pin"] for r in res["instruments"].values()))
        self.assertIn("current, no reload", lf.report(res, "2026-11-19"))

    def test_a_page_ahead_of_the_xml_is_a_lag_not_a_reload(self):
        res = lf.check(manifest(), {"rows": []}, get=getter(irpr_page=page("2026-11-05", "2026-11-01")))
        self.assertEqual(res["exit"], 2)
        self.assertTrue(res["instruments"]["IRPR"]["feed_lags"])
        # A later current-to date alone (IRPA, measured 2026-11-19) is no lag.
        self.assertNotIn("feed_lags", res["instruments"]["IRPA"])

    def test_an_unreadable_page_is_incomplete_not_current(self):
        """Review 2026-11-19: a page whose current-to line cannot be read must not pass as current."""
        res = lf.check(manifest(), {"rows": []}, get=getter(irpa_page=b"<p>Service unavailable</p>"))
        self.assertEqual(res["exit"], 3)
        self.assertTrue(res["instruments"]["IRPA"]["page_unread"])
        self.assertIn("INCOMPLETE", lf.report(res, "2026-11-19"))

    def test_a_changed_xml_needs_a_reload_and_names_the_review(self):
        old = [{"key": "IRPR 70", "instrument": "IRPR", "section": "70", "ord": 1, "text_sha256": "a", "status": "in_force"},
               {"key": "IRPR 70(1)(e)", "instrument": "IRPR", "section": "70", "ord": 2, "text_sha256": "b", "status": "in_force"},
               {"key": "IRPR 74", "instrument": "IRPR", "section": "74", "ord": 3, "text_sha256": "c", "status": "in_force"}]
        new = [dict(old[0], text_sha256="a2"), dict(old[1]), dict(old[2], text_sha256="c2"),
               {"key": "IRPR 87.4", "instrument": "IRPR", "section": "87.4", "ord": 4, "text_sha256": "d", "status": "in_force"}]
        cmap = {"rows": [{"visa_code": "PR-PNP-BASE", "provision_key": "IRPR 70(1)(e)", "reviewed_text_sha256": "b"},
                         {"visa_code": "PR-EE-CEC", "provision_key": "IRPR 74", "reviewed_text_sha256": "c"},
                         {"visa_code": "PR-EE-FSW", "provision_key": "IRPR 74", "reviewed_text_sha256": None}]}
        for r in old + new:
            r.setdefault("level", "section" if "(" not in r["key"] else "paragraph")
        old[1]["parent_key"] = new[1]["parent_key"] = "IRPR 70"
        rv = lf.review(old, new, cmap, "IRPR")
        self.assertEqual(rv["changed"], ["IRPR 70", "IRPR 74"])
        self.assertEqual(rv["cited_touched"], ["IRPR 74"])          # 70(1)(e) is unchanged, only its parent moved
        self.assertEqual(rv["signed_rows_stale"], [["", "PR-EE-CEC", "IRPR 74"]])   # the unsigned FSW row is not stale
        self.assertEqual(rv["new_sections"], ["IRPR 87.4"])
        self.assertEqual(rv["cited_lead_in_changed"], [])   # IRPR 70's own words did not change, only its hash

    def test_a_changed_lead_in_above_a_cited_key_is_named(self):
        old = [{"key": "IRPR 70", "instrument": "IRPR", "section": "70", "level": "section", "parent_key": None, "ord": 1,
                "own_text": "", "text_sha256": "a", "status": "in_force"},
               {"key": "IRPR 70(1)", "instrument": "IRPR", "section": "70", "level": "subsection", "parent_key": "IRPR 70",
                "ord": 2, "own_text": "An officer shall issue a visa if", "text_sha256": "b", "status": "in_force"},
               {"key": "IRPR 70(1)(e)", "instrument": "IRPR", "section": "70", "level": "paragraph", "parent_key": "IRPR 70(1)",
                "ord": 3, "own_text": "the foreign national meets the requirements", "text_sha256": "c", "status": "in_force"}]
        new = [dict(old[0], text_sha256="a2"), dict(old[1], own_text="An officer may issue a visa if", text_sha256="b2"),
               dict(old[2])]
        cmap = {"rows": [{"document_type": "SUBMISSION-LETTER", "visa_code": "PR-PNP-BASE", "provision_key": "IRPR 70(1)(e)",
                          "reviewed_text_sha256": "c"}]}
        rv = lf.review(old, new, cmap, "IRPR")
        self.assertEqual(rv["cited_touched"], [])
        self.assertEqual(rv["cited_lead_in_changed"], [["IRPR 70(1)(e)", "IRPR 70(1)"]])
        self.assertEqual(rv["signed_rows_stale"], [])   # its own hash holds, the lead-in list is where it shows

    def test_signed_rows_of_the_other_instrument_are_not_judged(self):
        """Review 2026-11-19: an IRPR reload must not call every signed IRPA row stale."""
        old = [{"key": "IRPR 74", "instrument": "IRPR", "section": "74", "level": "section", "ord": 1, "text_sha256": "c",
                "status": "in_force"}]
        cmap = {"rows": [{"document_type": "SUBMISSION-LETTER", "visa_code": "TR-VISIT", "provision_key": "IRPA 11(1)",
                          "reviewed_text_sha256": "x"}]}
        self.assertEqual(lf.review(old, [dict(old[0])], cmap, "IRPR")["signed_rows_stale"], [])

    def test_units_added_inside_an_existing_section_are_not_new_sections(self):
        old = [{"key": "IRPR 25.1", "instrument": "IRPR", "section": "25.1", "level": "section", "ord": 1, "text_sha256": "a",
                "status": "in_force"}]
        new = [dict(old[0], text_sha256="a2"),
               {"key": "IRPR 25.1(5.1)", "instrument": "IRPR", "section": "25.1", "level": "subsection", "parent_key": "IRPR 25.1",
                "ord": 2, "text_sha256": "b", "status": "in_force"}]
        rv = lf.review(old, new, {"rows": []}, "IRPR")
        self.assertEqual((rv["new_sections"], rv["added_inside_existing"]), ([], ["IRPR 25.1(5.1)"]))

    def test_a_changed_xml_runs_the_review_and_lists_new_pending_amendments(self):
        """End to end on the committed IRPR index: an XML that differs from the pin is parsed and diffed. Here it is the
        committed file's own source, so nothing differs but the pin, which proves the path without the network."""
        import json
        with open(os.path.join(ROOT, "law", "manifest.json"), encoding="utf-8") as f:
            real = json.load(f)
        irpr = next(i for i in real["instruments"] if i["instrument"] == "IRPR")
        stale = {"instruments": [dict(manifest()["instruments"][0]),
                                 dict(irpr, source_sha256="0" * 64, related_or_not_in_force=[])]}
        keep = os.environ.get("LAW_XML_DIR")
        if not keep or not os.path.exists(os.path.join(keep, "IRPR.xml")):
            self.skipTest("set LAW_XML_DIR to a folder with the IRPR.xml the committed index was built from")
        with open(os.path.join(keep, "IRPR.xml"), "rb") as f:
            data = f.read()
        res = lf.check(stale, {"rows": []}, get=getter(irpr=data))
        self.assertEqual(res["exit"], 1)
        rv = res["instruments"]["IRPR"]["review"]
        self.assertEqual((rv["added"], rv["changed"], rv["removed"]), ([], [], []))
        self.assertEqual(res["instruments"]["IRPR"]["pending_new"], irpr["related_or_not_in_force"])

    def test_the_cli_refuses_a_keep_folder_inside_the_repo(self):
        self.assertEqual(lf.main(["check", "--keep", os.path.join(ROOT, "law_tmp")]), 3)
        self.assertTrue(lf.inside_repo(ROOT))
        self.assertTrue(lf.inside_repo(os.path.join(ROOT, "law", "..", "law_tmp")))
        if os.name == "nt":   # case and separators do not open a way into the repo on Windows
            self.assertTrue(lf.inside_repo(ROOT.upper().replace("\\", "/") + "/law_tmp"))
        self.assertFalse(lf.inside_repo(os.path.dirname(ROOT)))

    def test_an_unexpected_error_is_exit_3_never_the_reload_code(self):
        import tempfile
        saved = lf.fetch
        lf.fetch = lambda url, timeout=120: (_ for _ in ()).throw(RuntimeError("boom"))
        try:
            with tempfile.TemporaryDirectory() as d:
                self.assertEqual(lf.main(["check", "--report", d]), 3)
        finally:
            lf.fetch = saved


if __name__ == "__main__":
    unittest.main()
