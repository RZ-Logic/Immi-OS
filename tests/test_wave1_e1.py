"""Wave 1 audit rules from the 2026-10-31 bug sweep, all under check E (fix IDs X-41.x): E19 IML written as text (The
Closer, H3), E20 text into an Airtable attachment field (Signed Contracts, H4) and E21 a Gmail search trigger that also
reads the account's Sent mail (Signed Contracts, M4). Synthetic fixtures shaped like the live modules. No network.
"""

import collections
import glob
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import audit_blueprints as ab  # noqa: E402

FILES = "tblSFR7Sg8uh8noO2"
ATTACH = "fld27JuPDFYTr2nBD"   # Files: Attachment (multipleAttachments)
RELATED = "fldUXWU5O4mPbvhGU"  # Files: Related Applicant (link)
DOCUMENT = "fldKGrlvT0PWwZXQm"  # Files: Document (text)
LINKS = ab.load_links(ab.DEFAULT_LINKS, required=True)
FOLDER = "1gkPgPWhXv6xFUIInItcQFQSsEhxIW3UM"  # the Drive folder ID in the committed Closer blueprint, not a secret


def bp(*flow, sid="1"):
    return ab.Blueprint(name="S", scenario_id=sid, source="test", bp={"name": "S", "flow": list(flow), "metadata": {}})


def rows(b, code, status=None):
    return [f for f in ab.check_e(b, LINKS, ab.Allowlist()) if f.rule == code and (status is None or f.status == status)]


def watch(mid=4):
    return {"id": mid, "module": "airtable:TriggerWatchRecords", "parameters": {"table": ab.LEAD_TABLE}}


def doc(mid=5, **mapper):
    return {"id": mid, "module": "google-docs:createADocumentFromTemplate", "mapper": mapper}


def gmail_trigger(q, filter_type="gmailSearch", mid=1):
    params = {"limit": 10, "markSeen": False, "filterType": filter_type}
    if q is not None:
        params["q"] = q
    return {"id": mid, "module": "google-email:triggerWatchNewEmails", "parameters": params}


ATTACH_SPEC = {"name": ATTACH, "type": "array", "label": "Attachment",
               "spec": [{"name": "url", "type": "text", "label": "File URL"}, {"name": "filename", "type": "filename", "label": "File name"}]}
RELATED_SPEC = {"name": RELATED, "type": "array", "label": "Related Applicant", "spec": {"name": "value", "label": "Record ID"}}
DOCUMENT_SPEC = {"name": DOCUMENT, "type": "text", "label": "Document"}


def files_write(mid=9, record=None, module="airtable:ActionCreateRecord", expect=True):
    m = {"id": mid, "module": module, "mapper": {"base": "app", "table": FILES, "record": record or {}}}
    if expect:
        m["metadata"] = {"expect": [{"name": "table", "type": "select"},
                                    {"name": "record", "type": "collection", "spec": [ATTACH_SPEC, RELATED_SPEC, DOCUMENT_SPEC]}]}
    return m


def upload(mid=3, iface=None):
    m = {"id": mid, "module": "google-drive:uploadAFile", "mapper": {"data": "{{6.data}}"}}
    if iface is not None:
        m["metadata"] = {"interface": iface}
    return m


# ---------------------------------------------------------------------------
# E19 IML written as text
# ---------------------------------------------------------------------------


class E19ImlAsTextTests(unittest.TestCase):
    def test_closer_date_outside_braces_fails(self):
        """H3: 3974028 module 5 requests.Date = formatDate({{4.`Last Modified`}}; "MMMM D, YYYY")."""
        b = bp(watch(), doc(requests={"Date": 'formatDate({{4.`Last Modified`}}; "MMMM D, YYYY")'}))
        fail = rows(b, "E19", ab.FAIL)
        self.assertEqual([f.module_id for f in fail], [5])
        self.assertIn("mapper.requests.Date holds formatDate( ... ) outside", fail[0].detail)
        self.assertTrue(fail[0].detail.startswith("E19 "))

    def test_closer_triple_quoted_fallback_fails(self):
        b = bp(watch(), doc(folderId='{{ifempty(4.`Drive Folder ID`; """' + FOLDER + '""")}}'))
        fail = rows(b, "E19", ab.FAIL)
        self.assertEqual([f.module_id for f in fail], [5])
        self.assertIn("mapper.folderId holds a string literal wrapped in quote characters", fail[0].detail)

    def test_both_subtests_give_two_rows(self):
        b = bp(watch(), doc(requests={"Date": 'formatDate({{4.`Last Modified`}}; "MMMM D, YYYY")'},
                            folderId='{{ifempty(4.`Drive Folder ID`; """' + FOLDER + '""")}}'))
        self.assertEqual(len(rows(b, "E19", ab.FAIL)), 2)

    def test_designed_fix_passes(self):
        b = bp(watch(), doc(requests={"Date": '{{formatDate(4.`Last Modified`; "MMMM D, YYYY"; "America/Toronto")}}'},
                            folderId='/{{ifempty(4.`Drive Folder ID`; "' + FOLDER + '")}}'))
        self.assertEqual(rows(b, "E19"), [])

    def test_single_quote_literal_passes(self):
        """A replace that strips quote characters uses a literal of four quotes, which is one quote, not a wrapped value."""
        b = bp(watch(), doc(name='{{replace(4.Name; """"; "\'")}}'))
        self.assertEqual(rows(b, "E19"), [])

    def test_prose_passes(self):
        for text in ("Sign it if (you agree) {{4.Name}}", "Call me (if needed), {{4.Name}}", "trim(x) then {{4.Name}}",
                     "bitmap({{4.Name}})", "obj.map({{4.Name}})", "formatDate(now) with no mapping"):
            with self.subTest(text=text):
                self.assertEqual(rows(bp(watch(), doc(body=text)), "E19"), [])

    def test_nested_call_outside_braces_fails(self):
        b = bp(watch(), doc(body='upper(formatDate({{4.x}}; "D"))'))
        self.assertEqual(len(rows(b, "E19", ab.FAIL)), 1)

    def test_unclosed_call_at_end_fails(self):
        b = bp(watch(), doc(body="Total: round({{4.Fee}}"))
        self.assertEqual(len(rows(b, "E19", ab.FAIL)), 1)

    def test_filter_parameters_and_error_route_are_covered(self):
        filtered = dict(doc(6), filter={"name": "f", "conditions": [[{"a": "lower({{4.Status}})", "o": "text:equal", "b": "x"}]]})
        params = {"id": 7, "module": "http:MakeRequest", "parameters": {"q": '{{ifempty(4.a; """b""")}}'}}
        handler = doc(8, body="trim({{4.Name}})")
        owner = dict(doc(9), onerror=[handler, {"id": 10, "module": "builtin:Ignore"}])
        got = sorted(f.module_id for f in rows(bp(watch(), filtered, params, owner), "E19", ab.FAIL))
        self.assertEqual(got, [6, 7, 8])

    def test_not_allowlistable(self):
        self.assertNotIn("E19", ab.ALLOW_RULES)


# ---------------------------------------------------------------------------
# E20 text into an attachment field
# ---------------------------------------------------------------------------


class E20AttachmentFieldTests(unittest.TestCase):
    def test_signed_contracts_web_view_link_fails(self):
        """H4: 3974254 module 9 maps {{3.webViewLink}} into Attachment."""
        b = bp(upload(), files_write(record={ATTACH: "{{3.webViewLink}}", RELATED: "{{7.id}}", DOCUMENT: "Signed Contract"}))
        fail = rows(b, "E20", ab.FAIL)
        self.assertEqual([f.module_id for f in fail], [9])
        self.assertIn(f"Field Attachment ({ATTACH}) is an attachment field", fail[0].detail)
        self.assertIn("airtable:uploadAnAttachment", fail[0].detail)

    def test_designed_fix_passes(self):
        """The candidate drops the key from 9 and uploads the PDF with airtable:uploadAnAttachment."""
        up = {"id": 40, "module": "airtable:uploadAnAttachment", "mapper": {"table": FILES, "id": "{{9.id}}", "columnId": ATTACH,
                                                                             "data": "{{6.data}}"}}
        b = bp(upload(), files_write(record={RELATED: "{{7.id}}", DOCUMENT: "Signed Contract"}), up)
        self.assertEqual(rows(b, "E20"), [])

    def test_text_and_literal_values_fail(self):
        for v in ("https://drive/{{3.id}}", "https://example.com/a.pdf", "{{3.name}} {{3.id}}", "{{ifempty(3.a; 3.b)}}"):
            with self.subTest(v=v):
                self.assertEqual(len(rows(bp(upload(), files_write(record={ATTACH: v})), "E20", ab.FAIL)), 1)

    def test_array_functions_pass(self):
        for v in ('{{map(3.files; "url")}}', "{{emptyarray}}", "{{ flatten(3.a) }}", "{{add(emptyarray; 3.a)}}", "{{toArray(3.a)}}"):
            with self.subTest(v=v):
                self.assertEqual(rows(bp(upload(), files_write(record={ATTACH: v})), "E20"), [])

    def test_bare_reference_to_interface_array_passes(self):
        src = upload(iface=[{"name": "Attachment", "type": "array", "spec": []}, {"name": "webViewLink", "type": "url"}])
        self.assertEqual(rows(bp(src, files_write(record={ATTACH: "{{3.Attachment}}"})), "E20"), [])
        self.assertEqual(len(rows(bp(src, files_write(record={ATTACH: "{{3.webViewLink}}"})), "E20", ab.FAIL)), 1)

    def test_bare_reference_without_interface_fails(self):
        self.assertEqual(len(rows(bp(upload(), files_write(record={ATTACH: "{{3.Attachment}}"})), "E20", ab.FAIL)), 1)

    def test_skips(self):
        cases = {"json list": files_write(record={ATTACH: [{"url": "{{3.url}}", "filename": "a.pdf"}]}),
                 "empty": files_write(record={ATTACH: ""}),
                 "no expect": files_write(record={ATTACH: "{{3.webViewLink}}"}, expect=False),
                 "link field": files_write(record={RELATED: "{{7.id}}"}),
                 "text field": files_write(record={DOCUMENT: "{{3.webViewLink}}"})}
        for name, m in cases.items():
            with self.subTest(name=name):
                self.assertEqual(rows(bp(upload(), m), "E20"), [])

    def test_update_and_error_route_are_covered(self):
        upd = files_write(11, {ATTACH: "{{3.webViewLink}}"}, module="airtable:ActionUpdateRecords")
        owner = dict(upload(12), onerror=[files_write(13, {ATTACH: "{{3.webViewLink}}"}), {"id": 14, "module": "builtin:Ignore"}])
        got = sorted(f.module_id for f in rows(bp(upload(), upd, owner), "E20", ab.FAIL))
        self.assertEqual(got, [11, 13])

    def test_not_allowlistable(self):
        self.assertNotIn("E20", ab.ALLOW_RULES)


# ---------------------------------------------------------------------------
# E21 Gmail search trigger reads Sent mail
# ---------------------------------------------------------------------------


class E21GmailSentMailTests(unittest.TestCase):
    LIVE_Q = "has:attachment filename:pdf subject:(retainer OR contract OR agreement OR signed)"

    def test_signed_contracts_query_fails(self):
        """M4: 3974254 trigger 1 has no -from:me, so it picks up The Closer's own retainer."""
        fail = rows(bp(gmail_trigger(self.LIVE_Q)), "E21", ab.FAIL)
        self.assertEqual([f.module_id for f in fail], [1])
        self.assertIn("Add -from:me", fail[0].detail)

    def test_designed_fix_passes(self):
        self.assertEqual(rows(bp(gmail_trigger(self.LIVE_Q + " -from:me")), "E21"), [])

    def test_live_passing_queries_and_other_exclusions(self):
        for q in ("-has:attachment -from:me -subject:(retainer OR contract OR agreement OR signed)",
                  'subject:("my visa" OR "any update") -from:me -has:attachment', "has:attachment -in:sent",
                  "has:attachment -label:sent", "has:attachment (-from:me)", "HAS:ATTACHMENT -FROM:ME"):
            with self.subTest(q=q):
                self.assertEqual(rows(bp(gmail_trigger(q)), "E21"), [])

    def test_near_misses_fail(self):
        for q in ("has:attachment from:me", "has:attachment in:inbox", "has:attachment -from:meg@example.com",
                  "has:attachment x-from:me", "", None):
            with self.subTest(q=q):
                self.assertEqual(len(rows(bp(gmail_trigger(q)), "E21", ab.FAIL)), 1)

    def test_skips(self):
        self.assertEqual(rows(bp(gmail_trigger(self.LIVE_Q, filter_type="folder")), "E21"), [])
        later = gmail_trigger(self.LIVE_Q, mid=2)
        self.assertEqual(rows(bp(watch(1), later), "E21"), [])  # only the first module is the trigger

    def test_not_allowlistable(self):
        self.assertNotIn("E21", ab.ALLOW_RULES)


# ---------------------------------------------------------------------------
# The committed snapshots
# ---------------------------------------------------------------------------


class SnapshotRowsTests(unittest.TestCase):
    """E19, E20 and E21 on blueprints/ (pulled before X-41.11 and X-41.12) raise exactly the rows the sweep names: two E19
    rows on The Closer 5 (date and folder), E20 on Signed Contracts 9 and E21 on Signed Contracts 1. A push that closes
    one updates EXPECTED in the same commit as its pull."""

    EXPECTED: collections.Counter = collections.Counter()  # X-41.11 and X-41.12 (2026-10-31) closed every row

    def test_exact_rows_on_live_snapshots(self):
        files = sorted(glob.glob(os.path.join(ROOT, "blueprints", "*__*.json")))
        if not files:
            self.skipTest("no committed snapshots")
        got = collections.Counter()
        for path in files:
            b = ab._load_blueprint_file(path)
            for f in ab.check_e(b, LINKS, ab.Allowlist()):
                if f.rule in ("E19", "E20", "E21") and f.status != ab.PASS:
                    got[(f.rule, str(b.scenario_id), f.module_id, f.status)] += 1
                    self.assertNotIn(";", f.detail)  # report prose carries no semicolons
                    self.assertNotIn("—", f.detail)
        self.assertEqual(got, self.EXPECTED)


if __name__ == "__main__":
    unittest.main()
