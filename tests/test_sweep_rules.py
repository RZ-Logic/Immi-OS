"""Audit rules from the 2026-10-30 bug sweep (docs/IMMIOS_BUG_SWEEP_2026-10-30.md), all under check E (fix IDs X-41.x):
the E5 extension (count tests that an empty search bundle defeats, B1 and H1), E12 self-retrigger of an Airtable watch
trigger (B3), E13 HeyGen output paths (B2) and E14 the phone format gate in front of a Bland call (H5). Synthetic
fixtures shaped like the live modules. No network.
"""

import glob
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import audit_blueprints as ab  # noqa: E402

LEAD = ab.LEAD_TABLE
FILES = "tblSFR7Sg8uh8noO2"
CAMPAIGN = "tbl0IzlSUYDdZIcxZ"
VIDEO_SENT = "fld3mvCpdEujuCyyi"   # Files: Approval Video Sent (checkbox)
FILE_STATUS = "fldZDjNz7CpX5SYnS"  # Files: File Status
PAY_STATUS = "fldqpWCzawUrtO5YA"   # Applicants: Payment Status
MOCK_STATUS = "fldYSv9WR2uwFZxVa"  # Applicants: Mock Interview Status
LINKS = ab.load_links(ab.DEFAULT_LINKS, required=True)


def bp(*flow, sid="1"):
    return ab.Blueprint(name="S", scenario_id=sid, source="test", bp={"name": "S", "flow": list(flow), "metadata": {}})


def rows(b, code, status=None):
    return [f for f in ab.check_e(b, LINKS, ab.Allowlist()) if f.rule == code and (status is None or f.status == status)]


def mail_trigger(mid=1):
    return {"id": mid, "module": "google-email:triggerWatchNewEmails", "parameters": {"limit": 1}}


def search(mid, table=FILES):
    return {"id": mid, "module": "airtable:ActionSearchRecords", "mapper": {"table": table, "formula": "{Client Email} = 'x'"}}


def agg(mid, feeder):
    return {"id": mid, "module": "builtin:BasicAggregator", "parameters": {"feeder": feeder}, "mapper": {"id": f"{{{{{feeder}.id}}}}"}}


def slack(mid, text="x"):
    return {"id": mid, "module": "slack:CreateMessage", "mapper": {"text": text}}


def filt(m, conditions, name="f"):
    m = dict(m)
    m["filter"] = {"name": name, "conditions": conditions}
    return m


def router(mid, *routes):
    return {"id": mid, "module": "builtin:BasicRouter", "routes": [{"flow": list(r)} for r in routes]}


def cond(a, op, b=None):
    c = {"a": a, "o": op}
    if b is not None:
        c["b"] = b
    return [[c]]


# ---------------------------------------------------------------------------
# E5 extension
# ---------------------------------------------------------------------------


class E5CountTests(unittest.TestCase):
    def test_vip_intake_length_equal_zero_fails_with_first_id_fix(self):
        """B1: 3920821 module 81, {{length(70.array)}} = 0 after search 11 and aggregator 70."""
        b = bp(mail_trigger(), search(11, LEAD), agg(70, 11), filt(slack(81), cond("{{length(70.array)}}", "number:equal", "0"), "Is New Lead?"))
        fail = rows(b, "E5", ab.FAIL)
        self.assertEqual([f.module_id for f in fail], [81])
        self.assertIn("first of map over 70.array with the key id", fail[0].detail)
        self.assertIn("one empty bundle", fail[0].detail)

    def test_length_comparisons_that_cannot_tell_0_hits_from_1_fail(self):
        """0 hits read 0 or 1 (the empty bundle), 1 hit reads 1, so a comparison that answers differently at 0 and 1 fails."""
        for op, lit in (("number:equal", "0"), ("number:notequal", "0"), ("number:equal", "1"), ("number:notequal", "1"),
                        ("number:greater", "0"), ("number:greaterorequal", "1"), ("number:less", "1"),
                        ("number:lessorequal", "0"), ("text:equal", "0")):
            b = bp(mail_trigger(), search(11), agg(111, 11), filt(slack(5), cond("{{length(111.array)}}", op, lit)))
            self.assertEqual([f.module_id for f in rows(b, "E5", ab.FAIL)], [5], (op, lit))

    def test_length_comparisons_that_answer_the_same_at_0_and_1_pass(self):
        """The duplicate test {{length(70.array)}} > 1 behind search 11 is sound: 0 hits and 1 hit both read at most 1."""
        for op, lit in (("number:greater", "1"), ("number:greaterorequal", "2"), ("number:less", "2"),
                        ("number:lessorequal", "1"), ("number:equal", "2")):
            b = bp(mail_trigger(), search(11, LEAD), agg(70, 11), filt(slack(81), cond("{{length(70.array)}}", op, lit)))
            self.assertEqual(rows(b, "E5"), [], (op, lit))

    def test_length_of_an_aggregator_fed_by_an_iterator_passes(self):
        it = {"id": 69, "module": "builtin:BasicFeeder", "mapper": {"array": "{{1.attachments}}"}}
        for lit in ("0", "2"):
            b = bp(mail_trigger(), it, agg(70, 69), filt(slack(81), cond("{{length(70.array)}}", "number:greater", lit)))
            self.assertEqual(rows(b, "E5"), [], lit)

    def test_literal_on_the_left_also_fails(self):
        b = bp(mail_trigger(), search(11), agg(111, 11), filt(slack(5), [[{"a": "0", "b": "{{length(111.array)}}", "o": "number:less"}]]))
        self.assertEqual(len(rows(b, "E5", ab.FAIL)), 1)
        b = bp(mail_trigger(), search(11), agg(111, 11), filt(slack(5), [[{"a": "1", "b": "{{length(111.array)}}", "o": "number:less"}]]))
        self.assertEqual(rows(b, "E5"), [])  # 1 < length is length > 1, the sound duplicate test
        b = bp(mail_trigger(), search(2), filt(slack(3), [[{"a": "1", "b": "{{2.`__IMTLENGTH__`}}", "o": "number:greater"}]]))
        self.assertEqual(len(rows(b, "E5", ab.FAIL)), 1)  # 1 > count is a not-found test the zero-count rule does not mirror

    def test_support_bot_router_shapes_fail(self):
        """H1: 3954492 filters 5 (> 0) and 7 (<= 0) on length(111.array), 135 and 138 on 5.__IMTLENGTH__ > 0."""
        count = "{{50.`__IMTLENGTH__`}}"
        b = bp(mail_trigger(), search(110), agg(111, 110),
               router(112, [filt(slack(5), cond("{{length(111.array)}}", "number:greater", "0"))],
                      [filt(slack(7), cond("{{length(111.array)}}", "number:lessorequal", "0"))]),
               search(50),
               router(6, [filt(slack(135), cond(count, "number:greater", "0"))],
                      [filt(slack(138), cond(count, "number:greater", "0"))]))
        fail = rows(b, "E5", ab.FAIL)
        self.assertEqual(sorted(f.module_id for f in fail), [5, 7])
        self.assertIn("first record ID of aggregator 111", {f.module_id: f.detail for f in fail}[7])
        review = rows(b, "E5", ab.REVIEW)
        self.assertEqual(sorted(f.module_id for f in review), [135, 138])
        self.assertIn("prefer {{50.id}} exists", review[0].detail)

    def test_count_not_found_forms_fail_and_found_forms_do_not(self):
        """A bundle count reads 0 only on the empty bundle, which a search emits only under a hidden option. A condition
        true at 0 is a not-found test and fails. count > 0 and >= 1 are found tests (REVIEW), count > 1 is sound."""
        count = "{{2.`__IMTLENGTH__`}}"
        for op, lit in (("number:notequal", "1"), ("number:less", "2"), ("number:lessorequal", "1")):
            b = bp(mail_trigger(), search(2), filt(slack(3), cond(count, op, lit)))
            fail = rows(b, "E5", ab.FAIL)
            self.assertEqual([f.module_id for f in fail], [3], (op, lit))
            self.assertIn("true at a bundle count of 0", fail[0].detail)
        for op, lit in (("number:greater", "0"), ("number:greaterorequal", "1"), ("number:notequal", "0")):
            b = bp(mail_trigger(), search(2), filt(slack(3), cond(count, op, lit)))
            self.assertEqual([(f.status, f.module_id) for f in rows(b, "E5")], [(ab.REVIEW, 3)], (op, lit))
        b = bp(mail_trigger(), search(2), filt(slack(3), cond(count, "number:greater", "1")))
        self.assertEqual(rows(b, "E5"), [])

    def test_existing_zero_count_row_is_not_repeated(self):
        b = bp(mail_trigger(), search(2), filt(slack(3), cond("{{2.`__IMTLENGTH__`}}", "number:equal", "0")))
        fail = rows(b, "E5", ab.FAIL)
        self.assertEqual(len(fail), 1)
        self.assertIn("never fires", fail[0].detail)

    def test_first_id_and_search_id_forms_pass(self):
        flows = (
            [mail_trigger(), search(11), agg(70, 11), filt(slack(81), cond('{{first(map(70.array; "id"))}}', "notexist"))],
            [mail_trigger(), search(11), agg(70, 11), filt(slack(81), cond('{{first(map(70.array; "id"))}}', "exist"))],
            [mail_trigger(), search(5), filt(slack(135), cond("{{5.id}}", "exist"))],
        )
        for flow in flows:
            self.assertEqual(rows(bp(*flow), "E5"), [], flow[-1]["filter"])

    def test_length_of_a_non_aggregator_or_a_body_array_passes(self):
        """Financial Guardrail 74 tests length(70.body.data) of a Stripe call. That is not an aggregator array."""
        stripe = {"id": 70, "module": "stripe:makeAnApiCall", "mapper": {"url": "/v1/invoices"}}
        b = bp(mail_trigger(), stripe, filt(slack(74), cond("{{length(70.body.data)}}", "number:greater", "0")))
        self.assertEqual(rows(b, "E5"), [])
        b = bp(mail_trigger(), slack(70), filt(slack(74), cond("{{length(70.array)}}", "number:greater", "0")))
        self.assertEqual(rows(b, "E5"), [])

    def test_count_of_a_search_that_is_not_upstream_passes(self):
        b = bp(mail_trigger(), router(3, [search(2)], [filt(slack(4), cond("{{2.`__IMTLENGTH__`}}", "number:greater", "0"))]))
        self.assertEqual(rows(b, "E5"), [])


# ---------------------------------------------------------------------------
# E12 self-retrigger
# ---------------------------------------------------------------------------


def watch(table=FILES, formula='{File Status} = "Approved"', trigger_field="Last Modified", mid=1):
    return {"id": mid, "module": ab.WATCH_TRIGGER,
            "parameters": {"table": table, "formula": formula, "config": {"triggerField": trigger_field, "labelField": "x"}}}


def update(mid, table, rid, record):
    return {"id": mid, "module": "airtable:ActionUpdateRecords", "mapper": {"table": table, "id": rid, "record": record}}


class E12SelfRetriggerTests(unittest.TestCase):
    def test_auto_celebrate_shape_fails_on_the_trigger(self):
        """B3: 5091060 module 27 writes Approval Video Sent on {{1.id}}, the formula is only {File Status} = "Approved"."""
        b = bp(watch(), slack(7), update(27, FILES, "{{1.id}}", {VIDEO_SENT: True}))
        fail = rows(b, "E12", ab.FAIL)
        self.assertEqual([f.module_id for f in fail], [1])
        self.assertIn("module 27 writes Approval Video Sent", fail[0].detail)
        self.assertIn("NOT({<field>})", fail[0].detail)

    def test_excluding_clauses_pass(self):
        for formula in ('AND({File Status} = "Approved", NOT({Approval Video Sent}))',
                        "AND({File Status} = 'Approved', {Approval Video Sent} = BLANK())",
                        "AND({File Status} = 'Approved', {Approval Video Sent} = FALSE())",
                        "AND(NOT({Approval Video Sent}), {File Status} = 'Approved')",
                        "AND({File Status} = 'Approved', BLANK() = {Approval Video Sent})"):
            b = bp(watch(formula=formula), update(27, FILES, "{{1.id}}", {VIDEO_SENT: True}))
            self.assertEqual(rows(b, "E12"), [], formula)

    def test_not_equal_the_written_value_passes_and_another_value_fails(self):
        f = "AND({File Status} = 'Approved', {Admin Note} != 'Celebrated')"
        note = "fld8irALOJwNDKu7N"
        self.assertEqual(rows(bp(watch(formula=f), update(9, FILES, "{{1.id}}", {note: "Celebrated"})), "E12"), [])
        self.assertEqual(len(rows(bp(watch(formula=f), update(9, FILES, "{{1.id}}", {note: "Other"})), "E12", ab.FAIL)), 1)

    def test_clause_inside_an_or_or_a_mapped_value_does_not_exclude(self):
        b = bp(watch(formula="OR({File Status} = 'Approved', NOT({Approval Video Sent}))"),
               update(27, FILES, "{{1.id}}", {VIDEO_SENT: True}))
        self.assertEqual(len(rows(b, "E12", ab.FAIL)), 1)
        b = bp(watch(formula="AND({File Status} = 'Approved', NOT({Approval Video Sent}))"),
               update(27, FILES, "{{1.id}}", {VIDEO_SENT: "{{6.data.status}}"}))
        self.assertEqual(len(rows(b, "E12", ab.FAIL)), 1)

    def test_writing_the_watched_status_away_passes(self):
        """Disqualified 5089451 and Financial Guardrail 3975479: the write moves the row out of the formula."""
        b = bp(watch(LEAD, '{Status} = "Disqualified"'),
               update(3, LEAD, "{{1.id}}", {ab.STATUS_FIELD: "Disqualified - Rejection Sent"}))
        self.assertEqual(rows(b, "E12"), [])
        guard = ("OR({Status} = 'Ready for Submission', AND({Status} = 'LOCKED - Payment Required', "
                 "{Payment Status} = 'Paid in Full'))")
        b = bp(watch(LEAD, guard),
               update(3, LEAD, "{{1.id}}", {ab.STATUS_FIELD: "LOCKED - Payment Required", PAY_STATUS: "Partial"}),
               update(4, LEAD, "{{1.id}}", {ab.STATUS_FIELD: "Payment Verified - Ready", PAY_STATUS: "Paid in Full"}))
        self.assertEqual(rows(b, "E12"), [])
        b = bp(watch(LEAD, guard), update(4, LEAD, "{{1.id}}", {ab.STATUS_FIELD: "Ready for Submission"}))
        self.assertEqual(len(rows(b, "E12", ab.FAIL)), 1)

    def test_other_record_other_table_and_created_time_pass(self):
        f = '{File Status} = "Approved"'
        self.assertEqual(rows(bp(watch(formula=f), update(27, FILES, "{{3.id}}", {VIDEO_SENT: True})), "E12"), [])
        self.assertEqual(rows(bp(watch(formula=f), update(27, LEAD, "{{1.id}}", {MOCK_STATUS: "x"})), "E12"), [])
        b = bp(watch(LEAD, "", "Created Time", mid=2), update(6, LEAD, "{{2.id}}", {ab.STATUS_FIELD: "VIP"}))
        self.assertEqual(rows(b, "E12"), [])

    def test_mapped_value_with_literal_outputs_is_evaluated_per_combination(self):
        """L4: Financial Guardrail lock 3 writes Status LOCKED and Payment Status if(...; "Partial"; "Unpaid"). Neither
        output can match the trigger formula, so no row. A mapped output that can match still fails."""
        guard = ("OR({Status} = 'Ready for Submission', AND({Status} = 'LOCKED - Payment Required', "
                 "{Payment Status} = 'Paid in Full'))")
        pay = '{{if(ifempty(1.`Amount Paid`; 0) > 0; "Partial"; "Unpaid")}}'
        b = bp(watch(LEAD, guard), update(3, LEAD, "{{1.id}}", {ab.STATUS_FIELD: "LOCKED - Payment Required", PAY_STATUS: pay}))
        self.assertEqual(rows(b, "E12"), [])
        pay = '{{if(1.x; "Paid in Full"; "Unpaid")}}'
        b = bp(watch(LEAD, guard), update(3, LEAD, "{{1.id}}", {ab.STATUS_FIELD: "LOCKED - Payment Required", PAY_STATUS: pay}))
        self.assertEqual(len(rows(b, "E12", ab.FAIL)), 1)
        status = '{{if(1.x; "Ready for Submission"; "LOCKED - Payment Required")}}'
        b = bp(watch(LEAD, guard), update(3, LEAD, "{{1.id}}", {ab.STATUS_FIELD: status, PAY_STATUS: "Unpaid"}))
        self.assertEqual(len(rows(b, "E12", ab.FAIL)), 1)

    def test_update_through_a_get_record_of_the_trigger_record_fails(self):
        """Get 3 reads {{1.id}} on the trigger table, update 27 writes {{3.id}}: the same loop as B3."""
        get = {"id": 3, "module": "airtable:ActionGetRecord", "mapper": {"table": FILES, "id": "{{1.id}}"}}
        get2 = {"id": 5, "module": "airtable:ActionGetRecord", "mapper": {"table": FILES, "id": "{{3.id}}"}}
        b = bp(watch(), get, update(27, FILES, "{{3.id}}", {VIDEO_SENT: True}))
        self.assertEqual([f.module_id for f in rows(b, "E12", ab.FAIL)], [1])
        b = bp(watch(), get, get2, update(27, FILES, "{{5.id}}", {VIDEO_SENT: True}))
        self.assertEqual([f.module_id for f in rows(b, "E12", ab.FAIL)], [1])
        other = {"id": 3, "module": "airtable:ActionGetRecord", "mapper": {"table": FILES, "id": "{{2.id}}"}}
        b = bp(watch(), other, update(27, FILES, "{{3.id}}", {VIDEO_SENT: True}))
        self.assertEqual(rows(b, "E12"), [])
        lead = {"id": 3, "module": "airtable:ActionGetRecord", "mapper": {"table": LEAD, "id": "{{1.id}}"}}
        b = bp(watch(), lead, update(27, FILES, "{{3.id}}", {VIDEO_SENT: True}))
        self.assertEqual(rows(b, "E12"), [])

    def test_trigger_with_another_module_id_and_an_empty_formula_fails(self):
        b = bp(watch(LEAD, "", mid=4), update(8, LEAD, "{{4.id}}", {ab.STATUS_FIELD: "x"}))
        fail = rows(b, "E12", ab.FAIL)
        self.assertEqual([f.module_id for f in fail], [4])

    def test_formula_evaluator(self):
        ex = ab.watch_formula_excludes
        self.assertTrue(ex("AND({A} = 'x', NOT({B}))", {"B": True}))
        self.assertFalse(ex("AND({A} = 'x', NOT({B}))", {"B": False}))
        self.assertFalse(ex("{A} = 'x'", {"B": True}))
        self.assertFalse(ex("", {"B": True}))
        self.assertFalse(ex("AND({A} = '{{1.x}}', NOT({B}))", {"B": True}))
        self.assertFalse(ex("AND(NOT({B}", {"B": True}))  # unparsable excludes nothing
        self.assertTrue(ex("AND({Mock Interview Status} = 'Ready to Call', {Phone} != '')", {"Mock Interview Status": "Calling"}))
        self.assertTrue(ex("{B} = TRUE()", {"B": False}))
        self.assertFalse(ex("{B} = 'Sent'", {"B": 3}))  # a text literal against a number is unknown


# ---------------------------------------------------------------------------
# E13 HeyGen outputs
# ---------------------------------------------------------------------------


def heygen_create(mid=4):
    return {"id": mid, "module": "heygen:createAnAvatarVideoV2", "version": 1, "mapper": {"title": "x"}}


def heygen_get(mid=6, feed="{{4.video_id}}", version=1):
    return {"id": mid, "module": "heygen:getVideo", "version": version, "mapper": {"video_id": feed}}


def gmail(mid, html):
    return {"id": mid, "module": "google-email:sendAnEmail", "mapper": {"contents": [{"text": html}]}}


class E13HeyGenTests(unittest.TestCase):
    def test_url_fails_and_names_the_real_path(self):
        """B2: Auto-Celebrate 5091060 module 7 maps {{6.url}} twice. One row per module and path."""
        b = bp(watch(), heygen_create(), heygen_get(), gmail(7, '<a href="{{6.url}}">Watch</a> or {{6.url}}'))
        fail = rows(b, "E13", ab.FAIL)
        self.assertEqual([f.module_id for f in fail], [7])
        self.assertIn("{{6.url}}", fail[0].detail)
        self.assertIn("data.video_url", fail[0].detail)
        self.assertIn("this reference maps empty", fail[0].detail)

    def test_data_video_url_and_other_outputs_pass(self):
        html = '<a href="{{6.data.video_url}}">Watch</a> {{6.data.status}} {{6.code}} {{6.message}} {{6.data.thumbnail_url}}'
        b = bp(watch(), heygen_create(), heygen_get(), gmail(7, html),
               filt(slack(8), cond("{{6.data.status}}", "text:equal", "completed")))
        self.assertEqual(rows(b, "E13"), [])

    def test_wrong_nested_field_and_extra_depth_fail(self):
        for ref in ("{{6.data.url}}", "{{6.data.video_url.href}}", "{{6.body.data.video_url}}", "{{4.id}}"):
            b = bp(watch(), heygen_create(), heygen_get(), gmail(7, ref))
            self.assertEqual(len(rows(b, "E13", ab.FAIL)), 1, ref)

    def test_error_references_in_handlers_and_strings_are_not_outputs(self):
        logger = {"id": 114, "module": "http:ActionSendData",
                  "mapper": {"urlEncodedBodyContent": [{"value": "{{6.error.type}}"}, {"value": "{{6.error.message}}"}]}}
        get = heygen_get()
        get["onerror"] = [logger, {"id": 115, "module": "builtin:Break"}]
        b = bp(watch(), heygen_create(), get, gmail(7, '{{replace("6.url"; "x"; "y")}}'))
        self.assertEqual(rows(b, "E13"), [])

    def test_dead_ifempty_first_argument_with_a_valid_fallback_is_review(self):
        """Support Bot 3954492 module 13 maps {{ifempty(14.body.data.video_url; 14.data.video_url)}}: the value comes from
        the second argument, so the link is right. REVIEW, not FAIL."""
        b = bp(watch(), heygen_create(), heygen_get(), gmail(7, "{{ifempty(6.body.data.video_url; 6.data.video_url)}}"))
        found = rows(b, "E13")
        self.assertEqual([(f.status, f.module_id) for f in found], [(ab.REVIEW, 7)])
        self.assertIn("dead first argument", found[0].detail)
        self.assertIn("{{6.data.video_url}}", found[0].detail)
        for html in ("{{ifempty(6.body.data.video_url; 6.data.url)}}", "{{ifempty(6.url; 4.video_id)}} {{6.url}}",
                     '{{ifempty(6.url; "x")}}', "{{ifempty(6.data.video_url; 6.url)}}"):
            b = bp(watch(), heygen_create(), heygen_get(), gmail(7, html))
            self.assertIn(ab.FAIL, [f.status for f in rows(b, "E13")], html)

    def test_unpinned_version_is_review(self):
        b = bp(watch(), heygen_create(), heygen_get(version=2), gmail(7, "{{6.data.video_url}}"))
        self.assertEqual([f.status for f in rows(b, "E13")], [ab.REVIEW])


# ---------------------------------------------------------------------------
# E14 Bland phone format gate
# ---------------------------------------------------------------------------

E164 = "^\\+[1-9][0-9]{7,14}$"


def bland(mid, phone="{{1.Phone}}"):
    return {"id": mid, "module": "bland:sendACall", "version": 1, "mapper": {"phone_number": phone, "task": "x"}}


def lead_update(mid, rid="{{1.id}}"):
    return update(mid, LEAD, rid, {ab.STATUS_FIELD: "Calling"})


def create(mid):
    return {"id": mid, "module": "airtable:ActionCreateRecord", "mapper": {"table": LEAD, "record": {ab.STATUS_FIELD: "VIP"}}}


class E14BlandPhoneGateTests(unittest.TestCase):
    def test_batch_shape_fails_on_the_search(self):
        """Batch Outbound Caller 3953105: search 1 on Status only, update 2 sets Calling, Bland 3 dials {{1.Phone}}. The
        gate belongs in the search formula, ahead of the Status write, so the row sits on 1."""
        b = bp({"id": 1, "module": "airtable:ActionSearchRecords",
                "mapper": {"table": LEAD, "formula": "{Status} = 'Pending Call'"}}, lead_update(2), bland(3))
        fail = rows(b, "E14", ab.FAIL)
        self.assertEqual([f.module_id for f in fail], [1])
        self.assertIn("Bland 3 dials {{1.Phone}}", fail[0].detail)
        self.assertIn("REGEX_MATCH({Phone}", fail[0].detail)

    def test_regex_match_in_the_search_or_trigger_formula_passes(self):
        f = "AND({Status} = 'Pending Call', REGEX_MATCH({Phone}, '^[+][1-9][0-9]{7,14}$'))"
        b = bp({"id": 1, "module": "airtable:ActionSearchRecords", "mapper": {"table": LEAD, "formula": f}}, lead_update(2), bland(3))
        self.assertEqual(rows(b, "E14"), [])
        b = bp(watch(LEAD, "AND({Mock Interview Status} = 'Ready to Call', REGEX_MATCH({Phone}, '^[+]1'))"), bland(2))
        self.assertEqual(rows(b, "E14"), [])
        b = bp(watch(LEAD, "AND({Mock Interview Status} = 'Ready to Call', {Phone} != '')"), bland(2))
        self.assertEqual([f.module_id for f in rows(b, "E14", ab.FAIL)], [1])  # The Interview Room (A) 3975140 shape

    def test_vip_shape_fails_on_the_call_and_a_pattern_filter_passes(self):
        """VIP 3920821: create 7 writes Status, Bland 10 dials {{7.Phone}}. A filter on a create is a Status-write change, so
        the gate is a text:pattern filter on 10 (X-41.2)."""
        b = bp(mail_trigger(), create(7), bland(10, "{{7.Phone}}"))
        self.assertEqual([f.module_id for f in rows(b, "E14", ab.FAIL)], [10])
        b = bp(mail_trigger(), create(7), filt(bland(10, "{{7.Phone}}"), cond("{{7.Phone}}", "text:pattern", E164)))
        self.assertEqual(rows(b, "E14"), [])
        b = bp(mail_trigger(), create(7), router(89, [filt(slack(9), cond("{{7.Phone}}", "text:pattern", E164)), bland(10, "{{7.Phone}}")],
                                                 [slack(90)]))
        self.assertEqual(rows(b, "E14"), [])  # the gate upstream on the route also counts

    def test_router_between_search_and_call_fails_on_the_call(self):
        """Campaign Launcher 3961751: search 3, router 6 splits the leads into a calling route and an email-only route. A
        formula gate on 3 would drop leads from the email route too, so the row sits on Bland 7 and asks for a filter
        (X-41.5). A REGEX_MATCH in the formula still passes."""
        def shape(formula, call):
            return bp(watch(), {"id": 3, "module": "airtable:ActionSearchRecords", "mapper": {"table": LEAD, "formula": formula}},
                      router(6, [filt(slack(9), cond("{{3.Phone}}", "text:startwith", "+1")), call], [slack(8)]))
        fail = rows(shape("{Blast Status} = 'Ready'", bland(7, "{{3.Phone}}")), "E14", ab.FAIL)
        self.assertEqual([f.module_id for f in fail], [7])
        self.assertIn("text:pattern", fail[0].detail)
        gated = filt(bland(7, "{{3.Phone}}"), cond("{{3.Phone}}", "text:pattern", "^\\+1[0-9]{10}$"))
        self.assertEqual(rows(shape("{Blast Status} = 'Ready'", gated), "E14"), [])
        f = "AND({Blast Status} = 'Ready', REGEX_MATCH({Phone}, '^[+]1[0-9]{10}$'))"
        self.assertEqual(rows(shape(f, bland(7, "{{3.Phone}}")), "E14"), [])

    def test_a_filter_on_another_value_or_operator_fails(self):
        for c in (cond("{{7.Email}}", "text:pattern", E164), cond("{{7.Phone}}", "exist"),
                  cond("{{7.Phone}}", "text:notpattern", E164)):
            b = bp(mail_trigger(), create(7), filt(bland(10, "{{7.Phone}}"), c))
            self.assertEqual([f.module_id for f in rows(b, "E14", ab.FAIL)], [10], c)

    def test_literal_number_and_error_route_calls_pass(self):
        self.assertEqual(rows(bp(mail_trigger(), bland(3, "+14165550199")), "E14"), [])
        s1 = slack(2)
        s1["onerror"] = [bland(3), {"id": 4, "module": "builtin:Ignore"}]
        self.assertEqual(rows(bp(mail_trigger(), s1), "E14"), [])


# ---------------------------------------------------------------------------
# E15 Watch Records trigger field
# ---------------------------------------------------------------------------


class E15TriggerFieldTests(unittest.TestCase):
    def test_interview_room_a_shape_fails_on_the_trigger(self):
        """The Interview Room (A) 3975140 before X-41.6: Last Modified tracks Status and Payment Status only."""
        b = bp(watch(LEAD, "{Mock Interview Status} = 'Ready to Call'", "Last Modified"), bland(2))
        fail = rows(b, "E15", ab.FAIL)
        self.assertEqual([f.module_id for f in fail], [1])
        self.assertIn("Mock Interview Status", fail[0].detail)

    def test_a_tracking_trigger_field_passes(self):
        self.assertEqual(rows(bp(watch(LEAD, "{Mock Interview Status} = 'Ready to Call'", "Mock Interview Modified"), bland(2)),
                              "E15"), [])
        f = "OR({Status} = 'Ready for Submission', AND({Status} = 'LOCKED - Payment Required', {Payment Status} = 'Paid in Full'))"
        self.assertEqual(rows(bp(watch(LEAD, f, "Last Modified"), slack(2)), "E15"), [])  # Financial Guardrail
        self.assertEqual(rows(bp(watch(FILES, 'AND({File Status} = "Approved", NOT({Approval Video Sent}))', "Last Modified"),
                                 slack(2)), "E15"), [])  # Files Last Modified tracks every field

    def test_the_trigger_field_itself_may_be_tested(self):
        f = "AND({Status} = 'Send Contract', IS_AFTER({Last Modified}, DATEADD(NOW(), -1, 'days')))"
        self.assertEqual(rows(bp(watch(LEAD, f, "Last Modified"), slack(2)), "E15"), [])

    def test_one_untracked_field_among_tracked_ones_fails(self):
        b = bp(watch(LEAD, "AND({Status} = 'Send Contract', {Email} != '')", "Last Modified"), slack(2))
        self.assertEqual([f.detail.split(",")[0] for f in rows(b, "E15", ab.FAIL)], ["E15 The formula tests Email"])

    def test_unpinned_trigger_field_is_review_and_created_time_is_skipped(self):
        self.assertEqual([f.status for f in rows(bp(watch(LEAD, "{Status} = 'VIP'", "Some New Field"), slack(2)), "E15")],
                         [ab.REVIEW])
        self.assertEqual(rows(bp(watch(LEAD, "{Status} = 'VIP'", "Created Time"), slack(2)), "E15"), [])
        self.assertEqual(rows(bp(watch(LEAD, "", "Last Modified"), slack(2)), "E15"), [])


# ---------------------------------------------------------------------------
# E16 client email claims, E17 Bland post-call webhook, E18 bulk lead search excludes Disqualified and Do Not Call
# ---------------------------------------------------------------------------


def lead_search(mid, formula, max_records="50"):
    return {"id": mid, "module": "airtable:ActionSearchRecords",
            "mapper": {"table": LEAD, "formula": formula, "maxRecords": max_records}}


class E16EmailClaimTests(unittest.TestCase):
    def test_nurture_shape_fails_twice(self):
        """Pending Call 3943741 module 14 before X-41.8: says a guide is attached, attaches nothing, promises a guarantee."""
        b = bp(mail_trigger(), gmail(14, "You need a higher score to guarantee an invitation.\nI have attached a free guide."))
        self.assertEqual(sorted(f.detail.split(" ")[1] for f in rows(b, "E16", ab.FAIL)), ["The", "The"])
        self.assertEqual(len(rows(b, "E16", ab.FAIL)), 2)

    def test_other_attachment_wordings_fail(self):
        for text in ("I have included a free guide as an attachment.", "I am attaching the checklist", "see the enclosure"):
            with self.subTest(text=text):
                self.assertEqual(len(rows(bp(mail_trigger(), gmail(14, text)), "E16", ab.FAIL)), 1)

    def test_real_attachment_and_plain_text_pass(self):
        m = gmail(8, "Please find the retainer attached.")
        m["mapper"]["attachments"] = [{"fileName": "x.pdf", "data": "{{5.data}}"}]
        self.assertEqual(rows(bp(mail_trigger(), m), "E16"), [])  # The Closer 8 shape
        self.assertEqual(rows(bp(mail_trigger(), gmail(14, "Here is your guide:\n{{20.text}}")), "E16"), [])

    def test_error_route_email_is_skipped(self):
        s1 = slack(2)
        s1["onerror"] = [gmail(3, "attached"), {"id": 4, "module": "builtin:Ignore"}]
        self.assertEqual(rows(bp(mail_trigger(), s1), "E16"), [])


class E17BlandWebhookTests(unittest.TestCase):
    def test_no_webhook_fails_and_a_webhook_passes(self):
        self.assertEqual([f.module_id for f in rows(bp(mail_trigger(), bland(10, "+14165550199")), "E17", ab.FAIL)], [10])
        m = bland(10, "+14165550199")
        m["mapper"]["webhook"] = "{{var.team.hook}}"
        self.assertEqual(rows(bp(mail_trigger(), m), "E17"), [])


class E18BulkSearchTests(unittest.TestCase):
    def test_campaign_shape_fails_once_on_the_search(self):
        """Campaign Launcher 3961751 search 3 before X-41.9 feeds emails 9 and 8 and Bland 7. One row, on the search."""
        s3 = lead_search(3, "AND({Industry} = '{{4.`Target Industry`}}', {Blast Status} = 'Ready')")
        b = bp(watch(CAMPAIGN, "{Status} = 'Active'", "Status Changed At", 2), s3,
               router(6, [gmail(9, "x"), bland(7, "{{3.Phone}}")], [gmail(8, "y")]))
        fail = rows(b, "E18", ab.FAIL)
        self.assertEqual([f.module_id for f in fail], [3])
        self.assertIn("Disqualified or Disqualified - Rejection Sent", fail[0].detail)

    def test_excluding_both_statuses_passes_with_mapped_values(self):
        f = ("AND(OR('{{4.`Target Industry`}}' = 'General', {Industry} = '{{4.`Target Industry`}}'), "
             "OR({Blast Status} = 'Ready', {Blast Status} = BLANK()), {Status} != 'Disqualified', "
             "{Status} != 'Disqualified - Rejection Sent', {Status} != 'Do Not Call', "
             "DATETIME_DIFF(NOW(), {Created Time}, 'days') <= 180)")
        self.assertEqual(rows(bp(watch(CAMPAIGN, "{Status} = 'Active'", "Status Changed At", 2), lead_search(3, f), gmail(9, "x")),
                              "E18"), [])

    def test_do_not_call_missing_fails(self):
        """D5 (2026-11-01): Campaign Launcher search 3 after X-41.9 excludes both Disqualified values but not Do Not Call."""
        f = ("AND(OR({Blast Status} = 'Ready', {Blast Status} = BLANK()), {Status} != 'Disqualified', "
             "{Status} != 'Disqualified - Rejection Sent')")
        fail = rows(bp(mail_trigger(), lead_search(3, f), gmail(9, "x")), "E18", ab.FAIL)
        self.assertEqual([f.module_id for f in fail], [3])
        self.assertIn("does not exclude Status Do Not Call,", fail[0].detail)

    def test_one_status_missing_still_fails(self):
        f = "AND({Blast Status} = 'Ready', {Status} != 'Disqualified')"
        fail = rows(bp(mail_trigger(), lead_search(3, f), gmail(9, "x")), "E18", ab.FAIL)
        self.assertIn("Disqualified - Rejection Sent", fail[0].detail)

    def test_mapping_inside_a_longer_literal_is_unknown(self):
        """Review 2026-10-31: the old substitution ran from one mapping to the next and deleted the FIND branch, and read
        '{{4.s}} - Rejection Sent' as a fixed literal. Both must FAIL."""
        for f in ("OR(AND({Status} != 'Disqualified', {Status} != 'Disqualified - Rejection Sent', {Industry} = '{{4.ind}}-2026'), "
                  "FIND('{{4.tag}}', {Tags}))",
                  "AND({Status} != 'Disqualified', OR({Status} = 'Nurture', {Status} = '{{4.s}} - Rejection Sent'))"):
            with self.subTest(f=f):
                self.assertEqual(len(rows(bp(mail_trigger(), lead_search(3, f), gmail(9, "x")), "E18", ab.FAIL)), 1)

    def test_pipeline_stage_single_record_and_non_lead_searches_pass(self):
        batch = lead_search(1, "AND({Status} = 'Pending Call', REGEX_MATCH({Phone}, '^[+][1-9][0-9]{7,14}$'))")
        self.assertEqual(rows(bp(mail_trigger(), batch, bland(3)), "E18"), [])  # Batch Outbound Caller 3953105
        self.assertEqual(rows(bp(mail_trigger(), lead_search(85, "LOWER({Email}) = 'x'", "1"), gmail(9, "x")), "E18"), [])
        self.assertEqual(rows(bp(mail_trigger(), search(11), gmail(9, "x")), "E18"), [])
        self.assertEqual(rows(bp(mail_trigger(), gmail(9, "x"), lead_search(3, "{Status} = 'VIP'")), "E18"), [])  # after the send


# ---------------------------------------------------------------------------
# The committed snapshots
# ---------------------------------------------------------------------------


class SnapshotRowsTests(unittest.TestCase):
    """The new rules on blueprints/ (pulled 2026-10-30) raise only the rows the sweep names. A fix that closes one of them
    removes it from the pull, which this subset test allows. A new row anywhere else fails it."""

    EXPECTED = {("E5", "3920821", 81, ab.FAIL), ("E5", "3954492", 5, ab.FAIL), ("E5", "3954492", 7, ab.FAIL),
                ("E5", "3954492", 135, ab.REVIEW), ("E5", "3954492", 138, ab.REVIEW), ("E12", "5091060", 1, ab.FAIL),
                ("E13", "5091060", 7, ab.FAIL), ("E13", "3954492", 13, ab.REVIEW),
                ("E14", "3953105", 1, ab.FAIL), ("E14", "3920821", 10, ab.FAIL), ("E14", "3961751", 7, ab.FAIL),
                ("E14", "3975140", 1, ab.FAIL), ("E15", "3975140", 1, ab.FAIL), ("E16", "3943741", 14, ab.FAIL),
                ("E17", "3953105", 3, ab.FAIL), ("E17", "3920821", 10, ab.FAIL), ("E18", "3961751", 3, ab.FAIL)}

    def test_new_rows_on_live_snapshots(self):
        files = sorted(glob.glob(os.path.join(ROOT, "blueprints", "*__*.json")))
        if not files:
            self.skipTest("no committed snapshots")
        got = set()
        for path in files:
            b = ab._load_blueprint_file(path)
            for f in ab.check_e(b, LINKS, ab.Allowlist()):
                if f.rule in ("E5", "E12", "E13", "E14", "E15", "E16", "E17", "E18") and f.status in (ab.FAIL, ab.REVIEW):
                    got.add((f.rule, str(b.scenario_id), f.module_id, f.status))
                    self.assertNotIn(";", f.detail)  # report prose carries no semicolons, the IML lives in CLAUDE.md
                    self.assertNotIn("—", f.detail)
        self.assertEqual(got - self.EXPECTED, set())


if __name__ == "__main__":
    unittest.main()
