"""X-36.2 call rows: check R rules R4a, R4b, R4c, R5 and R6 (specs/X-36.2-call-rows.md). Synthetic blueprints and a
temporary registry only, plus invariants on the committed snapshots. No network."""

import copy
import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import audit_blueprints as ab  # noqa: E402
import make_push  # noqa: E402
import prompt_registry as pr  # noqa: E402
from test_prompt_registry import MAPPER, Files, blueprint, claude, version  # noqa: E402

LINKS = ab.load_links(ab.DEFAULT_LINKS, required=True)
STAMPS = LINKS.tables[ab.LEDGER_TABLE]["stamp_fields"]
VAR = "var.team.IMMIOS_LOGGER_URL"
LOGGER = ab.LoggerSpec(None, None, VAR, None)
SID = "900001"
LABEL = "Synthetic Scenario"
SYSTEM_V2 = ("You grade synthetic interview transcripts for a test harness. Score clarity, accuracy and tone from one to "
             "five, and return a JSON object with the three scores and one sentence of feedback for each of them.")
MAPPER_V2 = dict(MAPPER, system=SYSTEM_V2)


def logger_call(mid):
    return {"id": mid, "module": "http:MakeRequest", "version": 4, "mapper": {"url": "{{%s}}" % VAR, "method": "post"}}


def handler(mid, directive="builtin:Resume"):
    return [logger_call(mid), {"id": mid + 1, "module": directive, "version": 1}]


def ledger(mid, record, onerror=None, module="airtable:ActionCreateRecord", **extra):
    m = {"id": mid, "module": module, "version": 3,
         "mapper": {"base": "appSYNTHETIC0000", "table": ab.LEDGER_TABLE, "record": record, "typecast": False, "useColumnId": True}}
    if onerror is not None:
        m["onerror"] = onerror
    m.update(extra)
    return m


def call_record(n, reg_row, resume=False):
    rec = {
        ab.LABEL_FIELD: LABEL,
        ab.OUTCOME_FIELD: '{{if(%s.id; "Success"; "Error")}}' % n if resume else "Success",
        ab.TOKEN_IN_FIELD: "{{%s.usage.input_tokens}}" % n,
        ab.TOKEN_OUT_FIELD: "{{%s.usage.output_tokens}}" % n,
        STAMPS["prompt_version"]: pr.stamp(reg_row["stage"], reg_row["version"]),
        STAMPS["prompt_sha256"]: reg_row["template_sha256"],
        STAMPS["model_requested"]: reg_row["model"],
        STAMPS["model_served"]: "{{%s.model}}" % n,
        STAMPS["stop_reason"]: '{{ifempty(%s.stop_reason; "no response")}}' % n if resume else "{{%s.stop_reason}}" % n,
        STAMPS["message_id"]: "{{%s.id}}" % n,
        STAMPS["execution_id"]: "{{var.scenario.executionId}}",
        STAMPS["inference_geo"]: "{{%s.usage.inference_geo}}" % n,
        STAMPS["cache_write_tokens"]: "{{%s.usage.cache_creation_input_tokens}}" % n,
        STAMPS["cache_read_tokens"]: "{{%s.usage.cache_read_input_tokens}}" % n,
    }
    return rec


SETVAR = {"id": 50, "module": "util:SetVariable2", "version": 1, "mapper": {"name": "x", "value": "1"}}


def lead_trigger(mid):
    return {"id": mid, "module": "airtable:TriggerWatchRecords", "parameters": {"table": ab.LEAD_TABLE}}


def owned_claude(mid, mapper=None, directive="builtin:Break"):
    m = claude(mid, mapper)
    m["onerror"] = handler(mid * 100 + 1, directive)
    return m


def outcome(mid, n, **record):
    rec = {ab.LABEL_FIELD: LABEL, ab.OUTCOME_FIELD: "Success",
           "fld7oKusxba5RuIZR": '{{first(map(%s.content; "text"; "type"; "text"))}}' % n}
    rec.update(record)
    return ledger(mid, rec, onerror=handler(mid * 100 + 1, "builtin:Resume"),
                  filter={"name": "end_turn", "conditions": [[{"a": "{{%s.stop_reason}}" % n, "o": "text:equal", "b": "end_turn"}]]})


class Base(unittest.TestCase):
    def setUp(self):
        self.f = Files([version(), version(v=2, mapper=MAPPER_V2)],
                       [{"scenario_id": int(SID), "module_id": 2, "stage": "test.sorter", "version": 1}])
        self.reg = pr.load(self.f.prompts, self.f.bindings)
        self.v1 = self.reg.versions[("test.sorter", 1)]
        self.v2 = self.reg.versions[("test.sorter", 2)]

    def tearDown(self):
        self.f.close()

    def run_r(self, flow, links=LINKS, logger=LOGGER, sid=SID):
        return ab.check_r_stamps(blueprint(flow, sid), self.reg, links, logger)

    def fails(self, flow, **kw):
        return [(f.rule, f.module_id) for f in self.run_r(flow, **kw) if f.status == ab.FAIL]

    def detail(self, flow, rule, mid, **kw):
        rows = [f.detail for f in self.run_r(flow, **kw) if f.rule == rule and f.module_id == mid]
        self.assertTrue(rows, f"no {rule} row on {mid}")
        return rows[0]

    def good_row(self, n=2, mid=3, resume=False, reg_row=None, **edit):
        rec = call_record(n, reg_row or self.v1, resume)
        for k, v in edit.items():
            if v is None:
                rec.pop(k, None)
            else:
                rec[k] = v
        return ledger(mid, rec, onerror=handler(mid * 100 + 1))


class TestCallRow(Base):
    def test_valid_call_row_passes(self):
        rows = self.run_r([owned_claude(2), self.good_row(), outcome(4, 2)])
        self.assertEqual([(f.status, f.rule, f.module_id) for f in rows], [(ab.PASS, "R", 3)])
        self.assertIn("test.sorter@1", rows[0].detail)

    def test_whitespace_next_to_a_delimiter_is_the_same_form(self):
        row = self.good_row(**{STAMPS["model_served"]: "{{ 2.model }}", ab.TOKEN_IN_FIELD: "{{  2.usage.input_tokens\n}}"})
        self.assertEqual(self.fails([owned_claude(2), row]), [])
        flow = [owned_claude(2, directive="builtin:Resume"),
                self.good_row(resume=True, **{STAMPS["stop_reason"]: '{{ifempty( 2.stop_reason ;"no response" )}}'})]
        self.assertEqual(self.fails(flow), [])

    def test_whitespace_inside_a_name_or_around_a_dot_is_not_the_form(self):
        # iml_refs (and Make) read {{2 . id}} as no reference, and {{2.mod el}} is a different field.
        for bad in ("{{2.mod el}}", "{{2 . model}}", "{{2. model}}"):
            self.assertIn(("R4b", 3), self.fails([owned_claude(2), self.good_row(**{STAMPS["model_served"]: bad})]), bad)

    def test_field_names_as_keys_resolve(self):
        row = self.good_row()
        row["mapper"]["record"] = {LINKS.field_label(ab.LEDGER_TABLE, k): v for k, v in row["mapper"]["record"].items()}
        row["mapper"]["useColumnId"] = False
        self.assertEqual(self.fails([owned_claude(2), row]), [])

    def test_filter_on_call_row_fails(self):
        row = self.good_row()
        row["filter"] = {"name": "ok", "conditions": [[{"a": "{{2.stop_reason}}", "o": "text:equal", "b": "end_turn"}]]}
        self.assertIn("has a filter", self.detail([owned_claude(2), row], "R4b", 3))

    def test_stale_version_literal_after_a_rebind_fails(self):
        # The module now runs version 2 and is bound to it, but its call row still names version 1.
        f = Files([version(), version(v=2, mapper=MAPPER_V2)],
                  [{"scenario_id": int(SID), "module_id": 2, "stage": "test.sorter", "version": 2}])
        try:
            self.reg = pr.load(f.prompts, f.bindings)
            d = self.detail([owned_claude(2, MAPPER_V2), self.good_row(reg_row=self.v1)], "R4b", 3)
            self.assertIn("test.sorter@2", d)
            self.assertIn(self.v2["template_sha256"], d)
            self.assertEqual(self.fails([owned_claude(2, MAPPER_V2), self.good_row(reg_row=self.reg.versions[("test.sorter", 2)])]), [])
        finally:
            f.close()

    def test_text_around_a_mapping_fails(self):
        d = self.detail([owned_claude(2), self.good_row(**{STAMPS["model_served"]: "Model {{2.model}}"})], "R4b", 3)
        self.assertIn("Model Served must be exactly {{2.model}}", d)

    def test_usage_of_another_module_fails(self):
        flow = [owned_claude(2), owned_claude(9), self.good_row(n=2, mid=3, **{ab.TOKEN_IN_FIELD: "{{9.usage.input_tokens}}"})]
        got = self.fails(flow)
        self.assertIn(("R4b", 3), got)
        # 3 is the call row of 2 only, so mapping 9's usage there is also an R4a row.
        self.assertIn(("R4a", 3), got)

    def test_missing_and_extra_keys_fail(self):
        d = self.detail([owned_claude(2), self.good_row(**{STAMPS["inference_geo"]: None, "fld7oKusxba5RuIZR": "{{2.id}}",
                                                            "fldHf8yjOMGfgyJhc": "abc"})], "R4b", 3)
        self.assertIn("does not write Inference Geo", d)
        self.assertIn("also writes AI Response, External Call ID", d)

    def test_label_must_be_a_literal(self):
        d = self.detail([owned_claude(2), self.good_row(**{ab.LABEL_FIELD: "{{1.label}}"})], "R4b", 3)
        self.assertIn("Scenario name must be", d)

    def test_handler_must_be_logger_then_resume(self):
        row = self.good_row()
        for oe in ([], handler(301, "builtin:Break"), handler(301, "builtin:Ignore"),
                   [{"id": 301, "module": "builtin:Resume", "version": 1}],
                   [logger_call(301), {"id": 302, "module": "slack:CreateMessage"}, {"id": 303, "module": "builtin:Resume"}],
                   [{"id": 301, "module": "http:MakeRequest", "mapper": {"url": "https://example.test/hook"}},
                    {"id": 302, "module": "builtin:Resume"}]):
            row["onerror"] = oe
            if not oe:
                row.pop("onerror")
            self.assertIn("handler is not exactly one Logger call followed by Resume", self.detail([owned_claude(2), row], "R4b", 3))

    def test_update_at_i_plus_1_is_judged_and_fails(self):
        row = self.good_row()
        row["module"] = "airtable:ActionUpdateRecords"
        self.assertIn("a call row is an airtable:ActionCreateRecord", self.detail([owned_claude(2), row], "R4b", 3))


class TestResumeOwner(Base):
    def test_resume_owner_needs_the_mapped_forms(self):
        d = self.detail([owned_claude(2, directive="builtin:Resume"), self.good_row()], "R4b", 3)
        self.assertIn('Stop Reason must be exactly {{ifempty(2.stop_reason;"no response")}}', d)
        self.assertIn('Execution Status must be exactly {{if(2.id;"Success";"Error")}}', d)

    def test_resume_owner_with_mapped_forms_passes(self):
        self.assertEqual(self.fails([owned_claude(2, directive="builtin:Resume"), self.good_row(resume=True)]), [])

    def test_a_resume_substitute_on_the_claude_module_fails(self):
        owner = owned_claude(2, directive="builtin:Resume")
        owner["onerror"][1]["mapper"] = {"id": "msg_fake", "stop_reason": "end_turn", "model": "", "content": []}
        self.assertIn("substitutes an output", self.detail([owner, self.good_row(resume=True)], "R4b", 3))
        owner["onerror"][1]["mapper"] = {"id": "", "stop_reason": "", "usage": {"input_tokens": ""}, "content": []}
        self.assertEqual(self.fails([owner, self.good_row(resume=True)]), [], "Make's empty substitute keys are fine")

    def test_break_and_ignore_owners_need_the_plain_forms(self):
        for directive in ("builtin:Break", "builtin:Ignore"):
            self.assertIn(("R4b", 3), self.fails([owned_claude(2, directive=directive), self.good_row(resume=True)]))
            self.assertEqual(self.fails([owned_claude(2, directive=directive), self.good_row()]), [])


class TestUnverifiable(Base):
    def test_r2_on_the_claude_module_makes_the_stamp_unverifiable(self):
        drift = dict(MAPPER, system=MAPPER["system"] + " Be brief.")
        self.assertIn("Stamp unverifiable", self.detail([owned_claude(2, drift), self.good_row()], "R4b", 3))

    def test_r1_unbound_claude_module_makes_the_stamp_unverifiable(self):
        d = self.detail([owned_claude(7), self.good_row(n=7, mid=8)], "R4b", 8)
        self.assertIn("has no registered prompt (R1)", d)

    def test_no_stamp_map_cannot_verify(self):
        d = self.detail([owned_claude(2), self.good_row()], "R4b", 3, links=ab.AirtableMap())
        self.assertIn("pins no System Logs stamp_fields", d)


class TestTokensAndPricing(Base):
    def test_usage_on_an_outcome_row_without_a_call_row_is_r4a(self):
        flow = [owned_claude(2), SETVAR, outcome(4, 2, **{ab.TOKEN_IN_FIELD: "{{2.usage.input_tokens}}"})]
        self.assertEqual(self.fails(flow), [("R4a", 4)])
        self.assertIn("Claude module 2", self.detail(flow, "R4a", 4))

    def test_usage_outside_the_call_row_is_r4a_even_with_a_call_row(self):
        flow = [owned_claude(2), self.good_row(), outcome(4, 2, **{ab.TOKEN_OUT_FIELD: "{{2.usage.output_tokens}}"})]
        self.assertEqual(self.fails(flow), [("R4a", 4)])

    def test_usage_in_an_error_route_ledger_write_is_r4a(self):
        owner = {"id": 5, "module": "http:MakeRequest", "mapper": {},
                 "onerror": [ledger(6, {ab.TOKEN_IN_FIELD: "{{2.usage.input_tokens}}"}), {"id": 7, "module": "builtin:Break"}]}
        self.assertIn(("R4a", 6), self.fails([owned_claude(2), self.good_row(), owner]))

    def test_tokens_copied_without_a_usage_reference_are_r4a(self):
        good = self.good_row()
        cases = {
            "the call row's own output": [ledger(4, {ab.TOKEN_IN_FIELD: "{{3.`Input Tokens`}}"})],
            "a set variable": [{"id": 51, "module": "util:SetVariable2", "mapper": {"name": "tin", "value": "{{2.usage.input_tokens}}"}},
                               ledger(4, {ab.TOKEN_IN_FIELD: "{{51.tin}}"})],
            "a numeric aggregator": [{"id": 54, "module": "builtin:NumericAggregator", "mapper": {"value": "{{2.usage.input_tokens}}"}},
                                     ledger(4, {ab.TOKEN_OUT_FIELD: "{{54.result}}"})],
            "a field name key": [ledger(4, {"Output Tokens": "{{9.x}}"}, useColumnId=False)],
            "a literal": [ledger(4, {ab.TOKEN_IN_FIELD: "12"})],
        }
        for what, tail in cases.items():
            rows = [f for f in self.run_r([owned_claude(2), good] + tail) if f.status == ab.FAIL]
            self.assertEqual([(f.rule, f.module_id) for f in rows], [("R4a", 4)], what)
            self.assertIn("is not a call row", rows[0].detail, what)

    def test_a_row_with_a_direct_usage_reference_gets_one_r4a_per_call_only(self):
        flow = [owned_claude(2), SETVAR, outcome(4, 2, **{ab.TOKEN_IN_FIELD: "{{2.usage.input_tokens}}"})]
        self.assertEqual(self.fails(flow), [("R4a", 4)])

    def test_no_usage_anywhere_is_r5(self):
        self.assertEqual(self.fails([owned_claude(2), outcome(4, 2)]), [("R5", 2)])

    def test_claude_module_in_an_error_route_is_out_of_stamping_scope(self):
        owner = {"id": 5, "module": "http:MakeRequest", "mapper": {}, "onerror": [claude(2)]}
        self.assertEqual(self.fails([owner]), [])

    def test_content_only_row_at_i_plus_1_is_not_a_call_row(self):
        # Pending Call 125: the F3 marker and decision row reads 172's content, never its usage, so it is not judged as a
        # call row, and the usage on a later row is R4a.
        marker = ledger(4, {ab.LABEL_FIELD: LABEL, "fld7oKusxba5RuIZR": '{{first(map(2.content; "text"; "type"; "text"))}}'},
                        onerror=handler(401, "builtin:Break"))
        flow = [owned_claude(2), marker, outcome(5, 2, **{ab.TOKEN_IN_FIELD: "{{2.usage.input_tokens}}"})]
        self.assertEqual(self.fails(flow), [("R4a", 5)])

    def test_call_row_inside_a_router_route(self):
        router = {"id": 6, "module": "builtin:BasicRouter", "routes": [{"flow": [owned_claude(2), self.good_row()]}, {"flow": []}]}
        rows = self.run_r([{"id": 1, "module": "gateway:CustomWebHook"}, router])
        self.assertEqual([(f.status, f.module_id) for f in rows], [(ab.PASS, 3)])

    def test_two_call_row_sums_are_r4a_for_the_other_call(self):
        both = outcome(4, 2, **{ab.TOKEN_IN_FIELD: "{{2.usage.input_tokens + ifempty(9.usage.input_tokens; 0)}}"})
        got = self.fails([owned_claude(2), owned_claude(9), SETVAR, both])
        self.assertEqual(got, [("R4a", 4), ("R4a", 4)])

    def test_two_call_row_at_i_plus_1_of_the_second_call_is_its_call_row(self):
        # Pending Call 83 today: right after 176 and mapping 172 + 176, so it is 176's call row (R4b) and maps 172's usage (R4a).
        both = outcome(4, 2, **{ab.TOKEN_IN_FIELD: "{{2.usage.input_tokens + ifempty(9.usage.input_tokens; 0)}}"})
        got = self.fails([owned_claude(2), owned_claude(9), both])
        self.assertEqual(sorted(got), [("R4a", 4), ("R4b", 4)])
        self.assertIn("Claude module 9", self.detail([owned_claude(2), owned_claude(9), both], "R4b", 4))

    def test_filtered_outcome_row_at_i_plus_1_is_a_broken_call_row(self):
        # Grader 9 today: the usage-bearing row right after 82 carries the parse filter, so it is judged as 82's call row.
        row = outcome(4, 2, **{ab.TOKEN_IN_FIELD: "{{2.usage.input_tokens}}"})
        self.assertIn("has a filter", self.detail([owned_claude(2), row], "R4b", 4))


class TestApplicantLink(Base):
    def test_link_forms_the_outcome_rows_use_pass(self):
        files = {"id": 5, "module": "airtable:ActionSearchRecords", "mapper": {"table": "tblSFR7Sg8uh8noO2"}}
        for value in ("{{1.id}}", '["{{1.id}}"]', ["{{1.id}}"], "{{first(5.`Related Applicant`)}}",
                      "{{remove(add(emptyarray; ifempty(first(5.`Related Applicant`); emptystring)); emptystring)}}"):
            flow = [lead_trigger(1), files, owned_claude(2), self.good_row(**{ab.LEAD_LINK_FIELD: value})]
            self.assertEqual(self.fails(flow), [], value)

    def test_link_from_a_router_ancestor_passes(self):
        router = {"id": 6, "module": "builtin:BasicRouter",
                  "routes": [{"flow": [owned_claude(2), self.good_row(**{ab.LEAD_LINK_FIELD: '["{{5.id}}"]'})]}]}
        get = {"id": 5, "module": "airtable:ActionGetRecord", "mapper": {"table": ab.LEAD_TABLE}}
        self.assertEqual(self.fails([{"id": 1, "module": "gateway:CustomWebHook"}, get, router]), [])

    def test_link_from_a_later_module_fails(self):
        flow = [owned_claude(2), self.good_row(**{ab.LEAD_LINK_FIELD: '["{{12.id}}"]'}),
                {"id": 12, "module": "airtable:ActionSearchRecords", "mapper": {"table": ab.LEAD_TABLE}}]
        self.assertIn("Applicant Link references module 12", self.detail(flow, "R4b", 3))

    def test_link_that_is_not_an_applicants_record_id_fails(self):
        other = {"id": 5, "module": "airtable:ActionSearchRecords", "mapper": {"table": "tblSFR7Sg8uh8noO2"}}
        for value, needle in (('["recAAAAAAAAAAAAAA"]', "never a literal"), ("recAAAAAAAAAAAAAA", "never a literal"),
                              ("{{1.`Full Name`}} {{1.Email}}", "never a literal"), ("{{var.scenario.executionId}}", "uses"),
                              ("{{1.Email}}", "not a link to Applicants"), ("{{5.id}}", "not the ID of an Applicants record"),
                              ('{{ifempty(1.id; "recAAAAAAAAAAAAAA")}}', "quoted literal"), ("{{lower(1.id)}}", "uses lower")):
            flow = [lead_trigger(1), other, owned_claude(2), self.good_row(**{ab.LEAD_LINK_FIELD: value})]
            self.assertIn(needle, self.detail(flow, "R4b", 3), value)

    def test_link_from_the_claude_module_itself_fails(self):
        self.assertIn("does not run before module 2",
                      self.detail([owned_claude(2), self.good_row(**{ab.LEAD_LINK_FIELD: "{{2.id}}"})], "R4b", 3))


class TestStampElsewhere(Base):
    def test_logger_style_ledger_create_writing_a_stamp_is_r4c(self):
        lg = ledger(4, {ab.LABEL_FIELD: "{{1.label}}", STAMPS["prompt_version"]: "{{1.prompt_version}}"})
        rows = [(f.rule, f.module_id, f.detail) for f in self.run_r([{"id": 1, "module": "gateway:CustomWebHook"}, lg])
                if f.status == ab.FAIL]
        self.assertEqual([(r, m) for r, m, _ in rows], [("R4c", 4)])
        self.assertIn("Prompt Version", rows[0][2])

    def test_stamp_in_an_error_route_and_on_an_update_is_r4c(self):
        owner = {"id": 5, "module": "http:MakeRequest", "mapper": {},
                 "onerror": [ledger(6, {STAMPS["stop_reason"]: "x"}), {"id": 7, "module": "builtin:Break"}]}
        upd = ledger(8, {STAMPS["message_id"]: "{{2.id}}"}, module="airtable:ActionUpdateRecords")
        got = self.fails([owned_claude(2), self.good_row(), owner, upd])
        self.assertIn(("R4c", 6), got)
        self.assertIn(("R4c", 8), got)

    def test_stamp_through_airtable_api_or_http_is_r4c(self):
        api = {"id": 4, "module": "airtable:makeApiCall", "mapper": {"url": "/v0/appX/tblf73Cdii3CsLKfL", "method": "PATCH",
                                                                       "body": '{"fields": {"Model Served": "x"}}'}}
        http = {"id": 5, "module": "http:MakeRequest", "mapper": {"url": "https://api.airtable.com/v0/appX/tblf73Cdii3CsLKfL",
                                                                   "method": "post", "data": '{"fields": {"%s": "1"}}' % STAMPS["prompt_sha256"]}}
        got = self.fails([api, http])
        self.assertEqual(sorted(got), [("R4c", 4), ("R4c", 5)])

    def test_table_by_name_or_mapped_and_api_writes_are_seen(self):
        by_name = ledger(4, {"Prompt Version": "x", ab.TOKEN_IN_FIELD: "{{2.usage.input_tokens}}", "fldeAVW2SAkT6KpZw": SYSTEM_V2})
        by_name["mapper"]["table"] = "system logs"
        mapped = ledger(5, {STAMPS["model_requested"]: "x"})
        mapped["mapper"]["table"] = "{{1.table}}"
        api = {"id": 6, "module": "airtable:makeApiCall",
               "mapper": {"url": "/v0/appX/System%20Logs", "method": "POST",
                          "body": '{"fields": {"Input Tokens": "{{2.usage.input_tokens}}", "Notes": "%s"}}' % SYSTEM_V2}}
        got = self.fails([owned_claude(2), self.good_row(), by_name, mapped, api])
        for row in (("R4a", 4), ("R4c", 4), ("R6", 4), ("R4c", 5), ("R4a", 6), ("R6", 6)):
            self.assertIn(row, got)

    def test_reads_through_the_api_are_not_stamp_writes(self):
        get = {"id": 4, "module": "airtable:makeApiCall",
               "mapper": {"url": "/v0/appX/tblf73Cdii3CsLKfL", "method": "GET",
                          "qs": [{"key": "filterByFormula", "value": "{Prompt Version} = ''"}]}}
        http_get = {"id": 5, "module": "http:MakeRequest",
                    "mapper": {"url": "https://api.airtable.com/v0/appX/tblf73Cdii3CsLKfL?fields[]=Stop%20Reason"}}
        patch = dict(get, id=6, mapper=dict(get["mapper"], method="PATCH", body='{"fields": {"Prompt Version": "x"}}'))
        self.assertEqual(self.fails([get, http_get, patch]), [("R4c", 6)])

    def test_api_write_to_another_table_naming_a_stamp_by_name_is_not_r4c(self):
        other = {"id": 4, "module": "airtable:makeApiCall",
                 "mapper": {"url": "/v0/appX/tblHk09sCKLcOJXr9", "method": "PATCH", "body": '{"fields": {"Stop Reason": "x"}}'}}
        self.assertEqual(self.fails([other]), [])

    def test_call_row_itself_is_not_r4c(self):
        self.assertEqual(self.fails([owned_claude(2), self.good_row()]), [])

    def test_stamp_field_on_another_table_is_not_r4c(self):
        other = {"id": 4, "module": "airtable:ActionCreateRecord",
                 "mapper": {"table": ab.LEAD_TABLE, "record": {STAMPS["prompt_version"]: "x"}}}
        self.assertEqual(self.fails([other]), [])


class TestPromptCopy(Base):
    SYS = MAPPER_V2["system"]

    def row_with(self, payload):
        return ledger(4, {ab.LABEL_FIELD: LABEL, "fldeAVW2SAkT6KpZw": payload})

    def test_80_characters_fail_and_79_pass(self):
        self.assertGreater(len(self.SYS), 120)
        self.assertEqual(self.fails([self.row_with("System: [" + self.SYS[10:89] + "]")]), [])
        self.assertEqual(len(self.SYS[10:89]), 79)
        got = self.run_r([self.row_with("System: [" + self.SYS[10:90] + "]")])
        self.assertEqual([(f.rule, f.module_id) for f in got if f.status == ab.FAIL], [("R6", 4)])
        self.assertIn("test.sorter", got[0].detail)

    def test_a_mapping_splits_the_run(self):
        cut = self.SYS[:60] + "{{1.x}}" + self.SYS[60:100]
        self.assertEqual(self.fails([self.row_with(cut)]), [])

    def test_whitespace_differences_still_count(self):
        copy_ = self.SYS[:100].replace(" ", "  ", 5).replace(",", ",\n", 1)
        self.assertEqual(self.fails([self.row_with(copy_)]), [("R6", 4)])

    def test_a_quoted_literal_inside_a_mapping_counts(self):
        self.assertEqual(self.fails([self.row_with('{{ifempty(1.x; "%s")}}' % self.SYS[:100])]), [("R6", 4)])

    def test_any_registered_version_counts_and_other_tables_do_not(self):
        self.assertEqual(self.fails([self.row_with(MAPPER["system"] * 3)]), [])   # v1 system is shorter than 80 characters
        other = {"id": 5, "module": "airtable:ActionCreateRecord", "mapper": {"table": ab.LEAD_TABLE, "record": {"x": self.SYS}}}
        self.assertEqual(self.fails([other]), [])


class TestInputsAndWiring(Base):
    def write_links(self, mutate):
        data = json.load(open(ab.DEFAULT_LINKS, encoding="utf-8"))
        mutate(data["tables"][ab.LEDGER_TABLE])
        d = tempfile.mkdtemp()
        path = os.path.join(d, "airtable_links.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f)
        return path

    def test_links_without_valid_stamp_fields_are_refused(self):
        for mutate, needle in ((lambda t: t.pop("stamp_fields"), "no stamp_fields"),
                               (lambda t: t["stamp_fields"].pop("message_id"), "exactly the roles"),
                               (lambda t: t["stamp_fields"].update(message_id="fldNOTINTHEMAPXX"), "not in the System Logs fields"),
                               (lambda t: t["stamp_fields"].update(message_id=ab.TOKEN_IN_FIELD), "distinct new fields")):
            with self.assertRaises(ab.InputError) as cm:
                ab.load_links(self.write_links(mutate))
            self.assertIn(needle, str(cm.exception))

    def test_committed_links_pin_ten_stamp_fields(self):
        self.assertEqual(sorted(STAMPS), sorted(ab.STAMP_ROLES))

    def test_fix_id_x_36_2_closes_check_r(self):
        self.assertEqual(make_push.fix_checks("X-36.2"), ("R",))

    def test_audit_runs_the_stamp_rules(self):
        labels = ab.Labels(confirmed=True, scenarios={SID: {"name": "Synthetic", "expected_label": LABEL}})
        res = ab.audit([blueprint([owned_claude(2), outcome(4, 2)])], labels, ab.Schema(label_options=[], status_options=[]), True, links=LINKS, prompts=self.reg,
                       partial=True)
        self.assertIn(("R5", 2), [(f.rule, f.module_id) for f in res.findings if f.check == "R" and f.status == ab.FAIL])


class TestPushTargets(Base):
    """The planned push path through make_push: the R4a rows sit on the outcome rows the push changes, and the call row it
    adds carries an R4 PASS. An R5 row sits on the Claude module, which the push does not change, so make_push cannot close
    it today (the exemption is a proposal for Rizwan, specs/X-36.2-call-rows.md)."""

    def delta(self, live_flow, cand_flow):
        labels = ab.Labels(confirmed=True, scenarios={SID: {"name": "Synthetic", "expected_label": LABEL}})

        def bp(flow):
            return {"name": "Synthetic", "flow": copy.deepcopy(flow), "metadata": {}}

        return make_push.compare_audits(bp(live_flow), bp(cand_flow), int(SID), "Synthetic", labels,
                                        ab.Schema(label_options=[LABEL], status_options=[]), links=LINKS,
                                        webhooks=ab.Webhooks(logger=LOGGER), prompts=self.reg)

    def r_rows(self, delta):
        return sorted((k[0], k[1], k[3][:3]) for k in delta.closed if k[0] == "R" and k[2] == ab.FAIL)

    def test_planned_push_closes_r4a_on_the_changed_outcome_row(self):
        tokens = {ab.TOKEN_IN_FIELD: "{{2.usage.input_tokens}}", ab.TOKEN_OUT_FIELD: "{{2.usage.output_tokens}}"}
        live = [lead_trigger(1), owned_claude(2), SETVAR, outcome(4, 2, **tokens)]
        cand = [lead_trigger(1), owned_claude(2), self.good_row(), SETVAR, outcome(4, 2)]
        d = self.delta(live, cand)
        self.assertEqual(self.r_rows(d), [("R", "4", "R4a")])
        # The stub Logger call fails check B's payload contract. The real call rows copy the owner's live Logger call.
        self.assertEqual([k for k in d.new_fails if k[0] == "R"], [])
        self.assertNotIn("R", {k[0] for k in d.remaining_fails})
        make_push.check_targets("X-36.2", [("R", "4")], d, {3, 301, 302, 4})

    def test_r5_cannot_be_closed_by_a_push_today(self):
        live = [lead_trigger(1), owned_claude(2), outcome(4, 2)]
        cand = [lead_trigger(1), owned_claude(2), self.good_row(), outcome(4, 2)]
        d = self.delta(live, cand)
        self.assertEqual(self.r_rows(d), [("R", "2", "R5 ")])
        with self.assertRaises(make_push.Abort):
            make_push.check_targets("X-36.2", [("R", "2")], d, {3, 301, 302})


class TestCommittedSnapshots(unittest.TestCase):
    """Invariants that hold through the rollout: every live Claude module is priced somewhere (R5) and nothing but a call
    row writes a stamp (R4c). The R4a, R4b and R6 rows close push by push."""

    def test_no_r4c_or_r5_on_the_pull(self):
        reg = pr.load()
        wh = ab.load_webhooks(ab.DEFAULT_WEBHOOKS)
        blueprints, _cov = ab.load_manifest_mode(os.path.join(ROOT, "blueprints"), os.path.join(ROOT, "blueprints", "manifest.json"))
        rows = [f for b in blueprints for f in ab.check_r_stamps(b, reg, LINKS, wh.logger)]
        self.assertEqual([(f.rule, f.module_id) for f in rows if f.rule in ("R4c", "R5")], [])


if __name__ == "__main__":
    unittest.main()
