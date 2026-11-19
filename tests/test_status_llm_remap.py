"""The X-15/X-18 LLM remap exception to hard rule 1 (approved by Rizwan 2026-10-30): a Status write may change only by
remapping a replaced OpenAI module's output to the Claude module in its place. Synthetic fixtures shaped like Pending
Call modules 13 (OpenAI), 172 (Claude) and 8 (Status write). No network."""

import copy
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import audit_blueprints as ab  # noqa: E402
import make_push  # noqa: E402

SUMMARY = "fldSummary0000001"
CLAUDE_TEXT = '{{first(map(172.content; "text"; "type"; "text"))}}'


def openai(mid=13):
    return {"id": mid, "module": "openai-gpt-3:CreateCompletion", "version": 1, "mapper": {"model": "gpt-5-mini"}}


def claude(mid=172):
    return {"id": mid, "module": "anthropic-claude:createAMessage", "version": 1,
            "mapper": {"model": "claude-haiku-5-5", "max_tokens": 4096}}


def status_write(summary, status="{{3.status}}", mid=8):
    return {"id": mid, "module": "airtable:ActionUpdateRecords", "version": 2,
            "filter": {"name": "allow", "conditions": [[{"a": "{{3.status}}", "b": "VIP", "o": "text:equal"}]]},
            "mapper": {"id": "{{7.id}}", "table": ab.LEAD_TABLE, "record": {ab.STATUS_FIELD: status, SUMMARY: summary}}}


def blueprint(*flow):
    return {"name": "Pending", "flow": [{"id": 1, "module": "gateway:CustomWebHook"}, *flow], "metadata": {}}


LIVE = blueprint(openai(), status_write("{{13.choices[].message.content}}"))


def check(fix, live, cand):
    return make_push.check_status_writes(fix, cand, make_push.diff_modules(live, cand), None, live)


class StatusLlmRemapTests(unittest.TestCase):
    def test_x18_and_x15_may_remap_the_summary(self):
        cand = blueprint(claude(), status_write(CLAUDE_TEXT))
        for fix in ("X-18", "X-15", "X-18.1"):
            with self.subTest(fix=fix):
                self.assertEqual(check(fix, LIVE, cand), [8])

    def test_token_fields_remap_too(self):
        live = blueprint(openai(), status_write("{{13.choices[].message.content}} {{13.usage.prompt_tokens}}"))
        cand = blueprint(claude(), status_write(CLAUDE_TEXT + " {{172.usage.input_tokens}}"))
        self.assertEqual(check("X-18", live, cand), [8])

    def test_anything_beyond_the_remap_aborts(self):
        cases = {
            "status value": blueprint(claude(), status_write(CLAUDE_TEXT, status="{{first(map(172.content; \"text\"; \"type\"; \"text\"))}}")),
            "status literal": blueprint(claude(), status_write(CLAUDE_TEXT, status="Disqualified")),
            "extra text": blueprint(claude(), status_write(CLAUDE_TEXT + " ok")),
            "wrong path": blueprint(claude(), status_write("{{172.content[1].text}}")),
            "other module": blueprint(claude(), status_write('{{first(map(99.content; "text"; "type"; "text"))}}')),
        }
        for name, cand in cases.items():
            with self.subTest(name=name):
                with self.assertRaises(make_push.Abort):
                    check("X-18", LIVE, cand)

    def test_an_untouched_status_write_is_not_this_rule(self):
        # The dangling reference to the removed module is the audit's to catch, not make_push's Status rule.
        self.assertEqual(check("X-18", LIVE, blueprint(claude(), status_write("{{13.choices[].message.content}}"))), [])

    def test_filter_handler_and_position_must_stay(self):
        for name, edit in {
            "filter": lambda m: m.update(filter=None),
            "handler": lambda m: m.update(onerror=[{"id": 90, "module": "builtin:Ignore"}]),
            "version": lambda m: m.update(version=3),
            "new field": lambda m: m["mapper"]["record"].update(fldOther000000001="x"),
        }.items():
            with self.subTest(name=name):
                w = status_write(CLAUDE_TEXT)
                edit(w)
                with self.assertRaises(make_push.Abort):
                    check("X-18", LIVE, blueprint(claude(), w))
        with self.assertRaises(make_push.Abort):
            check("X-18", LIVE, blueprint(status_write(CLAUDE_TEXT), claude()))

    def test_claude_must_take_the_openai_place(self):
        moved = blueprint(status_write(CLAUDE_TEXT), {"id": 50, "module": "builtin:BasicRouter", "routes": [{"flow": [claude()]}]})
        with self.assertRaises(make_push.Abort):
            check("X-18", LIVE, moved)
        not_claude = blueprint({**claude(), "module": "http:MakeRequest"}, status_write(CLAUDE_TEXT))
        with self.assertRaises(make_push.Abort):
            check("X-18", LIVE, not_claude)

    def test_id_guard_does_not_match_inside_a_longer_id(self):
        live = blueprint(openai(), status_write("{{113.choices[].message.content}}"))
        cand = blueprint(claude(), status_write('{{first(map(1172.content; "text"; "type"; "text"))}}'))
        with self.assertRaises(make_push.Abort):
            check("X-18", live, cand)

    def test_a_live_status_write_may_not_stop_writing_status(self):
        # Review 2026-10-30: the guard read only the candidate, so dropping the field, retargeting the table or deleting
        # the module touched no Status write.
        dropped = status_write(CLAUDE_TEXT)
        del dropped["mapper"]["record"][ab.STATUS_FIELD]
        retargeted = status_write(CLAUDE_TEXT)
        retargeted["mapper"]["table"] = "tblf73Cdii3CsLKfL"
        for name, cand in {"field dropped": blueprint(claude(), dropped),
                           "table changed": blueprint(claude(), retargeted),
                           "module deleted": blueprint(claude())}.items():
            for fix in ("X-18", "X-41"):
                with self.subTest(name=name, fix=fix):
                    with self.assertRaises(make_push.Abort):
                        check(fix, LIVE, cand)

    def test_status_under_another_key_spelling_may_not_be_remapped(self):
        for key in ("FLDFRKT1VDHWZYWRG", " " + ab.STATUS_FIELD, "Status"):
            with self.subTest(key=key):
                live = blueprint(openai(), {**status_write("x"), "mapper": {"id": "{{7.id}}", "table": ab.LEAD_TABLE,
                                 "record": {key: "{{13.choices[].message.content}}"}}})
                cand = blueprint(claude(), {**status_write("x"), "mapper": {"id": "{{7.id}}", "table": ab.LEAD_TABLE,
                                 "record": {key: CLAUDE_TEXT}}})
                with self.assertRaises(make_push.Abort):
                    check("X-18", live, cand)

    def test_other_fix_ids_still_may_not(self):
        cand = blueprint(claude(), status_write(CLAUDE_TEXT))
        for fix in ("X-41", "F-H9", "X-180", "X-15x"):
            with self.subTest(fix=fix):
                with self.assertRaises(make_push.Abort):
                    check(fix, LIVE, copy.deepcopy(cand))



class StatusAddFieldTests(unittest.TestCase):
    """The X-41.7 add-field exception (approved by Rizwan 2026-10-31): a Status write may gain only Applicants Industry."""
    INDUSTRY = "fldT1nsKs892JpfcY"

    def live(self):
        return blueprint(openai(), status_write("{{13.choices[].message.content}}"))

    def with_industry(self, value="{{5.industry}}", extra=None):
        w = status_write("{{13.choices[].message.content}}")
        w["mapper"]["record"][self.INDUSTRY] = value
        if extra:
            extra(w)
        return blueprint(openai(), w)

    def test_adding_industry_passes(self):
        for fix in ("X-41.7", "X-41.7.1"):
            with self.subTest(fix=fix):
                self.assertEqual(check(fix, self.live(), self.with_industry()), [8])

    def test_anything_else_aborts(self):
        cases = {
            "other field": lambda w: w["mapper"]["record"].update(fldOther000000001="x"),
            "status changed": lambda w: w["mapper"]["record"].update({ab.STATUS_FIELD: "Disqualified"}),
            "summary changed": lambda w: w["mapper"]["record"].update({SUMMARY: "x"}),
            "filter dropped": lambda w: w.update(filter=None),
            "typecast": lambda w: w["mapper"].update(typecast=True),
        }
        for name, edit in cases.items():
            with self.subTest(name=name):
                with self.assertRaises(make_push.Abort):
                    check("X-41.7", self.live(), self.with_industry(extra=edit))

    def test_other_fix_ids_may_not(self):
        for fix in ("X-41", "X-41.6", "X-41.70", "X-18"):
            with self.subTest(fix=fix):
                with self.assertRaises(make_push.Abort):
                    check(fix, self.live(), self.with_industry())


if __name__ == "__main__":
    unittest.main()
