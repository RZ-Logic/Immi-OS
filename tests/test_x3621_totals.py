"""X-36.2.1: check R rule R7, totals over System Logs once call rows exist (synthetic flows plus the committed pull)."""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import audit_blueprints as ab  # noqa: E402

LINKS = ab.load_links(ab.DEFAULT_LINKS, required=True)
DAY = "DATETIME_FORMAT(SET_TIMEZONE({Timestamp}, 'America/Toronto'), 'YYYY-MM-DD') = '{{1.day}}'"
BLANK = "AND(" + DAY + ", {Prompt Version} = BLANK())"


def search(mid, formula=DAY, limit="3200"):
    return {"id": mid, "module": "airtable:ActionSearchRecords", "version": 3,
            "mapper": {"table": ab.LEDGER_TABLE, "view": "viwTODAY", "formula": formula, "maxRecords": limit}}


def agg(mid, feeder, mapper=None):
    return {"id": mid, "module": "builtin:BasicAggregator", "parameters": {"feeder": feeder},
            "mapper": {"id": "{{%d.id}}" % feeder} if mapper is None else mapper}


def slack(mid, text):
    return {"id": mid, "module": "slack:CreateMessage", "mapper": {"text": text}}


def rows(flow):
    b = ab.Blueprint("Synthetic", "900001", "synthetic", {"name": "Synthetic", "flow": flow})
    return sorted((f.rule, f.module_id) for f in ab.check_r_totals(b, LINKS) if f.status == ab.FAIL)


SPEND = 'Spend {{sum(map(2.array; "Grand Total"))}}'
TASKS = 'Tasks {{length(map(4.array; "id"))}}'


class TestR7(unittest.TestCase):
    def test_the_fixed_shape_passes(self):
        flow = [search(1), agg(2, 1, {"Grand Total": "{{1.`Grand Total`}}"}), search(3, BLANK), agg(4, 3),
                slack(5, SPEND + " " + TASKS + '{{if(length(2.array) >= 3200; " limit"; "")}}{{if(length(4.array) >= 3200; " limit"; "")}}')]
        self.assertEqual(rows(flow), [])

    def test_the_live_shape_fails_three_ways(self):
        self.assertEqual(rows([search(1, "", limit="100"), agg(4, 1, {}), slack(5, "Tasks {{length(4.array)}} " + SPEND.replace("2.", "4."))]),
                         [("R7a", 5), ("R7b", 1), ("R7d", 1)])

    def test_a_total_needs_a_day_window(self):
        windows = (DAY, "IS_SAME({Timestamp}, TODAY(), 'day')", "IS_SAME({Timestamp}, '{{1.day}}', 'day')",
                   "AND(IS_AFTER({Timestamp}, '{{1.a}}'), IS_BEFORE({Timestamp}, '{{1.b}}'))")
        not_windows = ("", "{Scenario name} = 'x'", "OR(IS_SAME({Timestamp}, TODAY(), 'day'), 1)", "NOT({Timestamp} = BLANK())",
                       "IS_AFTER({Timestamp}, '2000-01-01')", "IS_BEFORE({Timestamp}, TODAY())", "{Timestamp} != BLANK()",
                       "NOT(IS_SAME({Timestamp}, TODAY(), 'day'))", "IF(OR(IS_SAME({Timestamp}, TODAY(), 'day'), TRUE()), 1, 0)",
                       "{Scenario name} != '{Timestamp}'")
        for formula in windows:
            self.assertEqual(rows([search(1, formula), agg(2, 1, {"g": "{{1.g}}"}), slack(5, SPEND)]), [], formula)
        for formula in not_windows:
            self.assertEqual(rows([search(1, formula), agg(2, 1, {"g": "{{1.g}}"}), slack(5, SPEND)]), [("R7d", 1)], formula)

    def test_a_limit_check_is_not_a_task_count(self):
        text = SPEND + '{{if(length(2.array) >= 3200; " limit reached"; "")}}{{if(length(map(2.array; "id")) > 3199; "x"; "")}}'
        self.assertEqual(rows([search(1), agg(2, 1), slack(5, text)]), [])
        self.assertEqual(rows([search(1), agg(2, 1), slack(5, "{{length(2.array) > 31}}")]), [("R7a", 5)])

    def test_a_count_needs_the_id_form_over_an_aggregator_that_collects_id(self):
        for bad in ("{{length(4.array)}}", '{{length(map(4.array; "Grand Total"))}}', '{{length(remove(map(4.array; "id"); emptystring))}}',
                    '{{length(distinct(map(4.array; "id")))}}', "{{length(slice(4.array; 0))}}"):
            self.assertEqual(rows([search(3, BLANK), agg(4, 3), slack(5, bad)]), [("R7a", 5)], bad)
        self.assertEqual(rows([search(3, BLANK), agg(4, 3, {"x": "{{3.`Scenario name`}}"}), slack(5, TASKS)]), [("R7a", 5)])

    def test_wrapped_totals_still_count_as_totals(self):
        # A wrapper must not hide the 100-row cap or the missing window.
        for text in ('{{length(remove(map(4.array; "id"); emptystring))}}', '{{sum(remove(map(4.array; "Grand Total"); emptystring))}}'):
            got = rows([search(1, "", "100"), agg(4, 1), slack(5, text)])
            self.assertIn(("R7b", 1), got, text)
            self.assertIn(("R7d", 1), got, text)

    def test_blank_test_forms_and_scope(self):
        for good in ("AND(" + DAY + ", {Prompt Version}='')", "AND(" + DAY + ', NOT({Prompt Version}), {Scenario name} != "x")',
                     "AND(" + DAY + ", LEN({Prompt Version}&'')=0)", "AND({x} = 1, " + DAY + ", {prompt version} = BLANK())",
                     "AND(" + DAY + ", {Prompt SHA256} = BLANK())"):
            self.assertEqual(rows([search(3, good), agg(4, 3), slack(5, TASKS)]), [], good)
        for bad in ("OR({Prompt Version} = BLANK(), {x} = 1)", "{Prompt Version} != ''", "{Execution ID} = BLANK()"):
            self.assertEqual(rows([search(3, "AND(" + DAY + ", " + bad + ")"), agg(4, 3), slack(5, TASKS)]), [("R7a", 5)], bad)

    def test_a_spend_total_without_the_call_rows_is_r7c(self):
        for field in ("Prompt Version", "Prompt SHA256", "Model Served", "Message ID"):
            formula = "AND(" + DAY + ", {%s} = BLANK())" % field
            self.assertEqual(rows([search(3, formula), agg(4, 3), slack(5, 'Spend {{sum(map(4.array; "Grand Total"))}}')]),
                             [("R7c", 5)], field)

    def test_function_and_numeric_aggregators_and_bundle_counts(self):
        fsum = {"id": 4, "module": "util:FunctionAggregator2", "parameters": {"fn": "sum", "feeder": 3}, "mapper": {"value": "{{3.g}}"}}
        fcount = {"id": 6, "module": "util:FunctionAggregator2", "parameters": {"fn": "count", "feeder": 1}, "mapper": {}}
        nsum = {"id": 7, "module": "builtin:NumericAggregator", "parameters": {"fn": "sum", "feeder": 3}, "mapper": {"value": "{{3.g}}"}}
        self.assertEqual(rows([search(3, "AND(" + DAY + ", {Prompt Version} = BLANK())", "50"), fsum]), [("R7b", 3), ("R7c", 4)])
        self.assertEqual(rows([search(1, ""), fcount]), [("R7a", 6), ("R7d", 1)])
        self.assertEqual(rows([search(3, BLANK), nsum]), [("R7c", 7)])
        self.assertEqual(rows([search(1, "", "10"), slack(5, "Tasks {{1.__IMTLENGTH__}}")]), [("R7a", 5), ("R7b", 1), ("R7d", 1)])

    def test_limit_below_the_make_maximum_is_r7b(self):
        for limit, want in (("100", [("R7b", 3)]), (3199, [("R7b", 3)]), ("{{1.x}}", [("R7b", 3)]), (None, [("R7b", 3)]),
                            ("3200", []), (5000, [])):
            self.assertEqual(rows([search(3, BLANK, limit), agg(4, 3), slack(5, TASKS)]), want, limit)

    def test_filters_and_found_tests_are_out_of_scope(self):
        # The F3 and F2d pattern, and the E5 duplicate test, only test. They report no total.
        gate = {"id": 6, "module": "util:SetVariable2", "filter": {"conditions": [[{"a": '{{first(map(4.array; "id"))}}', "o": "notexist"}]]}}
        dup = {"id": 7, "module": "util:SetVariable2", "filter": {"conditions": [[{"a": "{{length(4.array)}}", "o": "number:greater", "b": "1"}]]}}
        cap = {"id": 8, "module": "util:SetVariable2", "filter": {"conditions": [[{"a": "{{length(4.array)}}", "o": "number:greaterorequal", "b": "3200"}]]}}
        self.assertEqual(rows([search(3, "AND({External Call ID} = 'x')", "1"), agg(4, 3), gate, dup, cap]), [])
        self.assertEqual(rows([search(3, "AND({External Call ID} = 'x')", "1"), agg(4, 3), slack(9, '{{first(map(4.array; "id"))}}')]), [])

    def test_other_tables_are_out_of_scope(self):
        other = search(3, limit="10")
        other["mapper"]["table"] = ab.LEAD_TABLE
        self.assertEqual(rows([other, agg(4, 3), slack(5, "{{length(4.array)}}")]), [])


class TestCommittedPull(unittest.TestCase):
    def test_only_the_daily_cost_audit_has_r7_rows(self):
        blueprints, _cov = ab.load_manifest_mode(os.path.join(ROOT, "blueprints"), os.path.join(ROOT, "blueprints", "manifest.json"))
        got = {(str(b.scenario_id), f.rule, f.module_id) for b in blueprints for f in ab.check_r_totals(b, LINKS) if f.status == ab.FAIL}
        # A subset on purpose: the rows are gone from the pull once X-36.2.1 is pushed.
        self.assertTrue(got <= {("4229542", "R7a", 5), ("4229542", "R7b", 1), ("4229542", "R7d", 1)}, got)


if __name__ == "__main__":
    unittest.main()
