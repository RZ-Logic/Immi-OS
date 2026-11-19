"""Regression tests kept from the review of F-E5 v2 (2026-10-29).

Option C (decided by Rizwan 2026-10-29) retired the Error Monitor (check G), audit/critical_modules.json and the F-E5.2
simplify push, so their tests went with them. What stays is which handler modules a rewrite may remove: the F-E5.3 Logger
swap removes the same Shadow Ledger writes, Slack messages and handler routers and keeps the directive. Synthetic, no network.
"""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
sys.path.insert(0, os.path.join(ROOT, "tests"))

import audit_blueprints as ab  # noqa: E402
from test_audit_blueprints import directive, ledger, slack  # noqa: E402


# ---------------------------------------------------------------------------
# What a handler rewrite can remove
# ---------------------------------------------------------------------------


class RemovableHandlerTests(unittest.TestCase):
    def test_only_ledger_writes_slack_messages_and_routers_left_empty_are_removable(self):
        rt = {"id": 20, "module": "builtin:BasicRouter", "routes": [{"flow": [ledger(21)]}, {"flow": [slack(22)]}]}
        got = ab.removable_handler_modules([rt, directive(23, "Resume")])
        self.assertEqual(sorted(m["id"] for m in got), [20, 21, 22])

    def test_a_router_that_holds_a_filtered_directive_stays(self):
        real = {"name": "f", "conditions": [[{"a": "{{x}}", "b": "1", "o": "text:equal"}]]}
        rt = {"id": 20, "module": "builtin:BasicRouter",
              "routes": [{"flow": [ledger(21)]}, {"flow": [slack(22)]}, {"flow": [dict(directive(23), filter=real)]}]}
        got = ab.removable_handler_modules([rt])
        self.assertEqual(sorted(m["id"] for m in got), [21, 22])

    def test_other_modules_are_not_removable(self):
        got = ab.removable_handler_modules([ledger(21), {"id": 24, "module": "util:SetVariable2"}, directive(23, "Ignore")])
        self.assertEqual([m["id"] for m in got], [21])

    def test_a_router_that_shrinks_to_one_unfiltered_directive_goes_and_the_directive_stays(self):
        name_only = dict(slack(22), filter={"name": "Alert", "conditions": []})
        rt = {"id": 20, "module": "builtin:BasicRouter", "routes": [{"flow": [ledger(21)]}, {"flow": [name_only, directive(23)]}]}
        self.assertEqual(ab.flattenable_directive(rt)["id"], 23)
        got = ab.removable_handler_modules([rt])
        self.assertEqual(sorted(m["id"] for m in got), [20, 21, 22])

    def test_a_filtered_directive_a_fallback_directive_or_a_gating_filter_blocks_the_shrink(self):
        real = {"name": "f", "conditions": [[{"a": "{{x}}", "b": "1", "o": "text:equal"}]]}
        gated = dict(slack(22), filter=real)
        cases = {
            "filtered directive": {"id": 20, "module": "builtin:BasicRouter",
                                   "routes": [{"flow": [ledger(21)]}, {"flow": [slack(22), dict(directive(23), filter=real)]}]},
            "gating slack": {"id": 20, "module": "builtin:BasicRouter", "routes": [{"flow": [ledger(21)]}, {"flow": [gated, directive(23)]}]},
            "fallback": {"id": 20, "module": "builtin:BasicRouter", "parameters": {"else": 1},
                         "routes": [{"flow": [ledger(21)]}, {"flow": [slack(22), directive(23)]}]},
            "two directives": {"id": 20, "module": "builtin:BasicRouter",
                               "routes": [{"flow": [directive(24, "Ignore")]}, {"flow": [slack(22), directive(23)]}]},
            "filtered router": {"id": 20, "module": "builtin:BasicRouter", "filter": real,
                                "routes": [{"flow": [ledger(21)]}, {"flow": [slack(22), directive(23)]}]},
        }
        for name, rt in cases.items():
            self.assertIsNone(ab.flattenable_directive(rt), name)
            self.assertNotIn(20, [m["id"] for m in ab.removable_handler_modules([rt])], name)

    def test_a_removable_module_with_a_real_filter_stays_when_something_after_it_stays(self):
        real = {"name": "f", "conditions": [[{"a": "{{x}}", "b": "1", "o": "text:equal"}]]}
        got = ab.removable_handler_modules([dict(slack(22), filter=real), ledger(21), directive(23)])
        self.assertEqual([m["id"] for m in got], [21])
        got = ab.removable_handler_modules([ledger(21), dict(slack(22), filter=real)])
        self.assertEqual(sorted(m["id"] for m in got), [21, 22])


if __name__ == "__main__":
    unittest.main()
