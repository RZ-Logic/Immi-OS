"""Wave 1 audit rules E22 and E23 from the 2026-10-31 bug sweep fix plan (check E, fix IDs X-41.x and X-45.1):
E22 the HeyGen render gate in front of a client send that maps Get a Video output (M8) and E23 a Voice AI Ledger create
linked to its System Logs row (L5, the path-aware version). Synthetic fixtures shaped like the live modules, plus the
rows both rules raise on the committed snapshots. No network.
"""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import audit_blueprints as ab  # noqa: E402

LINKS = ab.load_links(ab.DEFAULT_LINKS, required=True)
SYSLOGS = ab.LEDGER_TABLE
VOICE = ab.VOICE_LEDGER_TABLE
LEAD = ab.LEAD_TABLE
FILES = "tblSFR7Sg8uh8noO2"
SYSTEM_LOG_LINK = "fldZOmFsO25WfXU3c"  # Voice AI Ledger: System Log Link
VOICE_LINK = "fldOEPxYOQwWj1v6p"       # System Logs: Voice AI Ledger (the inverse link)
COST = "fldx2WzOb94Iyf5pK"             # System Logs: Voice AI cost


def bp(*flow, sid="1"):
    return ab.Blueprint(name="S", scenario_id=sid, source="test", bp={"name": "S", "flow": list(flow), "metadata": {}})


def rows(b, code, status=None):
    return [f for f in ab.check_e(b, LINKS, ab.Allowlist()) if f.rule == code and (status is None or f.status == status)]


def filt(m, conditions, name="f"):
    m = dict(m)
    m["filter"] = {"name": name, "conditions": conditions}
    return m


def router(mid, *routes, fallback=None):
    r = {"id": mid, "module": "builtin:BasicRouter", "routes": [{"flow": list(x)} for x in routes]}
    if fallback is not None:
        r["parameters"] = {"else": fallback}
    return r


def slack(mid, text="x"):
    return {"id": mid, "module": "slack:CreateMessage", "mapper": {"text": text}}


# ---------------------------------------------------------------------------
# E22 HeyGen render gate
# ---------------------------------------------------------------------------


def watch(mid=1):
    return {"id": mid, "module": "airtable:TriggerWatchRecords", "parameters": {"table": FILES, "formula": "", "config": {}}}


def heygen_create(mid=4):
    return {"id": mid, "module": "heygen:createAnAvatarVideoV2", "version": 1, "mapper": {"title": "x"}}


def sleep(mid=5):
    return {"id": mid, "module": "util:FunctionSleep", "mapper": {"duration": "180"}}


def heygen_get(mid=6, feed="{{4.video_id}}"):
    return {"id": mid, "module": "heygen:getVideo", "version": 1, "mapper": {"video_id": feed}}


def gmail(mid, html='<a href="{{6.data.video_url}}">Watch</a>'):
    return {"id": mid, "module": "google-email:sendAnEmail", "mapper": {"to": "{{1.Email}}", "contents": [{"text": html}]}}


def gate(g=6, status_op="text:equal:ci", status="completed"):
    return [[{"a": f"{{{{{g}.data.status}}}}", "b": status, "o": status_op}, {"a": f"{{{{{g}.data.video_url}}}}", "o": "exist"}]]


def setvar(mid):
    return {"id": mid, "module": "util:SetVariable2", "mapper": {"name": "v", "value": "1"}}


def video_flow(*after):
    return (watch(), heygen_create(), sleep(), heygen_get()) + tuple(after)


class E22RenderGateTests(unittest.TestCase):
    def test_support_bot_shape_fails_on_the_send(self):
        """M8-SB: Support Bot 3954492 email 13 maps getVideo 14 with no filter after a fixed sleep."""
        b = bp(*video_flow(gmail(7)))
        fail = rows(b, "E22", ab.FAIL)
        self.assertEqual([f.module_id for f in fail], [7])
        self.assertIn("HeyGen Get a Video 6", fail[0].detail)
        self.assertIn("{{6.data.status}} text equal completed", fail[0].detail)
        self.assertIn("{{6.data.video_url}} exists", fail[0].detail)
        self.assertNotIn(";", fail[0].detail)

    def test_auto_celebrate_shape_passes(self):
        """Auto-Celebrate 5091060 router 123: email 7 carries the X-41.4 gate, the fallback logs and alerts."""
        log = {"id": 124, "module": "airtable:ActionCreateRecord", "mapper": {"table": SYSLOGS, "record": {"x": "{{6.data.status}}"}}}
        b = bp(*video_flow(router(123, [filt(gmail(7), gate()), slack(32)], [log, slack(127, "{{6.data.status}}")], fallback=1)))
        self.assertEqual(rows(b, "E22"), [])

    def test_gate_on_an_earlier_module_or_the_route_head_passes(self):
        b = bp(*video_flow(filt(setvar(8), gate()), gmail(7)))
        self.assertEqual(rows(b, "E22"), [])
        b = bp(*video_flow(router(10, [filt(setvar(8), gate()), slack(9), gmail(7)], [slack(11)])))
        self.assertEqual(rows(b, "E22"), [])
        b = bp(*video_flow(filt(router(10, [gmail(7)]), gate())))
        self.assertEqual(rows(b, "E22"), [], "a filter on the router module itself is on the path after 6")

    def test_case_sensitive_equal_passes_only_on_the_exact_value(self):
        b = bp(*video_flow(filt(gmail(7), gate(status_op="text:equal"))))
        self.assertEqual(rows(b, "E22"), [])
        b = bp(*video_flow(filt(gmail(7), gate(status_op="text:equal", status="Completed"))))
        self.assertEqual(len(rows(b, "E22", ab.FAIL)), 1)
        b = bp(*video_flow(filt(gmail(7), gate(status_op="text:equal:ci", status="Completed"))))
        self.assertEqual(rows(b, "E22"), [])

    def test_partial_or_wrong_gates_fail(self):
        status_only = [[{"a": "{{6.data.status}}", "b": "completed", "o": "text:equal"}]]
        url_only = [[{"a": "{{6.data.video_url}}", "o": "exist"}]]
        not_equal = gate(status_op="text:notequal")
        mapped = gate(status="{{1.status}}")
        two_groups = gate() + [[{"a": "{{1.id}}", "o": "exist"}]]
        split = [[{"a": "{{6.data.status}}", "b": "completed", "o": "text:equal"}], [{"a": "{{6.data.video_url}}", "o": "exist"}]]
        other_module = gate(g=4)
        contains = [[{"a": "{{6.data.status}}", "b": "completed", "o": "text:contain"}, {"a": "{{6.data.video_url}}", "o": "exist"}]]
        for conds in (status_only, url_only, not_equal, mapped, two_groups, split, other_module, contains):
            b = bp(*video_flow(filt(gmail(7), conds)))
            self.assertEqual(len(rows(b, "E22", ab.FAIL)), 1, conds)

    def test_extra_conditions_in_the_one_group_still_pass(self):
        conds = [gate()[0] + [{"a": "{{1.id}}", "o": "exist"}]]
        b = bp(*video_flow(filt(gmail(7), conds)))
        self.assertEqual(rows(b, "E22"), [])

    def test_gate_before_the_video_or_on_a_sibling_route_does_not_count(self):
        get = filt(heygen_get(), gate())  # a filter on 6 itself runs before 6 has output
        b = bp(watch(), heygen_create(), sleep(), get, gmail(7))
        self.assertEqual(len(rows(b, "E22", ab.FAIL)), 1)
        b = bp(*video_flow(router(10, [filt(setvar(8), gate())], [gmail(7)])))
        self.assertEqual([f.module_id for f in rows(b, "E22", ab.FAIL)], [7])

    def test_each_video_needs_its_own_gate(self):
        b = bp(watch(), heygen_create(), heygen_get(), heygen_get(16, "{{4.video_id}}"),
               filt(gmail(7, "{{6.data.video_url}} {{16.data.video_url}}"), gate()))
        fail = rows(b, "E22", ab.FAIL)
        self.assertEqual([f.module_id for f in fail], [7])
        self.assertIn("Get a Video 16", fail[0].detail)

    def test_non_sends_and_non_link_mappings(self):
        """Slack, a ledger row, a Logger call and a HeyGen module are not client sends. An email that reads the video only
        in its filter, or not at all, passes. An email that reads any other getVideo field still needs the gate."""
        logger = {"id": 9, "module": "http:MakeRequest", "mapper": {"url": "{{var.team.IMMIOS_LOGGER_URL}}",
                                                                    "urlEncodedBodyContent": [{"value": "{{6.data.status}}"}]}}
        log = {"id": 8, "module": "airtable:ActionCreateRecord", "mapper": {"table": SYSLOGS, "record": {"x": "{{6.data.video_url}}"}}}
        b = bp(*video_flow(slack(10, "{{6.data.video_url}}"), log, logger, heygen_get(11, "{{6.data.id}}"),
                           filt(gmail(12, "no link"), [[{"a": "{{6.data.status}}", "o": "exist"}]])))
        self.assertEqual(rows(b, "E22"), [])
        b = bp(*video_flow(gmail(7, "{{6.data.duration}} seconds")))
        self.assertEqual(len(rows(b, "E22", ab.FAIL)), 1)

    def test_send_in_an_error_route_is_skipped(self):
        get = heygen_get()
        get["onerror"] = [gmail(7), {"id": 15, "module": "builtin:Break"}]
        b = bp(watch(), heygen_create(), get, gmail(8, "{{6.data.video_url}}"))
        self.assertEqual([f.module_id for f in rows(b, "E22", ab.FAIL)], [8])

    def test_support_bot_candidate_shape_passes(self):
        """The X-41.16 candidate: router 142 after getVideo 14, route 0 [email 13 gated, Files flag 143, ledger 20], route 1
        (fallback) [ledger 146, Slack 149]."""
        flag = {"id": 143, "module": "airtable:ActionUpdateRecords",
                "mapper": {"id": "{{5.id}}", "table": FILES, "record": {"fld3mvCpdEujuCyyi": True}}}
        led = {"id": 20, "module": "airtable:ActionCreateRecord", "mapper": {"table": SYSLOGS, "record": {"x": "y"}}}
        err = {"id": 146, "module": "airtable:ActionCreateRecord",
               "mapper": {"table": SYSLOGS, "record": {"x": "render {{14.data.status}} {{14.data.error}}"}}}
        email = filt(gmail(13, '<a href="{{14.data.video_url}}">Watch</a> {{14.data.video_url}}'), gate(14, "text:equal:ci"))
        b = bp(watch(), heygen_create(11), sleep(12), heygen_get(14, "{{11.video_id}}"),
               router(142, [email, flag, led], [err, slack(149, "{{14.data.status}}")], fallback=1))
        self.assertEqual(rows(b, "E22"), [])



# ---------------------------------------------------------------------------
# E13 and E22 on HeyGen app version 2 (HeyGen API v3, B6, read 2026-10-31): flat outputs, no data envelope
# ---------------------------------------------------------------------------


def v2_create(mid=131):
    return {"id": mid, "module": "heygen:createAVideo", "version": 2,
            "mapper": {"video_type": "avatar", "avatar_id": "{{2.x}}", "speech_source": "script", "script": "{{2.y}}"}}


def v2_get(mid=135, feed="{{131.video_id}}"):
    return {"id": mid, "module": "heygen:getAVideo", "version": 2, "mapper": {"video_id": feed}}


def v2_gate(g=135, status_op="text:equal:ci"):
    return [[{"a": f"{{{{{g}.status}}}}", "b": "completed", "o": status_op}, {"a": f"{{{{{g}.video_url}}}}", "o": "exist"}]]


def v2_flow(*after):
    return (watch(), v2_create(), sleep(), v2_get()) + tuple(after)


class HeyGenV2Tests(unittest.TestCase):
    def test_flat_outputs_pass_e13(self):
        b = bp(*v2_flow(filt(gmail(7, '<a href="{{135.video_url}}">Watch</a> {{135.status}} {{131.video_id}}'), v2_gate())))
        self.assertEqual(rows(b, "E13"), [])
        self.assertEqual(rows(b, "E22"), [])

    def test_v1_paths_on_a_v2_module_fail_e13(self):
        for ref in ("{{135.data.video_url}}", "{{135.data.status}}", "{{135.url}}", "{{131.id}}"):
            b = bp(*v2_flow(filt(gmail(7, ref), v2_gate())))
            self.assertEqual(len(rows(b, "E13", ab.FAIL)), 1, ref)

    def test_ungated_send_fails_e22_with_the_flat_paths(self):
        fail = rows(bp(*v2_flow(gmail(7, "{{135.video_url}}"))), "E22", ab.FAIL)
        self.assertEqual([f.module_id for f in fail], [7])
        self.assertIn("{{135.status}} text equal completed", fail[0].detail)
        self.assertIn("{{135.video_url}} exists", fail[0].detail)
        self.assertNotIn("data.", fail[0].detail)

    def test_v1_gate_shape_does_not_gate_a_v2_module(self):
        b = bp(*v2_flow(filt(gmail(7, "{{135.video_url}}"), gate(135))))
        self.assertEqual(len(rows(b, "E22", ab.FAIL)), 1)

    def test_case_sensitive_equal_and_route_head_gate_pass(self):
        b = bp(*v2_flow(filt(gmail(7, "{{135.video_url}}"), v2_gate(status_op="text:equal"))))
        self.assertEqual(rows(b, "E22"), [])
        b = bp(*v2_flow(router(10, [filt(setvar(8), v2_gate()), gmail(7, "{{135.video_url}}")], [slack(11)])))
        self.assertEqual(rows(b, "E22"), [])

# ---------------------------------------------------------------------------
# E23 Voice AI Ledger linked to its System Logs row
# ---------------------------------------------------------------------------


def hook(mid=1):
    return {"id": mid, "module": "gateway:CustomWebHook", "parameters": {"hook": 1}}


def details(mid=19):
    return {"id": mid, "module": "bland:getCallDetails", "mapper": {"call_id": "{{1.call_id}}"}}


def syslog_search(mid=3, fid=19):
    return {"id": mid, "module": "airtable:ActionSearchRecords",
            "mapper": {"table": SYSLOGS, "formula": f"{{External Call ID}} = '{{{{{fid}.call_id}}}}'", "maxRecords": "1"}}


def syslog_update(mid, rid="{{3.id}}", record=None):
    return {"id": mid, "module": "airtable:ActionUpdateRecords", "mapper": {"id": rid, "table": SYSLOGS, "record": record or {COST: "1"}}}


def syslog_create(mid, record=None):
    return {"id": mid, "module": "airtable:ActionCreateRecord", "mapper": {"table": SYSLOGS, "record": record or {"x": "y"}}}


def voice_create(mid=2, src=19, link=None):
    rec = {"fldRjBE7U8tq8zAzo": f"{{{{round({src}.call_length * 60)}}}}", "fldr9IGcf4xCdeisR": f"{{{{{src}.call_id}}}}"}
    if link is not None:
        rec.update(link)
    return {"id": mid, "module": "airtable:ActionCreateRecord", "mapper": {"table": VOICE, "record": rec}}


def recon(*after, create=None):
    """Reconciliation Trigger for Campaign 4218934: 1, 19, 3, 23, then 2 behind {{3.id}} exists."""
    c = filt(create or voice_create(), [[{"a": "{{3.id}}", "o": "exist"}]])
    return bp(hook(), details(), syslog_search(), syslog_update(23, record={COST: "{{19.price}}"}), c, *after)


class E23VoiceLedgerLinkTests(unittest.TestCase):
    def test_recon_campaign_shape_fails_and_names_the_lookup(self):
        """L5: 4218934 module 2 maps only the cost fields and the call ID. The hint names search 3, not update 23."""
        fail = rows(recon(syslog_update(5, record={COST: "{{2.`Total Cost`}}"})), "E23", ab.FAIL)
        self.assertEqual([f.module_id for f in fail], [2])
        self.assertIn("[{{3.id}}]", fail[0].detail)
        self.assertIn(SYSTEM_LOG_LINK, fail[0].detail)
        self.assertNotIn(";", fail[0].detail)

    def test_forward_link_passes_in_every_value_form(self):
        """(a) Recon VIP 4226754 module 4 and Batch Call Reconciliation 6847022 module 5 map ["{{<lookup>.id}}"]."""
        for link in ({SYSTEM_LOG_LINK: ["{{3.id}}"]}, {SYSTEM_LOG_LINK: "{{3.id}}"}, {"System Log Link": ["{{3.id}}"]},
                     {"system log link": ["{{ 3.id }}"]}, {SYSTEM_LOG_LINK: ["{{23.id}}"]}):
            self.assertEqual(rows(recon(create=voice_create(link=link)), "E23"), [], link)

    def test_forward_link_to_the_wrong_record_fails(self):
        lead = {"id": 30, "module": "airtable:ActionSearchRecords", "mapper": {"table": LEAD, "formula": "x"}}
        for link in ({SYSTEM_LOG_LINK: ["{{19.id}}"]}, {SYSTEM_LOG_LINK: ["{{30.id}}"]}, {SYSTEM_LOG_LINK: ["{{3.call_id}}"]},
                     {SYSTEM_LOG_LINK: ["{{3.id}}", "{{19.call_id}}"]}, {SYSTEM_LOG_LINK: []}, {SYSTEM_LOG_LINK: "recABCDEFGHIJKLMN"},
                     {SYSTEM_LOG_LINK: ["{{40.id}}"]}, {"Applicant Link": ["{{3.id}}"]}):
            b = bp(hook(), details(), lead, syslog_search(), voice_create(link=link), syslog_create(40))
            self.assertEqual([f.module_id for f in rows(b, "E23", ab.FAIL)], [2], link)

    def test_forward_link_to_a_system_logs_module_in_an_error_route_fails(self):
        d = details()
        d["onerror"] = [syslog_create(50), {"id": 51, "module": "builtin:Break"}]
        b = bp(hook(), d, voice_create(link={SYSTEM_LOG_LINK: ["{{50.id}}"]}))
        self.assertEqual(len(rows(b, "E23", ab.FAIL)), 1)

    def test_back_link_from_a_later_system_logs_write_passes(self):
        """(b) Batch Call Reconciliation 6847022 module 7 maps Voice AI Ledger ["{{5.id}}"] on the looked-up row."""
        for record in ({VOICE_LINK: ["{{2.id}}"]}, {"Voice AI Ledger": "{{2.id}}"}):
            b = recon(syslog_update(5, record=record))
            self.assertEqual(rows(b, "E23"), [], record)
        b = recon(syslog_create(6, {VOICE_LINK: ["{{2.id}}"]}))
        self.assertEqual(rows(b, "E23"), [])

    def test_pending_call_shape_passes_through_a_later_route(self):
        """Pending Call 3943741: ledger row 76 has no forward link, marker rows 81 (route 0) and 136 (route 2) of router
        10 link back. Route 1 (83) does not, which (b) does not catch (one later path is enough)."""
        b = bp(hook(3), details(5), voice_create(76, 5),
               router(10, [syslog_create(81, {VOICE_LINK: ["{{76.id}}"]})], [syslog_create(83, {COST: "1"})],
                      [syslog_create(136, {VOICE_LINK: ["{{76.id}}"]})]))
        self.assertEqual(rows(b, "E23"), [])

    def test_back_link_that_cannot_reach_the_row_fails(self):
        before = syslog_create(7, {VOICE_LINK: ["{{2.id}}"]})  # runs before 2, so 2.id is empty there
        b = bp(hook(), details(), before, voice_create())
        self.assertEqual(len(rows(b, "E23", ab.FAIL)), 1)
        b = bp(hook(), details(), router(10, [voice_create()], [syslog_update(7, record={VOICE_LINK: ["{{2.id}}"]})]))
        self.assertEqual(rows(b, "E23"), [], "a later route of the same router runs after the create")
        b = bp(hook(), details(), router(10, [syslog_update(7, record={VOICE_LINK: ["{{2.id}}"]})], [voice_create()]))
        self.assertEqual(len(rows(b, "E23", ab.FAIL)), 1, "an earlier route runs before the create")
        v = voice_create()
        v["onerror"] = [syslog_create(8, {VOICE_LINK: ["{{2.id}}"]}), {"id": 9, "module": "builtin:Resume"}]
        b = bp(hook(), details(), v)
        self.assertEqual(len(rows(b, "E23", ab.FAIL)), 1, "an error route write does not count")
        b = bp(hook(), details(), voice_create(), syslog_update(7, record={VOICE_LINK: ["{{19.id}}"], COST: "{{2.id}}"}))
        self.assertEqual(len(rows(b, "E23", ab.FAIL)), 1, "the back link must reference this row, in the Voice AI Ledger field")

    def test_grader_shape_fails_and_the_candidate_passes(self):
        """The Interview Room (B) Grader 3975156: 22 sits on route 1 of router 24, after search 61 and update 62 on the main
        flow. X-45.1 adds System Log Link ["{{61.id}}"]."""
        def grader(link=None):
            return bp(hook(), details(60), syslog_search(61, 60),
                      filt(syslog_update(62, "{{61.id}}", {COST: "{{60.price}}"}), [[{"a": "{{61.id}}", "o": "exist"}]]),
                      router(24, [{"id": 14, "module": "airtable:ActionSearchRecords", "mapper": {"table": LEAD}}],
                             [voice_create(22, 60, link)]))
        fail = rows(grader(), "E23", ab.FAIL)
        self.assertEqual([f.module_id for f in fail], [22])
        self.assertIn("[{{61.id}}]", fail[0].detail)
        self.assertEqual(rows(grader({SYSTEM_LOG_LINK: ["{{61.id}}"]}), "E23"), [])

    def test_out_of_scope_modules_are_skipped(self):
        v = voice_create(20)
        upd = {"id": 21, "module": "airtable:ActionUpdateRecords", "mapper": {"id": "{{20.id}}", "table": VOICE, "record": {"x": "1"}}}
        d = details()
        d["onerror"] = [voice_create(30), {"id": 31, "module": "builtin:Break"}]
        b = bp(hook(), d, filt(v, []), upd)
        self.assertEqual([f.module_id for f in rows(b, "E23", ab.FAIL)], [20], "the update and the error-route create are skipped")

    def test_no_system_logs_module_gives_the_generic_fix(self):
        fail = rows(bp(hook(), details(), voice_create()), "E23", ab.FAIL)
        self.assertEqual(len(fail), 1)
        self.assertIn("the record ID of the run's System Logs row", fail[0].detail)


# ---------------------------------------------------------------------------
# The committed snapshots
# ---------------------------------------------------------------------------


def full_audit():
    """The audit as main() runs it on blueprints/ in manifest mode, without writing a report."""
    folder = os.path.join(ROOT, "blueprints")
    manifest = os.path.join(folder, "manifest.json")
    bps, coverage = ab.load_manifest_mode(folder, manifest)
    res = ab.audit(bps, ab.load_labels(os.path.join(ROOT, "audit", "scenario_labels.json")),
                   ab.load_schema(os.path.join(ROOT, "audit", "airtable_ledger_schema.json")), True, coverage, LINKS,
                   ab.load_allowlist(ab.DEFAULT_ALLOWLIST), ab.load_webhooks(ab.DEFAULT_WEBHOOKS),
                   ab.load_hooks_info(manifest), ab.secret_scan.load_secret_allowlist(ab.DEFAULT_SECRET_ALLOWLIST),
                   status_designs=ab.load_status_designs(ab.DEFAULT_STATUS_ALLOW), schedule=ab.load_schedule_info(manifest))
    ids = {b.name: str(b.scenario_id) for b in bps}
    return res, ids


class SnapshotRowsTests(unittest.TestCase):
    """E22 and E23 on the committed snapshots FAIL exactly the modules the wave 1 plan lists (critic section 3). Auto-Celebrate
    5091060 email 7 already carries the render gate (X-41.4). Pending Call 76, Batch Call Reconciliation 5 and Recon VIP 4
    link their System Logs row."""

    EXPECTED = set()  # X-45.1 closed E23. X-41.16 with B6 (2026-10-31, Support Bot v30) closed E22 on 13

    def test_rows_on_live_snapshots(self):
        if not os.path.exists(os.path.join(ROOT, "blueprints", "manifest.json")):
            self.skipTest("no committed snapshots")
        res, ids = full_audit()
        got = set()
        for f in res.findings:
            if f.rule in ("E22", "E23"):
                self.assertEqual(f.status, ab.FAIL, f.detail)
                self.assertNotIn(";", f.detail)  # report prose carries no semicolons
                self.assertNotIn("—", f.detail)
                got.add((f.rule, ids[f.scenario], f.module_id))
        self.assertEqual(got, self.EXPECTED)

    def test_rules_cannot_be_allowlisted(self):
        self.assertNotIn("E22", ab.ALLOW_RULES)
        self.assertNotIn("E23", ab.ALLOW_RULES)


if __name__ == "__main__":
    unittest.main()
