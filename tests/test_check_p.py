"""Check P, AI model pinning (X-15, X-18, decided by Rizwan 2026-10-30: Anthropic only, claude-opus-5-5 and
claude-haiku-5-5). Synthetic fixtures shaped like the live OpenAI calls (Customer Support Bot 2, 8, 10, Pending Call 13)
and their replacement, anthropic-claude:createAMessage v1. No network, no client data."""

import json
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import audit_blueprints as ab  # noqa: E402
import make_push  # noqa: E402

# Built with concatenation, never str.format or an f-string, so the braces stay as written.
def text_of(n):
    return "{{first(map(" + str(n) + '.content; "text"; "type"; "text"))}}'


def bp(*flow, name="Customer Support Bot for existing clients", sid="3954492"):
    return ab.Blueprint(name=name, scenario_id=sid, source="test",
                        bp={"name": "x", "flow": [{"id": 1, "module": "google-email:triggerWatchNewEmails"}, *flow],
                            "metadata": {}})


def claude(mid=20, model="claude-haiku-5-5", max_tokens=2048, version=1, **mapper):
    mp = {"model": model, "max_tokens": max_tokens,
          "messages": [{"role": "user", "inputType": "single", "content": "Reply to {{1.text}}"}]}
    mp.update(mapper)
    return {"id": mid, "module": "anthropic-claude:createAMessage", "version": version,
            "parameters": {"__IMTCONN__": 999999999}, "mapper": mp}


def opus(mid=20, max_tokens=16000, **mapper):
    mapper.setdefault("thinking", {"type": "adaptive"})
    return claude(mid, model="claude-opus-5-5", max_tokens=max_tokens, **mapper)


def openai(mid=2):
    return {"id": mid, "module": "openai-gpt-3:CreateCompletion", "version": 1,
            "mapper": {"model": "gpt-5-mini", "max_tokens": 2048, "temperature": "1", "top_p": "1",
                       "messages": [{"role": "user", "content": "x"}]}}


def ledger(mid, ai):
    return {"id": mid, "module": "airtable:ActionCreateRecord",
            "mapper": {"table": ab.LEDGER_TABLE, "record": {ab.AI_RESPONSE_FIELD: ai}}}


def gmail(mid, body):
    return {"id": mid, "module": "google-email:sendAnEmail", "mapper": {"to": ["{{1.from}}"], "html": body}}


def heygen(mid, script):
    return {"id": mid, "module": "heygen:createAvatarVideo", "mapper": {"input_text": script}}


def stop_filter(m, n, op="text:equal", value="end_turn", groups=None):
    cond = {"a": "{{" + str(n) + ".stop_reason}}", "o": op, "b": value}
    m = dict(m)
    m["filter"] = {"name": "Claude finished", "conditions": groups if groups is not None else [[cond]]}
    return m


def rows(*flow):
    return [(f.status, f.module_id, f.detail) for f in ab.check_p(bp(*flow))]


def fails(*flow):
    return {m: d for s, m, d in rows(*flow) if s == ab.FAIL}


class P1Tests(unittest.TestCase):
    def test_live_openai_call_fails_p1(self):
        r = rows(openai(2), ledger(18, "{{2.choices[].message.content}}"))
        self.assertEqual([(s, m) for s, m, _ in r], [("FAIL", 2)])
        self.assertIn("P1 openai-gpt-3:CreateCompletion", r[0][2])

    def test_openai_in_an_error_route_fails(self):
        owner = ledger(5, "x")
        owner["onerror"] = [openai(30), {"id": 31, "module": "builtin:Break"}]
        self.assertIn(30, fails(owner))

    def test_http_call_to_an_llm_host_fails(self):
        for url in ("https://api.openai.com/v1/chat/completions", "https://api.anthropic.com/v1/messages"):
            with self.subTest(url=url):
                h = {"id": 7, "module": "http:MakeRequest", "mapper": {"url": url, "method": "post"}}
                self.assertIn("P1 calls", fails(h)[7])

    def test_other_llm_app_modules_fail(self):
        for t in ("openai:createChatCompletion", "anthropic-claude:makeAnApiCall", "anthropic:createMessage",
                  "google-gemini-ai:generate"):
            with self.subTest(t=t):
                self.assertIn("P1", fails({"id": 9, "module": t, "mapper": {}})[9])

    def test_claude_module_of_another_version_fails(self):
        self.assertIn("P1", fails(claude(version=2))[20])

    def test_non_llm_modules_and_other_http_calls_have_no_row(self):
        h = {"id": 7, "module": "http:MakeRequest", "mapper": {"url": "https://api.bland.ai/v1/calls", "method": "post"}}
        self.assertEqual(rows(h, ledger(8, "{{7.data}}"), gmail(9, "hi")), [])


class P2P3P4Tests(unittest.TestCase):
    def test_haiku_and_opus_pinned_pass(self):
        self.assertEqual([(s, m) for s, m, _ in rows(claude(20), opus(21, thinking={"type": "adaptive"}))],
                         [("PASS", 20), ("PASS", 21)])

    def test_haiku_may_disable_thinking(self):
        self.assertEqual(fails(claude(thinking={"type": "disabled"})), {})

    def test_model_must_be_a_pinned_literal(self):
        for model in ("claude-sonnet-5-5", "claude-opus-5", "claude-haiku-latest", "gpt-5-mini", "", None,
                      "{{1.model}}", "Claude-Haiku-5-5"):
            with self.subTest(model=model):
                self.assertIn("P2 model", fails(claude(model=model))[20])

    def test_model_through_additional_parameters_fails(self):
        extra = [{"key": "model", "type": "text", "value": "claude-sonnet-5-5"}]
        self.assertIn("P2 additionalParameters sets model", fails(claude(additionalParameters=extra))[20])

    def test_sampling_parameters_fail(self):
        for k, v in (("temperature", 1), ("temperature", "0.2"), ("top_p", "1"), ("top_k", 40)):
            with self.subTest(k=k):
                self.assertIn(f"P3 sets {k}", fails(claude(**{k: v}))[20])

    def test_blank_sampling_fields_count_as_unset(self):
        self.assertEqual(fails(claude(temperature="", top_p=None)), {})

    def test_sampling_through_additional_parameters_fails(self):
        for k in ("temperature", "top_p", "top_k", "thinking", "budget_tokens"):
            with self.subTest(k=k):
                extra = [{"key": k, "type": "number", "value": 1}]
                self.assertIn(f"P3 additionalParameters sets {k}", fails(claude(additionalParameters=extra))[20])

    def test_thinking_enabled_or_budget_fails(self):
        self.assertIn("P3 thinking type is enabled", fails(claude(thinking={"type": "enabled", "budget_tokens": 1024}))[20])
        self.assertIn("budget_tokens", fails(claude(thinking={"type": "enabled", "budget_tokens": 1024}))[20])
        self.assertIn("P3 thinking carries budget_tokens", fails(opus(thinking={"type": "adaptive", "budget_tokens": 4000}))[20])

    def test_opus_thinking_disabled_fails(self):
        self.assertIn("P3 thinking is disabled on claude-opus-5-5", fails(opus(thinking={"type": "disabled"}))[20])

    def test_thinking_mapped_or_unknown_fails(self):
        self.assertIn("mapping", fails(opus(thinking={"type": "{{1.mode}}"}))[20])
        self.assertIn("not one of", fails(opus(thinking={"type": "auto"}))[20])
        self.assertIn("not a literal", fails(opus(thinking="{{1.mode}}"))[20])

    def test_max_tokens_floor_per_model(self):
        self.assertIn("P4 max_tokens 2048 is below 16000", fails(opus(max_tokens=2048))[20])
        self.assertIn("P4 max_tokens 1024 is below 2048", fails(claude(max_tokens=1024))[20])
        self.assertEqual(fails(opus(max_tokens="16000"), claude(21, max_tokens=4096)), {})

    def test_max_tokens_must_be_a_literal_integer(self):
        for v in ("{{1.n}}", "2048.5", None, "", True):
            with self.subTest(v=v):
                self.assertIn("P4 max_tokens", fails(claude(max_tokens=v))[20])

    def test_max_tokens_through_additional_parameters_fails(self):
        extra = [{"key": "max_tokens", "type": "number", "value": 100}]
        self.assertIn("P4 additionalParameters sets max_tokens", fails(claude(additionalParameters=extra))[20])


class P5Tests(unittest.TestCase):
    def test_the_accepted_form_passes(self):
        self.assertEqual(fails(claude(), ledger(18, text_of(20))), {})

    def test_the_form_inside_a_bigger_expression_passes(self):
        self.assertEqual(fails(claude(), ledger(18, "Answer: {{trim(" + text_of(20)[2:-2] + ")}} end")), {})

    def test_whitespace_inside_the_form_is_allowed(self):
        self.assertEqual(fails(claude(), ledger(18, '{{first( map( 20.content ; "text" ; "type" ; "text" ) )}}')), {})

    def test_index_bare_or_other_shapes_fail(self):
        for v in ("{{20.content[1].text}}", "{{20.content[].text}}", "{{20.content}}", "{{get(20.content; 1)}}",
                  '{{first(map(20.content; "text"))}}', '{{last(map(20.content; "text"; "type"; "text"))}}',
                  '{{first(map(20.content; "thinking"; "type"; "thinking"))}}', "{{20.`content`[1].text}}"):
            with self.subTest(v=v):
                self.assertIn("P5", fails(claude(), ledger(18, v)).get(18, ""))

    def test_reads_in_filters_and_error_routes_count(self):
        f = ledger(18, "x")
        f["filter"] = {"name": "has text", "conditions": [[{"a": "{{20.content[1].text}}", "o": "exist"}]]}
        self.assertIn("filter", fails(claude(), f)[18])
        owner = ledger(5, "x")
        owner["onerror"] = [ledger(30, "{{20.content}}"), {"id": 31, "module": "builtin:Ignore"}]
        self.assertIn(30, fails(claude(), owner))

    def test_openai_only_outputs_of_a_claude_module_fail(self):
        for v in ("{{20.choices[].message.content}}", "{{20.usage.prompt_tokens}}", "{{20.usage.completion_tokens}}",
                  "{{20.result}}"):
            with self.subTest(v=v):
                self.assertIn("P5", fails(claude(), ledger(18, v)).get(18, ""))
        self.assertEqual(fails(claude(), ledger(18, "{{20.usage.input_tokens}} {{20.usage.output_tokens}} {{20.stop_reason}}")), {})

    def test_status_write_mapping_the_text_by_index_fails_on_the_write(self):
        upd = {"id": 8, "module": "airtable:ActionUpdateRecords",
               "mapper": {"table": ab.LEAD_TABLE, "id": "{{1.id}}", "record": {ab.STATUS_FIELD: "{{20.content[1].text}}"}}}
        self.assertIn("P5", fails(claude(), upd)[8])

    def test_references_to_other_modules_are_not_p5(self):
        self.assertEqual(fails(claude(), ledger(18, "{{1.content[1].text}} {{7.choices}}")), {})

    def test_report_text_has_no_semicolons(self):
        detail = fails(claude(), ledger(18, "{{20.content}}"))[18]
        self.assertNotIn(";", detail)
        self.assertNotIn(";", ab.SECTION_INTRO["P"])


class P6Tests(unittest.TestCase):
    def test_send_without_the_stop_filter_fails(self):
        r = fails(claude(), gmail(9, text_of(20)))
        self.assertIn("P6", r[9])
        self.assertIn("{{20.stop_reason}}", r[9])

    def test_send_with_the_filter_on_itself_passes(self):
        self.assertEqual(fails(claude(), stop_filter(gmail(9, text_of(20)), 20)), {})

    def test_filter_on_an_earlier_module_after_the_claude_call_passes(self):
        self.assertEqual(fails(claude(), stop_filter(ledger(18, text_of(20)), 20), gmail(9, text_of(20))), {})

    def test_filter_on_the_first_module_of_a_route_passes(self):
        router = {"id": 50, "module": "builtin:BasicRouter",
                  "routes": [{"flow": [stop_filter(ledger(18, text_of(20)), 20), heygen(11, text_of(20))]},
                             {"flow": [heygen(12, text_of(20))]}]}
        r = fails(claude(), router)
        self.assertNotIn(11, r)
        self.assertIn("P6", r[12])

    def test_filter_before_the_claude_call_does_not_count(self):
        self.assertIn("P6", fails(stop_filter(ledger(18, "x"), 20), claude(), gmail(9, text_of(20)))[9])

    def test_wrong_filters_do_not_count(self):
        good = {"a": "{{20.stop_reason}}", "o": "text:equal", "b": "end_turn"}
        other = {"a": "{{1.id}}", "o": "exist"}
        cases = {
            "two OR groups": dict(groups=[[good], [other]]),
            "not equal": dict(op="text:notequal"),
            "another value": dict(value="max_tokens"),
            "case differs without :ci": dict(value="End_Turn"),
            "contains": dict(op="text:contain"),
        }
        for name, kw in cases.items():
            with self.subTest(name=name):
                self.assertIn("P6", fails(claude(), stop_filter(gmail(9, text_of(20)), 20, **kw))[9])
        self.assertIn("P6", fails(claude(), claude(21), stop_filter(gmail(9, text_of(20)), 21))[9])

    def test_case_insensitive_equal_and_extra_and_conditions_pass(self):
        self.assertEqual(fails(claude(), stop_filter(gmail(9, text_of(20)), 20, op="text:equal:ci", value="END_TURN")), {})
        groups = [[{"a": "{{1.id}}", "o": "exist"}, {"a": "{{20.stop_reason}}", "o": "text:equal", "b": "end_turn"}]]
        self.assertEqual(fails(claude(), stop_filter(gmail(9, text_of(20)), 20, groups=groups)), {})

    def test_client_send_kinds(self):
        sends = (gmail(9, text_of(20)), heygen(11, text_of(20)),
                 {"id": 12, "module": "twilio:SendSMS", "mapper": {"body": text_of(20)}},
                 {"id": 13, "module": "bland:sendACall", "mapper": {"task": text_of(20)}})
        for s in sends:
            with self.subTest(t=s["module"]):
                self.assertIn("P6", fails(claude(), s)[s["id"]])

    def test_sends_that_do_not_map_claude_text_need_no_filter(self):
        self.assertEqual(fails(claude(), gmail(9, "{{1.subject}} {{20.stop_reason}}")), {})

    def test_heygen_reads_are_not_sends(self):
        self.assertEqual(fails(claude(), {"id": 11, "module": "heygen:getVideoStatus", "mapper": {"q": text_of(20)}}), {})


class OtherChecksSeeClaudeTests(unittest.TestCase):
    """Checks B, D, E1, E2 and F3 treat anthropic-claude modules like the OpenAI module they replace."""

    def test_check_b_needs_a_handler_on_the_claude_call(self):
        res = ab.check_b(bp(claude()))
        self.assertEqual([(f.status, f.module_id) for f in res], [("FAIL", 20)])

    def test_f3_counts_the_claude_call_as_a_paid_call(self):
        self.assertTrue(ab.is_external(claude()))
        self.assertTrue(ab._is_effect(claude()))
        self.assertEqual(ab._f3_kind(claude(), ab._DEFAULT_LEAD), "paid call")

    def test_e1_skips_a_claude_module_with_no_interface_as_info_and_e2_accepts_the_form(self):
        res = ab.check_e(bp(claude(), ledger(18, text_of(20) + " {{20.usage.input_tokens}}")), ab.AirtableMap(), ab.Allowlist())
        e = [(f.status, f.module_id, f.rule) for f in res]
        self.assertNotIn(ab.FAIL, [s for s, _m, _r in e])
        self.assertIn((ab.INFO, 20, "E1"), e)

    def test_check_d_finds_an_anthropic_key_literal_in_a_claude_call(self):
        key = "sk" + "-ant-" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4"
        extra = [{"key": "x-api-key", "type": "text", "value": key}]
        res = ab.check_d(bp(claude(additionalParameters=extra)))
        self.assertTrue(res)
        self.assertTrue(all((f.status, f.module_id) == ("FAIL", 20) for f in res))
        self.assertIn("anthropic_api_key", " ".join(f.detail for f in res))
        self.assertFalse(any(key in f.detail for f in res))


class WiringTests(unittest.TestCase):
    def test_fix_ids_map_to_check_p(self):
        for fix in ("X-15", "X-18", "X-15.1"):
            self.assertEqual(make_push.fix_checks(fix), ("P",))

    def test_check_p_is_listed_and_runs_in_the_audit(self):
        self.assertIn("P", ab.CHECKS)
        self.assertIn("P", ab.CHECK_TITLES)
        self.assertIn("P", ab.SECTION_INTRO)
        labels = ab.Labels(confirmed=True, scenarios={})
        res = ab.audit([bp(openai(2))], labels, ab.Schema([], []), True, partial=True)
        self.assertEqual([(f.status, f.module_id) for f in res.findings if f.check == "P"], [("FAIL", 2)])

    def test_one_constant_holds_the_allowed_models(self):
        self.assertEqual(ab.CLAUDE_MODELS, ("claude-opus-5-5", "claude-haiku-5-5"))
        self.assertEqual(set(ab.CLAUDE_MIN_MAX_TOKENS), set(ab.CLAUDE_MODELS))


def http(mid, url, **mapper):
    mp = {"url": url, "method": "post"}
    mp.update(mapper)
    return {"id": mid, "module": "http:MakeRequest", "version": 4, "mapper": mp}


def setvar(mid, value):
    return {"id": mid, "module": "util:SetVariable2", "mapper": {"name": "r", "value": value}}


class ReviewFixTests(unittest.TestCase):
    """Review 2 of X-15 and X-18 (2026-10-30): each case passed check P before the fix."""

    # P6 transitive taint
    def test_relay_through_set_variable_needs_the_guard(self):
        r = fails(claude(), setvar(21, text_of(20)), gmail(22, "{{21.r}}"))
        self.assertIn("P6", r[22])
        self.assertNotIn(21, r)

    def test_relay_through_two_modules_needs_the_guard(self):
        parse = {"id": 21, "module": "json:ParseJSON", "mapper": {"json": text_of(20)}}
        row = ledger(22, "{{21.reply}}")
        self.assertIn("P6", fails(claude(), parse, row, gmail(23, "{{22.id}}"))[23])

    def test_relay_with_the_guard_passes(self):
        self.assertEqual(fails(claude(), stop_filter(setvar(21, text_of(20)), 20), gmail(22, "{{21.r}}")), {})

    def test_stop_reason_relay_is_not_text(self):
        self.assertEqual(fails(claude(), setvar(21, "{{20.stop_reason}}"), gmail(22, "{{21.r}}")), {})

    # P6 send kinds
    def test_more_client_send_kinds(self):
        sends = (http(21, "https://api.bland.ai/v1/calls", body=text_of(20)),
                 http(21, "https://api.twilio.com/2010-04-01/Accounts/x/Messages.json", body=text_of(20)),
                 {"id": 21, "module": "bland:makeAnApiCall", "mapper": {"url": "/v1/calls", "body": text_of(20)}},
                 {"id": 21, "module": "telegram:SendReplyMessage", "mapper": {"text": text_of(20)}},
                 {"id": 21, "module": "google-email:replyToAnEmail", "mapper": {"body": text_of(20)}},
                 {"id": 21, "module": "microsoft-email:replyToAnEmail", "mapper": {"body": text_of(20)}},
                 {"id": 21, "module": "google-email:forwardAnEmail", "mapper": {"body": text_of(20)}},
                 {"id": 21, "module": "twilio:makeAnApiCall", "mapper": {"url": "/Messages.json", "body": text_of(20)}})
        for s in sends:
            with self.subTest(t=s["module"], u=s["mapper"].get("url")):
                self.assertIn("P6", fails(claude(), s)[21])

    def test_http_to_other_hosts_is_not_a_send(self):
        self.assertEqual(fails(claude(), http(21, "https://api.example.com/v1/notes", body=text_of(20))), {})

    # P5 allow-list
    def test_fields_a_claude_message_does_not_have_fail(self):
        for v in ("{{20.completion}}", "{{20.message.content}}", "{{20.text}}", "{{20.usage.total_tokens}}",
                  "{{20.`usage`.`prompt_tokens`}}"):
            with self.subTest(v=v):
                self.assertIn("P5", fails(claude(), ledger(18, v)).get(18, ""))

    def test_get_on_a_claude_module_fails(self):
        for v in ('{{get(20; "content")}}', '{{get(20.usage; "prompt_tokens")}}', '{{get( 20 ; "choices")}}'):
            with self.subTest(v=v):
                self.assertIn("P5", fails(claude(), ledger(18, v)).get(18, ""))

    def test_claude_fields_pass(self):
        v = ("{{20.id}} {{20.model}} {{20.stop_reason}} {{20.stop_details.category}} {{20.usage.input_tokens}} "
             "{{20.usage.output_tokens}} {{20.usage.cache_read_input_tokens}}")
        self.assertEqual(fails(claude(), ledger(18, v)), {})

    def test_error_fields_only_in_the_claude_modules_own_handler(self):
        c = claude()
        c["onerror"] = [ledger(30, "{{20.error.type}} {{20.error.message}}"), {"id": 31, "module": "builtin:Break"}]
        self.assertEqual(fails(c), {})
        self.assertIn("P5", fails(claude(), ledger(18, "{{20.error.message}}")).get(18, ""))

    # P1 hosts and apps
    def test_more_llm_hosts_fail(self):
        for url in ("https://openrouter.ai/api/v1/chat/completions",
                    "https://myres.openai.azure.com/openai/deployments/x/chat/completions",
                    "https://bedrock-runtime.us-east-1.amazonaws.com/model/anthropic.claude-haiku/invoke",
                    "https://us-east5-aiplatform.googleapis.com/v1/projects/p/publishers/anthropic/models/c:rawPredict",
                    "https://api.x.ai/v1/chat/completions", "https://api.together.xyz/v1/chat/completions",
                    "https://api.fireworks.ai/inference/v1/chat/completions"):
            with self.subTest(url=url):
                self.assertIn("P1 calls", fails(http(30, url))[30])

    def test_mapped_http_host_fails_unless_it_is_the_logger(self):
        self.assertIn("P1", fails(http(30, "{{var.team.LLM_URL}}"))[30])
        self.assertIn("P1", fails(http(30, "https://{{1.host}}/v1/x"))[30])
        self.assertEqual(fails(http(30, "https://api.example.com/v1/{{1.id}}")), {})
        spec = ab.LoggerSpec(None, None, url_variable="var.team.IMMIOS_LOGGER_URL")
        res = ab.check_p(bp(http(30, "{{var.team.IMMIOS_LOGGER_URL}}")), spec)
        self.assertEqual([f for f in res if f.status == ab.FAIL], [])

    def test_more_llm_apps_fail(self):
        for t in ("openrouter:createChatCompletion", "replicate:createPrediction", "huggingface:x",
                  "xai:createChatCompletion", "google-vertex-ai:x", "aws-bedrock:x", "together-ai:x", "fireworks:x"):
            with self.subTest(t=t):
                self.assertIn("P1", fails({"id": 9, "module": t, "mapper": {}})[9])

    # P3 Opus thinking pinned
    def test_opus_thinking_missing_or_empty_fails(self):
        for th in (None, {}, {"type": ""}):
            with self.subTest(th=th):
                m = claude(model="claude-opus-5-5", max_tokens=16000)
                if th is not None:
                    m["mapper"]["thinking"] = th
                self.assertIn("P3 thinking", fails(m)[20])

    def test_haiku_without_thinking_still_passes(self):
        self.assertEqual(fails(claude()), {})

    # P2 and P3 additionalParameters keys
    def test_mapped_additional_key_fails(self):
        extra = [{"key": '{{"temperature"}}', "type": "number", "value": 0}]
        self.assertIn("P3 additionalParameters key is a mapping", fails(claude(additionalParameters=extra))[20])

    def test_additional_keys_compare_case_and_space_insensitive(self):
        for k in ("Temperature", " top_k ", "MODEL", "Max_Tokens"):
            with self.subTest(k=k):
                extra = [{"key": k, "type": "number", "value": 1}]
                self.assertIn("additionalParameters sets", fails(claude(additionalParameters=extra))[20])



UI_EXPECT = {"expect": [{"name": "outputFormat", "type": "collection",
                        "spec": [{"name": "type", "type": "select"}, {"name": "schema", "type": "json", "required": True}]}]}


def ui_saved(module):
    """A Claude module as a save in the Make UI leaves it: metadata.expect types outputFormat.schema as json."""
    module["metadata"] = dict(UI_EXPECT, designer={"x": 0, "y": 0})
    return module


class P7SchemaTextTests(unittest.TestCase):
    """Measured 2026-11-14 on VIP intake module 81: Make refuses an object schema before the call ("Invalid json string in
    parameter 'schema'. Value has to be string.") and runs the same schema saved as JSON text."""
    SCHEMA = {"type": "object", "properties": {"a": {"type": "string"}}, "required": ["a"], "additionalProperties": False}

    def test_object_schema_fails(self):
        f = fails(claude(outputFormat={"type": "json_schema", "schema": self.SCHEMA}))
        self.assertIn("P7", f.get(20, ""), f)
        self.assertIn("is a dict", f[20])

    def test_bad_text_schemas_fail(self):
        for bad, needle in (("{not json", "not valid JSON"), ('"just a string"', "of a str"), ("[1, 2]", "of a list"),
                            ('{"type": "{{1.x}}"}', "holds a mapping"), (None, "is a NoneType")):
            with self.subTest(bad=bad):
                f = fails(claude(outputFormat={"type": "json_schema", "schema": bad}))
                self.assertIn(needle, f.get(20, ""), f)

    def test_text_schema_on_a_ui_saved_module_and_text_format_pass(self):
        for fmt in ({"type": "json_schema", "schema": json.dumps(self.SCHEMA)},
                    {"type": "json_schema", "schema": json.dumps(self.SCHEMA, indent=2)}):
            with self.subTest(fmt=fmt):
                self.assertNotIn("P7", fails(ui_saved(claude(outputFormat=fmt))).get(20, ""))
        self.assertNotIn("P7", fails(claude(outputFormat={"type": "text"})).get(20, ""))

    def test_text_schema_on_an_api_built_module_fails(self):
        # Measured 2026-11-14 on Market Watchdog 79: text schema, no metadata.expect, 400 Input should be an object.
        f = fails(claude(outputFormat={"type": "json_schema", "schema": json.dumps(self.SCHEMA)}))
        self.assertIn("not typed as json in the module's metadata.expect", f.get(20, ""), f)
        other = ui_saved(claude(outputFormat={"type": "json_schema", "schema": json.dumps(self.SCHEMA)}))
        other["metadata"]["expect"][0]["spec"][1]["type"] = "text"
        self.assertIn("not typed as json", fails(other).get(20, ""))

    def test_nan_and_infinity_are_not_valid_json(self):
        for bad in ('{"type": "number", "maximum": NaN}', '{"m": Infinity}', '{"m": -Infinity}'):
            with self.subTest(bad=bad):
                self.assertIn("not valid JSON", fails(claude(outputFormat={"type": "json_schema", "schema": bad})).get(20, ""))

if __name__ == "__main__":
    unittest.main()
