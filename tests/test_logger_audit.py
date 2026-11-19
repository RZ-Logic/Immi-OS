"""Tests for F-E5 v3, Option C (decided by Rizwan 2026-10-29): check B v3 (one Logger call plus one directive), check C on
Logger call labels, check E6 and F2c on Logger call bodies, check L (the shared Logger) and the Logger entry of
audit/webhooks.json. The Error Monitor (check G) and audit/critical_modules.json are retired.

Everything is synthetic, or the shipped specs/logger.blueprint.json with the hook filled in. No network, no Make API.
"""

import copy
import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import audit_blueprints as ab  # noqa: E402

LEDGER = ab.LEDGER_TABLE
LEAD = ab.LEAD_TABLE
VAR = "var.team.IMMIOS_LOGGER_URL"
CONN = 4242
LOGGER_ID = "900"
HOOK = 77
SPEC = ab.LoggerSpec(LOGGER_ID, HOOK, VAR, CONN, "The shared Logger, a sentence")
SHIPPED = os.path.join(ROOT, "specs", "logger.blueprint.json")
SCHEMA = os.path.join(ROOT, "tests", "fixtures", "schema.json")
LABEL = "Lead Qualifier"   # a Single Select option of the fixture schema


# ---------------------------------------------------------------------------
# Synthetic module builders
# ---------------------------------------------------------------------------


def trigger(mid=1):
    return {"id": mid, "module": "google-email:triggerWatchNewEmails", "parameters": {"limit": 1}}


def ext(mid, module="google-sheets:addRow"):  # a neutral external call (an OpenAI module would FAIL check P1)
    return {"id": mid, "module": module}


def ledger(mid, label=LABEL, **record):
    rec = {ab.LABEL_FIELD: label}
    rec.update(record)
    return {"id": mid, "module": "airtable:ActionCreateRecord", "mapper": {"table": LEDGER, "record": rec}}


def slack(mid, text="{{error.message}}"):
    return {"id": mid, "module": "slack:CreateMessage", "mapper": {"text": text}}


def directive(mid, kind="Break", **mapper):
    m = {"id": mid, "module": "builtin:" + kind}
    if mapper:
        m["mapper"] = mapper
    return m


def with_handler(m, *handler):
    m = dict(m)
    m["onerror"] = list(handler)
    return m


def router(mid, *routes):
    return {"id": mid, "module": "builtin:BasicRouter", "routes": [{"flow": list(r)} for r in routes]}


def body(owner, label=LABEL, **over):
    """The contract body (specs/F-E5-v3-shared-logger.md section 4). over sets a field, None drops it."""
    b = {"label": label, "outcome": "Error", "module_id": str(owner), "module_name": "Completion",
         "error_type": "{{%s.error.type}}" % owner, "error_message": "{{%s.error.message}}" % owner,
         "execution_id": "{{var.scenario.executionId}}"}
    b.update(over)
    return [{"name": k, "value": v} for k, v in b.items() if v is not None]


def call(mid, owner, label=LABEL, params=None, **mapper):
    """A logger call that meets the contract. mapper overrides top-level mapper keys, a None value drops the key."""
    m = {"id": mid, "module": "http:MakeRequest", "version": 4,
         "parameters": params if params is not None else {"authenticationType": "apiKeyConnection", "apiKeyAccount": CONN},
         "mapper": {"url": "{{%s}}" % VAR, "method": "post", "headers": [], "queryParameters": [], "contentType": "urlEncoded",
                    "urlEncodedBodyContent": body(owner, label), "parseResponse": False, "stopOnHttpError": False,
                    "allowRedirects": False}}
    for k, v in mapper.items():
        if v is None:
            m["mapper"].pop(k, None)
        else:
            m["mapper"][k] = v
    return m


def blueprint(name, *flow, scenario_id="500", meta=None):
    return ab.Blueprint(name=name, scenario_id=scenario_id, source="test",
                        bp={"name": name, "flow": list(flow), "metadata": meta if meta is not None else {}})


def labels(confirmed=True, **entries):
    sc = {"500": {"name": "S", "expected_label": LABEL}}
    sc.update(entries)
    return ab.Labels(confirmed=confirmed, scenarios=sc)


def schema():
    return ab.load_schema(SCHEMA)


def rows(findings, status=None, check=None):
    return [f for f in findings if (status is None or f.status == status) and (check is None or f.check == check)]


def b_row(flow_owner, *handler, spec=SPEC, before=()):
    """The B row of module 2 in [trigger, *before, module 2 with this handler]."""
    res = ab.check_b(blueprint("S", trigger(), *before, with_handler(flow_owner, *handler)), spec)
    return next(f for f in res if f.module_id == flow_owner["id"])


# ---------------------------------------------------------------------------
# Check B v3
# ---------------------------------------------------------------------------


class CheckBTests(unittest.TestCase):
    def test_no_handler_is_a_fail_for_every_external_module(self):
        """The critical split is gone: an external module with no handler fails, whatever it is."""
        res = ab.check_b(blueprint("S", trigger(), ext(2)), SPEC)
        self.assertEqual([(f.status, f.module_id) for f in res], [(ab.FAIL, 2)])
        self.assertIn("Missing error handler", res[0].detail)
        self.assertIn("F-E5.3", res[0].detail)

    def test_logger_call_plus_one_directive_is_a_pass_with_the_directive_note(self):
        row = b_row(ext(2), call(20, 2), directive(21, "Break"))
        self.assertEqual(row.status, ab.PASS, row.detail)
        self.assertIn("then Break", row.detail)
        self.assertIn("Break stores an incomplete execution", row.detail)

    def test_ignore_and_resume_say_the_logger_row_is_the_only_trace(self):
        loop = {"id": 5, "module": "builtin:BasicFeeder"}
        row = b_row(ext(2), call(20, 2), directive(21, "Ignore"), before=(loop,))
        self.assertEqual(row.status, ab.PASS, row.detail)
        self.assertIn("only trace", row.detail)
        self.assertNotIn("Check the directive", row.detail)

    def test_a_contradicting_directive_stays_a_pass_with_the_note(self):
        """No loop upstream: Ignore contradicts the pattern. The row is still a PASS, the note says so."""
        row = b_row(ext(2), call(20, 2), directive(21, "Ignore"))
        self.assertEqual(row.status, ab.PASS)
        self.assertIn("Check the directive: nothing upstream emits more than one bundle", row.detail)

    def test_legacy_complete_handler_is_a_review_to_convert(self):
        row = b_row(ext(2), ledger(20), slack(21), directive(22, "Break"))
        self.assertEqual(row.status, ab.REVIEW, row.detail)
        self.assertIn("Convert to a logger call (F-E5.3)", row.detail)

    def test_legacy_handler_inside_a_router_is_still_complete(self):
        r = router(20, [ledger(21)], [slack(22), directive(23, "Break")])
        self.assertEqual(b_row(ext(2), r).status, ab.REVIEW)

    def test_ledger_write_module_needs_logger_call_or_slack_plus_directive(self):
        owner = ledger(2)
        self.assertEqual(b_row(owner, call(20, 2), directive(21)).status, ab.PASS)
        legacy = b_row(owner, slack(20), directive(21))
        self.assertEqual(legacy.status, ab.REVIEW, legacy.detail)
        self.assertIn("Slack message, directive Break", legacy.detail)
        self.assertEqual(b_row(owner, directive(21)).status, ab.FAIL)

    def test_partial_and_directive_only_handlers_fail(self):
        for handler in ([slack(20), directive(21)], [ledger(20), directive(21)], [directive(21)], [ledger(20), slack(21)],
                        [ledger(20), slack(21), directive(22), directive(23, "Ignore")]):
            row = b_row(ext(2), *handler)
            self.assertEqual(row.status, ab.FAIL, handler)
            self.assertIn("Partial handler", row.detail)

    def test_without_a_registered_logger_an_http_call_is_no_logger_call(self):
        row = b_row(ext(2), call(20, 2), directive(21), spec=None)
        self.assertEqual(row.status, ab.FAIL)
        self.assertIn("Partial handler", row.detail)

    def test_the_handler_shape_is_exactly_call_then_directive(self):
        cases = {
            "The handler also holds slack:CreateMessage": [call(20, 2), slack(22), directive(21)],
            "must come first": [directive(21), call(20, 2)],
            "Exactly one directive is needed (found 2)": [call(20, 2), directive(21), directive(22, "Ignore")],
            "Exactly one directive is needed (found 0)": [call(20, 2)],
            "2 logger calls": [call(20, 2), call(22, 2), directive(21)],
        }
        for text, handler in cases.items():
            row = b_row(ext(2), *handler)
            self.assertEqual(row.status, ab.FAIL, text)
            self.assertIn(text, row.detail)

    def test_a_filter_in_the_handler_fails(self):
        d = directive(21)
        d["filter"] = {"name": "x", "conditions": [[{"a": "{{2.id}}", "o": "exist"}]]}
        self.assertIn("carries a filter", b_row(ext(2), call(20, 2), d).detail)

    def call_row(self, c):
        return b_row(ext(2), c, directive(21))

    def test_logger_call_contract_violations_fail(self):
        no_body = call(20, 2)
        no_body["mapper"]["urlEncodedBodyContent"] = body(2, outcome="Success", module_id="3", error_type="{{3.error.type}}",
                                                          execution_id="{{var.scenario.id}}", lead_record_id="rec123", note="x")
        own_handler = with_handler(call(20, 2), directive(30, "Ignore"))
        filtered = call(20, 2)
        filtered["filter"] = {"name": "x", "conditions": [[{"a": "{{2.id}}", "o": "exist"}]]}
        cases = {
            "Return error if HTTP request fails": call(20, 2, stopOnHttpError=None),
            "turn it off": call(20, 2, stopOnHttpError=True),
            "is not a POST": call(20, 2, method="get"),
            "sets the key header by hand": call(20, 2, headers=[{"name": "x-make-apikey", "value": "{{var.team.K}}"}]),
            "application/x-www-form-urlencoded": call(20, 2, contentType="json", inputMethod="jsonString", jsonStringBodyContent="{}"),
            "does not send outcome Error": no_body,
            "does not send module_id 2": no_body,
            "does not send error_type as exactly {{2.error.type}}": no_body,
            "does not send execution_id as exactly": no_body,
            "sends lead_record_id that is not one mapped reference": no_body,
            "sends note, outside the Logger body": no_body,
            "has its own error handler": own_handler,
            "A module in the handler carries a filter": filtered,
            "is http:ActionSendData": dict(call(20, 2), module="http:ActionSendData"),
        }
        for text, c in cases.items():
            row = self.call_row(c)
            self.assertEqual(row.status, ab.FAIL, text)
            self.assertIn(text, row.detail)

    def test_missing_body_fields_fail(self):
        c = call(20, 2)
        c["mapper"]["urlEncodedBodyContent"] = body(2, error_message=None, execution_id=None)
        self.assertIn("does not send error_message, execution_id", self.call_row(c).detail)

    def test_optional_fields_are_one_mapped_reference(self):
        """An Applicants record ID and a Bland call ID from modules upstream of the owner pass (R2)."""
        c = call(20, 4)
        c["mapper"]["urlEncodedBodyContent"] = body(4, lead_record_id="{{2.id}}", call_id="{{3.call_id}}")
        row = b_row(ext(4), c, directive(21), before=(lead_search(2), bland_send(3)))
        self.assertEqual(row.status, ab.PASS, row.detail)

    def test_authentication_and_url_must_both_be_the_registered_ones(self):
        no_auth = call(20, 2, params={"authenticationType": "noAuth"})
        row = self.call_row(no_auth)   # identified by the URL variable, refused for the missing keychain
        self.assertIn("not authenticated by a keychain connection", row.detail)
        other = call(20, 2, params={"authenticationType": "apiKeyConnection", "apiKeyAccount": 99})
        self.assertIn("not the Logger connection 4242", self.call_row(other).detail)
        literal = call(20, 2, url="https://example.invalid/not-a-hook")
        row = self.call_row(literal)   # identified by the connection, refused for the URL
        self.assertIn("has a URL that is not exactly {{var.team.IMMIOS_LOGGER_URL}}", row.detail)
        legacy_keychain = call(20, 2, params={"authenticationType": "apiKey", "apiKeyKeychain": CONN})
        self.assertEqual(self.call_row(legacy_keychain).status, ab.PASS)

    def test_a_registry_without_a_connection_id_cannot_confirm_the_call(self):
        spec = ab.LoggerSpec(LOGGER_ID, HOOK, VAR, None)
        row = b_row(ext(2), call(20, 2), directive(21), spec=spec)
        self.assertEqual(row.status, ab.FAIL)
        self.assertIn("names no connection_id yet", row.detail)

    def test_the_logger_scenario_is_judged_by_check_l(self):
        res = ab.check_b(blueprint("Logger", trigger(), ext(2), scenario_id=LOGGER_ID), SPEC)
        self.assertEqual([(f.status, f.check) for f in res], [(ab.INFO, "B")])
        self.assertIn("check L", res[0].detail)

    def test_trigger_internal_modules_and_handler_modules_are_out_of_scope(self):
        res = ab.check_b(blueprint("S", ext(1), {"id": 2, "module": "util:SetVariable2"},
                                   with_handler(ext(3), call(20, 3), directive(21))), SPEC)
        self.assertEqual([f.module_id for f in res], [3])


# ---------------------------------------------------------------------------
# The Logger call contract, review round 2 (R2, LOG-4, LOG-6)
# ---------------------------------------------------------------------------


def lead_search(mid, table=LEAD):
    return {"id": mid, "module": "airtable:ActionSearchRecords", "mapper": {"table": table}}


def bland_send(mid):
    return {"id": mid, "module": "bland:sendACall", "mapper": {}}


def bland_fetch(mid=2, tid=1):
    return {"id": mid, "module": "bland:getCallDetails", "mapper": {"call_id": "{{%s.call_id}}" % tid}}


OTHER_TABLE = "tblOTHER0000000x"


def contract_links():
    """Applicants with two PII fields, a System Logs link field to Applicants and PII on the webhook body."""
    return ab.AirtableMap(tables={LEAD: {"name": "Applicants", "fields": {"fldEMAIL0000000": "Email", "fldNAME00000000": "Name"}},
                                  LEDGER: {"name": "System Logs", "fields": {"fldLINK00000000": "Applicant Link"},
                                           "links": {"fldLINK00000000": {"target": LEAD}}},
                                  OTHER_TABLE: {"name": "Files", "fields": {}}},
                          pii_fields={LEAD: ["Email", "Name"]}, source_pii={"gateway:CustomWebHook": ["email", "phone"]})


def registry(protection):
    extra = {"lookup_label": "S"} if protection == "fetch_back" else {}
    caller = "bland_post_call" if protection == "fetch_back" else "bland_pathway_node"
    return ab.Webhooks({"500": ab.WebhookEntry("500", 1, caller, protection, "A sentence of reason", **extra)}, SPEC)


class LoggerContractTests(unittest.TestCase):
    """logger_call_problems through check B: only the keychain connection and the form body carry anything, the body
    holds the contract fields only and no client data, lead_record_id is an Applicants record ID in scope and call_id
    a Bland call ID check F allows (review findings R2, LOG-4, LOG-6)."""

    def row(self, owner, c, *before, flow_head=None, webhooks=None, lnk=None, after=()):
        head = flow_head if flow_head is not None else [trigger()]
        res = ab.check_b(blueprint("S", *head, *before, with_handler(owner, c, directive(21)), *after), SPEC,
                         links=lnk if lnk is not None else contract_links(), webhooks=webhooks)
        return next(f for f in res if f.module_id == owner["id"])

    def with_body(self, owner, **over):
        c = call(20, owner)
        c["mapper"]["urlEncodedBodyContent"] = body(owner, **over)
        return c

    def assert_fail(self, row, text):
        self.assertEqual(row.status, ab.FAIL, row.detail)
        self.assertIn(text, row.detail)

    # --- R2: nothing outside the auth connection and the form body -------------------------------

    def test_query_parameters_fail(self):
        self.assert_fail(self.row(ext(4), call(20, 4, queryParameters=[{"name": "lead", "value": "{{3.id}}"}])), "queryParameters")
        self.assert_fail(self.row(ext(4), call(20, 4, queryParameters=[{"name": "debug", "value": "1"}])), "queryParameters")

    def test_qs_fails(self):
        self.assert_fail(self.row(ext(4), call(20, 4, qs=[{"name": "debug", "value": "1"}])), "qs")
        self.assert_fail(self.row(ext(4), call(20, 4, qs={"debug": "1"})), "qs")

    def test_any_extra_header_fails(self):
        row = self.row(ext(4), call(20, 4, headers=[{"name": "X-Trace", "value": "abc"}]))
        self.assert_fail(row, "sets header X-Trace")
        self.assertIn("sets the key header by hand", self.row(ext(4), call(20, 4, headers=[{"name": "x-make-apikey", "value": "k"}])).detail)

    def test_empty_query_and_header_lists_pass(self):
        c = call(20, 4, qs=[], headers=[{"name": "", "value": ""}])
        self.assertEqual(self.row(ext(4), c).status, ab.PASS, self.row(ext(4), c).detail)

    def test_a_mapping_outside_the_url_and_the_body_fails(self):
        row = self.row(ext(4), call(20, 4, jsonStringBodyContent='{"x": "{{3.Email}}"}'), lead_search(3))
        self.assert_fail(row, "maps data outside the form body (jsonStringBodyContent)")

    # --- R2: E6 over every body value ------------------------------------------------------------

    def test_client_data_in_any_body_value_fails_the_b_row(self):
        row = self.row(ext(4), self.with_body(4, lead_record_id="{{3.Email}}"), lead_search(3))
        self.assert_fail(row, "client data (E6)")
        self.assertIn("{{3.Email}}", row.detail)
        hook = registry("api_key")
        row = self.row(ext(4), self.with_body(4, call_id="{{1.email}}"), flow_head=[webhook()], webhooks=hook)
        self.assert_fail(row, "client data (E6)")
        self.assertIn("{{1.email}}", row.detail)

    # --- R2 and LOG-4: lead_record_id is an Applicants record ID in scope (check E3 inference) -----

    def test_lead_record_id_from_an_applicants_record_upstream_passes(self):
        row = self.row(ext(4), self.with_body(4, lead_record_id="{{3.id}}"), lead_search(3))
        self.assertEqual(row.status, ab.PASS, row.detail)
        # A link field of an Airtable record that targets Applicants is an Applicants record ID too (E3).
        ledger_get = {"id": 3, "module": "airtable:ActionGetRecord", "mapper": {"table": LEDGER, "id": "{{2.id}}"}}
        row = self.row(ext(4), self.with_body(4, lead_record_id="{{3.`Applicant Link`}}"), ledger_get)
        self.assertEqual(row.status, ab.PASS, row.detail)

    def test_lead_record_id_from_another_table_or_a_non_airtable_module_fails(self):
        self.assert_fail(self.row(ext(4), self.with_body(4, lead_record_id="{{3.id}}"), lead_search(3, OTHER_TABLE)),
                         "lead_record_id is not an Applicants record ID")
        self.assert_fail(self.row(ext(4), self.with_body(4, lead_record_id="{{1.id}}")), "lead_record_id is not an Applicants record ID")
        self.assert_fail(self.row(ext(4), self.with_body(4, lead_record_id="{{9.id}}")), "lead_record_id is not an Applicants record ID")

    def test_lead_record_id_not_in_scope_fails(self):
        # The lead search runs after the owner, so no lead is in scope when the owner fails.
        row = self.row(ext(4), self.with_body(4, lead_record_id="{{5.id}}"), after=(lead_search(5),))
        self.assert_fail(row, "not in scope")
        # The owner's own output does not exist when it fails.
        row = self.row(lead_search(4), self.with_body(4, lead_record_id="{{4.id}}"))
        self.assert_fail(row, "not in scope")

    def test_lead_record_id_with_text_or_a_function_around_it_fails(self):
        self.assert_fail(self.row(ext(4), self.with_body(4, lead_record_id="rec {{3.id}}"), lead_search(3)),
                         "lead_record_id that is not one mapped reference")
        self.assert_fail(self.row(ext(4), self.with_body(4, lead_record_id="{{lower(3.id)}}"), lead_search(3)),
                         "lead_record_id that is not one mapped reference")

    # --- R2: call_id is a bare reference check F allows ------------------------------------------

    def test_call_id_from_a_bland_module_upstream_passes(self):
        row = self.row(ext(4), self.with_body(4, call_id="{{3.call_id}}"), bland_send(3))
        self.assertEqual(row.status, ab.PASS, row.detail)

    def test_call_id_from_a_non_bland_module_or_a_wrong_field_fails(self):
        self.assert_fail(self.row(ext(4), self.with_body(4, call_id="{{1.call_id}}")), "call_id is not a Bland call ID")
        self.assert_fail(self.row(ext(4), self.with_body(4, call_id="{{3.id}}"), bland_send(3)), "call_id is not a Bland call ID")
        self.assert_fail(self.row(ext(4), self.with_body(4, call_id="{{5.call_id}}"), after=(bland_send(5),)), "not in scope")

    def test_call_id_from_an_unregistered_webhook_fails_and_from_an_api_key_webhook_passes(self):
        self.assert_fail(self.row(ext(4), self.with_body(4, call_id="{{1.call_id}}"), flow_head=[webhook()]),
                         "call_id is not a Bland call ID")
        row = self.row(ext(4), self.with_body(4, call_id="{{1.call_id}}"), flow_head=[webhook()], webhooks=registry("api_key"))
        self.assertEqual(row.status, ab.PASS, row.detail)

    def test_fetch_back_call_id_comes_from_the_call_details_module_only(self):
        hook = registry("fetch_back")
        self.assert_fail(self.row(ext(4), self.with_body(4, call_id="{{1.call_id}}"), bland_fetch(), flow_head=[webhook()], webhooks=hook),
                         "call-details module")
        self.assert_fail(self.row(ext(4), self.with_body(4, call_id="{{3.call_id}}"), bland_fetch(), bland_send(3),
                                  flow_head=[webhook()], webhooks=hook), "call-details module")
        row = self.row(ext(4), self.with_body(4, call_id="{{2.call_id}}"), bland_fetch(), flow_head=[webhook()], webhooks=hook)
        self.assertEqual(row.status, ab.PASS, row.detail)
        # The call-details module's own handler sends no call ID.
        row = self.row(bland_fetch(), self.with_body(2, call_id="{{2.call_id}}"), flow_head=[webhook()], webhooks=hook)
        self.assert_fail(row, "not in scope")

    # --- LOG-6: allowRedirects false, matching make_push ------------------------------------------

    def test_allow_redirects_must_be_false(self):
        self.assert_fail(self.row(ext(4), call(20, 4, allowRedirects=None)), "allowRedirects")
        self.assert_fail(self.row(ext(4), call(20, 4, allowRedirects=True)), "allowRedirects")
        self.assertEqual(self.row(ext(4), call(20, 4)).status, ab.PASS)

    def test_audit_passes_links_and_the_registry_to_check_b(self):
        """audit() gives check B the Airtable map and the registry, so a fetch-back handler is judged with check F's rule."""
        fetch = with_handler(bland_fetch(), self.with_body(2), directive(21))
        bad = self.with_body(4, call_id="{{1.call_id}}")
        bad["id"] = 30
        caller = blueprint("S", webhook(), fetch, with_handler(ext(4), bad, directive(31)))
        res = ab.audit([caller], labels(), schema(), True, links=contract_links(), allowlist=ab.Allowlist(), webhooks=registry("fetch_back"),
                       hooks=hooks(), secret_allowlist=[], partial=True, status_designs=ab.StatusDesigns(), schedule=state())
        b4 = next(f for f in res.findings if f.check == "B" and f.module_id == 4)
        self.assertEqual(b4.status, ab.FAIL)
        self.assertIn("call-details module", b4.detail)


# ---------------------------------------------------------------------------
# Check C on Logger call labels
# ---------------------------------------------------------------------------


class CheckCTests(unittest.TestCase):
    def run_c(self, *flow, lab=None, scenario_id="500", by_id=True):
        return ab.check_c(blueprint("S", trigger(), *flow, scenario_id=scenario_id), lab or labels(), schema(), by_id, SPEC)

    def test_logger_call_label_equal_to_the_expected_label_passes(self):
        res = self.run_c(with_handler(ext(2), call(20, 2), directive(21)))
        self.assertEqual([(f.status, f.module_id) for f in res], [(ab.PASS, 20)])
        self.assertIn('Logger call Sends "Lead Qualifier"', res[0].detail)

    def test_logger_call_with_the_wrong_label_fails(self):
        res = self.run_c(with_handler(ext(2), call(20, 2, label="Batch Outbound Caller"), directive(21)))
        self.assertEqual([(f.status, f.module_id) for f in res], [(ab.FAIL, 20)])
        self.assertIn('expected "Lead Qualifier"', res[0].detail)

    def test_mapped_missing_and_unknown_labels_fail(self):
        mapped = call(20, 2, label="{{1.name}}")
        missing = call(20, 2)
        missing["mapper"]["urlEncodedBodyContent"] = body(2, label=None)
        res = self.run_c(with_handler(ext(2), mapped, directive(21)))
        self.assertIn("Logger call Scenario label is not a fixed literal", res[0].detail)
        res = self.run_c(with_handler(ext(2), missing, directive(21)))
        self.assertEqual(res[0].detail, "Logger call sends no label")
        res = self.run_c(with_handler(ext(2), call(20, 2, label="Not An Option"), directive(21)),
                         lab=labels(**{"500": {"name": "S", "expected_label": "Not An Option"}}))
        self.assertTrue(any("not a Single Select option" in f.detail and f.status == ab.FAIL for f in res))

    def test_a_scenario_that_only_calls_the_logger_needs_a_labels_entry(self):
        res = self.run_c(with_handler(ext(2), call(20, 2), directive(21)), scenario_id="777")
        self.assertTrue(any(f.detail == "Scenario calls the Logger but has no entry in scenario_labels.json" for f in res))

    def test_unconfirmed_labels_give_unconfirmed_rows(self):
        res = self.run_c(with_handler(ext(2), call(20, 2, label="Wrong"), directive(21)), lab=labels(confirmed=False))
        self.assertEqual({f.status for f in res}, {ab.UNCONFIRMED})

    def test_the_logger_rows_mapped_label_is_exempt(self):
        lg = ledger(2, "{{1.label}}", **{ab.OUTCOME_FIELD: "Error"})
        res = ab.check_c(blueprint("Logger", webhook(), lg, scenario_id=LOGGER_ID), labels(), schema(), True, SPEC)
        self.assertEqual(res, [])
        # The exemption is the Logger's alone, and only for exactly the caller's label.
        res = ab.check_c(blueprint("S", webhook(), lg), labels(), schema(), True, SPEC)
        self.assertEqual([f.detail for f in res], ["Scenario label is not a fixed literal"])
        other = ledger(3, "{{1.label}} x")
        res = ab.check_c(blueprint("Logger", webhook(), lg, other, scenario_id=LOGGER_ID), labels(), schema(), True, SPEC)
        self.assertTrue(any(f.module_id == 3 and f.status == ab.FAIL for f in res))

    def test_ledger_writes_keep_their_existing_rows(self):
        res = self.run_c(ledger(2, "Batch Outbound Caller"))
        self.assertEqual(res[0].detail, 'Writes "Batch Outbound Caller", expected "Lead Qualifier"')


# ---------------------------------------------------------------------------
# E6 and F2c on Logger call bodies
# ---------------------------------------------------------------------------


def webhook(mid=1, hook=1):
    return {"id": mid, "module": "gateway:CustomWebHook", "parameters": {"hook": hook}}


def links():
    return ab.AirtableMap(tables={LEAD: {"name": "Applicants", "fields": {"fldEMAIL0000000": "Email", "fldNAME00000000": "Name"}}},
                          pii_fields={LEAD: ["Email", "Name"]}, source_pii={"gateway:CustomWebHook": ["email", "phone"]})


class E6Tests(unittest.TestCase):
    def e6(self, *flow, spec=SPEC):
        res = ab.check_e(blueprint("S", *flow), links(), ab.Allowlist(), spec)
        return [f for f in res if f.rule == "E6"]

    def lead(self):
        return {"id": 3, "module": "airtable:ActionSearchRecords", "mapper": {"table": LEAD}}

    def test_client_data_in_a_logger_call_body_fails(self):
        c = call(20, 4)
        c["mapper"]["urlEncodedBodyContent"] = body(4, module_name="Lead {{3.Email}}")
        res = self.e6(webhook(), self.lead(), with_handler(ext(4), c, directive(21)))
        self.assertEqual([(f.status, f.module_id) for f in res], [(ab.FAIL, 20)])
        self.assertIn("Logger call body {{3.Email}}", res[0].detail)
        self.assertIn("in the Logger call", res[0].detail)

    def test_client_data_from_outside_airtable_fails(self):
        c = call(20, 4)
        c["mapper"]["urlEncodedBodyContent"] = body(4, call_id="{{1.email}}")
        res = self.e6(webhook(), self.lead(), with_handler(ext(4), c, directive(21)))
        self.assertEqual([(f.status, f.module_id) for f in res], [(ab.FAIL, 20)])
        self.assertIn("client PII from outside Airtable", res[0].detail)

    def test_ids_only_pass_and_an_unregistered_http_call_is_not_scanned(self):
        c = call(20, 4)
        c["mapper"]["urlEncodedBodyContent"] = body(4, lead_record_id="{{3.id}}")
        self.assertEqual(self.e6(webhook(), self.lead(), with_handler(ext(4), c, directive(21))), [])
        leaky = call(20, 4)
        leaky["mapper"]["urlEncodedBodyContent"] = body(4, module_name="{{3.Email}}")
        self.assertEqual(self.e6(webhook(), self.lead(), with_handler(ext(4), leaky, directive(21)), spec=None), [])

    def test_slack_messages_are_still_scanned(self):
        res = self.e6(webhook(), self.lead(), slack(5, "{{3.Name}}"))
        self.assertEqual([f.module_id for f in res], [5])


class F2cTests(unittest.TestCase):
    def reg(self):
        return ab.Webhooks({"500": ab.WebhookEntry("500", 1, "bland_post_call", "fetch_back", "A sentence of reason", "S")}, SPEC)

    def f2c(self, *flow):
        res = ab.check_f(blueprint("S", *flow, meta={"scenario": {"sequential": True}}), ab.Allowlist(), self.reg(), None, None)
        return {f.module_id: f.detail for f in res if f.rule == "F2c"}

    def fetch(self, *handler):
        m = {"id": 2, "module": "bland:getCallDetails", "mapper": {"call_id": "{{1.call_id}}"}}
        return with_handler(m, *handler) if handler else m

    def test_a_logger_call_that_reads_the_request_call_id_fails(self):
        c = call(20, 2)
        c["mapper"]["urlEncodedBodyContent"] = body(2, call_id="{{1.call_id}}")
        rows_ = self.f2c(webhook(), self.fetch(c, directive(21)))
        self.assertIn(20, rows_)
        self.assertIn("Logger call body reads request field(s) call_id in an error handler", rows_[20])
        self.assertIn("{{2.call_id}}", rows_[20])

    def test_a_logger_call_with_the_call_details_call_id_or_none_does_not(self):
        bare = call(20, 2)
        later = call(30, 5)
        later["mapper"]["urlEncodedBodyContent"] = body(5, call_id="{{2.call_id}}")
        rows_ = self.f2c(webhook(), self.fetch(bare, directive(21)), with_handler(ext(5), later, directive(31)))
        self.assertNotIn(20, rows_)
        self.assertNotIn(30, rows_)


# ---------------------------------------------------------------------------
# The Logger entry of audit/webhooks.json
# ---------------------------------------------------------------------------


def entry(sid="5", hid=1, caller="bland_pathway_node", protection="api_key", **extra):
    e = {"scenario_id": sid, "hook_id": hid, "caller": caller, "protection": protection, "reason": "A sentence of reason"}
    e.update(extra)
    return e


def logger_entry(sid=None, hid=None, **extra):
    e = {"scenario_id": sid, "hook_id": hid, "caller": "make_http", "protection": "api_key",
         "blueprint": "specs/logger.blueprint.json", "reason": "The shared Logger, called from every handler"}
    e.update(extra)
    return e


class RegistryTests(unittest.TestCase):
    def load(self, data):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "webhooks.json")
            with open(p, "w", encoding="utf-8") as fh:
                json.dump(data, fh)
            return ab.load_webhooks(p)

    def test_a_pending_logger_sits_under_the_logger_key_with_null_ids(self):
        w = self.load({"scenarios": [entry()], "logger": logger_entry(url_variable=VAR, connection_id=None)})
        self.assertEqual(w.logger, ab.LoggerSpec(None, None, VAR, None, "The shared Logger, called from every handler"))
        self.assertEqual(sorted(w.entries), ["5"])

    def test_a_deployed_logger_lives_in_scenarios(self):
        w = self.load({"scenarios": [entry(), logger_entry(LOGGER_ID, HOOK, url_variable=VAR, connection_id=CONN)]})
        self.assertEqual((w.logger.scenario_id, w.logger.hook_id, w.logger.connection_id), (LOGGER_ID, HOOK, CONN))
        self.assertEqual(w.entries[LOGGER_ID].protection, "api_key")
        # The top-level key may also carry the IDs, and the entry then joins the F registry.
        w = self.load({"scenarios": [], "logger": logger_entry(LOGGER_ID, HOOK, url_variable=VAR)})
        self.assertIn(LOGGER_ID, w.entries)

    def test_bad_logger_entries_are_input_errors(self):
        cases = {
            "both under logger and in scenarios": {"scenarios": [logger_entry(LOGGER_ID, HOOK)], "logger": logger_entry()},
            "two Logger entries": {"scenarios": [logger_entry(LOGGER_ID, HOOK), logger_entry("901", 78)]},
            "must use api_key": {"scenarios": [], "logger": logger_entry(protection="fetch_back", lookup_label="X")},
            "custom variable": {"scenarios": [], "logger": logger_entry(url_variable="https://hook.us2.make.com/abc")},
            "connection_id must be null": {"scenarios": [], "logger": logger_entry(connection_id="4242")},
            "belong to the Logger entry": {"scenarios": [entry(url_variable=VAR)]},
            "caller must be make_http": {"scenarios": [], "logger": entry(None, None)},
            "scenario_id must be": {"scenarios": [logger_entry()]},
        }
        for text, data in cases.items():
            with self.assertRaises(ab.InputError, msg=text) as cm:
                self.load(data)
            self.assertIn(text, str(cm.exception))

    def test_the_repo_registry_loads(self):
        w = ab.load_webhooks(ab.DEFAULT_WEBHOOKS, required=True)
        self.assertTrue(w.entries)
        # Literal-URL mode since 2026-10-29 (account below Make Pro): no team variable, the hook token is pinned by hash.
        self.assertIsNotNone(w.logger)
        self.assertIsNone(w.logger.url_variable)
        self.assertRegex(w.logger.url_sha256 or "", r"^[0-9a-f]{64}$")
        self.assertEqual((w.logger.scenario_id, w.logger.hook_id, w.logger.connection_id), ("6832527", 3000983, 12036824))


# ---------------------------------------------------------------------------
# Check L, the shared Logger
# ---------------------------------------------------------------------------


SLACK_TEXT = ("ERROR: {{1.label}}\nModule: {{1.module_id}}\nError type: {{1.error_type}}\nExecution ID: {{1.execution_id}}\n"
              "Lead record ID: {{1.lead_record_id}}\nCall ID: {{1.call_id}}\nShadow Ledger row: {{2.id}}")
SETTINGS = {"scenario": {"sequential": False, "dlq": False}}


def logger_flow(ledger_handler=None, slack_handler=None, text=SLACK_TEXT, **record):
    rec = {ab.LABEL_FIELD: "{{1.label}}", ab.OUTCOME_FIELD: "Error", ab.AI_RESPONSE_FIELD: "{{1.error_type}}: {{1.error_message}}"}
    rec.update(record)
    lg = {"id": 2, "module": "airtable:ActionCreateRecord", "mapper": {"table": LEDGER, "record": rec},
          "onerror": [ledger_handler or directive(4, "Resume", id="NOT WRITTEN, the ledger write failed")]}
    sm = {"id": 3, "module": "slack:CreateMessage", "mapper": {"text": text}, "onerror": [slack_handler or directive(5, "Ignore")]}
    return [webhook(1, HOOK), lg, sm]


def hooks(count=1):
    return ab.HookInfo(True, {HOOK: {"id": HOOK, "apikey_count": count, "scenario_ids": [LOGGER_ID]}})


def state(active=True):
    return {LOGGER_ID: {"active": active}}


def run_l(flow=None, meta=None, spec=SPEC, schedule=None, hook_info=None, scenario_id=LOGGER_ID):
    b = ab.Blueprint("Logger", scenario_id, "test", {"name": "Logger", "flow": flow if flow is not None else logger_flow(),
                                                     "metadata": copy.deepcopy(SETTINGS) if meta is None else meta})
    return ab.check_l([b], spec, state() if schedule is None else schedule, hook_info or hooks())


def l_rows(res):
    return sorted({(f.rule, f.module_id) for f in res if f.status == ab.FAIL})


class CheckLTests(unittest.TestCase):
    def test_a_correct_logger_passes(self):
        res = run_l()
        self.assertEqual([(f.status, f.rule) for f in res], [(ab.PASS, "L"), (ab.INFO, "L6")])

    def test_every_check_l_run_says_the_team_variable_value_is_not_audited(self):
        """R5: the audit cannot read the value of the team variable, so every report carries that gap as an INFO row."""
        runs = [run_l(), run_l(spec=None), run_l(spec=ab.LoggerSpec(None, None, VAR)), run_l(hook_info=hooks(0))]
        for res in runs:
            info = [f for f in res if f.status == ab.INFO and f.rule == "L6"]
            self.assertEqual(len(info), 1, [f.detail for f in res])
            self.assertIn("not audited", info[0].detail)
            self.assertIn("IMMIOS_LOGGER_URL", info[0].detail)
        # The INFO row does not count as a FAIL and does not hide the PASS.
        self.assertFalse(any(f.status == ab.FAIL for f in runs[0]))

    def test_hook_key_unconfirmed_only_when_the_hook_list_is_unreadable(self):
        """R3: UNCONFIRMED is for a hook list the token could not read, or a hook entry with no key field."""
        res = run_l(hook_info=ab.HookInfo(note="GET /hooks returned 403"))
        self.assertIn(ab.HOOK_KEY_UNCONFIRMED, res[0].detail)
        res = run_l(hook_info=ab.HookInfo(True, {HOOK + 1: {"id": HOOK + 1, "apikey_count": 1}}))
        self.assertEqual(l_rows(res), [("L1", 1)])
        self.assertNotIn(ab.HOOK_KEY_UNCONFIRMED, res[0].detail)

    def test_not_registered_not_deployed_and_not_pulled_are_one_fail(self):
        for spec, text in ((None, "No Logger registered"), (ab.LoggerSpec(None, None, VAR), "Logger not deployed"),
                           (ab.LoggerSpec("999", HOOK, VAR, CONN), "is not in the pull")):
            res = run_l(spec=spec)
            self.assertEqual([(f.status, f.rule) for f in res], [(ab.FAIL, "L0"), (ab.INFO, "L6")], text)
            self.assertIn(text, res[0].detail)

    def test_trigger_hook_key_and_state(self):
        self.assertEqual(l_rows(run_l(hook_info=hooks(0))), [("L1", 1)])
        res = run_l(hook_info=ab.HookInfo(note="GET /hooks returned 401"))
        self.assertEqual(l_rows(res), [("L1", 1)])
        self.assertIn("UNCONFIRMED", res[0].detail)
        # R3: the hook list was read and the Logger hook is not in it. That is a FAIL with no UNCONFIRMED marker.
        res = run_l(hook_info=ab.HookInfo(True, {}))
        self.assertEqual(l_rows(res), [("L1", 1)])
        self.assertNotIn("UNCONFIRMED", res[0].detail)
        self.assertIn("is not in the hook list", res[0].detail)
        self.assertIn("UNCONFIRMED", run_l(hook_info=ab.HookInfo(True, {HOOK: {"id": HOOK, "apikey_count": None}}))[0].detail)
        self.assertIn("not active", run_l(schedule=state(False))[0].detail)
        self.assertIn("UNCONFIRMED, no scenario state", run_l(schedule={})[0].detail)
        flow = logger_flow()
        flow[0] = webhook(1, 5)
        self.assertIn("names hook 77", run_l(flow)[0].detail)
        flow[0] = {"id": 1, "module": "google-email:triggerWatchNewEmails"}
        self.assertTrue(any("not a gateway:CustomWebHook" in f.detail for f in run_l(flow)))

    def test_settings(self):
        self.assertIn("Process data in order is on", run_l(meta={"scenario": {"sequential": True, "dlq": False}})[0].detail)
        self.assertIn("Store incomplete executions is on", run_l(meta={"scenario": {"sequential": False, "dlq": True}})[0].detail)
        self.assertIn("UNCONFIRMED, no scenario settings", run_l(meta={})[0].detail)

    def test_ledger_row(self):
        res = run_l(logger_flow(**{ab.LABEL_FIELD: "Campaign Launcher"}))
        self.assertEqual(l_rows(res), [("L3", 2)])
        self.assertIn("exactly {{1.label}}", res[0].detail)
        self.assertIn("literal Error", run_l(logger_flow(**{ab.OUTCOME_FIELD: "{{1.outcome}}"}))[0].detail)
        res = run_l(logger_flow(**{ab.CALL_ID_FIELD: "{{1.call_id}}"}))
        self.assertIn("replay", res[0].detail)
        flow = logger_flow()
        flow[1]["filter"] = {"name": "x", "conditions": [[{"a": "{{1.label}}", "o": "exist"}]]}
        self.assertIn("A filter sits on the ledger row", run_l(flow)[0].detail)
        two = logger_flow()
        two.insert(2, ledger(6, "{{1.label}}", **{ab.OUTCOME_FIELD: "Error"}))
        self.assertTrue(any("exactly one Shadow Ledger create, found 2" in f.detail for f in run_l(two)))

    def test_slack_alert_ids_only_and_after_the_row(self):
        res = run_l(logger_flow(text=SLACK_TEXT + "\n{{1.error_message}} {{1.module_name}}"))
        self.assertEqual(l_rows(res), [("L4", 3)])
        self.assertIn("1.error_message, 1.module_name", res[0].detail)
        res = run_l(logger_flow(text="ERROR {{1.label}}"))
        self.assertIn("does not name the ledger row", res[0].detail)
        flow = logger_flow()
        flow[1], flow[2] = flow[2], flow[1]
        self.assertTrue(any("does not run after the ledger write" in f.detail for f in run_l(flow)))
        flow = logger_flow()
        flow.append(slack(7, "{{1.label}}"))
        flow[-1]["onerror"] = [directive(8, "Ignore")]
        self.assertTrue(any("exactly one Slack alert, found 2" in f.detail for f in run_l(flow)))

    def test_the_alert_still_goes_out_and_says_so_when_the_ledger_write_fails(self):
        # Ignore on the ledger drops the bundle, so the alert after it never runs.
        res = run_l(logger_flow(ledger_handler=directive(4, "Ignore")))
        self.assertEqual(l_rows(res), [("L4", 2), ("L4", 3)])
        self.assertTrue(any("must be Resume" in f.detail for f in res))
        # Resume with no literal substitute id: the alert shows an empty row ID.
        res = run_l(logger_flow(ledger_handler=directive(4, "Resume")))
        self.assertIn("instead of saying so", res[0].detail)
        # ifempty in the alert says so as well.
        text = SLACK_TEXT.replace("{{2.id}}", '{{ifempty(2.id; "NOT WRITTEN")}}')
        self.assertEqual(l_rows(run_l(logger_flow(ledger_handler=directive(4, "Resume"), text=text))), [])

    def test_a_router_with_the_alert_on_a_later_route_may_ignore_the_ledger_failure(self):
        flow = logger_flow(ledger_handler=directive(4, "Ignore"), text=SLACK_TEXT.replace("{{2.id}}", '{{ifempty(2.id; "NOT WRITTEN")}}'))
        r = {"id": 9, "module": "builtin:BasicRouter", "routes": [{"flow": [flow[1]]}, {"flow": [flow[2]]}]}
        self.assertEqual(l_rows(run_l([flow[0], r])), [])
        r["routes"].reverse()
        self.assertTrue(any("does not run after" in f.detail for f in run_l([flow[0], r])))

    def test_every_module_needs_a_handler_that_cannot_error(self):
        res = run_l(logger_flow(slack_handler=directive(5, "Break")))
        self.assertEqual(l_rows(res), [("L5", 3)])
        flow = logger_flow()
        flow[2]["onerror"] = [slack(5), directive(6, "Ignore")]
        self.assertEqual(l_rows(run_l(flow)), [("L5", 3)])
        flow = logger_flow()
        del flow[2]["onerror"]
        self.assertEqual(l_rows(run_l(flow)), [("L5", 3)])
        flow = logger_flow()
        flow.insert(2, {"id": 6, "module": "util:SetVariable2"})
        self.assertEqual(l_rows(run_l(flow)), [("L5", 6)])

    @unittest.skipUnless(os.path.exists(SHIPPED), "specs/logger.blueprint.json not present")
    def test_the_shipped_logger_blueprint_passes_once_the_hook_is_picked(self):
        with open(SHIPPED, encoding="utf-8") as fh:
            bp = json.load(fh)
        bp["flow"][0].setdefault("parameters", {})["hook"] = HOOK
        b = ab.Blueprint("Logger", LOGGER_ID, "shipped", bp)
        res = ab.check_l([b], SPEC, state(), hooks())
        self.assertEqual([(f.status, f.rule) for f in res], [(ab.PASS, "L"), (ab.INFO, "L6")], [f.detail for f in res])
        # Its Slack text passes E6, and check C exempts its mapped label.
        self.assertEqual(ab.check_c(b, labels(), schema(), True, SPEC), [])


# ---------------------------------------------------------------------------
# audit() and the CLI
# ---------------------------------------------------------------------------


class AuditTests(unittest.TestCase):
    def registry(self):
        return ab.Webhooks({LOGGER_ID: ab.WebhookEntry(LOGGER_ID, HOOK, "make_http", "api_key", "A sentence of reason")}, SPEC)

    def run_audit(self, partial=False):
        caller = blueprint("S", trigger(), with_handler(ext(2), call(20, 2), directive(21)))
        lg = ab.Blueprint("Logger", LOGGER_ID, "t", {"name": "Logger", "flow": logger_flow(), "metadata": copy.deepcopy(SETTINGS)})
        lab = labels()
        return ab.audit([caller, lg], lab, schema(), True, links=ab.AirtableMap(), allowlist=ab.Allowlist(), webhooks=self.registry(),
                        hooks=hooks(), secret_allowlist=[], partial=partial, status_designs=ab.StatusDesigns(), schedule=state())

    def test_a_converted_caller_and_a_correct_logger_pass(self):
        res = self.run_audit()
        fails = [(f.check, f.module_id, f.detail) for f in res.findings if f.status in (ab.FAIL, ab.UNCONFIRMED)]
        self.assertEqual(fails, [])
        self.assertEqual([f.status for f in res.findings if f.check == "L"], [ab.PASS, ab.INFO])
        self.assertEqual([f.status for f in res.findings if f.check == "B"], [ab.PASS, ab.INFO])
        self.assertFalse(res.failed)

    def test_a_partial_audit_skips_check_l(self):
        self.assertEqual([f for f in self.run_audit(partial=True).findings if f.check == "L"], [])

    def test_checks_and_retired_inputs(self):
        self.assertEqual(ab.CHECKS, "ABCDEFLMPRS")
        self.assertNotIn("G", ab.CHECK_TITLES)
        self.assertEqual(set(ab.SECTION_INTRO), set(ab.CHECKS))
        for gone in ("load_critical", "classify", "check_g", "load_monitor", "CriticalRules", "Monitor"):
            self.assertFalse(hasattr(ab, gone), gone)
        self.assertFalse(os.path.exists(os.path.join(ROOT, "audit", "critical_modules.json")))
        for flag in ("--critical", "--monitor", "--critical-table"):
            with self.assertRaises(SystemExit):
                with open(os.devnull, "w") as null:
                    stderr, sys.stderr = sys.stderr, null
                    try:
                        ab.build_parser().parse_args([flag, "x"] if flag != "--critical-table" else [flag])
                    finally:
                        sys.stderr = stderr


if __name__ == "__main__":
    unittest.main()


class LiteralUrlModeTests(unittest.TestCase):
    """Literal-URL mode (Rizwan 2026-10-29, account below Make Pro): the registry pins the hook token by SHA-256."""

    TOKEN = "a" * 8 + "b" * 8 + "c" * 8 + "d" * 8

    def spec(self, digest=None):
        import secret_scan
        return ab.LoggerSpec("6832527", 3000983, None, 12036824, "r", digest or secret_scan.token_digest(self.TOKEN))

    def module(self, url):
        return {"id": 50, "module": "http:MakeRequest", "mapper": {"url": url, "method": "post"}, "parameters": {}}

    def test_pinned_bare_url_is_a_logger_call(self):
        m = self.module("https://hook.us2.make.com/" + self.TOKEN)
        self.assertTrue(ab._logger_literal_url_ok(m, self.spec()))
        self.assertTrue(ab.is_logger_call(m, self.spec()))
        self.assertFalse(any("has a URL that is not" in p for p in ab.logger_call_problems(m, None, self.spec())))

    def test_other_token_or_extra_text_is_refused(self):
        for url in ("https://hook.us2.make.com/" + "z" * 32, "https://hook.us2.make.com/" + self.TOKEN + "?a=b",
                    "http://hook.us2.make.com/" + self.TOKEN, " https://hook.us2.make.com/" + self.TOKEN):
            m = self.module(url)
            self.assertFalse(ab._logger_literal_url_ok(m, self.spec()), url)
            self.assertTrue(any("has a URL that is not" in p for p in ab.logger_call_problems(m, None, self.spec())), url)

    def test_registry_refuses_both_modes_and_bad_digest(self):
        base = {"caller": "make_http", "protection": "api_key", "connection_id": 1, "reason": "x"}
        with self.assertRaises(ab.InputError):
            ab._logger_spec("w", "logger", dict(base, url_variable="var.team.X", url_sha256="0" * 64), "1", 2)
        with self.assertRaises(ab.InputError):
            ab._logger_spec("w", "logger", dict(base, url_sha256="XYZ"), "1", 2)
        self.assertEqual(ab._logger_spec("w", "logger", dict(base, url_sha256="0" * 64), "1", 2).url_sha256, "0" * 64)

    def test_committed_registry_and_secret_pin_agree(self):
        import json, os
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        reg = json.load(open(os.path.join(root, "audit", "webhooks.json"), encoding="utf-8"))["logger"]
        pin = json.load(open(os.path.join(root, "audit", "secret_allowlist.json"), encoding="utf-8"))["logger_hook"]
        self.assertEqual(reg.get("url_sha256"), pin["token_sha256"])
        self.assertEqual(str(reg["scenario_id"]), str(pin["scenario_id"]))
        self.assertEqual(reg["hook_id"], pin["hook_id"])
