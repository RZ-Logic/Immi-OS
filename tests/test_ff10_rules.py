"""F-F10 (2026-11-15, specs/F-F10-drafting-chain.md "Audit additions"): E29 no module writes Synthetic Test Case, E30 only
the owner pinned in audit/ff10.json writes Drafting Status and every write is keyed {{1.id}} of its Applicants Watch Records
trigger, E31 the ff13.drafting_context and ff13.validate_draft calls run only from the owner through PostgreSQL Execute a
function on the ff13_make connection with every argument in its pinned form, and E6 widened to the validator's and the
grounding call's free text and to Claude content. Synthetic fixtures shaped like the planned Module F Drafting Chain. The
record IDs are synthetic, no client data, no network.
"""

import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

sys.path.insert(0, os.path.join(ROOT, "tests"))

import audit_blueprints as ab  # noqa: E402
import make_push  # noqa: E402
import test_make_push as tp  # noqa: E402  (helpers only)

LEAD = ab.LEAD_TABLE
LEDGER = ab.LEDGER_TABLE
LINKS = ab.load_links(ab.DEFAULT_LINKS, required=True)
STAMPS = LINKS.tables[LEDGER]["stamp_fields"]
OWNER = "Module F Drafting Chain"
OWNER_ID = "7000001"
CONN = 12330102
PIN = ab.FF10Pin(OWNER_ID, OWNER, CONN)
PENDING = ab.FF10Pin(None, OWNER, CONN)
# X-16 (2026-11-16) moved production Docs to a staff-only review folder pinned in audit/x16.json. The E32 fixtures below
# use the committed pin with a synthetic owner and review folder, so the test Doc rule and the production rule are read
# as the owner would be after the pin is set.
REVIEW_FOLDER = "1SyntheticReviewFolder000"
X16 = ab.X16Pin(**{**ab.load_x16(ab.DEFAULT_X16).__dict__, "owner_scenario_id": OWNER_ID, "review_folder_id": REVIEW_FOLDER})
SYNTH = "fldsCjg7ftgursZvl"
DSTATUS = "fld5BxjXujOOFzzoE"
VAR = "var.team.IMMIOS_LOGGER_URL"
SPEC = ab.LoggerSpec("900", 77, VAR, 4242, "The shared Logger, a sentence")
FLAG = '{{if(1.`Synthetic Test Case`; "true"; "false")}}'


def bp(*flow, name=OWNER, sid=OWNER_ID):
    return ab.Blueprint(name=name, scenario_id=sid, source="test", bp={"name": name, "flow": list(flow), "metadata": {}})


def rows(b, code=None, status=ab.FAIL, pin=PIN, logger=None, x16=X16):
    return [f for f in ab.check_e(b, LINKS, ab.Allowlist(), logger=logger, bland_agents=ab.BlandAgents(), ff10=pin, x16=x16)
            if (code is None or f.rule == code) and (status is None or f.status == status)]


def trigger(mid=1, table=LEAD, use_ids=False):
    return {"id": mid, "module": "airtable:TriggerWatchRecords", "version": 3, "mapper": {},
            "parameters": {"table": table, "formula": "{Drafting Status} = 'Ready for AI Draft'", "maxRecords": 1,
                           "config": {"triggerField": "Drafting Modified"}, "useColumnId": use_ids}}


def update(mid, value="Drafting", key=DSTATUS, rid="{{1.id}}", module="airtable:ActionUpdateRecords", table=LEAD, **extra):
    rec = {key: value}
    rec.update(extra)
    mp = {"table": table, "record": rec}
    if rid is not None:
        mp["id"] = rid
    return {"id": mid, "module": module, "mapper": mp}


GROUNDING_NAMES = ("p_airtable_record_id", "p_make_execution_id", "p_visa_code", "p_document_type", "p_synthetic_flag")
GROUNDING_KEYS = dict(zip(GROUNDING_NAMES, ab.FF13_PARAMS["drafting_context"]))
VALIDATOR_NAMES = ("p_airtable_record_id", "p_make_execution_id", "p_visa_code", "p_document_type", "p_draft",
                   "p_applicant_name", "p_case_facts", "p_exemplar_terms", "p_model_requested", "p_model_served",
                   "p_stop_reason", "p_prompt_version", "p_prompt_sha256", "p_input_tokens", "p_output_tokens", "p_request_id")


def grounding(mid=4, **over):
    """ff13.drafting_context as the lead's decision 1 maps it, with the measured positional keys. Overrides name an argument
    by its migration parameter name (p_visa_code), translated to its key (@03:text)."""
    mp = {"p_airtable_record_id": "{{1.id}}", "p_make_execution_id": "{{var.scenario.executionId}}",
          "p_visa_code": "{{1.`Visa Code`}}", "p_document_type": "{{1.`Document Code`}}", "p_synthetic_flag": FLAG}
    params = {"account": CONN, "spname": '"ff13"."drafting_context"', "ignore": False,
              "isToManageDataInSharedTransaction": False, "returnsMultipleBundles": True}
    for k, v in over.items():
        target = params if k in ("account", "spname", "isToManageDataInSharedTransaction", "__IMTCONN__") else mp
        if v is None:
            target.pop(k, None)
        else:
            target[k] = v
    mp = {GROUNDING_KEYS.get(k, k): v for k, v in mp.items()}
    return {"id": mid, "module": "postgres:StoredProcedure", "version": 2, "parameters": params, "mapper": mp}


def claude(mid=30):
    return {"id": mid, "module": "anthropic-claude:createAMessage", "version": 1,
            "mapper": {"model": "claude-opus-5-5", "max_tokens": 16000, "messages": [{"role": "user", "content": "x"}]}}


def call_row(mid=31, n=30, use_ids=None):
    rec = {ab.LABEL_FIELD: OWNER, ab.OUTCOME_FIELD: "Success", ab.TOKEN_IN_FIELD: "{{%s.usage.input_tokens}}" % n,
           ab.TOKEN_OUT_FIELD: "{{%s.usage.output_tokens}}" % n}
    mp = {"table": LEDGER, "record": rec}
    if use_ids is not None:
        mp["useColumnId"] = use_ids
    return {"id": mid, "module": "airtable:ActionCreateRecord", "mapper": mp}


# The eight validator stamp arguments and the call-row field each reads (a09 to a16 of validator()).
STAMP_ARGS = {"a09": STAMPS["model_requested"], "a10": STAMPS["model_served"], "a11": STAMPS["stop_reason"],
              "a12": STAMPS["prompt_version"], "a13": STAMPS["prompt_sha256"], "a14": ab.TOKEN_IN_FIELD,
              "a15": ab.TOKEN_OUT_FIELD, "a16": STAMPS["message_id"]}


def id_stamps(c=31):
    return {k: "{{%s.%s}}" % (c, fid) for k, fid in STAMP_ARGS.items()}


def bulk(mid, cols, module="airtable:bulkUpdateRecords", table=LEAD, records=None):
    """An Airtable v3 bulk write in Enter manually mode: each column is {id, type, value} of records[].record[]."""
    recs = records if records is not None else [{"recordId": "{{1.id}}", "record": cols}]
    return {"id": mid, "module": module, "version": 3, "mapper": {"select": "map", "table": table, "records": recs}}


def api_patch(mid, body, url=f"v0/appX/{LEAD}/{{{{1.id}}}}", module="airtable:makeApiCall", method="PATCH"):
    return {"id": mid, "module": module, "version": 3, "mapper": {"url": url, "method": method, "body": body}}


def create_json(mid, fields):
    return {"id": mid, "module": "json:CreateJSON", "version": 1, "mapper": {"fields": fields}}


def http_v4(mid, body, url=f"https://api.airtable.com/v0/appX/{LEAD}/{{{{1.id}}}}"):
    return {"id": mid, "module": "http:MakeRequest", "version": 4, "parameters": {"authenticationType": "noAuth"},
            "mapper": {"url": url, "method": "patch", "contentType": "json", "inputMethod": "jsonString",
                       "jsonStringBodyContent": body}}


def pg_query(mid, command, account=CONN):
    params = {"account": account, "continueWhenNoRes": False, "isToManageDataInSharedTransaction": False}
    return {"id": mid, "module": "postgres:Query", "version": 2, "parameters": params, "mapper": {"command": command}}


# The validator's 16 arguments in migration order (a01 to a16 in the overrides below), under their parameter names, so E31
# holds each key to its role (FF13_PARAMS). An override key that is not a01 to a16 (a17) is used as is.
VALIDATOR_KEYS = {f"a{i:02d}": k for i, k in enumerate(ab.FF13_PARAMS["validate_draft"], 1)}


def validator(mid=7, d=30, c=31, raw_keys=False, **over):
    mp = {"a01": "{{1.id}}", "a02": "{{var.scenario.executionId}}", "a03": "{{1.`Visa Code`}}", "a04": "{{1.`Document Code`}}",
          "a05": '{{first(map(%s.content; "text"; "type"; "text"))}}' % d, "a06": "{{1.Name}}", "a07": "{{1.`Case Facts`}}",
          "a08": "", "a09": "{{%s.`Model Requested`}}" % c, "a10": "{{%s.`Model Served`}}" % c, "a11": "{{%s.`Stop Reason`}}" % c,
          "a12": "{{%s.`Prompt Version`}}" % c, "a13": "{{%s.`Prompt SHA256`}}" % c, "a14": "{{%s.`Input Tokens`}}" % c,
          "a15": "{{%s.`Output Tokens`}}" % c, "a16": "{{%s.`Message ID`}}" % c}
    for k, v in over.items():
        if v is None:
            mp.pop(k, None)
        else:
            mp[k] = v
    if not raw_keys:
        mp = {VALIDATOR_KEYS.get(k, k): v for k, v in mp.items()}
    return {"id": mid, "module": "postgres:StoredProcedure", "version": 2,
            "parameters": {"account": CONN, "spname": '"ff13"."validate_draft"', "isToManageDataInSharedTransaction": False,
                           "returnsMultipleBundles": True},
            "mapper": mp}


def chain(*tail, name=OWNER, sid=OWNER_ID):
    return bp(trigger(), update(2), grounding(), claude(), call_row(), validator(), update(8, "Draft Rejected"), *tail,
              name=name, sid=sid)


def slack(mid, text):
    return {"id": mid, "module": "slack:CreateMessage", "mapper": {"channel": "C0", "text": text}}


def logger_call(mid, owner, **extra):
    body = {"label": OWNER, "outcome": "Error", "module_id": str(owner), "module_name": "Validate",
            "error_type": "{{%s.error.type}}" % owner, "error_message": "{{%s.error.message}}" % owner,
            "execution_id": "{{var.scenario.executionId}}"}
    body.update(extra)
    return {"id": mid, "module": "http:MakeRequest", "version": 4,
            "parameters": {"authenticationType": "apiKeyConnection", "apiKeyAccount": 4242},
            "mapper": {"url": "{{%s}}" % VAR, "method": "post", "headers": [], "queryParameters": [], "contentType": "urlEncoded",
                       "urlEncodedBodyContent": [{"name": k, "value": v} for k, v in body.items()], "parseResponse": False,
                       "stopOnHttpError": False, "allowRedirects": False}}


# ---------------------------------------------------------------------------
# The planned chain passes when the owner is pinned
# ---------------------------------------------------------------------------


class OwnerChainTests(unittest.TestCase):
    def test_the_planned_chain_has_no_ff10_row(self):
        b = chain()
        self.assertEqual([f.detail for f in rows(b) if f.rule in ("E29", "E30", "E31", "E32")], [])

    def test_the_committed_pin_loads(self):
        """Only what stays true across build-order step 6, which commits the owner's scenario ID."""
        pin = ab.load_ff10(ab.DEFAULT_FF10)
        self.assertEqual((pin.owner_name, pin.connection_id), (OWNER, CONN))
        self.assertTrue(pin.owner_scenario_id is None or (pin.owner_scenario_id.isdigit() and int(pin.owner_scenario_id) > 0))

    def test_the_committed_pull_has_no_ff10_row(self):
        blueprints, _ = ab.load_manifest_mode(os.path.join(ROOT, "blueprints"), os.path.join(ROOT, "blueprints", "manifest.json"))
        # The audit passes the registered Logger, so a Logger call in an error route is not read as an Airtable write.
        webhooks = ab.load_webhooks(ab.DEFAULT_WEBHOOKS, required=True)
        found = [f for b in blueprints for f in ab.check_e(b, LINKS, ab.Allowlist(), webhooks.logger, webhooks, ff10=ab.load_ff10())
                 if f.rule in ("E29", "E30", "E31", "E32")]
        # The X-16.1 push (2026-11-17, version 9) moved the production Doc 24 to the review folder, so no row remains.
        self.assertEqual(found, [])


# ---------------------------------------------------------------------------
# E29 Synthetic Test Case has no writer
# ---------------------------------------------------------------------------


class E29Tests(unittest.TestCase):
    def test_a_record_key_by_id_or_name_fails_in_any_scenario(self):
        for key in (SYNTH, "Synthetic Test Case", " synthetic test case "):
            for b in (chain(update(9, True, key=key)), bp(trigger(), update(2, True, key=key), name="Other", sid="1")):
                fail = rows(b, "E29")
                self.assertEqual([f.module_id for f in fail], [9 if b.name == OWNER else 2], key)
                self.assertIn("by hand only", fail[0].detail)

    def test_a_create_and_an_error_route_count(self):
        create = update(9, True, key=SYNTH, rid=None, module="airtable:ActionCreateRecord")
        owner = dict(update(3, "x", key="fldWeOrgnVgfDO21O"))
        owner["onerror"] = [update(10, False, key="Synthetic Test Case"), {"id": 11, "module": "builtin:Resume"}]
        fail = rows(bp(trigger(), create, owner, name="Other", sid="1"), "E29")
        self.assertEqual(sorted(f.module_id for f in fail), [9, 10])
        self.assertTrue(any("error route" in f.detail for f in fail))

    def test_an_airtable_api_or_http_write_fails_and_a_get_passes(self):
        api = {"id": 5, "module": "airtable:makeApiCall",
               "mapper": {"url": f"/v0/base/{LEAD}/rec00000000000001", "method": "PATCH",
                          "body": '{"fields": {"Synthetic Test Case": true}}'}}
        http = {"id": 6, "module": "http:MakeRequest", "mapper": {"url": "https://api.airtable.com/v0/x", "method": "patch",
                                                                   "data": '{"fields": {"%s": true}}' % SYNTH}}
        get = {"id": 7, "module": "airtable:makeApiCall",
               "mapper": {"url": f"/v0/base/{LEAD}?filterByFormula=%7BSynthetic%20Test%20Case%7D", "method": "GET"}}
        fail = rows(bp(trigger(), api, http, get, name="Other", sid="1"), "E29")
        self.assertEqual(sorted(f.module_id for f in fail), [5, 6])

    def test_the_real_airtable_api_call_module_is_matched(self):
        """Airtable v3 names its Make an API call makeApiCall (Make MCP app-modules_list, 2026-11-15). The rule must catch
        that type, with its relative url and upper-case method, not only a made-up spelling."""
        self.assertTrue(ab._airtable_api_module({"module": "airtable:makeApiCall"}))
        self.assertTrue(ab._airtable_api_module({"module": "airtable:MakeAPICall"}))
        for method in ("PATCH", "patch", "POST", "PUT"):
            synth = api_patch(5, '{"fields": {"Synthetic Test Case": true}}', method=method)
            status = api_patch(6, '{"fields": {"Drafting Status": "Drafting"}}', method=method)
            b = bp(trigger(), synth, status, name="Some Other Scenario", sid="1")
            self.assertEqual([f.module_id for f in rows(b, "E29")], [5], method)
            self.assertEqual([f.module_id for f in rows(b, "E30")], [6], method)
        get = api_patch(5, "", url=f"v0/appX/{LEAD}?fields%5B%5D=Synthetic%20Test%20Case", method="GET")
        self.assertEqual(rows(bp(trigger(), get, name="Other", sid="1"), "E29"), [])

    def test_check_a_reads_the_real_api_call_module(self):
        m = api_patch(5, '{"fields": {"Status": "Disqualified"}}')
        self.assertEqual(ab.alias_status_write(m), ("Disqualified", False))

    def test_bulk_writes_by_column_id_value(self):
        for module in ("airtable:bulkUpdateRecords", "airtable:bulkCreateRecords", "airtable:bulkUpsertRecords"):
            for cid in (SYNTH, "Synthetic Test Case"):
                col = [{"id": cid, "type": "boolean", "value": True}]
                fail = rows(bp(trigger(), bulk(5, col, module=module), name="Some Other Scenario", sid="1"), "E29")
                self.assertEqual([f.module_id for f in fail], [5], (module, cid))
                self.assertIn("through a record key", fail[0].detail)
        other_name = bulk(5, [{"id": "Synthetic Test Case", "type": "boolean", "value": True}], table="tblSFR7Sg8uh8noO2")
        self.assertEqual(rows(bp(trigger(), other_name, name="Other", sid="1"), "E29"), [])
        other_cols = bulk(5, [{"id": "fldWeOrgnVgfDO21O", "type": "text", "value": "x"}])
        self.assertEqual(rows(bp(trigger(), other_cols, name="Other", sid="1"), "E29"), [])

    def test_a_mapped_bulk_records_list_fails_as_unknown(self):
        agg = {"id": 3, "module": "builtin:BasicAggregator", "version": 1, "parameters": {"feeder": 1}, "mapper": {}}
        cases = {"records": bulk(5, None, records="{{3.array}}"),
                 "record": bulk(5, None, records=[{"recordId": "{{1.id}}", "record": "{{3.cols}}"}]),
                 "column id": bulk(5, [{"id": "{{3.field}}", "type": "boolean", "value": True}])}
        for label, m in cases.items():
            b = bp(trigger(), agg, m, name="Some Other Scenario", sid="1")
            e29, e30 = rows(b, "E29"), rows(b, "E30")
            self.assertEqual([f.module_id for f in e29], [5], label)
            self.assertIn("may write", e29[0].detail, label)
            self.assertEqual([f.module_id for f in e30], [5], label)
        on_ledger = bulk(5, None, table=LEDGER, records="{{3.array}}")
        self.assertEqual(rows(bp(trigger(), agg, on_ledger, name="Other", sid="1"), "E29"), [])

    def test_a_native_write_with_a_mapped_record_fails_as_unknown(self):
        m = {"id": 5, "module": "airtable:ActionUpdateRecords", "mapper": {"table": LEAD, "id": "{{1.id}}", "record": "{{3.rec}}"}}
        self.assertEqual([f.module_id for f in rows(bp(trigger(), m, name="Other", sid="1"), "E29")], [5])

    def test_an_api_body_built_in_another_module_fails_as_unknown(self):
        writers = (http_v4(4, "{{3.json}}"), api_patch(4, "{{3.json}}"), api_patch(4, '{"fields": {{3.json}}}'),
                   api_patch(4, '{"fields": {"{{3.name}}": true}}'), api_patch(4, {"fields": "{{3.json}}"}))
        for field in ("Synthetic Test Case", SYNTH):
            for writer in writers:
                for name, sid in (("Some Other Scenario", "1"), (OWNER, OWNER_ID)):
                    b = bp(trigger(), create_json(3, {field: True}), writer, name=name, sid=sid)
                    e29 = rows(b, "E29")
                    self.assertEqual([f.module_id for f in e29], [4], (field, writer["mapper"], name))
                    self.assertIn("may write", e29[0].detail)
                    e30 = rows(b, "E30")
                    self.assertEqual([f.module_id for f in e30], [4], (writer["mapper"], name))
                    if name == OWNER:
                        self.assertIn("cannot tell which fields", e30[0].detail)

    def test_a_mapped_body_to_another_table_or_service_passes(self):
        cases = (http_v4(4, "{{3.json}}", url="https://example.invalid/v1/items"),
                 http_v4(4, "{{3.json}}", url=f"https://api.airtable.com/v0/appX/{LEDGER}"),
                 api_patch(4, "{{3.json}}", url="v0/appX/System%20Logs"),
                 api_patch(4, '{"fields": {"Name": "{{3.name}}"}}'))
        for m in cases:
            b = bp(trigger(), create_json(3, {"x": 1}), m, name="Other", sid="1")
            self.assertEqual(rows(b, "E29") + rows(b, "E30"), [], m["mapper"])

    def test_check_a_reads_a_v4_body_built_elsewhere(self):
        self.assertEqual(ab.alias_status_write(http_v4(4, "{{3.json}}")), (None, True))

    def test_a_read_of_the_flag_passes(self):
        self.assertEqual(rows(chain(), "E29"), [])

    def test_e29_cannot_be_allowlisted(self):
        self.assertNotIn("E29", ab.ALLOW_RULES)
        self.assertNotIn("E30", ab.ALLOW_RULES)
        self.assertNotIn("E31", ab.ALLOW_RULES)


# ---------------------------------------------------------------------------
# E30 Drafting Status has one owner
# ---------------------------------------------------------------------------


class E30Tests(unittest.TestCase):
    def test_another_scenario_fails(self):
        b = bp(trigger(), update(2, "Draft Failed"), name="Submission Letter", sid="3974513")
        fail = rows(b, "E30")
        self.assertEqual([f.module_id for f in fail], [2])
        self.assertIn(f"scenario {OWNER_ID}", fail[0].detail)

    def test_by_name_on_applicants_and_by_id_anywhere(self):
        by_name = update(2, "Drafting", key="drafting status", table="Applicants")
        by_id_elsewhere = update(3, "Drafting", table="tblSFR7Sg8uh8noO2")
        name_elsewhere = update(4, "Drafting", key="Drafting Status", table="tblSFR7Sg8uh8noO2")
        fail = rows(bp(trigger(), by_name, by_id_elsewhere, name_elsewhere, name="Other", sid="1"), "E30")
        self.assertEqual(sorted(f.module_id for f in fail), [2, 3])

    def test_the_owner_must_key_every_write_by_the_trigger(self):
        cases = {
            "{{2.id}}": "not exactly {{1.id}}",
            "rec00000000000001": "not a mapping",
            "{{1.id}} ": "not exactly {{1.id}}",
        }
        for rid, why in cases.items():
            fail = rows(bp(trigger(), update(2, rid=rid)), "E30")
            self.assertEqual(len(fail), 1, rid)
            self.assertIn(why, fail[0].detail)
        self.assertEqual(rows(bp(trigger(), update(2, rid="{{ 1.id }}")), "E30"), [])

    def test_a_create_or_upsert_in_the_owner_fails(self):
        for module in ("airtable:ActionCreateRecord", "airtable:ActionUpsertRecord"):
            fail = rows(bp(trigger(), update(2, module=module)), "E30")
            self.assertEqual(len(fail), 1, module)
            self.assertIn("only an update keyed by the trigger", fail[0].detail)

    def test_the_trigger_must_be_an_applicants_watch(self):
        other_table = rows(bp(trigger(table="tblSFR7Sg8uh8noO2"), update(2)), "E30")
        self.assertIn("not Applicants", other_table[0].detail)
        webhook = rows(bp({"id": 1, "module": "gateway:CustomWebHook"}, update(2)), "E30")
        self.assertIn("not an Airtable Watch Records trigger", webhook[0].detail)

    def test_error_route_writes_count(self):
        owner = grounding()
        owner["onerror"] = [update(12, "Draft Failed", rid="{{4.record_id}}"), {"id": 13, "module": "builtin:Ignore"}]
        fail = rows(bp(trigger(), owner), "E30")
        self.assertEqual([f.module_id for f in fail], [12])
        self.assertIn("error route", fail[0].detail)

    def test_an_api_write_in_the_owner_fails(self):
        api = {"id": 5, "module": "airtable:makeApiCall",
               "mapper": {"url": f"/v0/base/{LEAD}/{{{{1.id}}}}", "method": "PATCH", "body": '{"fields": {"Drafting Status": "x"}}'}}
        fail = rows(bp(trigger(), api), "E30")
        self.assertIn("API or HTTP call", fail[0].detail)

    def test_pending_owner_shows_one_pending_row_per_write(self):
        b = chain(sid=None)
        e30 = rows(b, "E30", pin=PENDING)
        self.assertEqual(sorted(f.module_id for f in e30), [2, 8])
        self.assertTrue(all(f.detail.startswith("E30 owner pending:") for f in e30))
        e31 = rows(b, "E31", pin=PENDING)
        self.assertEqual(sorted(f.module_id for f in e31), [4, 7])
        self.assertTrue(all(f.detail.startswith("E31 owner pending:") for f in e31))

    def test_pending_owner_keeps_the_shape_rows(self):
        e30 = rows(bp(trigger(), update(2, rid="{{2.id}}"), sid=None), "E30", pin=PENDING)
        self.assertEqual(len(e30), 2)
        self.assertEqual(sum(f.detail.startswith("E30 owner pending:") for f in e30), 1)

    def test_pending_owner_other_name_is_not_the_owner(self):
        fail = rows(bp(trigger(), update(2), name="Module F Drafting Chain copy", sid=None), "E30", pin=PENDING)
        self.assertEqual(len(fail), 1)
        self.assertIn("owner_scenario_id not pinned yet", fail[0].detail)

    def test_a_bulk_write_in_the_owner_fails(self):
        col = [{"id": DSTATUS, "type": "text", "value": "Drafting"}]
        fail = rows(chain(bulk(9, col)), "E30")
        self.assertEqual([f.module_id for f in fail], [9])
        self.assertIn("only a single-record update keyed by the trigger", fail[0].detail)
        fail = rows(bp(trigger(), bulk(5, col), name="Some Other Scenario", sid="1"), "E30")
        self.assertEqual([f.module_id for f in fail], [5])

    def test_a_pinned_owner_rejects_a_copy_with_the_owner_name(self):
        fail = rows(chain(sid="7000002"), "E30")
        self.assertEqual(sorted(f.module_id for f in fail), [2, 8])


# ---------------------------------------------------------------------------
# E31 the ff13 calls are pinned
# ---------------------------------------------------------------------------


class E31Tests(unittest.TestCase):
    def e31(self, *mods, **kw):
        return rows(bp(trigger(), *mods, **kw), "E31")

    def test_only_the_owner_calls_ff13(self):
        fail = self.e31(grounding(), name="Submission Letter", sid="3974513")
        self.assertEqual(len(fail), 1)
        self.assertIn("which only scenario 7000001", fail[0].detail)

    def test_an_http_rpc_call_is_found_and_fails_even_in_the_owner(self):
        http = {"id": 9, "module": "http:MakeRequest",
                "mapper": {"url": "https://example.supabase.co/rest/v1/rpc/drafting_context", "method": "post"}}
        fail = self.e31(http)
        self.assertIn("ff13 calls run only through postgres:StoredProcedure", fail[0].detail)
        self.assertEqual(len(self.e31(http, name="Other", sid="1")), 1)

    def test_a_logger_call_naming_the_function_is_not_a_call(self):
        lg = logger_call(9, 4, module_name="ff13.drafting_context")
        self.assertEqual(rows(bp(trigger(), lg, name="Other", sid="1"), "E31", logger=SPEC), [])

    def test_a_mapped_function_name_fails_anywhere(self):
        fail = self.e31(grounding(spname="{{1.fn}}"), name="Other", sid="1")
        self.assertIn("spname) is a mapping", fail[0].detail)

    def test_a_mapped_query_on_the_ff13_connection_fails_anywhere(self):
        sv = {"id": 3, "module": "util:SetVariable2", "version": 1,
              "mapper": {"name": "sql", "value": "select * from ff13.validate_draft('x')", "scope": "roundtrip"}}
        for name, sid in (("Some Other Scenario", "1"), (OWNER, OWNER_ID)):
            fail = self.e31(sv, pg_query(4, "{{3.sql}}"), name=name, sid=sid)
            self.assertEqual([f.module_id for f in fail], [4], name)
            self.assertIn("SQL is a mapping", fail[0].detail)

    def test_a_mapping_in_a_name_position_fails_on_any_connection(self):
        for command in ("select * from ff13.{{3.fn}}('x')", "select * from {{3.fn}}('x')", 'select * from "{{3.schema}}".f()',
                        "{{3.verb}} ff13.f()", "select {{3.call}}"):
            fail = self.e31(pg_query(4, command, account=555), name="Other", sid="1")
            self.assertEqual([f.module_id for f in fail], [4], command)

    def test_a_value_mapping_on_another_connection_passes(self):
        for command in ("select * from public.items where id = {{1.id}}", "select * from public.items where id = '{{1.id}}'",
                        "select public.f({{1.id}}, '{{1.x}}')"):
            self.assertEqual(self.e31(pg_query(4, command, account=555), name="Other", sid="1"), [], command)

    def test_any_module_on_the_ff13_connection_is_an_ff13_call(self):
        cases = (pg_query(4, "select * from public.items where id = {{1.id}}"),
                 grounding(4, spname="ff13.other_function"),
                 {"id": 4, "module": "postgres:SelectFromTable", "version": 2, "parameters": {"account": CONN},
                  "mapper": {"table": "items"}})
        for m in cases:
            for name, sid in (("Some Other Scenario", "1"), (OWNER, OWNER_ID)):
                fail = self.e31(m, name=name, sid=sid)
                self.assertEqual([f.module_id for f in fail], [4], (m["module"], name))
                self.assertIn("on the ff13_make connection", fail[0].detail)
        self.assertEqual(self.e31(grounding(4, account=555, spname="public.other"), name="Other", sid="1"), [])

    def test_settings(self):
        cases = {
            "account": (dict(account=999), "parameters.account is not the ff13_make connection"),
            "no account": (dict(account=None), "parameters.account is not set"),
            "imtconn": (dict(__IMTCONN__=5), "parameters.__IMTCONN__ is not the ff13_make connection"),
            "shared": (dict(isToManageDataInSharedTransaction=True), "isToManageDataInSharedTransaction is not false"),
            "shared missing": (dict(isToManageDataInSharedTransaction=None), "isToManageDataInSharedTransaction is not set"),
            "spname": (dict(spname="public.drafting_context"), "spname is not the literal ff13.drafting_context"),
        }
        for label, (over, why) in cases.items():
            fail = self.e31(grounding(**over))
            self.assertEqual(len(fail), 1, label)
            self.assertIn(why, fail[0].detail, label)
        version = grounding()
        version["version"] = 1
        self.assertIn("module version is 1", self.e31(version)[0].detail)
        self.assertEqual(self.e31(grounding(spname='"ff13"."drafting_context"')), [])

    def test_a_shared_transaction_string_is_not_false(self):
        self.assertEqual(len(self.e31(grounding(isToManageDataInSharedTransaction="false"))), 1)

    def test_grounding_arguments(self):
        cases = {
            "literal record ID": (dict(p_airtable_record_id="rec00000000000001"), "holds a literal"),
            "another record": (dict(p_airtable_record_id="{{2.id}}"), "maps {{2.id}}"),
            "flag form": (dict(p_synthetic_flag="{{1.`Synthetic Test Case`}}"), "synthetic flag"),
            "literal code": (dict(p_visa_code="EE-FSW"), "holds a literal"),
            "missing doc": (dict(p_document_type=None), "no argument maps the document type"),
            "twice": (dict(extra="{{1.id}}"), "maps the record ID more than once"),
            "empty": (dict(p_extra=""), "is empty, which is no argument of ff13.drafting_context"),
            "number": (dict(p_extra=5), "holds a literal"),
        }
        for label, (over, why) in cases.items():
            fail = self.e31(grounding(**over))
            self.assertEqual(len(fail), 1, label)
            self.assertIn(why, fail[0].detail, label)

    def test_a_literal_is_never_shown(self):
        fail = self.e31(grounding(p_visa_code="ZZ-TEST secret-ish literal"))
        self.assertNotIn("secret-ish", fail[0].detail)

    def test_whitespace_next_to_delimiters_is_ignored(self):
        self.assertEqual(self.e31(grounding(p_synthetic_flag='{{ if( 1.`Synthetic Test Case` ;"true" ; "false" ) }}')), [])

    def test_trigger_reading_field_ids_uses_id_forms(self):
        b = bp(trigger(use_ids=True), grounding(p_visa_code="{{1.flducJsQNA4cND9xC}}", p_document_type="{{1.fldnau52BJIL6MS3K}}",
                                                p_synthetic_flag='{{if(1.fldsCjg7ftgursZvl; "true"; "false")}}'))
        self.assertEqual(rows(b, "E31"), [])
        self.assertEqual(len(rows(bp(trigger(use_ids=True), grounding()), "E31")), 1)

    def test_the_trigger_must_be_an_applicants_watch(self):
        fail = rows(bp({"id": 1, "module": "gateway:CustomWebHook"}, grounding()), "E31")
        self.assertIn("not an Airtable Watch Records trigger", fail[0].detail)

    def test_validator_arguments(self):
        cases = {
            "stamps from the drafter": (dict(a12="{{30.model}}"), "maps {{30.model}}"),
            "draft index": (dict(a05="{{30.content[1].text}}"), "no argument maps the draft"),
            "name literal": (dict(a06="TEST Applicant"), "holds a literal"),
            "two empties": (dict(a17=""), "is empty"),
            "missing request ID": (dict(a16=None), "no argument maps the request ID"),
        }
        for label, (over, why) in cases.items():
            fail = rows(chain(), "E31") if not over else rows(
                bp(trigger(), grounding(), claude(), call_row(), validator(**over)), "E31")
            self.assertEqual(len(fail), 1, label)
            self.assertIn(why, fail[0].detail, label)

    def test_validator_without_exemplar_key_passes(self):
        self.assertEqual(rows(bp(trigger(), grounding(), claude(), call_row(), validator(a08=None)), "E31"), [])

    def test_validator_field_id_stamps_pass_when_the_call_row_maps_by_id(self):
        b = bp(trigger(), grounding(), claude(), call_row(use_ids=True), validator(**id_stamps()))
        self.assertEqual(rows(b, "E31"), [])

    def test_field_id_stamps_from_a_call_row_that_outputs_names_fail(self):
        """Make outputs the call row's fields by name when useColumnId is false (every Airtable action of the committed
        pull), so {{31.<field ID>}} maps blank and the validator would get null stamps."""
        for use_ids in (False, None):
            b = bp(trigger(), grounding(), claude(), call_row(use_ids=use_ids), validator(**id_stamps()))
            fail = rows(b, "E31")
            self.assertEqual(len(fail), 1, use_ids)
            self.assertIn("no argument maps the", fail[0].detail)
            self.assertIn("prompt version", fail[0].detail)
        one = {"a12": "{{31.%s}}" % STAMPS["prompt_version"]}
        fail = rows(bp(trigger(), grounding(), claude(), call_row(use_ids=False), validator(**one)), "E31")
        self.assertEqual(len(fail), 1)
        self.assertIn("@12:text maps", fail[0].detail)

    def test_name_stamps_from_a_call_row_that_outputs_ids_fail(self):
        fail = rows(bp(trigger(), grounding(), claude(), call_row(use_ids=True), validator()), "E31")
        self.assertEqual(len(fail), 1)
        self.assertIn("no argument maps the", fail[0].detail)

    def test_stamps_from_another_claude_modules_call_row_fail(self):
        b = bp(trigger(), grounding(), claude(20), call_row(21, 20), claude(), call_row(),
               validator(a12="{{21.`Prompt Version`}}"))
        fail = rows(b, "E31")
        self.assertEqual(len(fail), 1)
        self.assertIn("call row of Claude module 20, which is not the drafter", fail[0].detail)

    def test_a_drafter_without_call_row_is_named(self):
        b = bp(trigger(), grounding(), claude(), validator())
        fail = rows(b, "E31")
        self.assertIn("Claude module 30 has no call row", fail[0].detail)

    def test_a_drafter_after_the_validator_does_not_count(self):
        b = bp(trigger(), grounding(), validator(), claude(), call_row())
        fail = rows(b, "E31")
        self.assertIn("no argument maps the draft", fail[0].detail)


# ---------------------------------------------------------------------------
# E6 widened
# ---------------------------------------------------------------------------


class E6WidenedTests(unittest.TestCase):
    def test_slack_mapping_of_validator_grounding_or_claude_text_fails(self):
        for text, field in (("{{7.review_note}}", "review_note"), ("{{7.detail.gate_mode}}", "detail"),
                            ("{{4.provisions}}", "provisions"),
                            ('{{first(map(30.content; "text"; "type"; "text"))}}', "content")):
            fail = rows(chain(slack(40, f"Draft {text}")), "E6")
            self.assertEqual(len(fail), 1, text)
            self.assertIn(f"`{field}`", fail[0].detail)

    def test_ids_codes_and_verdict_pass(self):
        text = "{{1.id}} {{var.scenario.executionId}} {{7.verdict}} {{7.hard_fail_count}} {{4.gate_mode}} {{4.grounding_id}}"
        self.assertEqual(rows(chain(slack(40, text)), "E6"), [])

    def test_the_new_e6_rows_cannot_be_allowlisted(self):
        allow = ab.Allowlist([{"check": "E6", "scenario": OWNER_ID, "module": "40", "reason": "a test reason here",
                               "match": "review_note"}])
        found = [f for f in ab.check_e(chain(slack(40, "{{7.review_note}}")), LINKS, allow, bland_agents=ab.BlandAgents(),
                                       ff10=PIN) if f.rule == "E6"]
        self.assertEqual([f.status for f in found], [ab.FAIL])

    def test_listing_the_field_in_the_links_map_keeps_the_row_strict(self):
        """A later edit that adds review_note to non_airtable_pii (as the spec's wording invites) must not make the row
        allowlistable: strictness comes from FF10_SOURCE_PII alone."""
        import copy
        links = copy.deepcopy(LINKS)
        links.source_pii["postgres:StoredProcedure"] = ["review_note"]
        allow = ab.Allowlist([{"check": "E6", "scenario": OWNER_ID, "module": "40", "reason": "a test reason here",
                               "match": "review_note"}])
        found = [f for f in ab.check_e(chain(slack(40, "{{7.review_note}}")), links, allow, bland_agents=ab.BlandAgents(),
                                       ff10=PIN) if f.rule == "E6"]
        self.assertEqual([f.status for f in found], [ab.FAIL])
        self.assertEqual(ab.ff10_source_pii(links, "postgres:StoredProcedure"),
                         ({"review_note"}, {"review_note", "detail", "provisions"}))

    def test_a_logger_call_body_with_validator_text_fails_check_b(self):
        handled = grounding()
        handled["onerror"] = [logger_call(41, 4, error_message="{{4.provisions}}"), {"id": 42, "module": "builtin:Ignore"}]
        b = bp(trigger(), handled)
        e6 = rows(b, "E6", logger=SPEC)
        self.assertEqual(len(e6), 1)
        b_rows = [f for f in ab.check_b(b, SPEC, LINKS) if f.status == ab.FAIL]
        self.assertTrue(any("sends client data (E6)" in f.detail and "provisions" in f.detail for f in b_rows))

    def test_source_pii_merge(self):
        self.assertEqual(ab.ff10_source_pii(LINKS, "postgres:StoredProcedure")[1], {"review_note", "detail", "provisions"})
        self.assertEqual(ab.ff10_source_pii(LINKS, ab.CLAUDE_MODULE)[1], {"content"})
        self.assertEqual(ab.ff10_source_pii(LINKS, "slack:CreateMessage")[1], set())


# ---------------------------------------------------------------------------
# audit/ff10.json and make_push
# ---------------------------------------------------------------------------


class PinFileTests(unittest.TestCase):
    def load(self, data):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "ff10.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(data, fh)
            return ab.load_ff10(path)

    def test_valid_files(self):
        self.assertEqual(self.load({"owner_scenario_id": None, "owner_name": OWNER, "ff13_connection_id": CONN}), PENDING)
        self.assertEqual(self.load({"owner_scenario_id": 7000001, "owner_name": OWNER, "ff13_connection_id": CONN, "_use": "x"}), PIN)
        self.assertEqual(self.load({"owner_scenario_id": "7000001", "owner_name": OWNER, "ff13_connection_id": CONN}), PIN)

    def test_invalid_files(self):
        good = {"owner_scenario_id": None, "owner_name": OWNER, "ff13_connection_id": CONN}
        for bad in ({**good, "owner_scenario_id": "abc"}, {**good, "owner_scenario_id": True}, {**good, "owner_name": " "},
                    {**good, "ff13_connection_id": "12330102"}, {**good, "extra": 1}, []):
            with self.assertRaises(ab.InputError, msg=bad):
                self.load(bad)

    def test_a_missing_file_is_an_input_error(self):
        with self.assertRaises(ab.InputError):
            ab.load_ff10(os.path.join(ROOT, "audit", "no_such_ff10.json"))
        self.assertEqual(ab.load_ff10(os.path.join(ROOT, "audit", "no_such_ff10.json"), required=False), ab.FF10Pin())

    def test_the_audit_cli_reports_a_bad_pin(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "ff10.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"owner_name": ""}, fh)
            import io
            from contextlib import redirect_stderr
            err = io.StringIO()
            with redirect_stderr(err):
                code = ab.main(["--no-report", "--ff10", path])
            self.assertEqual(code, 2)
            self.assertIn("owner_name", err.getvalue())


# ---------------------------------------------------------------------------
# E31 by key: the migration's parameter names hold each argument to its role
# ---------------------------------------------------------------------------


class E31KeyTests(unittest.TestCase):
    def e31(self, *mods, status=ab.FAIL):
        return rows(bp(trigger(), grounding(), claude(), call_row(), *mods), "E31", status=status)

    def test_named_keys_in_order_pass_with_no_review(self):
        self.assertEqual(self.e31(validator()), [])
        self.assertEqual(self.e31(validator(), status=ab.REVIEW), [])

    def test_swapped_arguments_fail(self):
        """Every value is still a recognised form, so matching by value alone passed these (F-F10 review 2026-11-15)."""
        c = 31
        swaps = {
            "tokens": (dict(a14="{{%s.`Output Tokens`}}" % c, a15="{{%s.`Input Tokens`}}" % c), "takes the input tokens"),
            "models": (dict(a09="{{%s.`Model Served`}}" % c, a10="{{%s.`Model Requested`}}" % c), "takes the model requested"),
            "prompt": (dict(a12="{{%s.`Prompt SHA256`}}" % c, a13="{{%s.`Prompt Version`}}" % c), "takes the prompt version"),
            "name and facts": (dict(a06="{{1.`Case Facts`}}", a07="{{1.Name}}"), "takes the applicant name"),
            "record and execution": (dict(a01="{{var.scenario.executionId}}", a02="{{1.id}}"), "takes the record ID"),
        }
        for label, (over, why) in swaps.items():
            fail = self.e31(validator(**over))
            self.assertEqual(len(fail), 1, label)
            self.assertIn(why, fail[0].detail, label)
            self.assertIn("matched by key", fail[0].detail, label)

    def test_grounding_swaps_fail(self):
        b = bp(trigger(), grounding(p_visa_code="{{1.`Document Code`}}", p_document_type="{{1.`Visa Code`}}"))
        fail = rows(b, "E31")
        self.assertEqual(len(fail), 1)
        self.assertIn("@03:text holds the pinned form of the document type", fail[0].detail)

    def test_only_exemplar_terms_may_be_empty(self):
        fail = self.e31(validator(a08=None, a16=""))
        self.assertEqual(len(fail), 1)
        self.assertIn("only @08:text may be empty", fail[0].detail)
        fail = self.e31(validator(a08="{{1.id}}"))
        self.assertIn("takes the exemplar terms", fail[0].detail)

    def test_other_keys_fall_back_to_value_matching_with_a_review(self):
        self.assertEqual(self.e31(validator(raw_keys=True)), [])
        review = self.e31(validator(raw_keys=True), status=ab.REVIEW)
        self.assertEqual(len(review), 1)
        self.assertIn("matches the arguments by value only", review[0].detail)
        swapped = validator(raw_keys=True, a14="{{31.`Output Tokens`}}", a15="{{31.`Input Tokens`}}")
        self.assertEqual(self.e31(swapped), [])  # the gap the REVIEW names

    def test_another_scenario_gets_no_review(self):
        b = bp(trigger(), grounding(), claude(), call_row(), validator(raw_keys=True), name="Other", sid="5")
        self.assertEqual([f for f in rows(b, "E31", status=ab.REVIEW)], [])

    def test_parameter_names_equal_the_migration(self):
        path = os.path.join(ROOT, "supabase", "migrations", "20261115000006_ff10_drafting_context.sql")
        with open(path, encoding="utf-8") as fh:
            sql = fh.read()
        names = {"drafting_context": GROUNDING_NAMES, "validate_draft": VALIDATOR_NAMES}
        for fn, params in ab.FF13_PARAMS.items():
            body = sql.split(f"FUNCTION ff13.{fn}(", 1)[1].split(")", 1)[0]
            # Make labels each positional key with the parameter name (measured 2026-11-15), so the migration's order is
            # the key order.
            self.assertEqual([ln.split()[0] for ln in body.strip().splitlines()], list(names[fn]), fn)
            self.assertEqual(list(params), [f"@{i:02d}:text" for i in range(1, len(names[fn]) + 1)], fn)
            self.assertEqual([r for r in params.values() if r != "exemplar terms"], list(ab.FF13_REQUIRED[fn]), fn)


# ---------------------------------------------------------------------------
# E32 the Docs of the drafting chain
# ---------------------------------------------------------------------------

TEST_FOLDER = "/" + ab.load_x16(ab.DEFAULT_X16).test_folder_id  # the pinned Generated Submission test folder (audit/x16.json)
P5 = '{{first(map(%s.content; "text"; "type"; "text"))}}'


def doc(mid=40, mode="test", d=30, v=7, g=4, drop=(), **over):
    conds = {"verdict": {"a": "{{%s.verdict}}" % v, "b": "pass_with_flags", "o": "text:equal"},
             "stop": {"a": "{{%s.stop_reason}}" % d, "b": "end_turn", "o": "text:equal"},
             "mode": {"a": "{{%s.gate_mode}}" % g, "b": mode, "o": "text:equal"},
             "note": {"a": "{{%s.review_note}}" % v, "b": "F-F13 TEST MODE",
                      "o": "text:startwith" if mode == "test" else "text:notstartwith"}}
    if mode == "production":
        conds["folder"] = {"a": "{{1.`Drive Folder ID`}}", "o": "exist"}
    mp = {"name": "TEST, UNREVIEWED CITATION ROWS, NOT FOR CLIENT USE, {{1.id}}" if mode == "test"
          else "DRAFT for review by RCIC {{1.`RCIC of Record`}}, {{1.id}}",
          "content": P5 % d, "folderId": TEST_FOLDER if mode == "test" else f"/{REVIEW_FOLDER}",
          "destination": "drive", "header": False, "footer": False}
    mp.update(over)
    return {"id": mid, "module": "google-docs:createADocument", "version": 1, "parameters": {"__IMTCONN__": 7129814},
            "filter": {"name": "verdict", "conditions": [[c for k, c in conds.items() if k not in drop]]}, "mapper": mp}


class E32Tests(unittest.TestCase):
    def e32(self, *tail, pin=PIN, name=OWNER, sid=OWNER_ID):
        return rows(chain(*tail, name=name, sid=sid), "E32", pin=pin)

    def test_both_modes_pass(self):
        router = {"id": 50, "module": "builtin:BasicRouter", "routes": [{"flow": [doc(40)]}, {"flow": [doc(41, "production")]}]}
        self.assertEqual(self.e32(router), [])
        self.assertEqual(self.e32(doc(41, "production")), [])
        self.assertEqual(self.e32(doc(40), pin=PENDING, sid=None), [])

    def test_x16_drops_the_client_folder_test_and_fails_owner_pending_without_a_review_folder(self):
        """X-16 (2026-11-16): the production Doc no longer needs the Drive Folder ID exists filter, and while audit/x16.json
        review_folder_id is null every production Doc FAILs as owner pending in its own E32 (X-16) row. Test Docs are not
        touched by the pin."""
        self.assertEqual(self.e32(doc(41, "production", drop=("folder",))), [])
        null = ab.X16Pin(**{**X16.__dict__, "review_folder_id": None})
        fail = rows(chain(doc(41, "production")), "E32", x16=null)
        self.assertEqual(len(fail), 1)
        self.assertTrue(fail[0].detail.startswith("E32 (X-16) is the production Doc"))
        self.assertIn("owner pending: audit/x16.json review_folder_id is null", fail[0].detail)
        self.assertEqual(rows(chain(doc(40)), "E32", x16=null), [])

    def test_another_scenario_is_out_of_scope(self):
        self.assertEqual(self.e32(doc(40, folderId="/{{1.`Drive Folder ID`}}"), name="Other", sid="5"), [])

    def test_mutations_of_the_review_fail(self):
        """The four mutations of the F-F10 review (2026-11-15) that added no row before E32, plus the stop reason."""
        cases = {
            "test folder from the client": (doc(40, folderId="/{{1.`Drive Folder ID`}}"), "one literal folder"),
            "test folder placeholder": (doc(40, folderId="/__FF10_TEST_FOLDER_ID__"), "one literal folder"),
            "TEST title gone": (doc(40, name="Draft letter"), "does not start with TEST, UNREVIEWED"),
            "production fallback folder": (doc(41, "production", drop=("folder",),
                                               folderId="/{{ifempty(1.`Drive Folder ID`; \"1Shared0Default000\")}}"),
                                           "review_folder_id of audit/x16.json"),
            "production client folder (X-16)": (doc(41, "production", folderId="/{{1.`Drive Folder ID`}}"),
                                                "review_folder_id of audit/x16.json"),
            "production name without the record (X-16)": (doc(41, "production", name="DRAFT for review"), "does not hold {{1.id}}"),
            "content from the outline": (doc(40, content=P5 % 20), "not exactly the P5 form"),
            "no stop reason gate": (doc(40, drop=("stop",)), "{{30.stop_reason}} text equal end_turn"),
            "no verdict gate": (doc(40, drop=("verdict",)), "{{7.verdict}} text equal pass"),
            "no mode": (doc(40, drop=("mode",)), "pins one grounding mode"),
            "test note prefix": (doc(40, drop=("note",)), "to start with F-F13 TEST MODE"),
            "production note prefix": (doc(41, "production", drop=("note",)), "not to start with F-F13 TEST MODE"),
        }
        for label, (m, why) in cases.items():
            tail = (claude(20), m) if "outline" in label else (m,)
            fail = self.e32(*tail)
            self.assertEqual(len(fail), 1, label)
            self.assertIn(why, fail[0].detail, label)

    def test_a_path_that_pins_both_modes_pins_none(self):
        fail = self.e32(doc(40), doc(41, "production"))
        self.assertIn("pins one grounding mode", next(f.detail for f in fail if f.module_id == 41))

    def test_a_stop_gate_in_a_second_or_group_only_fails(self):
        m = doc(40)
        group = m["filter"]["conditions"][0]
        m["filter"]["conditions"] = [group, [c for c in group if "stop_reason" not in c["a"]]]
        self.assertEqual(len(self.e32(m)), 1)

    def test_a_gate_on_an_earlier_module_counts(self):
        gate = {"id": 39, "module": "util:SetVariable2", "mapper": {},
                "filter": {"name": "stop", "conditions": [[{"a": "{{30.stop_reason}}", "b": "end_turn", "o": "text:equal"}]]}}
        self.assertEqual(self.e32(gate, doc(40, drop=("stop",))), [])

    def test_a_doc_before_the_validator_fails(self):
        b = bp(trigger(), grounding(), claude(), call_row(), doc(40), validator())
        fail = rows(b, "E32")
        self.assertIn("no ff13.validate_draft call before it", fail[0].detail)

    def test_another_module_carrying_the_draft_fails(self):
        upload = {"id": 42, "module": "google-drive:uploadAFile", "version": 4, "mapper": {"data": P5 % 30, "filename": "x"}}
        fail = self.e32(upload)
        self.assertEqual(len(fail), 1)
        self.assertIn("carries the text of drafter 30", fail[0].detail)

    def test_e32_cannot_be_allowlisted(self):
        self.assertNotIn("E32", ab.ALLOW_RULES)

    def test_the_committed_blueprint(self):
        """The F-F10 blueprint passes E32 and E31 by key, and fails E32 without the stop gate or with the folder placeholder."""
        path = os.path.join(ROOT, "specs", "f-f10-drafting-chain.blueprint.json")
        with open(path, encoding="utf-8") as fh:
            spec = json.load(fh)

        def audit(data):
            b = ab.Blueprint(name=OWNER, scenario_id=None, source="test", bp=data)
            logger = ab.load_webhooks(ab.DEFAULT_WEBHOOKS, required=True).logger
            return [f for f in ab.check_e(b, LINKS, ab.Allowlist(), logger=logger, bland_agents=ab.BlandAgents(), ff10=PENDING)
                    if f.rule in ("E31", "E32") and f.status in (ab.FAIL, ab.REVIEW) and "owner pending" not in f.detail
                    and not f.detail.startswith("E32 (X-16)")]   # the X-16 review-folder row has its own tests

        self.assertEqual(audit(spec), [])
        mods = {}

        def walk(flow):
            for x in flow or []:
                mods[x["id"]] = x
                for r in x.get("routes") or []:
                    walk(r.get("flow"))
                walk(x.get("onerror"))

        walk(spec["flow"])
        self.assertTrue(all(any(c["a"] == "{{9.stop_reason}}" for c in g)
                            for mid in (20, 24) for g in mods[mid]["filter"]["conditions"]))
        for g in mods[20]["filter"]["conditions"] + mods[24]["filter"]["conditions"]:
            g[:] = [c for c in g if c["a"] != "{{9.stop_reason}}"]
        mods[20]["mapper"]["folderId"] = "/__FF10_TEST_FOLDER_ID__"
        found = audit(spec)
        self.assertEqual(sorted(f.module_id for f in found), [20, 24])
        self.assertIn("one literal folder", next(f.detail for f in found if f.module_id == 20))


class MakePushTests(unittest.TestCase):
    def test_fix_checks(self):
        self.assertEqual(make_push.FIX_CHECKS["F-F10"], ("E", "R"))
        self.assertEqual(make_push.fix_checks("F-F10"), ("E", "R"))
        self.assertEqual(make_push.fix_checks("F-F10.1"), ("E", "R"))

    def test_the_pin_is_an_audit_input_equal_to_head(self):
        with open(os.path.join(ROOT, "scripts", "make_push.py"), encoding="utf-8") as fh:
            s = fh.read()
        self.assertIn('("F-F10 owner pin", args.ff10)', s)
        self.assertIn("audit_blueprints.load_ff10(args.ff10, required=True)", s)


class PinGuardTests(tp.Base):
    """The owner pin is an audit input (E30, E31), so the push refuses an uncommitted, missing or invalid one before any request."""

    def test_the_default_run_still_passes(self):
        code, output = self.run_main(tp.FakeMake(tp.live_blueprint()))
        self.assertEqual(code, make_push.EXIT_OK, output)

    def test_an_uncommitted_pin_aborts_before_any_request(self):
        fake = tp.FakeMake(tp.live_blueprint())
        code, output = self.run_main(
            fake, snapshot_state=lambda path: "it differs from the last commit" if os.path.basename(path) == "ff10.json" else None)
        self.assertEqual(code, make_push.EXIT_ABORT)
        self.assertIn("F-F10 owner pin", output)
        self.assertEqual(fake.calls, [])

    def test_a_missing_or_invalid_pin_aborts(self):
        missing = os.path.join(self.tmp, "no_ff10.json")
        bad = os.path.join(self.tmp, "ff10.json")
        with open(bad, "w", encoding="utf-8") as fh:
            json.dump({"owner_scenario_id": "x", "owner_name": OWNER, "ff13_connection_id": CONN}, fh)
        for path in (missing, bad):
            fake = tp.FakeMake(tp.live_blueprint())
            code, output = self.run_main(fake, extra=("--ff10", path))
            self.assertEqual(code, make_push.EXIT_ABORT, path)
            self.assertIn("audit inputs", output)
            self.assertEqual(fake.calls, [])


if __name__ == "__main__":
    unittest.main()
