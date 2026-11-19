"""Tests for scripts/secret_scan.py.

Every secret-shaped value is assembled at runtime by concatenation so this
file itself never contains a literal the pre-commit hook would block.
All fixtures are synthetic.
"""

import contextlib
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import secret_scan  # noqa: E402
from secret_scan import scan_obj, scan_text  # noqa: E402

ALNUM = "A1b2C3d4E5f6G7h8J9k0L1m2N3p4Q5r6"
HEX64 = "0123456789abcdef" * 4


def fake(kind):
    """Build a synthetic secret of the given kind at runtime."""
    return {
        "stripe_sk_live": "sk" + "_live_" + ALNUM,
        "stripe_sk_test": "sk" + "_test_" + ALNUM,
        "stripe_rk_live": "rk" + "_live_" + ALNUM,
        "stripe_rk_test": "rk" + "_test_" + ALNUM,
        "whsec": "wh" + "sec_" + ALNUM,
        "openai": "sk" + "-" + ALNUM + ALNUM[:16],
        "openai_proj": "sk" + "-proj-" + ALNUM + "_" + ALNUM,
        "anthropic": "sk" + "-ant-api03-" + ALNUM + "-" + ALNUM,
        "airtable": "pat" + "Ab12Cd34Ef56Gh" + "." + HEX64,
        "slack_b": "xo" + "xb-" + "1234567890-" + ALNUM,
        "slack_p": "xo" + "xp-" + "1234567890-" + ALNUM,
        "jwt": "ey" + "JhbGciOiJIUzI1NiJ9" + "." + "eyJzdWIiOiJ0ZXN0In0" + "." + "c2lnbmF0dXJlLXNpZw",
        "postgres_url": "postgre" + "sql://postgres.abcdefghijklmnopqrst:" + ALNUM + "@aws-0-ca-central-1.pooler.example:5432/postgres",
        "postgres_url_short": "Postgres" + "://u:" + "pw" + "x@db.example/db",
        "postgres_url_bracketed": "postgre" + "sql://postgres.ref:[" + ALNUM[:12] + "]@aws-0.pooler.example:5432/postgres",
        "postgres_url_specials": "postgre" + "s://u:" + "p@s$w*rd%40" + ALNUM[:6] + "@db.example:5432/db",
        "postgres_url_driver_json": "postgre" + "sql+asyncpg:\\/\\/u:" + ALNUM[:10] + "@db.example\\/db",
    }[kind]


EXPECTED_TYPE = {
    "stripe_sk_live": "stripe_secret_key",
    "stripe_sk_test": "stripe_secret_key",
    "stripe_rk_live": "stripe_restricted_key",
    "stripe_rk_test": "stripe_restricted_key",
    "whsec": "stripe_webhook_secret",
    "openai": "openai_api_key",
    "openai_proj": "openai_api_key",
    "anthropic": "anthropic_api_key",
    "airtable": "airtable_pat",
    "slack_b": "slack_token",
    "slack_p": "slack_token",
    "jwt": "jwt",
    "postgres_url": "db_uri_with_password",
    "postgres_url_short": "db_uri_with_password",
    "postgres_url_bracketed": "db_uri_with_password",
    "postgres_url_specials": "db_uri_with_password",
    "postgres_url_driver_json": "db_uri_with_password",
}


def iml(s):
    """Expand << >> into Make mapping braces at runtime so this file's own
    lines never hold a hash call the text scan would flag."""
    return s.replace("<<", "{" + "{").replace(">>", "}" + "}")


def types(findings):
    return sorted(f["pattern_type"] for f in findings)


def http_module(headers, mid=3):
    """Synthetic Make HTTP module in export shape."""
    return {
        "id": mid,
        "module": "http:ActionSendData",
        "version": 3,
        "parameters": {},
        "mapper": {"url": "https://example.invalid/rest/v1/items", "method": "post", "headers": headers},
        "metadata": {"designer": {"x": 0, "y": 0}},
    }


def blueprint(*modules):
    return {"name": "Synthetic", "flow": list(modules), "metadata": {"version": 1}}


def set_module(value, mid=4):
    return {"id": mid, "module": "util:SetVariable2", "version": 1, "mapper": {"value": value}}


class LiteralPatternTests(unittest.TestCase):
    def test_every_pattern_in_text(self):
        for kind, expected in EXPECTED_TYPE.items():
            with self.subTest(kind=kind):
                found = scan_text("x\nkey = " + fake(kind) + " trailing\n", "f.txt")
                self.assertEqual(types(found), [expected])
                self.assertEqual(found[0]["location"], "f.txt:2")

    def test_every_pattern_in_obj(self):
        for kind, expected in EXPECTED_TYPE.items():
            with self.subTest(kind=kind):
                found = scan_obj(blueprint(set_module("prefix " + fake(kind))))
                self.assertEqual(types(found), [expected])
                self.assertEqual(found[0]["location"], "$.flow[0].mapper.value")

    def test_anthropic_not_double_reported_as_openai(self):
        self.assertEqual(types(scan_text(fake("anthropic"))), ["anthropic_api_key"])

    def test_secret_in_json_key_is_found_and_redacted_in_path(self):
        obj = {"a": {fake("stripe_sk_live"): 1}}
        found = scan_obj(obj)
        self.assertEqual(types(found), ["stripe_secret_key"])
        self.assertEqual(found[0]["location"], '$.a["<redacted>"]')

    def test_nested_routes_and_onerror_paths(self):
        inner = set_module(fake("slack_b"), mid=9)
        router = {"id": 5, "module": "builtin:BasicRouter", "routes": [{"flow": [{"id": 6, "module": "x:Y", "onerror": [inner]}]}]}
        found = scan_obj(blueprint(router))
        self.assertEqual(found, [{"pattern_type": "slack_token", "location": "$.flow[0].routes[0].flow[0].onerror[0].mapper.value"}])

    def test_bare_prefixes_and_lookalikes_are_clean(self):
        clean = [
            "Stripe keys start with sk" + "_live_ or rk" + "_test_ or wh" + "sec_",
            "OpenAI keys start with sk" + "-",
            "desk-" + ALNUM,  # no boundary before sk
            "task" + "-" + ALNUM,
            "sk" + "-learn-is-a-python-library",  # no digit
            "xo" + "xo hugs",
            "pat" + "tern." + HEX64,  # wrong length before the dot
            "ey" + "J only one segment",
            "rec" + "rjR4pzVXNXTGbt app" + "dQ4ThUSMpdVK21 tbl" + "Hk09sCKLcOJXr9",
            # Postgres URIs without an inline password, or with the Connect dialog's placeholder.
            "postgre" + "sql://postgres.abcdefghijklmnopqrst@aws-0-ca-central-1.pooler.example:5432/postgres",
            "postgre" + "sql://postgres.abcdefghijklmnopqrst:[YOUR-PASSWORD]@aws-0.pooler.example:5432/postgres",
            "postgre" + "s://user:<password>@host/db",
            "postgre" + "s://user:$PGPASSWORD@host/db",
            "postgre" + "s://user:password@host/db",
            "postgre" + "s://user:****@host/db",
            "postgre" + "s://user:${PGPASSWORD}@host/db",
            "postgre" + "s://user:{{1.pw}}@host/db",
            "postgre" + "sql://postgres.ref:[password]@host:5432/postgres",
        ]
        for s in clean:
            with self.subTest(s=s[:12]):
                self.assertEqual(scan_text(s), [])


class MakeWebhookUrlTests(unittest.TestCase):
    """A Make custom webhook URL carries a bearer token. Built at runtime."""

    TOKEN = "q7" + "W3e9R1t5Y7u2I4o6P8a0S2d4F6g8H0j2"

    def url(self, host):
        return "https://" + host + "/" + self.TOKEN

    def test_zone_and_plain_hosts_are_found_in_text_and_objects(self):
        for host in ("hook.us2.make.com", "hook.eu1.make.com", "hook.eu2.make.com", "hook.us1.make.com",
                     "hook.make.com", "hook.eu2.make.celonis.com", "hook.integromat.com"):
            text = "POST to " + self.url(host) + " now"
            found = scan_text(text, "doc.md")
            self.assertEqual([f["pattern_type"] for f in found], ["make_webhook_url"], host)
            obj = scan_obj({"nodes": [{"data": {"url": self.url(host)}}]})
            self.assertEqual([f["pattern_type"] for f in obj], ["make_webhook_url"], host)
            self.assertEqual(obj[0]["location"], "$.nodes[0].data.url")

    def test_scheme_is_optional(self):
        found = scan_text("hook.us2.make.com/" + self.TOKEN)
        self.assertEqual([f["pattern_type"] for f in found], ["make_webhook_url"])

    def test_findings_never_carry_the_token(self):
        for f in scan_text(self.url("hook.us2.make.com")) + scan_obj({"u": self.url("hook.us2.make.com")}):
            self.assertNotIn(self.TOKEN, json.dumps(f))
            self.assertNotIn(self.TOKEN[:8], json.dumps(f))

    def test_placeholders_short_paths_and_other_hosts_are_clean(self):
        clean = ("https://hook.us2.make.com/<MAKE_WEBHOOK_URL redacted>", "https://hook.us2.make.com/short",
                 "https://notahook.us2.make.com/" + self.TOKEN, "https://www.make.com/" + self.TOKEN,
                 "https://make.com/hook/" + self.TOKEN, "https://us2.make.com/api/v2/scenarios/3943741/logs")
        for text in clean:
            self.assertEqual(scan_text(text), [], text)
            self.assertEqual(scan_obj({"u": text}), [], text)

    def test_escaped_slash_case_percent_encoding_and_iml_string_forms_are_found(self):
        """safety-R6: these forms passed the text scan, so a .md or broken .json carried a live hook."""
        host = "hook.us1.make.com"
        forms = {
            "json-escaped slashes": "https:\\/\\/" + host + "\\/" + self.TOKEN,
            "upper-case host": "https://" + host.upper() + "/" + self.TOKEN,
            "mixed-case host": "https://Hook.us1.Make.com/" + self.TOKEN,
            "percent-encoded": "https%3A%2F%2F" + host + "%2F" + self.TOKEN,
            "token in an IML string": "https://" + host + '/{{"' + self.TOKEN + '"}}',
        }
        for label, text in forms.items():
            with self.subTest(label):
                self.assertEqual([f["pattern_type"] for f in scan_text(text, "doc.md")], ["make_webhook_url"])
                self.assertEqual([f["pattern_type"] for f in scan_obj({"u": text})], ["make_webhook_url"])
                # An unparseable .json is scanned as text, which is where these forms hid.
                found = secret_scan.scan_bytes(("{ broken " + text).encode(), "x.json")
                self.assertEqual([f["pattern_type"] for f in found], ["make_webhook_url"])
                self.assertNotIn(self.TOKEN, json.dumps(found))

    def test_a_repeated_character_placeholder_token_is_clean(self):
        for ch in ("x", "X", "0", "-"):
            text = "https://hook.us1.make.com/" + ch * 24
            self.assertEqual(scan_text(text), [], text)
            self.assertEqual(scan_obj({"u": text}), [], text)
        # A real-looking token with a repeated stretch still counts.
        self.assertEqual([f["pattern_type"] for f in scan_text("hook.us1.make.com/" + "x" * 12 + "ab12CD34ef56")],
                         ["make_webhook_url"])

    def test_documentation_and_mailhook_hosts_stay_clean_in_every_form(self):
        for text in ("https://docs.make.com/" + self.TOKEN, "https://www.make.com/en/help/" + self.TOKEN,
                     "https://webhook.site/" + self.TOKEN, "https://eu1.make.com/hooks/" + self.TOKEN,
                     "https%3A%2F%2Fdocs.make.com%2F" + self.TOKEN):
            self.assertEqual(scan_text(text), [], text)

    def test_a_pathway_style_file_is_flagged_until_redacted(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "pathway.json")
            doc = {"nodes": [{"type": "Webhook", "data": {"url": self.url("hook.us2.make.com")}}]}
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(doc, fh, indent=2)
            self.assertEqual([f["pattern_type"] for f in secret_scan.scan_paths([path])], ["make_webhook_url"])
            doc["nodes"][0]["data"]["url"] = "<MAKE_WEBHOOK_URL redacted>"
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(doc, fh, indent=2)
            self.assertEqual(secret_scan.scan_paths([path]), [])

    def test_the_committed_bland_pathway_copy_is_clean_and_redacted(self):
        path = os.path.join(ROOT, "bland", "immigration-screener-pathway.json")
        if not os.path.exists(path):
            self.skipTest("no bland pathway copy in this checkout")
        self.assertEqual(secret_scan.scan_paths([path]), [])
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn("<MAKE_WEBHOOK_URL redacted>", text)
        self.assertNotIn("hook.us2", text)


class AuthorizationHeaderTests(unittest.TestCase):
    def scan_header(self, value, name="Authorization"):
        return scan_obj(blueprint(http_module([{"name": name, "value": value}])))

    def test_literal_bearer_value_flagged(self):
        found = self.scan_header("Bearer " + "opaque-but-hardcoded-123")
        self.assertEqual(found, [{"pattern_type": "authorization_header_literal", "location": "$.flow[0].mapper.headers[0].value"}])

    def test_literal_without_scheme_flagged(self):
        self.assertEqual(types(self.scan_header("abc" + "123")), ["authorization_header_literal"])

    def test_header_name_case_insensitive(self):
        self.assertEqual(types(self.scan_header("Basic " + "dXNlcjpwYXNz", name="authorization")), ["authorization_header_literal"])

    def test_known_pattern_and_literal_both_reported(self):
        found = self.scan_header("Bearer " + fake("openai"))
        self.assertEqual(types(found), ["authorization_header_literal", "openai_api_key"])

    def test_quoted_literal_inside_mapping_flagged(self):
        self.assertEqual(types(self.scan_header('{{ifempty(1.token; "fallback' + 'value")}}')), ["authorization_header_literal"])

    def test_pure_mappings_clean(self):
        for v in ["{{1.token}}", "Bearer {{1.token}}", "Token {{var.input.make_token}}", "  ", "", "Bearer {{ifempty(1.a; 2.b)}}", "{{2.`Api Token`}}"]:
            with self.subTest(v=v):
                self.assertEqual(self.scan_header(v), [])

    def test_api_key_header_flagged(self):
        found = self.scan_header("hardcoded" + "anonkey", name="apikey")
        self.assertEqual(types(found), ["api_key_header_literal"])
        self.assertEqual(self.scan_header("{{3.anon}}", name="x-api-key"), [])

    def test_header_as_object_key(self):
        obj = {"mapper": {"headers": {"Authorization": "Bearer " + "literal" + "value"}}}
        self.assertEqual(scan_obj(obj), [{"pattern_type": "authorization_header_literal", "location": "$.mapper.headers.Authorization"}])

    def test_interface_spec_and_restore_metadata_clean(self):
        obj = {
            "interface": [{"name": "Authorization", "type": "text", "label": "Authorization"}],
            "restore": {"expect": {"Authorization": {"mode": "chose"}}},
            "headers": [{"name": "Content-Type", "value": "application/json"}],
        }
        self.assertEqual(scan_obj(obj), [])


class HashKeyTests(unittest.TestCase):
    def scan_value(self, v):
        return scan_obj(blueprint(set_module(v)))

    def test_literal_keys_flagged(self):
        cases = [
            "<<sha256(1.body; hex; signing" + "secret)>>",
            '<<sha256(1.body; "hex"; "signing' + 'secret")>>',
            "<<SHA512(1.body; base64; k3y" + "val; text)>>",
            "<<sha1(1.body; ; abc" + "def)>>",
            '<<sha256(1.body; hex; ifempty(2.key; "fall' + 'back"))>>',
            "t=<<1.t>> sig=<<sha256(1.t + 1.raw; hex; literal" + "key)>>",
            '<<hmac(1.body; "my' + 'key"; "hex")>>',
            '<<upper(sha256(1.body; hex; "lit' + 'eral"))>>',
        ]
        for v in cases:
            with self.subTest(v=v):
                found = self.scan_value(iml(v))
                self.assertEqual(found, [{"pattern_type": "hash_key_literal", "location": "$.flow[0].mapper.value"}])

    def test_mapped_or_absent_keys_clean(self):
        cases = [
            "{{sha256(1.body)}}",
            "{{sha256(1.body; hex)}}",
            "{{sha256(1.body; hex; )}}",
            "{{sha256(1.body; hex; 2.signing_secret)}}",
            "{{sha256(1.body; hex; var.input.webhook_key; text)}}",
            "{{sha512(1.body; base64; 3.`Signing Key`)}}",
            "{{md5(1.body)}}",
            '{{if(7.call_id; "Bland Call"; "Gmail")}}',
            "sha256(text; hex; key) outside a mapping",
            '{{replace(1.text; "sha256(x; y; z)"; "")}}',
            "{{hmac(1.body; 2.key; hex)}}",
        ]
        for v in cases:
            with self.subTest(v=v):
                self.assertEqual(self.scan_value(v), [])

    def test_hash_key_in_text_mode(self):
        found = scan_text(iml("line one\nsig: <<sha256(1.raw; hex; lit" + "key)>>\n"), "spec.md")
        self.assertEqual(found, [{"pattern_type": "hash_key_literal", "location": "spec.md:2"}])


class ImlFalsePositiveTests(unittest.TestCase):
    def test_common_mappings_clean(self):
        values = [
            "{{1.id}}",
            "{{error.message}}",
            "{{2.choices[].message.content}}",
            "{{5.`Client Name`}}",
            "{{if(7.call_id; 7.error.message; message)}}",
            '{{ifempty(4.Drive_Folder_ID; """""")}}',
            "Hi {{1.Name}}, your file {{1.`Application ID`}} is ready.",
            "{{formatDate(now; YYYY-MM-DD)}}",
            "{{true}}",
            "{{unterminated",
        ]
        obj = blueprint(*[set_module(v, mid=i) for i, v in enumerate(values)])
        obj["flow"].append({"id": 99, "module": "airtable:ActionCreateRecord", "mapper": {"record": {"fld" + "FC0g1pzkgHOV3g": "Synthetic Label"}}, "parameters": {"__IMTCONN__": 1234567}})
        self.assertEqual(scan_obj(obj), [])

    def test_non_string_scalars_clean(self):
        self.assertEqual(scan_obj({"a": [1, 2.5, None, True, {"b": False}]}), [])


class OutputNeverLeaksTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_main(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = secret_scan.main(argv)
        return code, out.getvalue() + err.getvalue()

    def assert_no_leak(self, text, secrets):
        for s in secrets:
            self.assertNotIn(s, text)
            # No fragment beyond the public prefix either.
            for i in range(0, len(s) - 7):
                self.assertNotIn(s[i : i + 8], text, "8-char fragment of a secret leaked")

    def test_cli_paths_output_has_types_and_locations_only(self):
        secrets = [fake(k) for k in EXPECTED_TYPE]
        txt = os.path.join(self.tmp, "notes.txt")
        with open(txt, "w", encoding="utf-8") as fh:
            fh.write("\n".join("v=" + s for s in secrets))
        bp = blueprint(
            http_module([{"name": "Authorization", "value": "Bearer " + "plainliteral" + "token"}]),
            set_module(iml("<<sha256(1.body; hex; plain" + "hmackey)>>")),
        )
        js = os.path.join(self.tmp, "bp.json")
        with open(js, "w", encoding="utf-8") as fh:
            json.dump(bp, fh)
        code, out = self.run_main([self.tmp])
        self.assertEqual(code, 1)
        for t in set(EXPECTED_TYPE.values()) | {"authorization_header_literal", "hash_key_literal"}:
            self.assertIn(t, out)
        self.assertIn("notes.txt:1", out)
        self.assertIn("bp.json:$.flow[0].mapper.headers[0].value", out)
        self.assert_no_leak(out, secrets + ["plainliteraltoken", "plainhmackey"])

    def test_findings_dicts_carry_no_value(self):
        s = fake("airtable")
        found = scan_obj({"k": s}) + scan_text(s)
        self.assertEqual(len(found), 2)
        for f in found:
            self.assertEqual(set(f), {"pattern_type", "location"})
            self.assert_no_leak(json.dumps(f), [s])

    def test_clean_path_exits_zero(self):
        p = os.path.join(self.tmp, "ok.json")
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(blueprint(set_module("{{1.id}}")), fh)
        self.assertEqual(self.run_main([p]), (0, ""))

    def test_binary_file_skipped(self):
        p = os.path.join(self.tmp, "img.png")
        with open(p, "wb") as fh:
            fh.write(b"\x89PNG\x00\x00" + fake("stripe_sk_live").encode())
        self.assertEqual(self.run_main([p])[0], 0)

    def test_no_args_is_usage_error(self):
        self.assertEqual(self.run_main([])[0], 2)

    def test_repo_sources_are_clean(self):
        paths = [os.path.join(ROOT, p) for p in ("scripts", "tests", "CLAUDE.md", ".githooks")]
        self.assertEqual(secret_scan.scan_paths([p for p in paths if os.path.exists(p)]), [])


def fake_uuid():
    return "-".join(["3f2a9c1e", "7b4d", "4e8a", "9c2f", "1a2b3c4d5e6f"])


LIT = "Zq" + "9xLiteralCred7"


class ReviewRegressionTests(unittest.TestCase):
    """Findings from the 2026-10-28 adversarial review (security-SEC-2 to SEC-6)."""

    def header(self, value, name="Authorization"):
        return types(scan_obj(blueprint(http_module([{"name": name, "value": value}]))))

    # SEC-2: unquoted literals inside IML calls and bare braces.
    def test_unquoted_literal_in_header_function_flagged(self):
        self.assertEqual(self.header("Bearer {{ifempty(1.tok; " + LIT + ")}}"), ["authorization_header_literal"])
        self.assertEqual(self.header("{{" + LIT + "}}"), ["authorization_header_literal"])
        self.assertEqual(self.header("{{trim(" + LIT + ")}}", name="x-api-key"), ["api_key_header_literal"])

    def test_header_mappings_with_functions_stay_clean(self):
        for v in ["Bearer {{trim(1.token)}}", "Basic {{base64(1.user + \":\" + 1.pass)}}",
                  "{{toBinary(2.key; base64)}}", "{{substring(1.token; 0; 40)}}", "Token {{var.input.make_token}}"]:
            with self.subTest(v=v):
                self.assertEqual(self.header(v), [])

    # SEC-3: Make token and plain-text Authorization headers in text files.
    def test_secret_assignment_in_text_flagged(self):
        for line in ["MAKE_API" + "_TOKEN=" + fake_uuid(), "export AIRTABLE" + "_PAT=" + "abc123def456ghi",
                     "STRIPE_SECRET" + "_KEY: '" + "x9" + ALNUM + "'"]:
            with self.subTest(line=line[:10]):
                self.assertEqual(types(scan_text(line, "x.md")), ["secret_assignment_literal"])

    def test_secret_assignment_placeholders_clean(self):
        for line in ["MAKE_API" + "_TOKEN=", "MAKE_API" + "_TOKEN=your-token-here", "MAKE_API" + "_TOKEN=<token>",
                     "MAKE_API" + "_TOKEN=${MAKE_API_TOKEN}", "MAKE_ZONE=us2", "MAKE_TEAM_ID=1234567",
                     "token = values[\"MAKE_API" + "_TOKEN\"].strip()"]:
            with self.subTest(line=line):
                self.assertEqual(scan_text(line, "x.md"), [])

    def test_authorization_text_flagged(self):
        for line in ["curl -H 'Authori" + "zation: Token " + fake_uuid() + "'",
                     '{"Authori' + 'zation": "Bearer ' + "x9" + ALNUM + '"}',
                     "Bea" + "rer " + "x9" + ALNUM]:
            with self.subTest(line=line[:12]):
                self.assertEqual(types(scan_text(line, "x.md")), ["authorization_header_literal"])

    def test_authorization_text_placeholders_clean(self):
        for line in ["Auth header: `Authori" + "zation: Token {MAKE_API_TOKEN}`.", "Authori" + "zation: Bearer <token>",
                     "Authori" + "zation: Bearer $TOKEN", "the Authori" + "zation header carries the token"]:
            with self.subTest(line=line):
                self.assertEqual(scan_text(line, "x.md"), [])

    # SEC-4: query params, URL credentials, basic-auth fields, Slack webhooks, Supabase keys.
    def test_http_credential_fields_flagged(self):
        def mod(mapper):
            return types(scan_obj(blueprint({"id": 2, "module": "http:ActionSendData", "mapper": mapper})))
        slack_hook = "https://hooks." + "slack.com/services/" + "T0123ABCD/B0123ABCD/" + "abcdEFGHijklMNOPqrstUVWX"
        cases = [
            ({"qs": [{"name": "api_key", "value": LIT}]}, "credential_param_literal"),
            ({"qs": [{"name": "access_token", "value": LIT}]}, "credential_param_literal"),
            ({"url": "https://h.invalid/x?apikey=" + LIT}, "url_credential_literal"),
            ({"url": "https://user:" + LIT + "@h.invalid/"}, "url_credential_literal"),
            ({"authUser": "u", "authPass": LIT}, "credential_field_literal"),
            ({"url": slack_hook}, "slack_webhook_url"),
            ({"data": "key " + "sb" + "_secret_" + ALNUM}, "supabase_secret_key"),
        ]
        for mapper, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(mod(mapper), [expected])

    def test_mapped_http_credentials_clean(self):
        mapper = {"qs": [{"name": "api_key", "value": "{{1.key}}"}, {"name": "page", "value": "2"}],
                  "url": "https://{{1.user}}:{{1.pass}}@h.invalid/x?apikey={{var.input.k}}&q=hello",
                  "authUser": "{{1.user}}", "authPass": "{{1.pass}}", "password": ""}
        obj = blueprint({"id": 2, "module": "http:ActionSendData", "mapper": mapper})
        obj["flow"][0]["interface"] = [{"name": "token", "type": "text"}]
        self.assertEqual(scan_obj(obj), [])

    # SEC-5: hash keys with dots or spaces, or wrapped in a nested call.
    def test_hash_key_reference_lookalikes_flagged(self):
        for v in ["<<sha256(1.body; hex; Sup3r.S3cret2026)>>", "<<sha256(1.body; hex; my secret.key)>>",
                  "<<sha256(1.body; hex; trim(" + LIT + "))>>", "<<sha256(1.body; hex; lower(trim(" + LIT + ")))>>"]:
            with self.subTest(v=v):
                self.assertEqual(types(scan_obj(blueprint(set_module(iml(v))))), ["hash_key_literal"])

    def test_hash_key_nested_mappings_clean(self):
        for v in ["<<sha256(1.body; hex; trim(2.key))>>", "<<sha256(1.body; hex; get(var.input.keys; 1))>>",
                  "<<sha256(1.body; hex; toBinary(2.key; base64))>>", "<<sha256(1.t + 1.raw; hex; 3.`Signing Key`)>>"]:
            with self.subTest(v=v):
                self.assertEqual(scan_obj(blueprint(set_module(iml(v)))), [])

    # SEC-6: UTF-16 and UTF-32 text is decoded, unknown binaries fail closed.
    def test_wide_encodings_are_scanned(self):
        text = "note " + fake("stripe_sk_live") + "\n"
        for enc in ("utf-16", "utf-16-le", "utf-16-be", "utf-32"):
            with self.subTest(enc=enc):
                self.assertEqual(types(secret_scan.scan_bytes(text.encode(enc), "notes.txt")), ["stripe_secret_key"])

    def test_unknown_binary_is_reported_known_binary_skipped(self):
        blob = b"\x00\x01\x02\x03\xff\x00\x10" * 20
        self.assertEqual(secret_scan.scan_bytes(blob, "data.bin"), [{"pattern_type": "unscannable_binary", "location": "data.bin"}])
        self.assertEqual(secret_scan.scan_bytes(blob, "docs/Assets/x.png"), [])


@unittest.skipUnless(shutil.which("git"), "git required")
class RealRepoGitTests(unittest.TestCase):
    """security-SEC-7 and SEC-9 against this repo's own git settings."""

    def git(self, *args):
        return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True)

    def test_hook_is_executable_in_the_index(self):
        r = self.git("ls-files", "-s", ".githooks/pre-commit")
        if r.returncode != 0 or not r.stdout.strip():
            self.skipTest("hook not staged yet")
        self.assertTrue(r.stdout.startswith("100755"),
                        "stage the hook with: git update-index --add --chmod=+x .githooks/pre-commit")

    def test_tabular_and_env_files_are_ignored_everywhere(self):
        for p in ("blueprints/a.csv", "specs/x.csv", "audit/x.tsv", "docs/x.xlsx", "tests/x.xls",
                  "scripts/prod.env", "audit/.env.local", ".env"):
            with self.subTest(p=p):
                self.assertEqual(self.git("check-ignore", "-q", p).returncode, 0, p + " is not ignored")
        for p in (".env.example", "scripts/secret_scan.py", "tests/fixtures/x.csv"):
            with self.subTest(p=p):
                self.assertNotEqual(self.git("check-ignore", "-q", p).returncode, 0, p + " is ignored")

    def test_bland_tracks_only_sanitized_pathway_exports(self):
        """safety-R8: a recording or transcript dropped in bland/ must not be trackable."""
        for p in ("bland/call-recording.mp3", "bland/transcript.json", "bland/notes.txt", "bland/sub/a-pathway.json"):
            with self.subTest(p=p):
                self.assertEqual(self.git("check-ignore", "-q", p).returncode, 0, p + " is not ignored")
        self.assertNotEqual(self.git("check-ignore", "-q", "bland/immigration-screener-pathway.json").returncode, 0)


@unittest.skipUnless(shutil.which("git") and shutil.which("sh"), "git and sh required")
class StagedAndHookTests(unittest.TestCase):
    def setUp(self):
        self.repo = tempfile.mkdtemp()
        self.git("init", "-q")
        self.git("config", "user.name", "Test")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "commit.gpgsign", "false")
        os.makedirs(os.path.join(self.repo, "scripts"))
        os.makedirs(os.path.join(self.repo, ".githooks"))
        shutil.copy(os.path.join(ROOT, "scripts", "secret_scan.py"), os.path.join(self.repo, "scripts"))
        shutil.copy(os.path.join(ROOT, ".githooks", "pre-commit"), os.path.join(self.repo, ".githooks"))
        self.git("config", "core.hooksPath", ".githooks")

    def tearDown(self):
        shutil.rmtree(self.repo, ignore_errors=True)

    def git(self, *args):
        return subprocess.run(["git", *args], cwd=self.repo, capture_output=True, text=True)

    def write(self, rel, text):
        p = os.path.join(self.repo, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)

    def test_staged_scan_reads_index_not_worktree(self):
        secret = fake("whsec")
        self.write("blueprints/a.json", json.dumps(blueprint(set_module(secret))))
        self.git("add", "blueprints/a.json")
        # Clean the working tree after staging: the staged blob still leaks.
        self.write("blueprints/a.json", json.dumps(blueprint(set_module("{{1.id}}"))))
        found = secret_scan.scan_staged(cwd=self.repo)
        self.assertEqual(found, [{"pattern_type": "stripe_webhook_secret", "location": "blueprints/a.json:$.flow[0].mapper.value"}])

    def test_dotenv_staged_flagged_example_allowed(self):
        self.write(".env", "MAKE_API_TOKEN=x\n")
        self.write(".env.example", "MAKE_API_TOKEN=\n")
        self.git("add", "-f", ".env", ".env.example")
        found = secret_scan.scan_staged(cwd=self.repo)
        self.assertEqual(found, [{"pattern_type": "dotenv_file_staged", "location": ".env"}])

    def test_hook_blocks_secret_and_hides_value(self):
        secret = fake("anthropic")
        self.write("specs/x.md", "key " + secret + "\n")
        self.git("add", "-A")
        r = self.git("commit", "-q", "-m", "test")
        self.assertNotEqual(r.returncode, 0)
        out = r.stdout + r.stderr
        self.assertIn("anthropic_api_key", out)
        self.assertIn("specs/x.md:1", out)
        self.assertNotIn(secret[8:], out)
        self.assertNotEqual(self.git("rev-parse", "-q", "--verify", "HEAD").returncode, 0)

    def test_hook_blocks_utf16_secret(self):
        # security-SEC-6: PowerShell 5.1 '>' writes UTF-16LE.
        p = os.path.join(self.repo, "specs", "u16.txt")
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as fh:
            fh.write(("note " + fake("stripe_sk_live") + "\n").encode("utf-16"))
        self.git("add", "-A")
        r = self.git("commit", "-q", "-m", "u16")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("stripe_secret_key", r.stdout + r.stderr)

    def test_type_change_is_scanned(self):
        # security-SEC-8: a symlink replaced by a regular file shows as T.
        target = subprocess.run(["git", "hash-object", "-w", "--stdin"], cwd=self.repo, input="target",
                                capture_output=True, text=True).stdout.strip()
        self.git("update-index", "--add", "--cacheinfo", "120000," + target + ",tc3")
        r = self.git("-c", "core.hooksPath=no-hooks", "commit", "-q", "-m", "link")
        self.assertEqual(r.returncode, 0, r.stderr)
        blob = subprocess.run(["git", "hash-object", "-w", "--stdin"], cwd=self.repo,
                              input="k " + fake("stripe_sk_live") + "\n", capture_output=True, text=True).stdout.strip()
        self.git("update-index", "--cacheinfo", "100644," + blob + ",tc3")
        self.assertIn("T\ttc3", self.git("diff", "--cached", "--name-status").stdout)
        self.assertEqual(types(secret_scan.scan_staged(cwd=self.repo)), ["stripe_secret_key"])

    def test_env_named_and_tabular_files_blocked(self):
        # security-SEC-3 (*.env) and SEC-9 (CSV exports).
        self.write("scripts/prod.env", "X=1\n")
        self.write("audit/applicants.csv", "name,email\n")
        self.write("tests/fixtures/synthetic.csv", "a,b\n")
        self.git("add", "-f", "-A")
        found = sorted((f["pattern_type"], f["location"]) for f in secret_scan.scan_staged(cwd=self.repo))
        self.assertEqual(found, [("dotenv_file_staged", "scripts/prod.env"),
                                 ("tabular_data_file_staged", "audit/applicants.csv")])

    def test_non_pathway_files_under_bland_are_blocked(self):
        # safety-R8: transcripts and recordings are client data, and the scanner has no PII rules.
        self.write("bland/immigration-screener-pathway.json", json.dumps({"nodes": []}))
        self.write("bland/transcript-2026-10-28.json", json.dumps({"transcript": "client said hello"}))
        self.write("bland/recording.mp3", "x")
        self.git("add", "-f", "-A")
        found = sorted((f["pattern_type"], f["location"]) for f in secret_scan.scan_staged(cwd=self.repo))
        self.assertEqual(found, [("bland_non_pathway_file_staged", "bland/recording.mp3"),
                                 ("bland_non_pathway_file_staged", "bland/transcript-2026-10-28.json")])

    def test_hook_allows_clean_commit(self):
        self.write("specs/y.md", "Mapped {{1.id}} only.\n")
        self.git("add", "-A")
        r = self.git("commit", "-q", "-m", "clean")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


HOOK_TAIL = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"
HOOK_URL = "https://hook." + "us2.make.com/" + HOOK_TAIL
OTHER_URL = "https://hook." + "us2.make.com/" + "z9y8x7w6v5u4t3s2r1q0p9o8n7m6l5k4"
HOOK_SHA = hashlib.sha256(HOOK_TAIL.encode()).hexdigest()


def send_call(mid=7, url=HOOK_URL, **mapper):
    return {"id": mid, "module": "bland:sendACall", "mapper": {"task": "hello", "webhook": url, **mapper}}


def entry(scenario_id="5", module_id=7, target="6", **kw):
    return {"scenario_id": scenario_id, "module_id": module_id, "pattern_type": "make_webhook_url",
            "reason": "Points at a fetch-back hook", "requires_fetch_back_hook": target, "token_sha256": HOOK_SHA, **kw}


class PinnedAllowlistTests(unittest.TestCase):
    def split(self, bp, entries, sid="5"):
        return secret_scan.split_findings(bp, sid, secret_scan.parse_secret_allowlist({"entries": entries}))

    def test_a_pinned_url_in_a_send_call_webhook_field_is_allowed(self):
        blocking, allowed = self.split(blueprint(send_call()), [entry()])
        self.assertEqual(blocking, [])
        self.assertEqual([(a["pattern_type"], a["module_id"], a["requires_fetch_back_hook"]) for a in allowed],
                         [("make_webhook_url", 7, "6")])
        self.assertNotIn("a1b2c3d4", json.dumps(allowed))

    def test_scan_obj_itself_never_allows_anything(self):
        self.assertEqual(types(scan_obj(blueprint(send_call()))), ["make_webhook_url"])

    def test_nothing_else_is_excused(self):
        key = fake("stripe_sk_live")
        cases = {
            "another scenario": (blueprint(send_call()), [entry(scenario_id="9")], "5"),
            "another module": (blueprint(send_call(8)), [entry()], "5"),
            "another module type": (blueprint({"id": 7, "module": "http:ActionSendData", "mapper": {"webhook": HOOK_URL}}), [entry()], "5"),
            "another field": (blueprint({"id": 7, "module": "bland:sendACall", "mapper": {"task": "go to " + HOOK_URL}}), [entry()], "5"),
            "no scenario ID": (blueprint(send_call()), [entry()], None),
        }
        for label, (bp, entries, sid) in cases.items():
            blocking, allowed = self.split(bp, entries, sid)
            self.assertEqual((label, types(blocking), allowed), (label, ["make_webhook_url"], []))
        blocking, allowed = self.split(blueprint(send_call(task=key)), [entry()])
        self.assertEqual((types(blocking), len(allowed)), (["stripe_secret_key"], 1))

    def test_a_url_in_another_field_of_the_same_module_still_blocks(self):
        two = blueprint(send_call(7, webhook_extra=HOOK_URL))
        blocking, allowed = self.split(two, [entry()])
        self.assertEqual((types(blocking), len(allowed)), (["make_webhook_url"], 1))

    def test_a_different_url_in_the_pinned_field_blocks(self):
        """R5: the allowlist pins a value, not a location."""
        blocking, allowed = self.split(blueprint(send_call(url=OTHER_URL)), [entry()])
        self.assertEqual((types(blocking), allowed), (["make_webhook_url"], []))

    def test_two_urls_in_one_field_block_even_when_one_is_pinned(self):
        """R5 probe: findings dedupe per location, so one entry used to clear a second, foreign URL."""
        for both in (HOOK_URL + " " + OTHER_URL, OTHER_URL + " " + HOOK_URL, HOOK_URL + "," + HOOK_URL.replace("a1b2", "q1w2")):
            blocking, allowed = self.split(blueprint(send_call(url=both)), [entry()])
            self.assertEqual((types(blocking), allowed), (["make_webhook_url"], []), both)
        # The same URL twice is one token, which is fine.
        blocking, allowed = self.split(blueprint(send_call(url=HOOK_URL + " " + HOOK_URL)), [entry()])
        self.assertEqual((blocking, len(allowed)), ([], 1))

    def test_a_module_shaped_dict_nested_in_another_modules_mapper_does_not_match(self):
        """R5 probe: module_at took the deepest dict, so a fake send-call module 7 inside an HTTP mapper passed."""
        nested = {"id": 9, "module": "http:ActionSendData",
                  "mapper": {"body": {"id": 7, "module": "bland:sendACall", "mapper": {"webhook": HOOK_URL}}}}
        blocking, allowed = self.split(blueprint(nested), [entry(module_id=7)])
        self.assertEqual((types(blocking), allowed), (["make_webhook_url"], []))

    def test_the_module_may_sit_in_a_route_or_an_error_route(self):
        routed = {"id": 3, "module": "builtin:BasicRouter", "routes": [{"flow": [send_call(7)]}]}
        blocking, allowed = self.split(blueprint(routed), [entry()])
        self.assertEqual((blocking, len(allowed)), ([], 1))
        handled = {"id": 3, "module": "http:ActionSendData", "mapper": {}, "onerror": [send_call(7)]}
        blocking, allowed = self.split(blueprint(handled), [entry()])
        self.assertEqual((blocking, len(allowed)), ([], 1))

    def test_the_token_digest_is_a_plain_sha256_of_the_token(self):
        self.assertEqual(secret_scan.token_digest(HOOK_TAIL), HOOK_SHA)

    def test_the_allowlist_file_accepts_make_webhook_url_only_and_needs_a_reason_and_a_target(self):
        ok = entry()
        self.assertEqual(secret_scan.parse_secret_allowlist({"entries": [ok]})[0]["module_id"], 7)
        bad = [{**ok, "pattern_type": "stripe_secret_key"}, {**ok, "pattern_type": "anything"}, {**ok, "reason": ""}, {**ok, "reason": "x"},
               {**ok, "scenario_id": "abc"}, {**ok, "scenario_id": True}, {**ok, "module_id": "x"}, {**ok, "module_id": True},
               {**ok, "requires_fetch_back_hook": None}, {**ok, "requires_fetch_back_hook": ""},
               {**ok, "token_sha256": None}, {**ok, "token_sha256": ""}, {**ok, "token_sha256": HOOK_SHA.upper()},
               {**ok, "token_sha256": HOOK_SHA[:-1]}, {**ok, "token_sha256": HOOK_TAIL}]
        for b in bad:
            with self.assertRaises(secret_scan.SecretAllowlistError, msg=b):
                secret_scan.parse_secret_allowlist({"entries": [b]})
        no_pin = dict(ok)
        del no_pin["token_sha256"]
        with self.assertRaises(secret_scan.SecretAllowlistError):
            secret_scan.parse_secret_allowlist({"entries": [no_pin]})
        for junk in ({}, {"entries": "x"}, {"entries": [1]}, []):
            with self.assertRaises(secret_scan.SecretAllowlistError):
                secret_scan.parse_secret_allowlist(junk)
        with self.assertRaises(secret_scan.SecretAllowlistError):
            secret_scan.parse_secret_allowlist({"entries": [ok, ok]})

    def test_a_missing_file_is_no_allowance_and_a_broken_one_is_an_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(secret_scan.load_secret_allowlist(os.path.join(tmp, "none.json")), [])
            path = os.path.join(tmp, "a.json")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("{not json")
            with self.assertRaises(secret_scan.SecretAllowlistError):
                secret_scan.load_secret_allowlist(path)

    def test_the_committed_allowlist_loads(self):
        entries = secret_scan.load_secret_allowlist()
        self.assertEqual({e["pattern_type"] for e in entries}, {"make_webhook_url"})
        self.assertTrue(all(len(e["token_sha256"]) == 64 for e in entries))

    def test_the_committed_blueprints_match_their_committed_pins(self):
        """Each pinned URL in the live snapshot hashes to its entry, so make_pull, check D, make_push and the hook all accept it."""
        bp_dir = os.path.join(ROOT, "blueprints")
        manifest = os.path.join(bp_dir, "manifest.json")
        if not os.path.exists(manifest):
            self.skipTest("no snapshot")
        with open(manifest, encoding="utf-8") as fh:
            rows = {str(r["id"]): r for r in json.load(fh)["scenarios"]}
        allowlist = secret_scan.load_secret_allowlist()
        for e in allowlist:
            row = rows.get(e["scenario_id"])
            if row is None or not row.get("file"):
                self.skipTest("scenario not in the snapshot")
            with open(os.path.join(bp_dir, row["file"]), encoding="utf-8") as fh:
                bp = json.load(fh)
            # The Logger allowance rides along, since converted handlers carry the Logger hook URL (F-E5.3).
            blocking, allowed = secret_scan.split_findings(bp, e["scenario_id"], [e], allowlist.logger)
            pinned = [a["module_id"] for a in allowed if a["kind"] == secret_scan.PINNED_KIND]
            self.assertEqual((blocking, pinned), ([], [e["module_id"]]), e["scenario_id"])

    def test_value_at_and_tokens_stay_in_memory(self):
        bp = blueprint(send_call())
        loc = scan_obj(bp)[0]["location"]
        self.assertEqual(secret_scan.value_at(bp, loc), HOOK_URL)
        self.assertEqual(secret_scan.make_webhook_tokens(HOOK_URL), ["a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"])
        self.assertEqual(secret_scan.make_webhook_tokens("https://hook." + "us2.make.com/" + "x" * 20), [])


@unittest.skipUnless(shutil.which("git") and shutil.which("sh"), "git and sh required")
class StagedBlueprintAllowlistTests(unittest.TestCase):
    """The pre-commit hook scans staged blueprints with the same rule as make_pull."""

    setUp = StagedAndHookTests.setUp
    tearDown = StagedAndHookTests.tearDown
    git = StagedAndHookTests.git
    write = StagedAndHookTests.write

    BP = "blueprints/send-call__5.json"

    def manifest(self, **row):
        base = {"id": 5, "file": "send-call__5.json",
                "allowlisted_findings": [{"module_id": 7, "pattern_type": "make_webhook_url"}]}
        return json.dumps({"scenarios": [{**base, **row}]})

    def stage(self, bp, entries=None, allowlist_text=None, manifest=True):
        self.write(self.BP, json.dumps(bp, indent=2))
        if manifest is True:
            self.write("blueprints/manifest.json", self.manifest())
        elif manifest:
            self.write("blueprints/manifest.json", manifest)
        if allowlist_text is not None:
            self.write("audit/secret_allowlist.json", allowlist_text)
        elif entries is not None:
            self.write("audit/secret_allowlist.json", json.dumps({"entries": entries}))
        self.git("add", "-A")

    def test_a_pinned_url_in_a_staged_blueprint_is_accepted(self):
        self.stage(blueprint(send_call()), [entry()])
        self.assertEqual(secret_scan.scan_staged(cwd=self.repo), [])
        r = self.git("commit", "-q", "-m", "pinned")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_without_an_entry_the_url_blocks_and_the_value_stays_hidden(self):
        self.stage(blueprint(send_call()))
        found = secret_scan.scan_staged(cwd=self.repo)
        self.assertEqual([f["pattern_type"] for f in found], ["make_webhook_url"])
        r = self.git("commit", "-q", "-m", "nope")
        self.assertNotEqual(r.returncode, 0)
        self.assertNotIn("a1b2c3d4", r.stdout + r.stderr)

    def test_other_findings_in_the_same_blueprint_still_block(self):
        self.stage(blueprint(send_call(task=fake("stripe_sk_live"))), [entry()])
        found = secret_scan.scan_staged(cwd=self.repo)
        self.assertEqual([f["pattern_type"] for f in found], ["stripe_secret_key"])

    def test_an_entry_for_another_scenario_does_not_help(self):
        self.stage(blueprint(send_call()), [entry(scenario_id="9")])
        self.assertEqual([f["pattern_type"] for f in secret_scan.scan_staged(cwd=self.repo)], ["make_webhook_url"])

    def test_an_invalid_staged_allowlist_blocks_the_blueprint_commit(self):
        self.stage(blueprint(send_call()), allowlist_text=json.dumps({"entries": [{**entry(), "pattern_type": "stripe_secret_key"}]}))
        found = [f["pattern_type"] for f in secret_scan.scan_staged(cwd=self.repo)]
        self.assertIn("secret_allowlist_invalid", found)
        self.assertIn("make_webhook_url", found)

    def test_the_allowlist_is_read_from_the_index_not_the_worktree(self):
        self.stage(blueprint(send_call()), [entry()])
        self.write("audit/secret_allowlist.json", json.dumps({"entries": []}))   # worktree emptied after staging
        self.assertEqual(secret_scan.scan_staged(cwd=self.repo), [])

    def test_a_hand_made_blueprint_file_the_manifest_does_not_name_blocks(self):
        """R5 probe: a hand-made blueprints/anything__<id>.json with a pinned URL used to commit clean."""
        for label, manifest in (("no manifest", False),
                                ("another file name", self.manifest(file="send-call__5-copy.json")),
                                ("finding not listed", self.manifest(allowlisted_findings=[])),
                                ("another module listed", self.manifest(allowlisted_findings=[{"module_id": 8, "pattern_type": "make_webhook_url"}])),
                                ("another scenario", self.manifest(id=6)),
                                ("not json", "{nope")):
            with self.subTest(label):
                self.stage(blueprint(send_call()), [entry()], manifest=manifest)
                if not manifest and os.path.exists(os.path.join(self.repo, "blueprints", "manifest.json")):
                    os.remove(os.path.join(self.repo, "blueprints", "manifest.json"))
                    self.git("add", "-A")
                found = [f["pattern_type"] for f in secret_scan.scan_staged(cwd=self.repo)]
                self.assertEqual(found, ["make_webhook_url"], label)

    def test_a_different_url_in_a_staged_blueprint_blocks_even_with_a_manifest(self):
        self.stage(blueprint(send_call(url=OTHER_URL)), [entry()])
        self.assertEqual([f["pattern_type"] for f in secret_scan.scan_staged(cwd=self.repo)], ["make_webhook_url"])
        r = self.git("commit", "-q", "-m", "other")
        self.assertNotEqual(r.returncode, 0)
        self.assertNotIn("z9y8x7w6", r.stdout + r.stderr)

    def test_two_urls_in_a_staged_blueprint_field_block(self):
        self.stage(blueprint(send_call(url=HOOK_URL + " " + OTHER_URL)), [entry()])
        self.assertEqual([f["pattern_type"] for f in secret_scan.scan_staged(cwd=self.repo)], ["make_webhook_url"])

    def test_the_manifest_is_read_from_the_index(self):
        self.stage(blueprint(send_call()), [entry()])
        self.write("blueprints/manifest.json", self.manifest(allowlisted_findings=[]))   # worktree edited after staging
        self.assertEqual(secret_scan.scan_staged(cwd=self.repo), [])

    def test_only_files_named_like_blueprints_get_the_allowance(self):
        self.write("specs/x.json", json.dumps(blueprint(send_call())))
        self.write("audit/secret_allowlist.json", json.dumps({"entries": [entry()]}))
        self.git("add", "-A")
        self.assertEqual([f["pattern_type"] for f in secret_scan.scan_staged(cwd=self.repo)], ["make_webhook_url"])


# R6: the dormant literal-URL fallback (logger_hook). The Logger hook URL is accepted only as the whole url field of an HTTP
# module that is a Logger call, never in another field, in a query string or in another module.
LOGGER_SID = "900777"
LOGGER_HOOK_ID = 5551
LOGGER_URL_VAR = "{{var.team.IMMIOS_LOGGER_URL}}"


def logger_allowlist():
    pin = {"scenario_id": LOGGER_SID, "hook_id": LOGGER_HOOK_ID, "token_sha256": HOOK_SHA,
           "reason": "Every error handler calls the shared Logger, whose hook needs x-make-apikey"}
    reg = {"scenarios": [{"scenario_id": LOGGER_SID, "hook_id": LOGGER_HOOK_ID, "caller": "make_http", "protection": "api_key",
                          "reason": "The shared Logger, called by Make HTTP modules that send the key"}]}
    return secret_scan.parse_secret_allowlist({"entries": [], "logger_hook": pin}, webhooks_data=reg)


def logger_call(mid=3, url=HOOK_URL, auth="apiKeyConnection", module="http:MakeRequest", **mapper):
    mp = {"url": url, "method": "post", "headers": [], "queryParameters": [], "contentType": "urlEncoded",
          "urlEncodedBodyContent": [{"name": "label", "value": "Campaign Launcher"}, {"name": "outcome", "value": "Error"},
                                    {"name": "execution_id", "value": "{{var.scenario.executionId}}"}],
          "stopOnHttpError": False, "allowRedirects": False}
    mp.update(mapper)
    params = {"authenticationType": auth, "apiKeyAccount": 4242} if auth is not None else {}
    return {"id": mid, "module": module, "version": 4, "parameters": params, "mapper": mp}


def handler_of(call, owner=2):
    return {"id": owner, "module": "openai-gpt-3:CreateCompletion", "mapper": {},
            "onerror": [call, {"id": 99, "module": "builtin:Break"}]}


class LoggerLiteralUrlFallbackTests(unittest.TestCase):
    def split(self, bp):
        return secret_scan.split_findings(bp, "5", logger_allowlist())

    def assert_blocks(self, label, bp):
        blocking, allowed = self.split(bp)
        self.assertEqual((label, types(blocking), allowed), (label, ["make_webhook_url"], []))

    def test_the_url_field_of_a_logger_call_in_a_handler_is_allowed(self):
        for auth in ("apiKeyConnection", "apiKey"):
            blocking, allowed = self.split(blueprint(handler_of(logger_call(auth=auth))))
            self.assertEqual(blocking, [], auth)
            self.assertEqual([(a["module_id"], a["kind"], a["location"]) for a in allowed],
                             [(3, "logger_hook", "$.flow[0].onerror[0].mapper.url")], auth)
            self.assertNotIn(HOOK_TAIL, json.dumps(allowed))

    def test_a_logger_call_outside_an_error_route_is_allowed(self):
        """The scratch test of spec section 8 step 7 calls the Logger from the main flow. The URL only goes to the Logger."""
        blocking, allowed = self.split(blueprint(logger_call()))
        self.assertEqual((blocking, [a["module_id"] for a in allowed]), ([], [3]))

    def test_another_field_of_a_logger_call_blocks(self):
        cases = {
            "body value": logger_call(url=LOGGER_URL_VAR, urlEncodedBodyContent=[{"name": "note", "value": HOOK_URL}]),
            "query parameter": logger_call(url=LOGGER_URL_VAR, queryParameters=[{"name": "u", "value": HOOK_URL}]),
            "header value": logger_call(url=LOGGER_URL_VAR, headers=[{"name": "X-Next", "value": HOOK_URL}]),
            "other mapper key": logger_call(url=LOGGER_URL_VAR, data=HOOK_URL),
            "parameters": {**logger_call(url=LOGGER_URL_VAR), "parameters": {"authenticationType": "apiKeyConnection",
                                                                              "apiKeyAccount": 4242, "note": HOOK_URL}},
            "url field and body": logger_call(urlEncodedBodyContent=[{"name": "note", "value": HOOK_URL}]),
        }
        for label, call in cases.items():
            blocking, allowed = self.split(blueprint(handler_of(call)))
            if label == "url field and body":
                # The url field itself stays allowed. The copy in the body blocks.
                self.assertEqual((types(blocking), [a["location"] for a in allowed]),
                                 (["make_webhook_url"], ["$.flow[0].onerror[0].mapper.url"]), label)
                self.assertFalse(blocking[0]["location"].endswith(".mapper.url"), label)
                continue
            self.assertEqual((label, types(blocking), allowed), (label, ["make_webhook_url"], []))

    def test_the_url_inside_a_query_string_or_with_extra_text_blocks(self):
        encoded = HOOK_URL.replace(":", "%3A").replace("/", "%2F")
        cases = {
            "query of another host": "https://collector.example.invalid/in?next=" + HOOK_URL,
            "encoded in another host's query": "https://collector.example.invalid/in?next=" + encoded,
            "own query string": HOOK_URL + "?label=x",
            "fragment": HOOK_URL + "#x",
            "trailing path": HOOK_URL + "/extra",
            "leading text": " " + HOOK_URL,
            "trailing text": HOOK_URL + " ",
            "mapping around it": "{{ifempty(1.x; \"" + HOOK_URL + "\")}}",
            "http scheme": HOOK_URL.replace("https://", "http://"),
            "no scheme": HOOK_URL.replace("https://", ""),
            "userinfo host": "https://user@" + HOOK_URL[len("https://"):],
        }
        for label, url in cases.items():
            self.assert_blocks(label, blueprint(handler_of(logger_call(url=url))))

    def test_the_url_in_another_module_blocks(self):
        cases = {
            "set variable": {"id": 3, "module": "util:SetVariable2", "mapper": {"value": HOOK_URL}},
            "slack text": {"id": 3, "module": "slack:CreateMessage", "mapper": {"text": HOOK_URL}},
            "slack url field": {"id": 3, "module": "slack:CreateMessage", "mapper": {"url": HOOK_URL}},
            "legacy http module": logger_call(module="http:ActionSendData"),
            "http get": logger_call(method="get"),
            "http without a key keychain": logger_call(auth=None),
            "http basic auth": logger_call(auth="basicAuth"),
            "http no auth": logger_call(auth="noAuth"),
            "http with routes": {**logger_call(), "routes": [{"flow": []}]},
        }
        for label, mod in cases.items():
            self.assert_blocks(label, blueprint(handler_of(mod)))

    def test_a_logger_call_shaped_object_nested_in_a_mapper_blocks(self):
        nested = {"id": 4, "module": "util:SetVariable2", "mapper": {"value": logger_call(mid=9)}}
        self.assert_blocks("nested", blueprint(nested))

    def test_an_inactive_pin_allows_nothing_even_in_a_logger_call(self):
        pin = {"scenario_id": LOGGER_SID, "hook_id": LOGGER_HOOK_ID, "token_sha256": HOOK_SHA, "reason": "Dormant Logger pin"}
        al = secret_scan.parse_secret_allowlist({"entries": [], "logger_hook": pin}, webhooks_data=None)
        blocking, allowed = secret_scan.split_findings(blueprint(handler_of(logger_call())), "5", al)
        self.assertEqual((types(blocking), allowed), (["make_webhook_url"], []))

    def test_logger_url_matches_takes_only_the_bare_hook_url(self):
        """make_push.logger_url_ok reads this for the literal fallback, so it must reject everything but the bare URL."""
        pin = logger_allowlist().logger
        self.assertTrue(secret_scan.logger_url_matches(HOOK_URL, pin))
        for bad in (HOOK_URL + "?a=b", HOOK_URL + "#f", " " + HOOK_URL, HOOK_URL + "/x", "x " + HOOK_URL,
                    "https://collector.example.invalid/?u=" + HOOK_URL, HOOK_URL.replace("https://", "http://"),
                    OTHER_URL, "", None):
            self.assertFalse(secret_scan.logger_url_matches(bad, pin), repr(bad)[-14:])
        self.assertFalse(secret_scan.logger_url_matches(HOOK_URL, None))

    def test_the_repo_pin_is_the_logger_hook(self):
        """Rizwan said yes to the fallback 2026-10-29 (no team variables below Make Pro), so the committed file pins the Logger hook."""
        with open(os.path.join(ROOT, "audit", "secret_allowlist.json"), encoding="utf-8") as fh:
            data = json.load(fh)
        self.assertEqual((data["logger_hook"]["scenario_id"], data["logger_hook"]["hook_id"]), ("6832527", 3000983))
        self.assertRegex(data["logger_hook"]["token_sha256"], r"^[0-9a-f]{64}$")
        self.assertIn("url field of an http:MakeRequest", data["_comment"])


if __name__ == "__main__":
    unittest.main()
