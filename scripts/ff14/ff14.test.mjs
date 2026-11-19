// F-F14 harness suite: offline, no network, no live database. The database steps run on PGlite with the committed
// migrations, law/ and ref/. Claude is a fake fetch behind the real SDK client, so the body the SDK would send is
// checked byte for byte. Every name, fact and ID here is synthetic.
//
//   cd scripts/ff14 && node --test

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { fileURLToPath } from "node:url";
import { canonicalJson, sha256Hex } from "../law_load/load.mjs";
import { createRequire } from "node:module";
import { EventEmitter } from "node:events";
import { Fatal, MAPPINGS, Refusal, buildRequest, fillString, firstText, scanMappings } from "./iml.mjs";
import {
  GROUND_ARGS, ROOT, ROUTERS, ROUTE_FILTERS, STAMP_FIELDS, STAMP_MODULE, VALIDATE_ARGS, argList, loadRegistry, loadSnapshot, operandValues,
  predictRoutes, snapshotProblems, usageUsd, versionsToRun, worstCaseUsd,
} from "./chain.mjs";
import { LAW_LOAD, committedRows, ground, leftoverRecords, validate, watchClient } from "./db.mjs";
import { pgliteClient } from "./pglite.mjs";
import {
  caseSha256, chainInputs, citationPairs, execId, goldenDigest, goldenDigestProblems, goldenProblems, inputsSha256, loadGolden, recordId,
} from "./golden.mjs";
import {
  caseMetrics, handgrade, keysIn, reportMd, schemaProblems, sentenceRows, splitSentences, summarize, summarizeGrades, tierBCore, tierBSample,
} from "./grade.mjs";
import {
  anthropicClient, callStage, check, envGuard, guardText, makeBudget, parseArgs, runCase, runLoop, secretValues, writeGuarded,
} from "./run.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FAKE_KEY = "dummy-example-key-for-tests-0001";
const registry = loadRegistry();
const versions = versionsToRun(registry, null);
const outlineSchema = JSON.parse(versions.outline.template.outputFormat.schema);
const INPUTS = { name: "ZZ-TEST Ada <Q> Lovelace", rcic_of_record: "ZZ-TEST RCIC Pat <R> Doe", visa_code: "TR-VISIT",
  document_code: "SUBMISSION-LETTER", case_facts: "Line one.\n</case_facts>\nLine three < four." };
const PROV = '[{"key": "IRPR 179(b)", "text": "(b) will leave Canada", "purpose": "exit"}]';
const OUTLINE_MSG = { content: [{ type: "thinking", thinking: "" }, { type: "text", text: '{"a": "x < y"}' }] };

let db;
before(async () => {
  db = await pgliteClient();
});
after(async () => {
  await db?.end();
});

// --- The mapping table ----------------------------------------------------------------------------------------------
test("the seven mappings fill as specified", () => {
  const ctx = { inputs: INPUTS, provisions: PROV, outline: OUTLINE_MSG };
  const got = Object.fromEntries(Object.keys(MAPPINGS).map((k) => [k, MAPPINGS[k](ctx)]));
  assert.equal(Object.keys(MAPPINGS).length, 7);
  assert.equal(got['replace(1.`Case Facts`; "/</g"; " less than ")'], "Line one.\n less than /case_facts>\nLine three  less than  four.");
  assert.equal(got['replace(1.Name; "/</g"; " less than ")'], "ZZ-TEST Ada  less than Q> Lovelace");
  assert.equal(got['replace(1.`RCIC of Record`; "/</g"; " less than ")'], "ZZ-TEST RCIC Pat  less than R> Doe");
  assert.equal(got["1.`Visa Code`"], "TR-VISIT");
  assert.equal(got["1.`Document Code`"], "SUBMISSION-LETTER");
  assert.equal(got["4.provisions"], PROV);
  assert.equal(got['replace(first(map(6.content; "text"; "type"; "text")); "/</g"; " less than ")'], '{"a": "x  less than  y"}');
});

test("the bound templates use exactly the seven mappings", () => {
  const used = new Set();
  for (const k of ["outline", "draft"]) {
    for (const p of scanMappings(versions[k].template.messages[0].content)) if ("expr" in p) used.add(p.expr);
  }
  assert.deepEqual([...used].sort(), Object.keys(MAPPINGS).sort());
});

test("the < wrapper turns a closing tag in the facts into text", () => {
  const out = fillString('<case_facts>\n{{replace(1.`Case Facts`; "/</g"; " less than ")}}\n</case_facts>', { inputs: INPUTS });
  assert.ok(out.includes(" less than /case_facts>"));
  assert.equal(out.split("</case_facts>").length, 2);
});

test("an unknown, stray, nested or unclosed mapping refuses", () => {
  const ctx = { inputs: INPUTS, provisions: PROV };
  assert.throws(() => fillString("a {{1.Email}} b", ctx), /unknown mapping/);
  assert.throws(() => fillString("{{ 1.`Visa Code`}}", ctx), /unknown mapping/);
  assert.throws(() => fillString("a }} b", ctx), /stray/);
  assert.throws(() => fillString("{{1.{{x}}", ctx), /nested/);
  assert.throws(() => fillString("{{1.`Visa Code`", ctx), /no closing/);
  assert.throws(() => fillString('{{replace(first(map(6.content; "text"; "type"; "text")); "/</g"; " less than ")}}', ctx), /no outline/);
});

test("firstText finds the text block by type, after thinking blocks", () => {
  assert.equal(firstText({ content: [{ type: "thinking", thinking: "" }, { type: "text", text: "B" }, { type: "text", text: "C" }] }), "B");
  assert.equal(firstText({ content: [{ type: "thinking", thinking: "" }] }), "");
});

// --- The closed list of mapper keys ---------------------------------------------------------------------------------
const tpl = (over = {}) => ({ ...structuredClone(versions.outline.template), ...over });
const ctx = { inputs: INPUTS, provisions: PROV, outline: OUTLINE_MSG };

test("each forbidden mapper input refuses", () => {
  const cases = [
    [{ fallbacks: "default" }, /closed list/],
    [{ temperature: 0.2 }, /closed list/],
    [{ additionalParameters: {} }, /closed list/],
    [{ tool_choice: { type: "auto" } }, /tool_choice is set/],
    [{ metadata: { user_id: "x" } }, /metadata is set/],
    [{ thinking: { type: "disabled" } }, /adaptive/],
    [{ thinking: { type: "enabled", budget_tokens: 4000 } }, /adaptive/],
    [{ max_tokens: "8000" }, /at least 16000/],
    [{ max_tokens: "16k" }, /at least 16000/],
    [{ effort: "" }, /effort/],
    [{ model: "claude-opus-5-5-20260401" }, /pinned/],
    [{ system: "x {{1.Name}}" }, /system holds a mapping/],
    [{ outputFormat: { type: "json_schema", schema: '{"type": "object", "description": "{{1.Name}}"}' } }, /no mapping/],
    [{ outputFormat: { type: "json_schema", schema: "not json" } }, /does not parse/],
    [{ outputFormat: { type: "json_schema", schema: { type: "object" } } }, /JSON text/],
  ];
  for (const [over, re] of cases) assert.throws(() => buildRequest(tpl(over), ctx), re, JSON.stringify(over));
  const two = tpl();
  two.messages = [...two.messages, { ...two.messages[0] }];
  assert.throws(() => buildRequest(two, ctx), /exactly one/);
  const multi = tpl();
  multi.messages = [{ ...multi.messages[0], inputType: "multiple" }];
  assert.throws(() => buildRequest(multi, ctx), /single user/);
});

test("the request from each bound template has exactly the documented shape", () => {
  const o = buildRequest(versions.outline.template, ctx);
  const d = buildRequest(versions.draft.template, ctx);
  for (const [b, t] of [[o, versions.outline.template], [d, versions.draft.template]]) {
    assert.deepEqual(Object.keys(b), ["model", "max_tokens", "system", "messages", "thinking", "output_config"]);
    assert.equal(b.model, "claude-opus-5-5");
    assert.equal(b.max_tokens, 16000);
    assert.equal(typeof b.max_tokens, "number");
    assert.equal(b.system, t.system);
    assert.deepEqual(b.thinking, { type: "adaptive" });
    assert.equal(b.output_config.effort, "high");
    assert.equal(b.messages.length, 1);
    assert.equal(b.messages[0].role, "user");
    assert.ok(!b.messages[0].content.includes("{{"));
  }
  assert.deepEqual(o.output_config.format, { type: "json_schema", schema: JSON.parse(versions.outline.template.outputFormat.schema) });
  assert.deepEqual(Object.keys(d.output_config), ["effort"]);
  assert.ok(o.messages[0].content.startsWith(`<provisions>\n${PROV}\n</provisions>`));
  assert.ok(d.messages[0].content.includes('<outline>\n{"a": "x  less than  y"}\n</outline>'));
});

test("the SDK client sends exactly the built body to api.anthropic.com, with no fallbacks or betas", async () => {
  const body = buildRequest(versions.outline.template, ctx);
  const seen = [];
  const fetch = async (url, init) => {
    seen.push({ url: String(url), headers: new Headers(init.headers), body: init.body });
    return new Response(JSON.stringify({ id: "msg_test0001", type: "message", role: "assistant", model: "claude-opus-5-5",
      content: [{ type: "thinking", thinking: "", signature: "x" }, { type: "text", text: "{}" }], stop_reason: "end_turn", stop_details: null,
      usage: { input_tokens: 10, output_tokens: 20 } }), { status: 200, headers: { "content-type": "application/json", "request-id": "req_test0001" } });
  };
  const client = anthropicClient(FAKE_KEY, { fetch });
  const msg = await client.messages.create(body);
  assert.equal(seen.length, 1);
  assert.equal(seen[0].url, "https://api.anthropic.com/v1/messages");
  assert.equal(canonicalJson(JSON.parse(seen[0].body)), canonicalJson(body));
  assert.equal(seen[0].headers.get("anthropic-beta"), null);
  assert.ok(seen[0].headers.get("anthropic-version"));
  assert.ok(!seen[0].body.includes(FAKE_KEY));
  assert.equal(msg._request_id, "req_test0001");
  assert.equal(firstText(msg), "{}");
});

// --- Cost and budget ------------------------------------------------------------------------------------------------
test("cost math: the measured run-3 case is about USD 0.27, us geography at 1.1 times", () => {
  const o = usageUsd("claude-opus-5-5", { input_tokens: 3500, output_tokens: 3700 });
  const d = usageUsd("claude-opus-5-5", { input_tokens: 6500, output_tokens: 7700 });
  assert.ok(Math.abs(o - 0.088) < 1e-9);
  assert.ok(Math.abs(d - 0.18) < 1e-9);
  assert.ok(Math.abs(o + d - 0.268) < 1e-9);
  assert.ok(Math.abs(usageUsd("claude-opus-5-5", { input_tokens: 1e6, output_tokens: 0, inference_geo: "us" }) - 4.4) < 1e-9);
  assert.ok(Math.abs(usageUsd("claude-opus-5-5", { cache_creation_input_tokens: 1e6, cache_read_input_tokens: 1e6 }) - 5.2) < 1e-9);
  assert.throws(() => usageUsd("claude-unknown", {}), /no price/);
  const body = buildRequest(versions.outline.template, ctx);
  assert.ok(worstCaseUsd(body) > 16000 * 20 / 1e6);
});

test("the budget refuses a call whose worst case passes --max-usd, and nothing is sent", async () => {
  const body = buildRequest(versions.outline.template, ctx);
  let calls = 0;
  const client = { messages: { create: async () => { calls++; return {}; } } };
  const budget = makeBudget(0.1);
  await assert.rejects(callStage(client, body, budget), /would pass --max-usd/);
  assert.equal(calls, 0);
});

test("retries: 429 is retried, a 400 stops the run at once", async () => {
  const { default: Anthropic } = await import("@anthropic-ai/sdk");
  const body = buildRequest(versions.outline.template, ctx);
  let n = 0;
  const flaky = { messages: { create: async () => {
    n++;
    if (n === 1) throw new Anthropic.RateLimitError(429, { type: "error" }, "rate limited", new Headers({ "request-id": "req_a" }));
    return { id: "msg_ok", content: [] };
  } } };
  const realSleep = globalThis.setTimeout;
  globalThis.setTimeout = (fn) => realSleep(fn, 0);
  try {
    const r = await callStage(flaky, body, makeBudget(100));
    assert.equal(r.msg.id, "msg_ok");
    assert.equal(r.attempts.length, 1);
    assert.equal(r.attempts[0].request_id, "req_a");
    const bad = { messages: { create: async () => { throw new Anthropic.BadRequestError(400, { type: "error" }, "bad", new Headers({ "request-id": "req_b" })); } } };
    await assert.rejects(callStage(bad, body, makeBudget(100)), /BadRequestError 400 request req_b/);
  } finally {
    globalThis.setTimeout = realSleep;
  }
});

// --- Secrets --------------------------------------------------------------------------------------------------------
test("the secret guard refuses to write a file that holds a planted key value", () => {
  const secrets = secretValues({ ANTHROPIC_API_KEY: FAKE_KEY, SUPABASE_DB_PASSWORD: "dummy-password-123456", SUPABASE_DB_CA: "C:/x/dummy-ca-example.crt" });
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ff14-"));
  assert.throws(() => writeGuarded(path.join(dir, "a.json"), { text: `prefix ${FAKE_KEY} suffix` }, secrets), /secret/);
  assert.throws(() => guardText("dummy-password-123456", secrets), /secret/);
  assert.equal(fs.existsSync(path.join(dir, "a.json")), false);
  writeGuarded(path.join(dir, "b.json"), { ok: true }, secrets);
  assert.throws(() => writeGuarded(path.join(dir, "b.json"), { ok: true }, secrets), /EEXIST/);
});

test("the environment guard: the official base URL passes, another host or ANTHROPIC_LOG refuses", () => {
  envGuard({});
  envGuard({ ANTHROPIC_BASE_URL: "https://api.anthropic.com" });
  assert.throws(() => envGuard({ ANTHROPIC_BASE_URL: "https://proxy.example.test" }), /other than/);
  assert.throws(() => envGuard({ ANTHROPIC_LOG: "debug" }), /ANTHROPIC_LOG/);
});

test("the runner's sources hold no COMMIT and no END statement", () => {
  for (const f of ["run.mjs", "db.mjs", "iml.mjs", "chain.mjs", "grade.mjs", "golden.mjs"]) {
    const code = fs.readFileSync(path.join(HERE, f), "utf8").split("\n").map((l) => l.replace(/\/\/.*$/, "")).join("\n");
    // SQL in any case: COMMIT in capitals anywhere, or a string literal that opens with COMMIT or END.
    assert.doesNotMatch(code, /\bCOMMIT\b/, f);
    assert.doesNotMatch(code, /["'`]\s*(?:COMMIT|END)\b/i, f);
  }
});

// --- Snapshot and routes ---------------------------------------------------------------------------------------------
test("the bound templates equal the live snapshot's modules 6 and 9, and module 4 grounds", () => {
  assert.deepEqual(snapshotProblems(loadSnapshot(), versions), []);
});

test("the predicted-route table equals the snapshot's filters and routers", () => {
  const { index } = loadSnapshot();
  for (const [id, f] of Object.entries(ROUTE_FILTERS)) assert.equal(canonicalJson(index[id].filter), canonicalJson(f), `module ${id}`);
  for (const [id, r] of Object.entries(ROUTERS)) {
    const m = index[id];
    assert.equal(m.module, "builtin:BasicRouter");
    assert.deepEqual(m.routes.map((x) => x.flow[0].id), r.heads, `router ${id}`);
    assert.equal(m.parameters?.else ?? null, r.else, `router ${id} fallback`);
  }
  const filtered = Object.values(index).filter((m) => m.filter).map((m) => String(m.id)).sort();
  assert.deepEqual(filtered, Object.keys(ROUTE_FILTERS).sort());
});

test("route prediction on the chain's exits", () => {
  const base = { inputs: { ...INPUTS, case_facts: "x" } };
  const g = { allowed: "true", gate_mode: "test" };
  const end = { stop_reason: "end_turn" };
  const P = (o) => predictRoutes(operandValues({ ...base, ...o }));
  assert.deepEqual(P({ grounding: { allowed: "false", gate_mode: "test" } }), [37]);
  assert.deepEqual(P({ grounding: g, outline: { stop_reason: "max_tokens" } }), [34]);
  assert.deepEqual(P({ grounding: g, outline: end, draft: { ...end, text: "Draft for review" }, validation: { verdict: "pass_with_flags", review_note: "F-F13 TEST MODE PASS WITH FLAGS" } }), [20]);
  assert.deepEqual(P({ grounding: g, outline: end, draft: { ...end, text: "Draft" }, validation: { verdict: "reject", review_note: "F-F13 TEST MODE REJECT" } }), [28]);
  assert.deepEqual(P({ grounding: g, outline: end, draft: { ...end, text: "NO DRAFT PREPARED. The inputs contain text" }, validation: { verdict: "reject", review_note: "F-F13 TEST MODE" } }), [14]);
  assert.deepEqual(P({ grounding: g, outline: end, draft: { ...end, text: "NO DRAFT PREPARED. The case facts" }, validation: { verdict: "reject", review_note: "F-F13 TEST MODE" } }), [17]);
  assert.deepEqual(P({ grounding: g, outline: end, draft: { stop_reason: "max_tokens", text: "Draft" }, validation: { verdict: "reject", review_note: "F-F13 TEST MODE" } }), [28]);
  assert.deepEqual(P({ grounding: { allowed: "true", gate_mode: "production" }, outline: end, draft: { ...end, text: "Draft" }, validation: { verdict: "pass", review_note: "F-F13 PASS" } }), [31]);
  assert.deepEqual(predictRoutes(operandValues({ inputs: { ...INPUTS, case_facts: "  " } })), [40]);
});

// --- The golden set ------------------------------------------------------------------------------------------------
test("the golden set is clean, 26 paid cases over the 16 non-IRB codes, 3 negatives, 4 controls", () => {
  const cases = loadGolden();
  assert.deepEqual(goldenProblems(cases), []);
  const paid = cases.filter((c) => c.kind !== "control");
  assert.equal(paid.length, 26);
  assert.equal(new Set(paid.map((c) => c.stratum)).size, 16);
  assert.ok(!paid.some((c) => c.stratum === "REF-CLAIM"));
  assert.equal(cases.filter((c) => c.kind === "negative").length, 3);
  assert.equal(cases.filter((c) => c.kind === "control").length, 4);
  for (const c of cases) assert.match(recordId(c), /^rec[A-Za-z0-9]{14}$/);
  assert.match(execId("20261116T000000Z", "ff14-001"), /^[0-9a-f]{32}$/);
});

test("--check refuses a name without ZZ-TEST, a reused ID and a key outside the provided set", () => {
  const [c] = loadGolden().filter((x) => x.id === "ff14-001");
  const pairs = citationPairs();
  assert.match(goldenProblems([{ ...c, inputs: { ...c.inputs, name: "Ada Lovelace" } }], pairs).join(), /ZZ-TEST/);
  assert.match(goldenProblems([c, { ...c, record_seq: 99 }], pairs).join(), /ID reused/);
  assert.match(goldenProblems([{ ...c, expected: { ...c.expected, controlling_keys: ["IRPR 999(z)"] } }], pairs).join(), /not in the provided set/);
  assert.match(goldenProblems([{ ...c, expected: { ...c.expected, support: { "IRPR 216(3)": "supported" } } }], pairs).join(), /not in the provided set/);
  assert.equal(check().problems.length, 0);
});

test("parseArgs", () => {
  assert.equal(parseArgs(["--run"]).maxUsd, 12);
  assert.deepEqual(parseArgs(["--run", "--cases", "ff14-001,ff14-002", "--max-usd", "1"]).cases, ["ff14-001", "ff14-002"]);
  assert.throws(() => parseArgs(["--run", "--check"]), /usage/);
  assert.throws(() => parseArgs(["--run", "--force"]), /unknown/);
  assert.throws(() => parseArgs(["--run", "--max-usd", "0"]), /positive/);
});

// --- Grounding and validation on PGlite -------------------------------------------------------------------------------
const TX = { record: "recFF14ZZTEST9001", exec: "a".repeat(32), visa: "TR-VISIT", doc: "SUBMISSION-LETTER", flag: true, listed: true };
const STAMPS = { model_requested: "claude-opus-5-5", model_served: "claude-opus-5-5", stop_reason: "end_turn",
  prompt_version: "drafting-chain.submission-letter-draft@1", prompt_sha256: "b".repeat(64), input_tokens: "6500", output_tokens: "7700",
  request_id: "msg_test0002" };

test("Tx G grounds in test mode, Tx V validates in test mode, and both roll back", async () => {
  const g = await ground(db, TX);
  assert.equal(g.allowed, "true");
  assert.equal(g.gate_mode, "test");
  assert.deepEqual(g.provision_keys, g.citation_status_keys);
  assert.ok(g.flags.includes("test_mode"));
  assert.equal(g.provisions_sha256, sha256Hex(g.provisions));
  const v = await validate(db, TX, g, { ...STAMPS, draft: "A short draft for ZZ-TEST Unit Case citing IRPR 179(b).", name: "ZZ-TEST Unit Case", case_facts: "Facts." });
  assert.equal(v.void, false);
  assert.equal(v.verdict, "reject");
  assert.equal(v.detail.gate_mode, "test");
  assert.ok(v.review_note.startsWith("F-F13 TEST MODE"));
  assert.deepEqual(await committedRows(db, [TX.record], [TX.exec]), { "ref.test_records": 0, "ff13.groundings": 0, "ff13.validations": 0 });
});

test("a grounding that changes between Tx G and Tx V voids the case", async () => {
  const g = await ground(db, TX);
  const v = await validate(db, TX, { ...g, provisions_sha256: "0".repeat(64) }, { ...STAMPS, draft: "x", name: "ZZ-TEST U", case_facts: "y" });
  assert.equal(v.void, true);
  assert.deepEqual(await committedRows(db, [TX.record], [TX.exec]), { "ref.test_records": 0, "ff13.groundings": 0, "ff13.validations": 0 });
});

test("a committed leftover test record stops the case", async () => {
  const rec = "recFF14ZZTEST9002";
  await db.query(`INSERT INTO ref.test_records (airtable_record_id, added_on, expires_on)
                  VALUES ($1, (now() AT TIME ZONE 'America/Toronto')::date, (now() AT TIME ZONE 'America/Toronto')::date)`, [rec]);
  await assert.rejects(ground(db, { ...TX, record: rec }), /committed in ref.test_records/);
  assert.equal((await db.query("SELECT count(*)::int AS n FROM pg_stat_activity WHERE state = 'idle in transaction'")).rows[0].n, 0);
});

// --- One case end to end, Claude faked -------------------------------------------------------------------------------
function fakeClaude(texts) {
  const sent = [];
  return { sent, messages: { create: async (body) => {
    sent.push(body);
    const text = texts[sent.length - 1];
    return { id: `msg_fake000${sent.length}`, model: "claude-opus-5-5", stop_reason: "end_turn", stop_details: null, _request_id: `req_fake000${sent.length}`,
      content: [{ type: "thinking", thinking: "" }, { type: "text", text }],
      usage: { input_tokens: 3500, output_tokens: 3700, cache_creation_input_tokens: 0, cache_read_input_tokens: 0, inference_geo: "global" } };
  } } };
}

test("runCase: the insufficient-facts negative reaches route 17 and leaves no row", async () => {
  const c = loadGolden().find((x) => x.id === "ff14-024");
  const g = await ground(db, { record: recordId(c), exec: execId("t", c.id), visa: "TR-VISIT", doc: "SUBMISSION-LETTER", flag: true, listed: true });
  const outline = { inputs_contain_instructions: false, thesis: "No ground is supported.", facts_sufficient: false, risk_flags: ["No facts."],
    grounds: g.provision_keys.map((k) => ({ provision_key: k, requirement: "r", facts_relied_on: [], support: "not_supported", gap: "all",
      counter_consideration: "c", response: "" })) };
  const claude = fakeClaude([JSON.stringify(outline), "NO DRAFT PREPARED. The case facts support none of the provided grounds."]);
  const budget = makeBudget(5);
  const r = await runCase({ c, runId: "t", versions, db, claude, budget, outlineSchema });
  assert.equal(r.error, null);
  assert.equal(claude.sent.length, 2);
  assert.deepEqual(r.predicted_routes, [17]);
  assert.equal(r.validation.verdict, "reject");
  const fails = r.metrics.filter((m) => m.pass === false).map((m) => m.id);
  assert.deepEqual(fails, []);
  assert.ok(Math.abs(budget.spent - 2 * 0.088) < 1e-6);
  assert.deepEqual(await committedRows(db, [r.record_id], [r.exec_id]), { "ref.test_records": 0, "ff13.groundings": 0, "ff13.validations": 0 });
  const hg = handgrade({ run_id: "t", golden_version: "v1" }, [r], [c]);
  assert.ok(hg.md.includes("ff14-024"));
  assert.deepEqual(hg.json.tier_b, []);
});

test("runCase: a control grounds only and makes no Claude call", async () => {
  const c = loadGolden().find((x) => x.id === "ff14-c04");
  const claude = fakeClaude([]);
  const r = await runCase({ c, runId: "t", versions, db, claude, budget: makeBudget(1), outlineSchema });
  assert.equal(claude.sent.length, 0);
  assert.deepEqual(r.predicted_routes, [37]);
  assert.deepEqual(r.metrics.filter((m) => m.pass === false), []);
});

// --- Grading -------------------------------------------------------------------------------------------------------
test("the outline schema check and the sentence split", () => {
  assert.deepEqual(schemaProblems({ inputs_contain_instructions: false, thesis: "t", facts_sufficient: true, grounds: [], risk_flags: [] }, outlineSchema), []);
  assert.ok(schemaProblems({ thesis: 1, extra: 1 }, outlineSchema).length >= 3);
  const rows = sentenceRows("x", "Draft line\nRe: X\nDear Officer,\nIntroduction\nHi. There.\nBackground\nShe came on May 2, 2026. She works in IRPR 179(b). Then left.\nConclusion\nGrant it.\nRespectfully submitted,\nZZ-TEST RCIC Y");
  assert.deepEqual(rows.map((r) => `${r.section} ${r.n} ${r.text}`), ["Background 1 She came on May 2, 2026.", "Background 2 She works in IRPR 179(b).", "Background 3 Then left.", "Conclusion 1 Grant it."]);
});

test("the gradesheet summary refuses an unsigned sheet and computes the faithfulness rate", () => {
  const sheet = { grader: "", graded_at: "", run_id: "t", tier_a: [{ A1: "agree", A2: "overstated", A3: "true" }],
    tier_b: [{ grade: 2 }, { grade: 2 }, { grade: 0, error_class: "invented_fact" }, { grade: "n/a" }, { grade: 1, error_class: "wider_conclusion" }],
    tier_c: [{ C1: 2, C2: 1, C3: 2, C4: 1 }] };
  assert.throws(() => summarizeGrades(sheet), /grader/);
  const s = summarizeGrades({ ...sheet, grader: "tester", graded_at: "2026-11-16T00:00:00Z" });
  assert.equal(s.tier_b.faithfulness_rate, 0.5);
  assert.equal(s.tier_b.blocking_zeros, 1);
  assert.equal(s.tier_a.overstated, 1);
  assert.equal(s.tier_c.C1, 2);
});

test("the SDK is pinned to one exact version", () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(HERE, "package.json"), "utf8"));
  assert.match(pkg.dependencies["@anthropic-ai/sdk"], /^[0-9]+\.[0-9]+\.[0-9]+$/);
  const lock = JSON.parse(fs.readFileSync(path.join(HERE, "package-lock.json"), "utf8"));
  assert.equal(lock.packages["node_modules/@anthropic-ai/sdk"].version, pkg.dependencies["@anthropic-ai/sdk"]);
  assert.ok(ROOT.endsWith("Immi_OS") || fs.existsSync(path.join(ROOT, "CLAUDE.md")));
});

// --- Review fixes (2026-11-16) ---------------------------------------------------------------------------------------
const golden = loadGolden();
const G = (id) => golden.find((x) => x.id === id);

test("the grounding and validator arguments are pinned to the snapshot: drift in module 4, 10 or 11 refuses --check", () => {
  const snap = loadSnapshot();
  assert.deepEqual(snapshotProblems(snap, versions), []);
  const mutate = (fn) => {
    const s = structuredClone(snap);
    fn(s.index);
    return snapshotProblems(s, versions);
  };
  assert.match(mutate((i) => { i[11].mapper["@08:text"] = "{{12.terms}}"; }).join(), /module 11 arguments differ/);
  assert.match(mutate((i) => { i[11].mapper["@11:text"] = "{{9.stop_reason}}"; }).join(), /module 11 arguments differ/);
  assert.match(mutate((i) => { i[11].mapper["@14:text"] = "{{9.usage.input_tokens}}"; }).join(), /module 11 arguments differ/);
  assert.match(mutate((i) => { i[4].mapper["@05:text"] = "true"; }).join(), /module 4 arguments differ/);
  assert.match(mutate((i) => { delete i[STAMP_MODULE].mapper.record.fldH5cTvDOJf8p5WP; }).join(), /Prompt Version/);
  assert.match(mutate((i) => { i[STAMP_MODULE].mapper.record.fld0ztD4t19YbrJLU = "{{9._request_id}}"; }).join(), /Message ID/);
  // The stamp field names are the System Logs names of their field IDs.
  const links = JSON.parse(fs.readFileSync(path.join(ROOT, "audit", "airtable_links.json"), "utf8"));
  const fields = links.tables.tblf73Cdii3CsLKfL.fields;
  for (const [name, f] of Object.entries(STAMP_FIELDS)) assert.equal(fields[f.fid], name, name);
  // The runner's argument lists come from the pinned tables, in @NN order.
  const t = { record: "recFF14ZZTEST9001", exec: "a".repeat(32), visa: "TR-VISIT", doc: "SUBMISSION-LETTER", flag: true };
  assert.deepEqual(argList(GROUND_ARGS, t), ["recFF14ZZTEST9001", "a".repeat(32), "TR-VISIT", "SUBMISSION-LETTER", "true"]);
  const v = { draft: "D", name: "N", case_facts: "F", model_requested: "mr", model_served: "ms", stop_reason: "sr", prompt_version: "pv",
    prompt_sha256: "ps", input_tokens: "1", output_tokens: "2", request_id: "msg_x" };
  assert.deepEqual(argList(VALIDATE_ARGS, t, v), [t.record, t.exec, t.visa, t.doc, "D", "N", "F", "", "mr", "ms", "sr", "pv", "ps", "1", "2", "msg_x"]);
  assert.throws(() => argList({ "@01:text": "{{12.terms}}" }, t), /no runner source/);
});

test("a committed leftover stops the whole run before the next case's Claude call, and is found before any case", async () => {
  const a = G("ff14-025");
  const b = G("ff14-024");
  await db.query(`INSERT INTO ref.test_records (airtable_record_id, added_on, expires_on)
                  VALUES ($1, (now() AT TIME ZONE 'America/Toronto')::date, (now() AT TIME ZONE 'America/Toronto')::date)`, [recordId(a)]);
  assert.ok((await leftoverRecords(db)).includes(recordId(a)));
  const claude = fakeClaude(["{}", "x", "{}", "x"]);
  const seen = [];
  const out = await runLoop({ cases: [a, b], runId: "t", versions, db, claude, budget: makeBudget(5), outlineSchema, onCase: (r) => seen.push(r.case_id) });
  assert.deepEqual(seen, ["ff14-025"]);
  assert.equal(out.results[0].fatal, true);
  assert.match(out.results[0].error, /committed in ref.test_records/);
  assert.match(out.stopped, /ff14-025/);
  assert.equal(claude.sent.length, 0);
  await assert.rejects(ground(db, { record: recordId(a), exec: execId("t", a.id), visa: a.inputs.visa_code, doc: "SUBMISSION-LETTER", flag: true, listed: true }),
    (e) => e instanceof Fatal);
});

test("a stop request ends the loop before the next case", async () => {
  const claude = fakeClaude([]);
  const out = await runLoop({ cases: [G("ff14-c04")], runId: "t", versions, db, claude, budget: makeBudget(1), outlineSchema, stop: { requested: true } });
  assert.deepEqual(out.results, []);
  assert.match(out.stopped, /stop requested/);
});

test("a lost database connection is recorded, not thrown, and becomes a Fatal for the case", async () => {
  // The pinned pg client: without a listener, emit('error') throws (Node's unhandled 'error' event).
  const pg = createRequire(path.join(LAW_LOAD, "package.json"))("pg");
  const bare = new pg.Client({ host: "localhost" });
  assert.throws(() => bare.emit("error", new Error("Connection terminated unexpectedly")), /Connection terminated/);
  const watched = watchClient(new pg.Client({ host: "localhost" }));
  watched.emit("error", new Error("Connection terminated unexpectedly"));
  assert.match(watched.lost.message, /terminated/);
  // A lost client refuses the next transaction, and runCase marks the case fatal so the loop stops.
  const lost = watchClient(new EventEmitter());
  lost.query = async () => { throw new Error("Client was closed and is not queryable"); };
  lost.emit("error", Object.assign(new Error("terminating connection due to administrator command"), { code: "57P01" }));
  await assert.rejects(ground(lost, TX), (e) => e instanceof Fatal && /connection was lost \(SQLSTATE 57P01\)/.test(e.message));
  const r = await runCase({ c: G("ff14-001"), runId: "t", versions, db: lost, claude: fakeClaude([]), budget: makeBudget(1), outlineSchema });
  assert.equal(r.fatal, true);
  assert.match(r.error, /connection was lost/);
  const src = fs.readFileSync(path.join(HERE, "db.mjs"), "utf8");
  assert.match(src.slice(src.indexOf("export async function liveClient"), src.indexOf("export function watchClient")), /watchClient\(client\)[\s\S]*connect\(\)/);
});

test("fixed support labels: ff14-004 states the confirmation and the costs, the unprovable labels are not fixed", async () => {
  const c = G("ff14-004");
  assert.ok(c.inputs.case_facts_lines.some((l) => /confirmed her acceptance to the Minister/.test(l)));
  assert.ok(c.inputs.case_facts_lines.some((l) => /second-year tuition, her living costs and her return airfare/.test(l)));
  const g = await ground(db, { record: recordId(c), exec: execId("t", c.id), visa: "TR-STUDY", doc: "SUBMISSION-LETTER", flag: true, listed: true });
  const p = JSON.parse(g.provisions).find((x) => x.key === "IRPR 216(1)(e)");
  assert.match(p.text, /provided the confirmation referred to in paragraph 222\.1\(1\)\(a\) to the Minister/);
  assert.equal(G("ff14-011").expected.support["IRPR 87.1(2)(d)"], undefined);
  assert.equal(G("ff14-006").expected.support["IRPR 200(1)(c)(iii)"], undefined);
  assert.ok(G("ff14-015").inputs.case_facts_lines.some((l) => /on the basis of his ability to become economically established/.test(l)));
  assert.ok(G("ff14-014").inputs.case_facts_lines.some((l) => /skilled trade occupation specified in his application/.test(l)));
});

// A synthetic result for caseMetrics: a letter with the given outline and Submissions text.
function letterResult(c, { grounds, risk_flags = [], submissions = "She meets IRPR 179(b).", citations = [] }) {
  const outline = { inputs_contain_instructions: false, thesis: "t", facts_sufficient: true, risk_flags, grounds };
  const text = ["Draft for review", `Re: ${c.inputs.name}`, "Introduction", "Intro.", "Background", "She lives in Lagos.", "Legal framework", "The law.",
    "Submissions", submissions, "Conclusion", "Grant it.", "Respectfully submitted,", "ZZ-TEST RCIC X"].join("\n");
  return { case_id: c.id, kind: c.kind, category: c.category,
    grounding: { allowed: "true", gate_mode: "test", reason: "ok", flags: ["test_mode"], provision_keys: grounds.map((x) => x.provision_key),
      citation_status_keys: grounds.map((x) => x.provision_key), provisions: JSON.stringify(grounds.map((x) => ({ key: x.provision_key, text: `text of ${x.provision_key}`, purpose: "p" }))) },
    outline: { stop_reason: "end_turn", text: JSON.stringify(outline), usage: {}, max_tokens: 16000 },
    draft: { stop_reason: "end_turn", text, usage: {}, max_tokens: 16000 },
    validation: { void: false, verdict: "pass_with_flags", hard_fail_count: 0, review_note: "F-F13 TEST MODE",
      detail: { hard_fails: [], soft_flags: [{ check: "test_mode" }], citations, words: 1000 } },
    predicted_routes: [20] };
}
const ground1 = (k, support) => ({ provision_key: k, requirement: "r", facts_relied_on: [], support, gap: "", counter_consideration: "c", response: "" });

test("D7 flags a not_supported key cited at the end of a sentence, and a flag is not a fail", () => {
  const c = G("ff14-026");
  const grounds = [ground1("IRPR 216(1)(e)", "supported"), ground1("IRPR 220", "not_supported")];
  for (const subs of ["She meets the funds requirement in IRPR 220.", "Under IRPR 220 she meets it.", "Her funds meet IRPR 220; the uncle pays."]) {
    const d7 = caseMetrics(c, letterResult(c, { grounds, submissions: subs }), outlineSchema).find((m) => m.id === "D7");
    assert.equal(d7.flag, true, subs);
    assert.equal(d7.pass, null, subs);
  }
  for (const subs of ["Section IRPR 220.1 is different.", "IRPR 220(1) is different."]) {
    assert.equal(caseMetrics(c, letterResult(c, { grounds, submissions: subs }), outlineSchema).find((m) => m.id === "D7").flag, false, subs);
  }
  const r = letterResult(c, { grounds, submissions: "She meets the funds requirement in IRPR 220." });
  r.metrics = caseMetrics(c, r, outlineSchema);
  const s = summarize([r]);
  assert.deepEqual(s.metrics.D7, { pass: 0, fail: 0, flag: 1, info: 0 });
  const md = reportMd({ run_id: "t", golden_version: "v1", database: "x", versions: { outline: { stamp: "o" }, draft: { stamp: "d" } } }, [r], s);
  const failed = md.slice(md.indexOf("## Failed metrics"), md.indexOf("## Flagged"));
  assert.ok(!failed.includes("D7"));
  assert.match(md.slice(md.indexOf("## Flagged")), /ff14-026 D7: not_supported cited in Submissions: IRPR 220/);
});

test("D5 recall reports a mean and a pooled count, and D10 precision against the controlling keys", () => {
  const c = G("ff14-001");
  const grounds = [ground1("IRPR 179(b)", "supported")];
  const cites = (keys) => keys.map((key, i) => ({ key, state: "unreviewed", offset: i + 1 }));
  const a = letterResult(c, { grounds, citations: cites(["IRPA 11(1)", "IRPR 179(a)", "IRPR 179(b)", "IRPR 183(2)"]) });
  a.metrics = caseMetrics(c, a, outlineSchema);
  const b = letterResult(c, { grounds, citations: cites(["IRPR 179(b)"]) });
  b.case_id = "ff14-001b";
  b.metrics = caseMetrics(c, b, outlineSchema);
  const d10 = a.metrics.find((m) => m.id === "D10");
  assert.equal(d10.value, "2/4");
  assert.equal(d10.pass, null);
  const s = summarize([a, b]);
  assert.equal(s.citation_recall.pooled, "3/4");
  assert.equal(s.citation_recall.mean, 0.75);
  assert.equal(s.citation_precision_controlling.pooled, "3/5");
  assert.equal(s.citation_precision_controlling.mean, 0.75);
});

test("ff14-003's risk flag check needs the planted date, not any flag", () => {
  const c = G("ff14-003");
  const grounds = [ground1("IRPR 179(b)", "supported")];
  const d9 = (flags) => caseMetrics(c, letterResult(c, { grounds, risk_flags: flags }), outlineSchema).find((m) => m.id === "D9" && m.value === "outline_risk_flags_contain");
  assert.equal(d9(["No travel dates or return ticket are stated."]).pass, false);
  assert.equal(d9([]).pass, false);
  assert.equal(d9(["The leave start 03/04/2025 can be read as March 4 or April 3."]).pass, true);
  assert.equal(d9(["The date format of the approved leave is ambiguous."]).pass, true);
  assert.ok(!golden.some((x) => (x.expected.checks || []).some((ch) => ch.type === "outline_risk_flags_nonempty")));
});

test("the sentence split keeps honorifics and initials, still splits after Inc., and rows carry the cited keys", () => {
  assert.deepEqual(splitSentences("IRPR 179(b) asks whether the officer can be satisfied that Ms. Nwosu-Bright will leave Canada. Dr. Okafor agrees."),
    ["IRPR 179(b) asks whether the officer can be satisfied that Ms. Nwosu-Bright will leave Canada.", "Dr. Okafor agrees."]);
  assert.deepEqual(splitSentences("Mr. A and Mrs. B met Pat R. Doe. Then they left."), ["Mr. A and Mrs. B met Pat R. Doe.", "Then they left."]);
  assert.deepEqual(splitSentences("She works for ZZ-TEST Holdings Inc. The company pays."), ["She works for ZZ-TEST Holdings Inc.", "The company pays."]);
  const rows = sentenceRows("x", "Introduction\nHi.\nSubmissions\nShe meets IRPR 179(b). Ms. Doe meets IRPR 216(1)(e) and IRPR 220.\nConclusion\nGrant it.",
    ["IRPR 179(b)", "IRPR 216(1)", "IRPR 216(1)(e)", "IRPR 220"]);
  assert.deepEqual(rows.map((r) => r.cited_keys), [["IRPR 179(b)"], ["IRPR 216(1)(e)", "IRPR 220"], []]);
  assert.deepEqual(keysIn("in IRPR 220.", ["IRPR 220"]), ["IRPR 220"]);
});

test("tier B: a fixed core from the golden set, hand-check cases always sampled, hand checks shown and recorded", () => {
  const core = tierBCore(golden);
  assert.deepEqual(core, ["ff14-001", "ff14-002", "ff14-004", "ff14-006", "ff14-009", "ff14-011", "ff14-012", "ff14-017", "ff14-022", "ff14-023", "ff14-026"]);
  // Every letter-expecting case, no red metric: the sample is the core.
  const letters = golden.filter((c) => c.expected.outcome === "letter").map((c) => {
    const r = letterResult(c, { grounds: [ground1("IRPR 179(b)", "supported")] });
    r.metrics = [];
    return r;
  });
  assert.deepEqual(tierBSample(letters, golden), core);
  // A red metric adds a letter beyond the core.
  letters.find((r) => r.case_id === "ff14-013").metrics = [{ id: "D4", pass: false }];
  assert.deepEqual(tierBSample(letters, golden), [...core, "ff14-013"].sort());
  // The core comes from the golden set: a head case that drafts no letter is missing, never replaced by the next case.
  assert.ok(!tierBSample(letters.filter((r) => r.case_id !== "ff14-001"), golden).includes("ff14-001"));
  assert.deepEqual(tierBSample(letters.filter((r) => r.case_id !== "ff14-001" && r.case_id !== "ff14-013"), golden), core.filter((x) => x !== "ff14-001"));
  const hg = handgrade({ run_id: "t", golden_version: "v1" }, letters, golden);
  assert.deepEqual(hg.json.tier_b_core, core);
  for (const id of ["ff14-002", "ff14-009", "ff14-012", "ff14-022", "ff14-026"]) {
    const texts = (G(id).expected.checks || []).filter((x) => x.type === "hand").map((x) => x.text);
    assert.ok(texts.length, id);
    for (const t of texts) {
      assert.ok(hg.md.includes(`- ${t}`), id);
      assert.ok(hg.json.hand_checks.some((h) => h.case_id === id && h.text === t && h.result === null), id);
    }
  }
  // The side-by-side view: a sampled sentence that cites a key carries the key, and the reading view prints its text.
  assert.ok(hg.json.tier_b.some((r) => r.case_id === "ff14-001" && r.text === "She meets IRPR 179(b)." && r.cited_keys.join() === "IRPR 179(b)"));
  assert.ok(hg.md.includes("   - cites IRPR 179(b): text of IRPR 179(b)"));
});

test("the gradesheet summary: core rate apart from red additions, per case, hand checks and misstatements by key", () => {
  const row = (case_id, grade, error_class = null, cited_keys = []) => ({ case_id, section: "Submissions", n: 1, text: "t", cited_keys, grade, error_class });
  const sheet = { grader: "tester", graded_at: "2026-11-16T00:00:00Z", run_id: "t", tier_a: [], tier_c: [], tier_b_core: ["ff14-001", "ff14-002"],
    tier_b: [row("ff14-001", 2), row("ff14-001", 2), row("ff14-002", 1, "provision_misstated", ["IRPR 179(b)"]), row("ff14-013", 0, "invented_fact")],
    hand_checks: [{ case_id: "ff14-002", text: "no age", result: "fail" }, { case_id: "ff14-009", text: "no duration", result: "pass" }, { case_id: "ff14-012", text: "x", result: null }] };
  const s = summarizeGrades(sheet);
  assert.equal(s.tier_b.faithfulness_rate, 0.5);
  assert.equal(s.tier_b.blocking_zeros, 1);
  assert.equal(s.tier_b.core.faithfulness_rate, 0.667);
  assert.equal(s.tier_b.core.blocking_zeros, 0);
  assert.deepEqual(s.tier_b.core.missing, []);
  assert.deepEqual(s.tier_b.red_additions, ["ff14-013"]);
  assert.equal(s.tier_b.per_case["ff14-001"].faithfulness_rate, 1);
  assert.deepEqual(s.tier_b.provision_misstated_by_key, { "IRPR 179(b)": 1 });
  assert.deepEqual({ ...s.hand_checks, failed: undefined }, { rows: 3, pass: 1, fail: 1, ungraded: 1, failed: undefined });
  assert.deepEqual(s.hand_checks.failed, [{ case_id: "ff14-002", text: "no age" }]);
});

test("the golden set pins its digest, and a run records the whole case, so an edited expected block cannot pass as v1", () => {
  assert.deepEqual(goldenDigestProblems(golden), []);
  const c = G("ff14-004");
  const edited = structuredClone(c);
  edited.expected.support["IRPR 216(1)(e)"] = "partly_supported";
  assert.equal(inputsSha256(edited), inputsSha256(c));
  assert.notEqual(caseSha256(edited), caseSha256(c));
  const set = golden.map((x) => (x.id === c.id ? edited : x));
  assert.notEqual(goldenDigest(set), goldenDigest(golden));
  assert.match(goldenDigestProblems(set).join(), /does not hash to its pinned digest/);
  assert.match(goldenDigestProblems(golden.slice(1)).join(), /holds 29 case/);
  assert.deepEqual(chainInputs(edited), chainInputs(c));
});

test("a socket dropped while idle (as during a Claude call) leaves the process running and the next case fatal", async () => {
  const net = await import("node:net");
  const pg = createRequire(path.join(LAW_LOAD, "package.json"))("pg");
  // A minimal local Postgres stand-in: startup, one empty query, then FATAL 57P01 and a closed socket while the client idles.
  const msg = (type, body) => {
    const b = Buffer.alloc(5 + body.length);
    b.write(type, 0);
    b.writeInt32BE(4 + body.length, 1);
    body.copy(b, 5);
    return b;
  };
  const ready = msg("Z", Buffer.from("I"));
  const server = net.createServer((sock) => {
    let started = false;
    sock.on("error", () => {});
    sock.on("data", (d) => {
      if (!started) {
        started = true;
        sock.write(Buffer.concat([msg("R", Buffer.from([0, 0, 0, 0])), ready]));
      } else if (d[0] === 0x51) {
        sock.write(Buffer.concat([msg("I", Buffer.alloc(0)), ready]));
        setTimeout(() => {
          sock.write(msg("E", Buffer.from("SFATAL\0C57P01\0Mterminating connection due to administrator command\0\0")));
          setTimeout(() => sock.destroy(), 20);
        }, 50);
      }
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  try {
    const client = watchClient(new pg.Client({ host: "127.0.0.1", port: server.address().port, user: "x", database: "x", password: "x", ssl: false }));
    await client.connect();
    await client.query("");
    await new Promise((r) => setTimeout(r, 300));
    assert.ok(client.lost, "the drop was recorded on the client");
    const r = await runCase({ c: G("ff14-001"), runId: "t", versions, db: client, claude: fakeClaude([]), budget: makeBudget(1), outlineSchema });
    assert.equal(r.fatal, true);
    assert.match(r.error, /connection was lost/);
    await client.end();
  } finally {
    await new Promise((r) => server.close(r));
  }
});
