// X-32 harness suite (scripts/ff14/x32.mjs): offline, no network, no live database. Holds the @1 path unchanged (the
// committed full run's ff14-001 requests rebuild to their recorded hashes, parseArgs without the new flags is what it
// was), the JavaScript ranker to the Python reference through the committed overlay, the exemplar request, the X
// metrics, @08 reaching the validator on PGlite, the NO_PICK sentinel against both readings of Make's map, the terms
// rule against the validator's own line split, A2 running only with an exemplar, the run provenance, and the database
// ranker inside Tx S and Tx V (ff13.rank_exemplars of migration 20261116000008, on its own PGlite instance).

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { after, before, test } from "node:test";
import { ROOT, loadRegistry, versionsToRun } from "./chain.mjs";
import { committedRows, committedX32Rows, ground, selectExemplarDb, validate, validateWithTerms } from "./db.mjs";
import { chainInputs, loadGolden, recordId } from "./golden.mjs";
import { Refusal, buildRequest, requestSha256 } from "./iml.mjs";
import { pgliteClient } from "./pglite.mjs";
import { parseArgs } from "./run.mjs";
import {
  NO_PICK, X32_SKELETON_EXPR, aggregatedRows, armsCheck, armsLoop, armsRunRecord, buildDraftX32, codeOk, draftTemplateProblems,
  exemplarOf, loadSeeds, loadVocab, longestSharedRun, mapFirst, ngramShare, overlayProblems, parseArms, rankReference, rankKey,
  runArmsCase, selectExemplar, summarizeArms, termCount, termsStatusOk, weakKeys, wholeWordHits, x32Metrics, x5Metric,
} from "./x32.mjs";

const registry = loadRegistry();
const versions = versionsToRun(registry, null);
const { seeds, problems: seedProblems } = loadSeeds();
const vocab = loadVocab();
const overlay = JSON.parse(fs.readFileSync(path.join(ROOT, "eval", "x32", "overlay", "v1.json"), "utf8"));
const X32_TEMPLATE = (() => {
  const t = JSON.parse(JSON.stringify(versions.draft.template));
  t.messages[0].content += `\n\n<exemplar>\n{{${X32_SKELETON_EXPR}}}\n</exemplar>`;
  return t;
})();
const CTX = { inputs: { name: "ZZ-TEST Ada Lovelace", rcic_of_record: "ZZ-TEST RCIC Pat Doe", visa_code: "TR-VISIT",
  document_code: "SUBMISSION-LETTER", case_facts: "Line one." }, provisions: "[]", outline: { content: [{ type: "text", text: "{}" }] } };

let db;
before(async () => {
  db = await pgliteClient();
});
after(async () => {
  await db?.end();
});

test("the @1 requests of the committed full run rebuild byte for byte (no --arms path touched)", () => {
  // The first full run, committed in 085aac5, so the guard holds on every clean checkout. A missing file fails.
  const file = path.join(ROOT, "eval", "ff14", "runs", "20261116T195149Z", "cases", "ff14-001.json");
  assert.ok(fs.existsSync(file), "the committed run folder eval/ff14/runs/20261116T195149Z is missing");
  const rec = JSON.parse(fs.readFileSync(file, "utf8"));
  const c = loadGolden().find((x) => x.id === "ff14-001");
  const ob = buildRequest(versions.outline.template, { inputs: chainInputs(c), provisions: rec.grounding.provisions });
  assert.equal(requestSha256(ob), rec.outline.request_sha256);
  assert.ok(rec.outline.request_sha256.startsWith("683ee954"));
  const db2 = buildRequest(versions.draft.template, { inputs: chainInputs(c), provisions: rec.grounding.provisions,
    outline: { content: [{ type: "text", text: rec.outline.text }] } });
  assert.equal(requestSha256(db2), rec.draft.request_sha256);
  assert.ok(rec.draft.request_sha256.startsWith("056e1e86"));
});

test("parseArgs without the new flags is unchanged, and the new flags refuse misuse", () => {
  assert.deepEqual(Object.keys(parseArgs(["--run"])).sort(), ["cases", "db", "maxUsd", "mode", "show", "versions"]);
  const o = parseArgs(["--check", "--arms", "A0,A1,A2", "--exemplars", "eval/x32/overlay/v1.json", "--versions", "draft@2"]);
  assert.equal(o.arms, "A0,A1,A2");
  assert.throws(() => parseArgs(["--run", "--exemplars", "x.json"]), /--exemplars goes with --arms/);
  assert.throws(() => parseArgs(["--preflight", "--arms", "A0"]), /--arms/);
  assert.throws(() => parseArgs(["--run", "--arms", "A0", "--db", "pglite"]), /--arms/);
  assert.deepEqual(parseArms("A2,A0"), ["A0", "A2"]);
  assert.throws(() => parseArms("A3"), Refusal);
  assert.throws(() => parseArms("A1,A1"), Refusal);
});

test("the seeds match their digests and the JavaScript ranker matches the Python overlay", () => {
  assert.deepEqual(seedProblems, []);
  assert.deepEqual(overlayProblems(overlay, loadGolden(), seeds, vocab), []);
});

test("rankReference: weak keys score, ties break by code, production refuses any TEST mark", () => {
  const ids = overlay.seed_record_ids;
  // The two TR-WP-EMP seeds take opposite routes, and each one's tag addresses the route it leaves out.
  const v1 = seeds.find((s) => s.code === "ZZ-TEST-EX-TR-WP-EMP-001");
  const v2 = seeds.find((s) => s.code === "ZZ-TEST-EX-TR-WP-EMP-002");
  const lines = [rankKey(ids[v1.code], v1), rankKey(ids[v2.code], v2)].join("\n");
  const listed = new Set(Object.values(ids));
  assert.equal(rankReference(lines, ["IRPR 200(1)(c)(iii)"], "TR-WP-EMP", "SUBMISSION-LETTER", vocab, listed).exemplar_code, v2.code);
  assert.equal(rankReference(lines, ["IRPR 200(1)(c)(ii.1)"], "TR-WP-EMP", "SUBMISSION-LETTER", vocab, listed).exemplar_code, v1.code);
  assert.equal(rankReference(lines, [], "TR-WP-EMP", "SUBMISSION-LETTER", vocab, listed).exemplar_code, v1.code);
  const none = rankReference(lines, [], "TR-WP-EMP", "SUBMISSION-LETTER", vocab, new Set());
  assert.deepEqual([none.exemplar_code, none.exemplar_record_id], ["", NO_PICK]);
  const prod = rankReference(lines.replace(/\|TEST\|/g, "|Active|"), [], "TR-WP-EMP", "SUBMISSION-LETTER", vocab, new Set(), "production");
  assert.ok(prod.flags.includes("test_seed_in_production"));
  assert.ok(rankReference(lines, [], "HC-PR", "SUBMISSION-LETTER", vocab, listed).flags.includes("excluded_cell"));
});

test("weakKeys reads the outline's weak grounds and selects nothing for a NO DRAFT outline", () => {
  const o = { inputs_contain_instructions: false, facts_sufficient: true, grounds: [
    { provision_key: "IRPR 179(b)", support: "supported" }, { provision_key: "IRPR 183(2)", support: "partly_supported" },
    { provision_key: "IRPR 999", support: "not_supported" }] };
  assert.deepEqual(weakKeys(JSON.stringify(o), ["IRPR 179(b)", "IRPR 183(2)"]).keys, ["IRPR 183(2)"]);
  assert.equal(weakKeys(JSON.stringify({ ...o, facts_sufficient: false }), []).keys, null);
  assert.equal(weakKeys("not json", []).flag, "outline_unreadable");
  const lmia = { inputs_contain_instructions: false, facts_sufficient: true, grounds: [
    { provision_key: "IRPR 200(1)(c)(ii.1)", support: "supported" }, { provision_key: "IRPR 200(1)(c)(iii)", support: "not_supported" }] };
  const sel = selectExemplar({ outlineText: JSON.stringify(lmia), grounding: { provision_keys: ["IRPR 200(1)(c)(iii)", "IRPR 200(1)(c)(ii.1)"] },
    visa: "TR-WP-EMP", doc: "SUBMISSION-LETTER", seeds, vocab, ids: overlay.seed_record_ids });
  assert.equal(sel.seed.code, "ZZ-TEST-EX-TR-WP-EMP-002");
  // The supported keys the grounding provided feed the conflicts (decided 2026-11-19).
  assert.deepEqual(weakKeys(JSON.stringify(o), ["IRPR 179(b)", "IRPR 183(2)"]).strong, ["IRPR 179(b)"]);
  assert.deepEqual(weakKeys(JSON.stringify(o), ["IRPR 183(2)"]).strong, []);
  // ff14-018: a spouse in Canada with IRPR 124 supported and nothing weak gets the in-Canada seed, not the lower code.
  const inland = { inputs_contain_instructions: false, facts_sufficient: true, grounds: [{ provision_key: "IRPR 124", support: "supported" }] };
  const sp = selectExemplar({ outlineText: JSON.stringify(inland), grounding: { provision_keys: ["IRPR 124", "IRPR 117(1)(a)"] },
    visa: "FAM-SPOUSE", doc: "SUBMISSION-LETTER", seeds, vocab, ids: overlay.seed_record_ids });
  assert.deepEqual([sp.seed.code, sp.result.score, sp.result.conflicts, sp.supported_keys], ["ZZ-TEST-EX-FAM-SPOUSE-002", 0, 0, ["IRPR 124"]]);
  const notProvided = selectExemplar({ outlineText: JSON.stringify(inland), grounding: { provision_keys: ["IRPR 117(1)(a)"] },
    visa: "FAM-SPOUSE", doc: "SUBMISSION-LETTER", seeds, vocab, ids: overlay.seed_record_ids });
  assert.equal(notProvided.seed.code, "ZZ-TEST-EX-FAM-SPOUSE-001");   // a key the grounding did not provide is no conflict
});

test("buildDraftX32: the empty exemplar, a skeleton escaped like Make, and a template with no block refused", () => {
  const empty = buildDraftX32(X32_TEMPLATE, CTX, "");
  const at1 = buildRequest(versions.draft.template, CTX);
  assert.equal(empty.messages[0].content, `${at1.messages[0].content}\n\n<exemplar>\n\n</exemplar>`);
  assert.equal(empty.system, at1.system);
  const full = buildDraftX32(X32_TEMPLATE, CTX, "Skeleton line < with a sign.");
  assert.ok(full.messages[0].content.endsWith("<exemplar>\nSkeleton line  less than  with a sign.\n</exemplar>"));
  assert.ok(!full.messages[0].content.includes("X32SENTINEL"));
  assert.ok(draftTemplateProblems(versions.draft.template).length > 0);
  assert.throws(() => buildDraftX32(versions.draft.template, CTX, ""), Refusal);
  assert.throws(() => buildDraftX32(X32_TEMPLATE, CTX, null), Refusal);
});

test("X metrics: leak and shadow hits, the longest shared run, 8-gram share and copied placeholders", () => {
  const seed = seeds.find((s) => s.code === "ZZ-TEST-EX-TR-VISIT-001");
  assert.deepEqual(wholeWordHits("Worked at the harrowgate ceramics guild.", seed.terms), ["Harrowgate Ceramics Guild"]);
  const copied = "The position is permanent and salaried, the applicant has held it since";
  assert.equal(longestSharedRun(copied, seed.skeleton), 12);
  assert.ok(ngramShare(copied, seed.skeleton) > 0.5);
  assert.equal(longestSharedRun("Zebra quantum lattice.", seed.skeleton), 0);
  // The fixed first line is not content: its whole run is not found, only single common words of it.
  assert.ok(longestSharedRun("Not for submission until the RCIC of record has reviewed and signed it.", seed.skeleton) < 3);
  const m = Object.fromEntries(x32Metrics("A2", `A [CITY] stay near the kiln restoration apprenticeship. ${copied}`, seed,
    { detail: { hard_fails: [{ check: "exemplar_leak" }] } }).map((x) => [x.id, x]));
  assert.equal(m.X1.pass, false);
  assert.equal(m.X2.value, 1);
  assert.equal(m.X4.value, 1);
  assert.deepEqual(x32Metrics("A1", "Clean.", null, null).map((x) => x.id), ["X4"]);
});

test("validateWithTerms sends @08 to the validator, validate keeps it empty", async () => {
  const TX = { record: "recFF14ZZTEST9101", exec: "c".repeat(32), visa: "TR-VISIT", doc: "SUBMISSION-LETTER", flag: true, listed: true };
  const STAMPS = { model_requested: "claude-opus-5-5", model_served: "claude-opus-5-5", stop_reason: "end_turn",
    prompt_version: "drafting-chain.submission-letter-draft@1", prompt_sha256: "b".repeat(64), input_tokens: "1", output_tokens: "1",
    request_id: "msg_x32" };
  const g = await ground(db, TX);
  const v = { ...STAMPS, draft: "A short draft for ZZ-TEST Unit Case that names Harrowgate Ceramics Guild.", name: "ZZ-TEST Unit Case", case_facts: "Facts." };
  const leak = await validateWithTerms(db, TX, g, v, "Harrowgate Ceramics Guild\nVelmora Valley");
  const plain = await validate(db, TX, g, v);
  const checks = (r) => (r.detail.hard_fails || []).map((h) => h.check);
  assert.ok(checks(leak).includes("exemplar_leak"));
  assert.ok(!checks(plain).includes("exemplar_leak"));
});

test("armsCheck drops only the exemplar-mapping problems of an unbound X-32 draft and keeps every other one", () => {
  const cases = loadGolden();
  const x32 = { ...versions.draft, template: X32_TEMPLATE, stamp: "drafting-chain.submission-letter-draft@2", bound: false };
  const chk = { registry, cases, versions: { ...versions, draft: x32 },
    problems: [`ff14-001: unknown mapping {{${X32_SKELETON_EXPR}}}, add it to MAPPINGS in a reviewed commit with a test`,
      "module 4 arguments differ from GROUND_ARGS"] };
  const opts = { arms: "A0,A1,A2", exemplars: "eval/x32/overlay/v1.json" };
  const a = armsCheck(chk, opts);
  assert.deepEqual(a.problems, ["module 4 arguments differ from GROUND_ARGS"]);
  assert.equal(a.versions.bound_draft.stamp, "drafting-chain.submission-letter-draft@1");
  assert.ok(armsCheck({ ...chk, versions }, opts).problems.some((p) => p.includes("--versions draft@N")));
  assert.ok(armsCheck(chk, { arms: "A0,A1" }).problems.some((p) => p.includes("--exemplars")));
});

test("codes: the ranker drops a code that is not (ZZ-TEST-)EX-<its visa code>-NNN as candidate_malformed", () => {
  const ok = "recAAAAAAAAAAAAAA|EX-TR-VISIT-001|Active|TR-VISIT|SUBMISSION-LETTER|1|home-ties-thin";
  for (const code of ["EX-TR-VISIT-Okafor", "Okafor family, Moncton", "EX-TR-VISIT-OKAFOR-001", "EX-TR-STUDY-001", "EX-TR-VISIT-01",
    "ZZ-TEST-EX-TR-VISIT-1234"]) {
    const r = rankReference(ok.replace("EX-TR-VISIT-001", code), [], "TR-VISIT", "SUBMISSION-LETTER", vocab, new Set(), "production");
    assert.deepEqual([r.exemplar_code, r.exemplar_record_id, r.flags.includes("candidate_malformed")], ["", NO_PICK, true], code);
  }
  assert.equal(rankReference(ok, [], "TR-VISIT", "SUBMISSION-LETTER", vocab, new Set(), "production").exemplar_code, "EX-TR-VISIT-001");
  assert.ok(codeOk("ZZ-TEST-EX-TR-WP-EMP-007", "TR-WP-EMP"));
  assert.ok(!codeOk("EX-TR-WP-EMP-007", "TR-WP"));
});

test("NO_PICK: with candidates in the cell and no pick, an empty value would hand the first skeleton to the drafter under one reading of map", () => {
  const ids = overlay.seed_record_ids;
  const agg = aggregatedRows(seeds, ids, "TR-VISIT", "SUBMISSION-LETTER");
  assert.equal(agg.length, 2);
  // The two readings of an empty filter value disagree: that is the leak the sentinel closes.
  assert.equal(mapFirst(agg, "skeleton", "", false), "");
  assert.equal(mapFirst(agg, "skeleton", "", true), agg[0].skeleton);
  assert.throws(() => exemplarOf(agg, ""), Refusal);
  assert.deepEqual(exemplarOf(agg, NO_PICK), { skeleton: "", terms: "" });
  const v2 = seeds.find((s) => s.code === "ZZ-TEST-EX-TR-VISIT-002");
  assert.deepEqual(exemplarOf(agg, ids[v2.code]), { skeleton: v2.skeleton, terms: v2.terms.join("\n") });
  // An empty cell: the search's one empty bundle. Both readings give nothing, with or without the sentinel.
  const empty = aggregatedRows(seeds, ids, "HC-PR", "SUBMISSION-LETTER");   // a cell with no seed (excluded)
  assert.deepEqual(exemplarOf(empty, NO_PICK), { skeleton: "", terms: "" });
  // Every no-pick outcome of the ranker is the sentinel: NO DRAFT, unreadable outline, excluded cell, production refusal.
  const lines = agg.map((x) => x.rank_key).join("\n");
  for (const r of [
    selectExemplar({ outlineText: JSON.stringify({ facts_sufficient: false, inputs_contain_instructions: false, grounds: [] }),
      grounding: { provision_keys: [] }, visa: "TR-VISIT", doc: "SUBMISSION-LETTER", seeds, vocab, ids }).result,
    selectExemplar({ outlineText: "not json", grounding: { provision_keys: [] }, visa: "TR-VISIT", doc: "SUBMISSION-LETTER", seeds, vocab, ids }).result,
    rankReference(lines, [], "HC-PR", "SUBMISSION-LETTER", vocab, new Set(Object.values(ids))),
    rankReference(lines, [], "TR-VISIT", "SUBMISSION-LETTER", vocab, new Set(Object.values(ids)), "production"),
  ]) {
    assert.equal(r.exemplar_record_id, NO_PICK);
    assert.deepEqual(exemplarOf(agg, r.exemplar_record_id), { skeleton: "", terms: "" });
  }
});

test("the terms rule of the Status formula makes Term Count equal the validator's own count of @08 lines (PGlite)", async () => {
  const mig = fs.readFileSync(path.join(ROOT, "supabase", "migrations", "20261116000007_ff13_2_sections_vocabulary.sql"), "utf8");
  const SPLIT = String.raw`regexp_split_to_table(v_terms, '\r\n|[\n\v\f\r\u0085\u2028\u2029]')`;
  const KEEP = "btrim(normalize(translate(ff13._fold(t), '_', ' '), NFC))";
  assert.ok(mig.includes(SPLIT) && mig.includes(KEEP), "the validator's term split moved: update this test with it");
  const sql = String.raw`SELECT count(*)::int AS n FROM regexp_split_to_table($1, '\r\n|[\n\v\f\r\u0085\u2028\u2029]') t
    WHERE btrim(normalize(translate(ff13._fold(t), '_', ' '), NFC)) <> ''`;
  const count = async (text) => (await db.query(sql, [text])).rows[0].n;
  // The findings' cases: each would make Term Count differ from the validator, and each is refused.
  for (const bad of ["Moncton\nwelding\n", "Velmora Valley\n \nHarrowgate Ceramics Guild", "a\rb", "a\u2028b", "a\n\u00a0\nb",
    "\nMoncton", "a\n_\nb", "a\tb", "a\u000bb", "a\fb", "a\u0085b", "a\u2029b", "a\n\u3000\nb", ""]) {
    assert.equal(termsStatusOk(bad), false, JSON.stringify(bad));
  }
  const parts = ["Moncton", "welding", "", " ", "\u00a0", "_", "\t", "\r", "\u2028", "a b", "\u200b", "x_y", "\u3000"];
  let accepted = 0;
  for (const a of parts) {
    for (const b of parts) {
      for (const text of [a, `${a}\n${b}`, `${a}\n${b}\n`, `${a}\n\n${b}`, `\n${a}`, `${a}\r\n${b}`]) {
        if (!termsStatusOk(text)) continue;
        accepted++;
        assert.equal(termCount(text), await count(text), JSON.stringify(text));
      }
    }
  }
  assert.ok(accepted > 20);
  for (const s of seeds) assert.ok(termsStatusOk(s.terms.join("\n")) && termCount(s.terms.join("\n")) === s.terms.length, s.code);
});

const FAKE = (id) => ({ id, model: "claude-opus-5-5", stop_reason: "end_turn", usage: { input_tokens: 10, output_tokens: 10 } });
function mockStage(outlineObj) {
  const calls = [];
  const fn = async (_claude, body) => {
    calls.push(body);
    const text = calls.length === 1 ? JSON.stringify(outlineObj) : "Dear Officer,\nZZ-TEST draft.";
    return { msg: { ...FAKE(`msg_${calls.length}`), content: [{ type: "text", text }] }, latency_ms: 1, attempts: [] };
  };
  return { fn, calls };
}
const OUTLINE = { facts_sufficient: true, inputs_contain_instructions: false, grounds: [] };
const ARMS_VERSIONS = { outline: versions.outline, bound_draft: versions.draft,
  draft: { ...versions.draft, template: X32_TEMPLATE, stamp: "drafting-chain.submission-letter-draft@2", bound: false } };

test("A2 runs and is paid for only when an exemplar was selected, and the A2 summary is paired with A1 and A0", async () => {
  const cases = loadGolden();
  const results = [];
  const budget = { add() {}, spent: 0 };
  const outlineSchema = JSON.parse(versions.outline.template.outputFormat.schema);
  // ff14-022 is HC-PR: the database ranker grounds it and selects nothing (excluded_cell), so A2 is not run.
  for (const [id, want] of [["ff14-001", 4], ["ff14-022", 3]]) {
    const c = cases.find((k) => k.id === id);
    const m = mockStage(OUTLINE);
    const r = await runArmsCase({ c, runId: "x32test", arms: ["A0", "A1", "A2"], versions: ARMS_VERSIONS, db, claude: null, budget,
      outlineSchema, seeds, vocab, ids: overlay.seed_record_ids, callStage: m.fn });
    assert.equal(r.error, null, id);
    assert.equal(m.calls.length, want, `${id}: the outline and one draft per applicable arm`);
    assert.ok(r.inputs_sha256 && r.case_sha256);
    results.push(r);
  }
  const [withSeed, without] = results;
  assert.equal(withSeed.arms.A2.exemplar_code, overlay.cases["ff14-001"].pick);
  assert.notEqual(withSeed.arms.A2.draft.request_sha256, withSeed.arms.A1.draft.request_sha256);
  assert.equal(without.arms.A2.not_applicable, true);
  assert.equal(without.arms.A2.draft, undefined);
  assert.equal(without.selection.exemplar_record_id, NO_PICK);
  // The X-32 migration exists, so ff13.rank_exemplars picked in Tx S and again in Tx V: X5 is measured.
  assert.ok(withSeed.selection.ranker.startsWith("ff13.rank_exemplars"), withSeed.selection.ranker);
  assert.equal(withSeed.selection.exemplar_code, withSeed.selection.reference_pick);
  const x5 = withSeed.arms.A2.metrics.find((x) => x.id === "X5");
  assert.equal(x5.pass, true);
  assert.ok(!withSeed.arms.A2.validation.detail.hard_fails.some((h) => h.check.startsWith("exemplar_terms_")));
  assert.ok(without.arms.A2.reason.includes("excluded_cell"), without.arms.A2.reason);
  const s = summarizeArms(results, ["A0", "A1", "A2"]);
  assert.equal(s.A2.n, 1);
  assert.equal(s.A1.n, 2);
  assert.deepEqual(s.paired.cases, ["ff14-001"]);
  assert.deepEqual([s.paired.A0.n, s.paired.A1.n, s.paired.A2.n], [1, 1, 1]);
  assert.deepEqual(s.A2_not_applicable.map((x) => x.case_id), ["ff14-022"]);
});

test("armsLoop stops when the validator version changes between arms or cases, and on a stop request", async () => {
  const mk = (id, vv) => ({ case_id: id, arms: Object.fromEntries(vv.map((v, i) => [`A${i}`, { validation: { detail: { validator_version: v } } }])) });
  const cases = [{ id: "c1" }, { id: "c2" }, { id: "c3" }];
  const same = await armsLoop({ cases, runCase: async (c) => mk(c.id, ["V1", "V1"]) });
  assert.deepEqual([same.results.length, same.validatorVersion, same.stopped], [3, "V1", null]);
  const moved = await armsLoop({ cases, runCase: async (c) => mk(c.id, c.id === "c2" ? ["V1", "V2"] : ["V1"]) });
  assert.equal(moved.results.length, 2);
  assert.match(moved.stopped, /c2: validator version changed mid-run \(V1 then V2/);
  const stop = { requested: false };
  const halted = await armsLoop({ cases, stop, runCase: async (c) => mk(c.id, ["V1"]), onCase: () => { stop.requested = true; } });
  assert.deepEqual([halted.results.length, halted.stopped], [1, "stop requested (Ctrl-C) before the next case"]);
});

test("armsRunRecord carries the F-F14 provenance", () => {
  const a = { arms: ["A0", "A1", "A2"], versions: ARMS_VERSIONS, seed_digests: [{ file: "x.json", sha256: "0".repeat(64) }] };
  const chk = { versions, cases: [{ id: "ff14-001" }], snapshot: { version: 8 }, digest: "d".repeat(64) };
  const run = armsRunRecord({ runId: "r", started: "s", a, chk, opts: { exemplars: "eval/x32/overlay/v1.json", maxUsd: 20 },
    results: [{ case_id: "ff14-001", selection: { ranker: "reference" } }], validatorVersion: "F-F13.2+F-F10", stopped: null,
    law: [{ instrument: "IRPA" }], committed: { "ref.test_records": 0 }, spent: 1.5, exit: 0, git: { head: "abc", clean: true } });
  for (const k of ["git_head", "git_clean", "sdk", "snapshot_version", "validator_version", "validator_version_expected", "law_sources",
    "golden_version", "golden_digest", "stopped_early", "seeds", "cases_run", "pricing"]) assert.ok(k in run, k);
  assert.equal(run.versions.x32_draft.template_sha256, versions.draft.template_sha256);
  assert.ok(run.sdk["@anthropic-ai/sdk"] && run.sdk.pg);
});

test("the database ranker runs in Tx S and again in Tx V beside the grounding, and nothing persists (ff13.rank_exemplars on its own PGlite)", async () => {
  const db2 = await pgliteClient();
  try {
    const c = loadGolden().find((k) => k.id === "ff14-001");
    const tx = { record: recordId(c), exec: "e".repeat(32), visa: "TR-VISIT", doc: "SUBMISSION-LETTER", flag: true, listed: true };
    const ids = overlay.seed_record_ids;
    const agg = aggregatedRows(seeds, ids, "TR-VISIT", "SUBMISSION-LETTER");
    const rank = { outline: JSON.stringify(OUTLINE), candidates: agg.map((x) => x.rank_key).join("\n"),
      seeds: agg.map((x) => ({ id: x.id, code: x.rank_key.split("|")[1] })) };
    // The migration's function: an outline with no weak ground scores every seed 0, so the lowest code is picked.
    const pick = await selectExemplarDb(db2, tx, rank);
    assert.deepEqual([pick.exemplar_record_id, pick.exemplar_code, pick.score, pick.flags], [agg[0].id, agg[0].rank_key.split("|")[1], 0, ["test_mode"]]);
    assert.equal(pick.candidate_count, agg.length);
    // Without the harness listing in its own transaction the same lines select nothing: the seeds are listed only in Tx S.
    const unlisted = await selectExemplarDb(db2, tx, { ...rank, seeds: [] });
    assert.equal(unlisted.exemplar_record_id, NO_PICK);
    const g = await ground(db2, tx);
    const v = { draft: "A short draft for ZZ-TEST Unit Case.", name: "ZZ-TEST Unit Case", case_facts: "Facts.", model_requested: "claude-opus-5-5",
      model_served: "claude-opus-5-5", stop_reason: "end_turn", prompt_version: "drafting-chain.submission-letter-draft@2",
      prompt_sha256: "b".repeat(64), input_tokens: "1", output_tokens: "1", request_id: "msg_x32" };
    const val = await validateWithTerms(db2, tx, g, v, agg[0].terms, rank);
    assert.equal(val.void, false);
    assert.equal(val.selection.exemplar_record_id, pick.exemplar_record_id);
    assert.equal(val.detail.exemplar_code, pick.exemplar_code);
    assert.ok(!val.detail.hard_fails.some((h) => h.check.startsWith("exemplar_terms_")), val.review_note);
    assert.equal(x5Metric(pick, val).pass, true);
    assert.equal(x5Metric(pick, { selection: { exemplar_record_id: NO_PICK } }).pass, false);
    // @08 that is not the picked seed's term list fails the cross-check.
    const wrong = await validateWithTerms(db2, tx, g, v, agg[0].terms.split("\n").slice(1).join("\n"), rank);
    assert.ok(wrong.detail.hard_fails.some((h) => h.check === "exemplar_terms_mismatch"), wrong.review_note);
    const committed = { ...(await committedRows(db2, [tx.record], [tx.exec])), ...(await committedX32Rows(db2, [tx.record], [tx.exec], Object.values(ids))) };
    assert.deepEqual(Object.keys(committed).sort(), ["ff13.groundings", "ff13.selections", "ff13.validations", "ref.exemplar_test_seeds", "ref.test_records"]);
    assert.deepEqual(Object.values(committed).filter((n) => n > 0), []);
  } finally {
    await db2.end();
  }
});
