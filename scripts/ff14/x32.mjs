// F-F14 support for X-32, the exemplar layer of Module F (specs/X-32-exemplars.md section 10). New code paths only: the
// runner reaches this file only with --arms, so every run without it is the @1 run it was before (a test rebuilds the
// smoke run's ff14-001 requests to their recorded hashes).
//
//   node scripts/ff14/run.mjs --check --arms A0,A1,A2 --exemplars eval/x32/overlay/v1.json --versions draft@2
//   node scripts/ff14/run.mjs --dry-run --arms A0,A1,A2 --exemplars eval/x32/overlay/v1.json --versions draft@2 [--cases a,b]
//   node scripts/ff14/run.mjs --run --arms A0,A1,A2 --exemplars eval/x32/overlay/v1.json --versions draft@2 --max-usd 20
//
// Arms, per paid case, on one outline: A0 the bound draft version (draft@1) with no exemplar, A1 the X-32 draft version
// (named by --versions) with an empty exemplar and an empty @08, A2 the X-32 version with the exemplar the ranker picks
// from this run's own outline and @08 the seed's terms. Runs go to eval/x32/runs/<UTC timestamp>/, never eval/ff14/runs.
//
// The ranker. Each case first asks the database (selectExemplarDb, Tx S: list the record, ground, list the harness seed
// IDs, ff13.rank_exemplars, ROLLBACK). Until the X-32 migration exists that returns null and the pick comes from
// rankReference, the JavaScript port of the reference ranker of scripts/x32_seeds.py (steps 4 to 7 of section 3, test
// mode), which --check holds to the committed overlay. Tx V of arm A2 calls ff13.rank_exemplars again before
// ff13.validate_draft, because the validator's @08 cross-check reads the selection row of the same record and execution
// and Tx S has rolled back by then. X5 compares the two database picks. The skeleton and @08 come from the aggregated
// candidate rows through exemplarOf, which evaluates the Make expression under both readings of map with an empty filter
// value and refuses when they differ, so the NO_PICK sentinel is what keeps a refused exemplar out of the draft.

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { sha256Hex } from "../law_load/load.mjs";
import { GROUNDING_MODULE, PRICING, ROOT, SCENARIO_ID, STAGES, operandValues, predictRoutes, registeredVersion, usageUsd } from "./chain.mjs";
import {
  committedRows, committedX32Rows, ground, lawSources, leftoverRecords, liveClient, lostError, pgVersion, readSecrets, selectExemplarDb,
  validate, validateWithTerms,
} from "./db.mjs";
import { GOLDEN_VERSION, caseSha256, chainInputs, execId, inputsSha256, isPaid, recordId } from "./golden.mjs";
import { caseMetrics, summarize } from "./grade.mjs";
import { Fatal, Refusal, buildRequest, expressionsOf, firstText, requestSha256 } from "./iml.mjs";

export const ARMS = ["A0", "A1", "A2"];
// The aggregator and the ranker of the push numbering (scripts/x32_candidate.py PUSH_ID_SEQUENCE 207, so 209 and 210), as
// draft@2 names them once it is registered from that candidate. A test holds the two files to the same IDs.
export const X32_AGGREGATOR = 209;
export const X32_RANKER = 210;
export const X32_SKELETON_EXPR = `replace(first(map(${X32_AGGREGATOR}.array; "skeleton"; "id"; ${X32_RANKER}.exemplar_record_id)); "/</g"; " less than ")`;
export const X32_TERMS_EXPR = `{{first(map(${X32_AGGREGATOR}.array; "terms"; "id"; ${X32_RANKER}.exemplar_record_id))}}`;
export const SEEDS_DIR = path.join(ROOT, "eval", "x32", "seeds", "v1");
export const SEED_MANIFEST = path.join(ROOT, "eval", "x32", "seeds", "manifest.json");
export const VOCAB = path.join(ROOT, "ref", "exemplar_tags.json");
export const RUNS = path.join(ROOT, "eval", "x32", "runs");
const EXCLUDED = ["REF-CLAIM", "REF-RESETTLE", "HC-PR"];
const DOC = "SUBMISSION-LETTER";
// A bracketed upper-case token, the seeds' TEST mark [ZZ-TEST SEED] included (X4 counts a copied one).
const PLACEHOLDER = /\[[A-Z][A-Z -]*[A-Z]\]/g;
const HERE = path.dirname(fileURLToPath(import.meta.url));
// The X-32 migration replaces the validator (20261116000008), and the arms run after it is applied, since A2 needs the
// @08 cross-check against the selection row.
const EXPECTED_VALIDATOR = "F-F13.2+F-F10+X-32";
// The ranker's answer when it selects nothing (scripts/x32_seeds.py NO_PICK): never empty, so the Make expression
// first(map(<agg>.array; key; "id"; <rank>.exemplar_record_id)) filters to nothing whatever Make does with an empty value.
export const NO_PICK = "none";
const CODE = /^(ZZ-TEST-)?EX-[A-Z]+(-[A-Z]+)*-[0-9]{3}$/;
// scripts/x32_seeds.py code_ok: the code's visa part is exactly the row's visa code, so a name in capitals is not a code.
export const codeOk = (code, visa) => CODE.test(code) && /^[A-Z]+(-[A-Z]+)*$/.test(visa)
  && (code === `EX-${visa}-${code.slice(-3)}` || code === `ZZ-TEST-EX-${visa}-${code.slice(-3)}`);

// The Residual Quasi-Identifiers clauses of the Status formula and the Term Count formula (scripts/x32_seeds.py
// terms_status_ok and term_count). A test holds them, on PGlite, to the validator's own line split of @08.
const BLANK_LINE = /(^|\n)[ _\u00a0\u1680\u2000-\u200a\u202f\u205f\u3000]*(\n|$)/;
const SEPARATOR = /[\t\r\u000b\f\u0085\u2028\u2029]/;
export const termsStatusOk = (text) => typeof text === "string" && text !== "" && !BLANK_LINE.test(text) && !SEPARATOR.test(text);
export const termCount = (text) => (text === "" ? 0 : text.split("\n").length);
const FIXED_LINES = new Set(["Dear Officer,", "Introduction", "Background", "Legal framework", "Submissions", "Conclusion", "Respectfully submitted,"]);

const readJson = (file) => JSON.parse(fs.readFileSync(file, "utf8"));
const lf = (file) => fs.readFileSync(file).toString("utf8").replace(/\r\n/g, "\n");

export function parseArms(spec) {
  const arms = String(spec).split(",").map((s) => s.trim()).filter(Boolean);
  if (!arms.length || arms.some((a) => !ARMS.includes(a)) || new Set(arms).size !== arms.length) {
    throw new Refusal(`--arms takes a comma list of ${ARMS.join(", ")}, not ${spec}`);
  }
  return ARMS.filter((a) => arms.includes(a));
}

// --- Seeds, vocabulary and the overlay ------------------------------------------------------------------------------
export function loadSeeds(dir = SEEDS_DIR, manifestFile = SEED_MANIFEST) {
  const problems = [];
  const files = fs.readdirSync(dir).filter((f) => f.endsWith(".json")).sort();
  const want = readJson(manifestFile).seeds || [];
  const got = files.map((f) => ({ file: f, sha256: sha256Hex(lf(path.join(dir, f))) }));
  if (JSON.stringify(got) !== JSON.stringify(want)) problems.push("eval/x32/seeds/manifest.json does not match the seed files");
  const seeds = files.map((f) => {
    const s = readJson(path.join(dir, f));
    // One blank line between paragraphs, the Form rule of draft@1, as scripts/x32_seeds.py skeleton() (finding 2026-11-16).
    return { ...s, skeleton: s.skeleton_lines.join("\n\n") };
  });
  return { seeds, problems, digests: got };
}

export const loadVocab = (file = VOCAB) => readJson(file).exemplar_tags;

export function rankKey(recordIdValue, seed, status = "TEST") {
  return [recordIdValue, seed.code, status, seed.visa_code, seed.document_code, String(seed.terms.length), seed.tags.join(", ")].join("|");
}

// Steps 4 to 7 of ff13.rank_exemplars, as scripts/x32_seeds.py rank (the reference). A score of 0 still selects.
export function rankReference(lines, weakKeys, visa, doc, vocab, listed, mode = "test", strongKeys = []) {
  if (EXCLUDED.includes(visa) || doc !== DOC) return { exemplar_record_id: NO_PICK, exemplar_code: "", score: 0, conflicts: 0, flags: ["excluded_cell"] };
  const flags = [];
  const rows = [];
  for (const line of String(lines).split("\n")) {
    if (!line.trim()) continue;
    const p = line.split("|");
    if (p.length !== 7 || !/^rec[A-Za-z0-9]{14}$/.test(p[0].trim()) || !codeOk(p[1].trim(), p[3].trim()) || !/^[0-9]{1,9}$/.test(p[5].trim())) {
      flags.push("candidate_malformed");
      continue;
    }
    rows.push({ id: p[0].trim(), code: p[1].trim(), status: p[2].trim(), visa: p[3].trim(), doc: p[4].trim(), terms: Number(p[5].trim()),
      tags: p[6].split(",").map((t) => t.trim()).filter(Boolean) });
  }
  if (rows.length + flags.filter((f) => f === "candidate_malformed").length >= 100) flags.push("candidates_truncated");
  const eligible = [];
  for (const r of rows) {
    if (r.visa !== visa || r.doc !== doc) {
      flags.push("cross_cell_candidate");
      continue;
    }
    if (r.terms < 1) continue;
    const testMark = r.status !== "Active" || r.code.startsWith("ZZ-TEST-") || listed.has(r.id);
    if (mode === "production") {
      if (testMark) return { exemplar_record_id: NO_PICK, exemplar_code: "", score: 0, conflicts: 0, flags: [...flags, "test_seed_in_production"] };
      eligible.push(r);
    } else if (r.status === "TEST" && r.code.startsWith("ZZ-TEST-") && listed.has(r.id)) {
      eligible.push(r);
    }
  }
  const addresses = new Map();
  for (const v of vocab) {
    if (v.visa_code === visa && (mode === "test" || v.review_state === "reviewed")) {
      if (!addresses.has(v.tag)) addresses.set(v.tag, new Set());
      for (const k of v.addresses) addresses.get(v.tag).add(k);
    }
  }
  const weak = new Set(weakKeys);
  const strong = new Set(strongKeys);
  let best = null;
  for (const r of eligible) {
    const covered = new Set();
    const conflicts = new Set();
    for (const t of r.tags) {
      if (!addresses.has(t)) {
        flags.push("unknown_tag");
        continue;
      }
      for (const k of addresses.get(t)) {
        if (weak.has(k)) covered.add(k);
        if (strong.has(k)) conflicts.add(k);
      }
    }
    // Conflicts first (decided 2026-11-19): fewest supported keys the tags say the letter leaves out, then the score.
    const key = [conflicts.size, -covered.size, r.code, r.id];
    const less = (a, b) => { for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return a[i] < b[i]; return false; };
    if (!best || less(key, best.key)) best = { key, r, score: covered.size, conflicts: conflicts.size };
  }
  const uniq = [...new Set(flags)].sort();
  if (!best) return { exemplar_record_id: NO_PICK, exemplar_code: "", score: 0, conflicts: 0, flags: uniq };
  return { exemplar_record_id: best.r.id, exemplar_code: best.r.code, score: best.score, conflicts: best.conflicts,
    flags: [...uniq, ...(mode === "test" ? ["test_mode"] : [])] };
}

// Step 3: the weak grounds of an outline, kept only when the grounding provided the key. null means nothing is selected
// (an unreadable outline, or one whose draft is a NO DRAFT line).
export function weakKeys(outlineText, provisionKeys) {
  let o;
  try {
    o = JSON.parse(outlineText);
  } catch {
    return { keys: null, flag: "outline_unreadable" };
  }
  // Not an object, or grounds that are not a list, is unreadable (ff13.rank_exemplars step 3 reads it the same way).
  if (!o || typeof o !== "object" || Array.isArray(o) || (o.grounds !== undefined && o.grounds !== null && !Array.isArray(o.grounds))) {
    return { keys: null, flag: "outline_unreadable" };
  }
  if (o.inputs_contain_instructions === true || o.facts_sufficient === false) return { keys: null, flag: "no_draft_expected" };
  const provided = new Set(provisionKeys);
  const pick = (labels) => [...new Set((o.grounds || []).filter((g) => labels.includes(g?.support) && provided.has(g?.provision_key))
    .map((g) => g.provision_key))].sort();
  return { keys: pick(["not_supported", "partly_supported"]), strong: pick(["supported"]), flag: null };
}

// The seed record IDs are the overlay's (harness-only recX32ZZTEST IDs, never in ref/exemplar_test_seeds.json).
export function candidateLines(seeds, ids) {
  return seeds.filter((s) => ids[s.code]).map((s) => rankKey(ids[s.code], s)).join("\n");
}

export function selectExemplar({ outlineText, grounding, visa, doc, seeds, vocab, ids }) {
  const w = weakKeys(outlineText, grounding.provision_keys || []);
  if (w.keys === null) return { seed: null, weak_keys: [], supported_keys: [], result: { exemplar_record_id: NO_PICK, exemplar_code: "", score: 0, conflicts: 0, flags: [w.flag] } };
  const cell = seeds.filter((s) => s.visa_code === visa && s.document_code === doc);
  const result = rankReference(candidateLines(cell, ids), w.keys, visa, doc, vocab, new Set(Object.values(ids)), "test", w.strong);
  return { seed: seeds.find((s) => s.code === result.exemplar_code) || null, weak_keys: w.keys, supported_keys: w.strong, result };
}

// The search and the aggregator of the chain (208 and 209 in the push numbering), for the harness: the cell's seeds as the aggregator's array of
// {id, rank_key, skeleton, terms}. A search that finds nothing can emit one empty bundle (CLAUDE.md, measured
// 2026-10-30), so an empty cell gives one empty item.
export function aggregatedRows(seeds, ids, visa, doc) {
  const cell = seeds.filter((s) => s.visa_code === visa && s.document_code === doc && ids[s.code]);
  if (!cell.length) return [{ id: "", rank_key: "", skeleton: "", terms: "" }];
  return [...cell].sort((a, b) => (a.code < b.code ? -1 : 1)).map((s) => ({ id: ids[s.code], rank_key: rankKey(ids[s.code], s),
    skeleton: s.skeleton, terms: s.terms.join("\n") }));
}

// first(map(array; key; "id"; pick)) under one reading of an empty filter value: emptyIsNoFilter true reads it as no
// filter (every item kept), false as a filter no item passes. Make documents neither (help.make.com, map).
export function mapFirst(array, key, pick, emptyIsNoFilter) {
  const kept = emptyIsNoFilter && (pick === "" || pick === null || pick === undefined) ? array : array.filter((x) => x.id === pick);
  return kept.length ? String(kept[0][key] ?? "") : "";
}

// The skeleton the drafter gets and the @08 the validator gets for a ranker pick, as the E37 forms compute them. Refuses
// when the two readings of map differ, which happens exactly when the pick is empty and the cell holds candidates: then
// what the drafter sees would depend on undocumented Make behaviour. The ranker's NO_PICK makes both readings empty.
export function exemplarOf(array, pick) {
  const a = { skeleton: mapFirst(array, "skeleton", pick, false), terms: mapFirst(array, "terms", pick, false) };
  const b = { skeleton: mapFirst(array, "skeleton", pick, true), terms: mapFirst(array, "terms", pick, true) };
  if (a.skeleton !== b.skeleton || a.terms !== b.terms) {
    throw new Refusal(`the exemplar for pick ${JSON.stringify(pick)} depends on how Make's map reads an empty filter value. `
      + `The ranker returns ${NO_PICK} when it selects nothing`);
  }
  return a;
}

export function overlayProblems(overlay, cases, seeds, vocab) {
  const out = [];
  const ids = overlay.seed_record_ids || {};
  const lines = candidateLines(seeds, ids);
  for (const c of cases) {
    const e = c.expected || {};
    const want = overlay.cases?.[c.id];
    if (!want) {
      out.push(`overlay has no entry for ${c.id}`);
      continue;
    }
    let pick = null;
    if (e.grounding?.allowed === "true" && e.outcome === "letter" && c.kind !== "control") {
      const weak = Object.entries(e.support || {}).filter(([, v]) => ["not_supported", "partly_supported"].includes(v)).map(([k]) => k).sort();
      const strong = Object.entries(e.support || {}).filter(([, v]) => v === "supported").map(([k]) => k).sort();
      pick = rankReference(lines, weak, c.inputs.visa_code, c.inputs.document_code, vocab, new Set(Object.values(ids)), "test", strong)
        .exemplar_code || null;
    }
    if (pick !== want.pick) out.push(`${c.id}: the JavaScript ranker picks ${pick}, the overlay says ${want.pick}`);
  }
  return out;
}

// --- The draft request with an exemplar ------------------------------------------------------------------------------
export function draftTemplateProblems(template) {
  const content = template?.messages?.[0]?.content || "";
  const n = expressionsOf(content).filter((e) => e === X32_SKELETON_EXPR).length;
  const out = [];
  if (n !== 1) out.push(`the X-32 draft template maps the exemplar skeleton ${n} times, not once`);
  if (!/<exemplar>\n\{\{/.test(content) || !content.includes("}}\n</exemplar>")) out.push("the X-32 draft template has no <exemplar> block");
  return out;
}

// buildRequest knows only the seven @1 mappings, so the exemplar expression is swapped for a one-time sentinel, the
// request is built, and the sentinel is replaced by the skeleton with < escaped as Make's replace does.
export function buildDraftX32(template, ctx, skeleton) {
  if (draftTemplateProblems(template).length) throw new Refusal(draftTemplateProblems(template).join("; "));
  if (typeof skeleton !== "string") throw new Refusal("no exemplar skeleton value (use the empty string for none)");
  const sentinel = `X32SENTINEL${sha256Hex(`${Date.now()}:${Math.random()}`).slice(0, 24)}`;
  const t = JSON.parse(JSON.stringify(template));
  t.messages[0].content = t.messages[0].content.replace(`{{${X32_SKELETON_EXPR}}}`, sentinel);
  const body = buildRequest(t, ctx);
  const parts = body.messages[0].content.split(sentinel);
  if (parts.length !== 2) throw new Refusal("the exemplar sentinel did not survive the fill exactly once");
  body.messages[0].content = parts.join(skeleton.replace(/</g, " less than "));
  return body;
}

// --- Metrics (tier A, X1 to X5 of section 10) ----------------------------------------------------------------------
const words = (s) => (String(s).toLowerCase().match(/[a-z0-9']+/g) || []);
export const wholeWordHits = (text, terms) => terms.filter((t) => new RegExp(`(?<![\\w])${t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?![\\w])`, "i").test(text));

function contentWords(skeleton) {
  // Blank lines first, so the first three lines are the first line, the Re line and Dear Officer whatever the spacing.
  const lines = skeleton.split("\n").filter((l) => l.trim()).slice(3).filter((l) => !FIXED_LINES.has(l) && !l.startsWith("[RCIC"));
  return words(lines.join(" ").replace(PLACEHOLDER, " "));
}

export function longestSharedRun(draft, skeleton) {
  const a = words(draft);
  const b = contentWords(skeleton);
  let best = 0;
  const prev = new Array(b.length + 1).fill(0);
  for (let i = 1; i <= a.length; i++) {
    let diag = 0;
    for (let j = 1; j <= b.length; j++) {
      const keep = prev[j];
      prev[j] = a[i - 1] === b[j - 1] ? diag + 1 : 0;
      if (prev[j] > best) best = prev[j];
      diag = keep;
    }
  }
  return best;
}

export function ngramShare(draft, skeleton, n = 8) {
  const grams = (w) => new Set(w.slice(0, Math.max(0, w.length - n + 1)).map((_, i) => w.slice(i, i + n).join(" ")));
  const d = grams(words(draft));
  const s = grams(contentWords(skeleton));
  if (!d.size) return 0;
  let hit = 0;
  for (const g of d) if (s.has(g)) hit++;
  return Number((hit / d.size).toFixed(4));
}

export function x32Metrics(arm, draftText, seed, validation) {
  const M = [];
  const hard = validation?.detail?.hard_fails || [];
  const hardIds = Array.isArray(hard) ? hard.map((h) => (typeof h === "string" ? h : h?.check || h?.id)) : [];
  if (arm === "A2" && seed) {
    const leaks = hardIds.filter((h) => h === "exemplar_leak").length;
    M.push({ id: "X1", pass: leaks === 0, value: leaks, detail: "exemplar_leak hard fails" });
    const shadow = wholeWordHits(draftText, seed.shadow_terms);
    M.push({ id: "X2", pass: shadow.length === 0, value: shadow.length, detail: shadow.length ? "shadow canary in the draft" : "" });
    const run = longestSharedRun(draftText, seed.skeleton);
    M.push({ id: "X3", pass: run <= 25, value: { longest_run: run, share_8grams: ngramShare(draftText, seed.skeleton) },
      detail: run > 25 ? "a shared run over 25 words, review for copying" : "" });
  }
  const placeholders = (String(draftText).match(PLACEHOLDER) || []).length;
  M.push({ id: "X4", pass: placeholders === 0, value: placeholders, detail: placeholders ? "a copied placeholder" : "" });
  return M;
}

// --- One case, all arms ----------------------------------------------------------------------------------------------
function stageRecord(version, body, call) {
  const m = call.msg;
  const usage = JSON.parse(JSON.stringify(m.usage || {}));
  return { stamp: version.stamp, template_sha256: version.template_sha256, model_requested: body.model, max_tokens: body.max_tokens,
    request_sha256: requestSha256(body), user_message: body.messages[0].content, model_served: m.model, message_id: m.id,
    request_id: m._request_id ?? null, stop_reason: m.stop_reason, stop_details: m.stop_details ?? null, usage,
    usd: Number(usageUsd(m.model, usage).toFixed(6)), latency_ms: call.latency_ms, content_types: (m.content || []).map((b) => b.type),
    text: firstText(m), retries: call.attempts };
}

export async function runArmsCase({ c, runId, arms, versions, db, claude, budget, outlineSchema, seeds, vocab, ids, callStage }) {
  const record = recordId(c);
  const exec = execId(runId, c.id);
  const inputs = chainInputs(c);
  const tx = { record, exec, visa: c.inputs.visa_code, doc: c.inputs.document_code, flag: c.inputs.synthetic_flag, listed: c.inputs.listed };
  const out = { case_id: c.id, kind: c.kind, record_id: record, exec_id: exec, inputs_sha256: inputsSha256(c), case_sha256: caseSha256(c),
    grounding: null, outline: null, selection: null, arms: {}, error: null };
  try {
    out.grounding = await ground(db, tx);
    if (!(out.grounding.allowed === "true" && isPaid(c))) return out;
    const ob = buildRequest(versions.outline.template, { inputs, provisions: out.grounding.provisions });
    const oc = await callStage(claude, ob, budget);
    out.outline = stageRecord(versions.outline, ob, oc);
    budget.add(out.outline.usd);
    if (out.outline.stop_reason !== "end_turn") return out;
    // The selection: the database (Tx S) once ff13.rank_exemplars exists, else the reference port on the same outline.
    const agg = aggregatedRows(seeds, ids, c.inputs.visa_code, c.inputs.document_code);
    const rank = { outline: out.outline.text, candidates: agg.map((x) => x.rank_key).join("\n"),
      seeds: agg.filter((x) => x.id).map((x) => ({ id: x.id, code: x.rank_key.split("|")[1] })) };
    const sel = selectExemplar({ outlineText: out.outline.text, grounding: out.grounding, visa: c.inputs.visa_code, doc: c.inputs.document_code,
      seeds, vocab, ids });
    const dbSel = await selectExemplarDb(db, tx, rank);
    const picked = dbSel || sel.result;
    const ex = exemplarOf(agg, picked.exemplar_record_id);
    const seed = ex.skeleton ? seeds.find((s) => ids[s.code] === picked.exemplar_record_id) || null : null;
    out.selection = { exemplar_record_id: picked.exemplar_record_id, exemplar_code: picked.exemplar_code, score: picked.score,
      weak_keys: sel.weak_keys, supported_keys: sel.supported_keys, reference_conflicts: sel.result.conflicts, flags: picked.flags,
      ranker: dbSel ? "ff13.rank_exemplars (Tx S)" : "reference (JavaScript port, ff13.rank_exemplars not migrated)",
      reference_pick: sel.result.exemplar_code || null };
    for (const arm of arms) {
      if (arm === "A2" && !ex.skeleton) {
        // No exemplar for this case: an A2 draft would be byte for byte the A1 request, so it is not run or paid for.
        out.arms.A2 = { not_applicable: true, reason: (picked.flags || []).join(", ") || "no exemplar selected" };
        continue;
      }
      const version = arm === "A0" ? versions.bound_draft : versions.draft;
      const ctx = { inputs, provisions: out.grounding.provisions, outline: oc.msg };
      const body = arm === "A0" ? buildRequest(version.template, ctx) : buildDraftX32(version.template, ctx, arm === "A2" ? ex.skeleton : "");
      const dc = await callStage(claude, body, budget);
      const draft = stageRecord(version, body, dc);
      budget.add(draft.usd);
      const u = draft.usage;
      const v = { draft: draft.text, name: inputs.name, case_facts: inputs.case_facts, model_requested: draft.model_requested,
        model_served: draft.model_served, stop_reason: draft.stop_reason, prompt_version: version.stamp, prompt_sha256: version.template_sha256,
        input_tokens: String(u.input_tokens), output_tokens: String(u.output_tokens), request_id: draft.message_id };
      const validation = arm === "A2" ? await validateWithTerms(db, tx, out.grounding, v, ex.terms, rank) : await validate(db, tx, out.grounding, v);
      const r = { case_id: c.id, grounding: out.grounding, outline: out.outline, draft, validation, error: null };
      r.predicted_routes = predictRoutes(operandValues({ inputs, grounding: r.grounding, outline: r.outline, draft: r.draft,
        validation: validation && !validation.void ? validation : null }));
      r.metrics = [...caseMetrics(c, r, outlineSchema), ...x32Metrics(arm, draft.text, arm === "A2" ? seed : null, validation)];
      if (arm === "A2") r.metrics.push(x5Metric(dbSel, validation));
      out.arms[arm] = { exemplar_code: arm === "A2" && seed ? seed.code : null, draft, validation, predicted_routes: r.predicted_routes, metrics: r.metrics };
    }
  } catch (e) {
    out.error = e instanceof Fatal ? e.message : db.lost ? lostError(db).message : `${e?.code ? `SQLSTATE ${e.code} ` : ""}${e?.message || e}`;
    out.fatal = e instanceof Fatal || Boolean(db.lost);
  }
  return out;
}

// X5, selection determinism: the database pick of Tx S (the one the draft used) equals the database pick of Tx V (the
// selection row the validator cross-checks @08 against). Not measured while the reference port picks.
export function x5Metric(dbSel, validation) {
  const again = validation?.selection;
  if (!dbSel || !again) return { id: "X5", pass: null, value: null, detail: "not measured: ff13.rank_exemplars is not migrated, the reference port picked" };
  const same = again.exemplar_record_id === dbSel.exemplar_record_id;
  return { id: "X5", pass: same, value: { tx_s: dbSel.exemplar_record_id, tx_v: again.exemplar_record_id },
    detail: same ? "" : "the ranker picked differently on the same outline and candidates" };
}

// Per arm, the ordinary F-F14 summary of the arm's drafts (each sharing the case's one outline) and the X metrics. A2 runs
// only where an exemplar was selected, so its comparison with A1 and A0 is paired: "paired" holds A0, A1 and A2 over
// exactly those cases, with their n. The all-case A0 and A1 summaries stay for the push gate (A1 not worse than A0).
export function summarizeArms(results, arms) {
  const armRows = (arm, keep) => results.filter((r) => r.arms[arm] && !r.arms[arm].not_applicable && keep(r))
    .map((r) => ({ case_id: r.case_id, outline: r.outline, draft: r.arms[arm].draft, validation: r.arms[arm].validation,
      metrics: r.arms[arm].metrics, error: r.error }));
  const one = (rs) => ({ ...summarize(rs), n: rs.length, verdicts: Object.fromEntries(rs.map((r) => [r.case_id, r.validation?.verdict ?? null])) });
  const out = {};
  for (const arm of arms) out[arm] = one(armRows(arm, () => true));
  const withExemplar = new Set(results.filter((r) => r.arms.A2 && !r.arms.A2.not_applicable).map((r) => r.case_id));
  if (arms.includes("A2")) {
    out.paired = { n: withExemplar.size, cases: [...withExemplar].sort(),
      note: "A2 against A1 (lift) and A0 on exactly the cases where A2 received an exemplar" };
    for (const arm of arms) out.paired[arm] = one(armRows(arm, (r) => withExemplar.has(r.case_id)));
    out.A2_not_applicable = results.filter((r) => r.arms.A2?.not_applicable).map((r) => ({ case_id: r.case_id, reason: r.arms.A2.reason }));
  }
  out.selection = results.filter((r) => r.selection).map((r) => ({ case_id: r.case_id, ...r.selection }));
  out.usd_total = Number(results.reduce((a, r) => a + (r.outline?.usd || 0) + Object.values(r.arms).reduce((b, x) => b + (x.draft?.usd || 0), 0), 0).toFixed(4));
  return out;
}

// The cases in order, as runLoop of run.mjs does for the @1 runs: a Fatal case, a change of the validator version between
// any two validations (any arm, any case) or a stop request between cases ends the loop.
export async function armsLoop({ cases, runCase, stop = { requested: false }, onCase = () => {} }) {
  const results = [];
  let validatorVersion = null;
  let stopped = null;
  for (const c of cases) {
    if (stop.requested) {
      stopped = "stop requested (Ctrl-C) before the next case";
      break;
    }
    const r = await runCase(c);
    for (const arm of Object.keys(r.arms || {}).sort()) {
      const vv = r.arms[arm]?.validation?.detail?.validator_version;
      if (!vv) continue;
      if (validatorVersion && vv !== validatorVersion && !r.fatal) {
        r.error = `validator version changed mid-run (${validatorVersion} then ${vv}, arm ${arm})`;
        r.fatal = true;
      }
      validatorVersion ||= vv;
    }
    results.push(r);
    onCase(r, c);
    if (r.fatal) {
      stopped = `${c.id}: ${r.error}`;
      break;
    }
  }
  return { results, validatorVersion, stopped };
}

function gitState() {
  try {
    const head = execFileSync("git", ["rev-parse", "HEAD"], { cwd: ROOT }).toString().trim();
    const dirty = execFileSync("git", ["status", "--porcelain", "--", "scripts/ff14", "scripts/x32_seeds.py", "eval/ff14/golden", "eval/x32",
      "ref", "blueprints", "supabase"], { cwd: ROOT }).toString().trim();
    return { head, clean: dirty === "" };
  } catch {
    return { head: null, clean: false };
  }
}

const sdkVersion = () => JSON.parse(fs.readFileSync(path.join(HERE, "node_modules", "@anthropic-ai", "sdk", "package.json"), "utf8")).version;

// run.json of an arms run: the F-F14 provenance (specs/F-F14-evaluation-harness.md, Outputs) plus the arms, the seeds and
// the ranker.
export function armsRunRecord({ runId, started, a, chk, opts, results, validatorVersion, stopped, law, committed, spent, exit, git }) {
  const tmpl = (v) => ({ stamp: v.stamp, template_sha256: v.template_sha256, bound: v.bound ?? null });
  return {
    run_id: runId, started, ended: new Date().toISOString(), database: "live Supabase (owner role, rolled back)", git_head: git.head,
    git_clean: git.clean, runner: "scripts/ff14/run.mjs --arms (scripts/ff14/x32.mjs)", sdk: { "@anthropic-ai/sdk": sdkVersion(), pg: pgVersion() },
    scenario_id: SCENARIO_ID, snapshot_version: chk.snapshot?.version ?? null, grounding_module: GROUNDING_MODULE, arms: a.arms,
    versions: { outline: tmpl(chk.versions.outline), A0: tmpl(a.versions.bound_draft), x32_draft: tmpl(a.versions.draft) },
    ranker: results.some((r) => r.selection?.ranker?.startsWith("ff13.")) ? "ff13.rank_exemplars" : "reference (JavaScript port of scripts/x32_seeds.py)",
    seeds: a.seed_digests, overlay: opts.exemplars, validator_version: validatorVersion, validator_version_expected: EXPECTED_VALIDATOR,
    law_sources: law, golden_version: GOLDEN_VERSION, golden_digest: chk.digest ?? null, cases: chk.cases.map((c) => c.id),
    cases_run: results.map((r) => r.case_id), stopped_early: stopped, pricing: PRICING, max_usd: opts.maxUsd,
    spent_usd: Number(spent.toFixed(6)), committed_rows: committed, exit,
  };
}

// --- Check, dry run and run ------------------------------------------------------------------------------------------
export function armsCheck(chk, opts) {
  const arms = parseArms(opts.arms);
  // check() builds every paid case's request with the closed @1 mapping list, so an X-32 draft template gives one
  // "unknown mapping" problem per case for the exemplar expression. Those, and only those, are dropped here and replaced
  // by building each request with buildDraftX32 below. Every other check problem stands.
  const exemplarMapping = `unknown mapping {{${X32_SKELETON_EXPR}}}`;
  const problems = chk.problems.filter((p) => !(arms.some((a) => a !== "A0") && !chk.versions.draft.bound && p.includes(exemplarMapping)));
  if (!opts.exemplars) problems.push("--arms needs --exemplars <overlay>, such as eval/x32/overlay/v1.json");
  if (arms.some((a) => a !== "A0") && chk.versions.draft.bound) {
    problems.push("A1 and A2 run the X-32 draft version: name it with --versions draft@N (registered with --no-bind)");
  }
  if (arms.some((a) => a !== "A0")) {
    const tp = draftTemplateProblems(chk.versions.draft.template);
    problems.push(...tp);
    if (!tp.length) {
      for (const c of chk.cases.filter(isPaid)) {
        try {
          buildDraftX32(chk.versions.draft.template, { inputs: chainInputs(c), provisions: "[]",
            outline: { content: [{ type: "text", text: "[CHECK]" }] } }, "");
        } catch (e) {
          problems.push(`${c.id}: ${e.message}`);
        }
      }
    }
  }
  const { seeds, problems: seedProblems, digests } = loadSeeds();
  problems.push(...seedProblems);
  const vocab = loadVocab();
  let overlay = null;
  if (opts.exemplars) {
    overlay = readJson(path.resolve(ROOT, opts.exemplars));
    problems.push(...overlayProblems(overlay, chk.cases, seeds, vocab));
  }
  const boundStamp = chk.versions.draft.bound_version.stamp;
  const boundDraft = registeredVersion(chk.registry, STAGES.draft, Number(boundStamp.split("@")[1]));
  return { problems, arms, seeds, vocab, ids: overlay?.seed_record_ids || {}, versions: { ...chk.versions, bound_draft: boundDraft },
    seed_digests: digests };
}

export async function armsMain(opts, chk, deps) {
  const a = armsCheck(chk, opts);
  console.log(`x32 arms ${a.arms.join(",")}: ${a.seeds.length} seed(s), A0 ${a.versions.bound_draft.stamp}, X-32 draft ${a.versions.draft.stamp}`);
  if (a.problems.length) {
    for (const p of a.problems) console.log(`  problem: ${p}`);
    return 1;
  }
  if (opts.mode === "--check") {
    console.log("x32 check: clean");
    return 0;
  }
  const outlineSchema = JSON.parse(chk.versions.outline.template.outputFormat.schema);
  if (opts.mode === "--dry-run") {
    const { pgliteClient } = await import("./pglite.mjs");
    const db = await pgliteClient();
    try {
      for (const c of chk.cases.filter(isPaid)) {
        const tx = { record: recordId(c), exec: execId("dryrun", c.id), visa: c.inputs.visa_code, doc: c.inputs.document_code,
          flag: c.inputs.synthetic_flag, listed: c.inputs.listed };
        const g = await ground(db, tx);
        if (g.allowed !== "true") continue;
        const ctx = { inputs: chainInputs(c), provisions: g.provisions, outline: { content: [{ type: "text", text: "[DRY RUN outline]" }] } };
        const want = readJson(path.resolve(ROOT, opts.exemplars)).cases[c.id]?.pick;
        const ex = exemplarOf(aggregatedRows(a.seeds, a.ids, c.inputs.visa_code, c.inputs.document_code), want ? a.ids[want] : NO_PICK);
        const shapes = {};
        for (const arm of a.arms) {
          if (arm === "A2" && !ex.skeleton) {
            shapes[arm] = { not_applicable: true };
            continue;
          }
          const body = arm === "A0" ? buildRequest(a.versions.bound_draft.template, ctx)
            : buildDraftX32(a.versions.draft.template, ctx, arm === "A2" ? ex.skeleton : "");
          shapes[arm] = { request_sha256: requestSha256(body), user_chars: body.messages[0].content.length };
        }
        console.log(JSON.stringify({ case: c.id, overlay_pick: want ?? null, arms: shapes }));
      }
    } finally {
      await db.end();
    }
    console.log("x32 dry run: no API call made");
    return 0;
  }
  const env = readSecrets(path.join(ROOT, ".env"));
  const secrets = deps.secretValues(env);
  const say = (s) => console.log(deps.guardText(s, secrets));
  const db = await liveClient(env);
  const runId = new Date().toISOString().replace(/[-:]/g, "").replace(/\.\d+Z$/, "Z");
  const started = new Date().toISOString();
  const dir = path.join(RUNS, runId);
  const used = { records: chk.cases.map(recordId), execs: chk.cases.map((c) => execId(runId, c.id)), seeds: Object.values(a.ids) };
  let exit = 0;
  try {
    const left = await leftoverRecords(db);
    if (left.length) throw new Fatal(`ref.test_records holds ${left.length} committed harness record(s). Stop and investigate`);
    const claude = deps.anthropicClient(env.ANTHROPIC_API_KEY);
    const budget = deps.makeBudget(opts.maxUsd);
    const stop = { requested: false };
    process.once("SIGINT", () => {
      stop.requested = true;
      console.log("x32: stop requested, finishing the current case, then the proof and the run files. Ctrl-C again to abort");
    });
    const { results, validatorVersion, stopped } = await armsLoop({
      cases: chk.cases, stop,
      runCase: (c) => runArmsCase({ c, runId, arms: a.arms, versions: a.versions, db, claude, budget, outlineSchema, seeds: a.seeds,
        vocab: a.vocab, ids: a.ids, callStage: deps.callStage }),
      onCase: (r, c) => {
        deps.writeGuarded(path.join(dir, "cases", `${c.id}.json`), r, secrets);
        say(`${c.id}: pick ${r.selection?.exemplar_code || "-"}, ${a.arms.map((x) => `${x} ${r.arms[x]?.not_applicable ? "n/a" : r.arms[x]?.validation?.verdict ?? "-"}`).join(", ")}${r.error ? `, error: ${r.error}` : ""}`);
      },
    });
    if (stopped) {
      exit = 1;
      say(`run stopped early: ${stopped}`);
    }
    const fresh = await liveClient(env);
    let committed;
    let law;
    try {
      committed = { ...(await committedRows(fresh, used.records, used.execs)), ...(await committedX32Rows(fresh, used.records, used.execs, used.seeds)) };
      law = await lawSources(fresh);
    } finally {
      await fresh.end();
    }
    if (Object.values(committed).some((n) => n > 0)) exit = 1;
    const run = armsRunRecord({ runId, started, a, chk, opts, results, validatorVersion, stopped, law, committed, spent: budget.spent, exit,
      git: gitState() });
    deps.writeGuarded(path.join(dir, "run.json"), run, secrets);
    deps.writeGuarded(path.join(dir, "summary.json"), summarizeArms(results, a.arms), secrets);
    say(`x32 run ${runId} done: spent USD ${budget.spent.toFixed(4)}, committed rows ${JSON.stringify(committed)}, results in ${path.relative(ROOT, dir)}`);
    if (validatorVersion && validatorVersion !== EXPECTED_VALIDATOR) say(`note: validator version ${validatorVersion}, expected ${EXPECTED_VALIDATOR}`);
    return exit;
  } finally {
    await db.end();
  }
}
