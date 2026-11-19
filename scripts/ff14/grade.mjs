#!/usr/bin/env node
// F-F14 scoring: the automatic metrics per case, the run summary and report, the hand-grading reading view and empty
// gradesheet (regulated-rag handgrade_scaffold.py, ported), and the summary of a filled gradesheet.
//
//   node scripts/ff14/grade.mjs --summarize eval/ff14/runs/<run id>    reads handgrade.json, writes handgrade_summary.json

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ROOT, ROUTE_NAMES } from "./chain.mjs";
import { NO_DRAFT } from "./golden.mjs";

const TEST_PAIR = ["test_mode", "test_mode_unreviewed_grounding"];
const BAD_STATES = ["fabricated", "unprovided", "not_in_force"];
export const HEADINGS = ["Introduction", "Background", "Legal framework", "Submissions", "Conclusion"];
const GRADED_SECTIONS = ["Background", "Legal framework", "Submissions", "Conclusion"];
export const ERROR_CLASSES = ["invented_fact", "drawn_fact", "computed_duration", "wider_conclusion", "provision_misstated", "not_supported_argued", "other"];
export const PROMPT_BAND = [900, 1800];

// --- A JSON schema subset (the registered outline schema uses only these keywords) -----------------------------------
export function schemaProblems(value, schema, at = "$") {
  const out = [];
  const type = schema.type;
  const typeOk = type === "object" ? value !== null && typeof value === "object" && !Array.isArray(value)
    : type === "array" ? Array.isArray(value)
    : type === "string" ? typeof value === "string"
    : type === "boolean" ? typeof value === "boolean"
    : type === "integer" ? Number.isInteger(value)
    : type === "number" ? typeof value === "number"
    : type === undefined;
  if (!typeOk) return [`${at} is not ${type}`];
  if (schema.enum && !schema.enum.includes(value)) out.push(`${at} is not one of ${schema.enum.join(", ")}`);
  if (type === "object") {
    for (const k of schema.required || []) if (!(k in value)) out.push(`${at}.${k} is missing`);
    for (const [k, v] of Object.entries(value)) {
      if (schema.properties && k in schema.properties) out.push(...schemaProblems(v, schema.properties[k], `${at}.${k}`));
      else if (schema.additionalProperties === false) out.push(`${at}.${k} is not allowed`);
    }
  }
  if (type === "array" && schema.items) value.forEach((v, i) => out.push(...schemaProblems(v, schema.items, `${at}[${i}]`)));
  return out;
}

const fold = (s) => s.replace(/\s+/g, " ").trim().toLowerCase();

// The draft's lines grouped by section heading. Lines before Introduction are the head.
export function sections(letter) {
  const out = { head: [] };
  let at = "head";
  for (const raw of letter.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line) continue;
    if (HEADINGS.includes(line)) {
      at = line;
      out[at] = [];
      continue;
    }
    if (line === "Respectfully submitted,") at = "closing";
    (out[at] ||= []).push(line);
  }
  return out;
}

// Deterministic sentence split: line breaks, then a full stop, question or exclamation mark followed by a space and a
// capital letter, except after an honorific (Mr, Ms, Mrs, Mx, Dr, Prof) or a single capital initial, which never end a
// sentence ("Ms. Nwosu-Bright", "Pat R. Doe"). Inc., Ltd. and the like can end a sentence, so they still split.
export const splitSentences = (line) => line.split(/(?<=[.?!])(?<!(?:^|[\s(])(?:Mr|Ms|Mrs|Mx|Dr|Prof|[A-Z])\.)\s+(?=[A-ZÀ-Þ])/u)
  .map((s) => s.trim()).filter(Boolean);

// A provision key as the draft cites it: the validator's spacing rule (a space may be any run of spaces or hyphens), and
// not followed by a digit (with or without a dot), a letter or an opening parenthesis. So IRPR 220 never matches IRPR
// 220.1 or IRPR 220(1), while a key that ends a sentence ("in IRPR 220.") still matches.
const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
export const keyRegex = (key) => new RegExp(`${escapeRe(key).replace(/ /g, "[\\s\\u00a0-]+")}(?!\\.?[0-9]|[A-Za-z(])`);
export const keysIn = (text, keys) => keys.filter((k) => keyRegex(k).test(text));

export function sentenceRows(caseId, letter, keys = []) {
  const secs = sections(letter);
  const rows = [];
  for (const s of GRADED_SECTIONS) {
    let n = 0;
    for (const line of secs[s] || []) {
      for (const t of splitSentences(line)) rows.push({ case_id: caseId, section: s, n: ++n, text: t, cited_keys: keysIn(t, keys) });
    }
  }
  return rows;
}

export function parseOutline(text) {
  try {
    return { value: JSON.parse(text), error: null };
  } catch (e) {
    return { value: null, error: "the outline text is not JSON" };
  }
}

// --- Case checks (D9) ----------------------------------------------------------------------------------------------
function factsBlock(userMessage) {
  const a = userMessage.indexOf("<case_facts>\n");
  const b = userMessage.lastIndexOf("\n</case_facts>");
  return a === -1 || b === -1 ? null : userMessage.slice(a + "<case_facts>\n".length, b);
}

function caseCheck(ch, c, r) {
  const draft = r.draft?.text;
  const soft = (r.validation?.detail?.soft_flags || []).map((x) => x.check);
  const hard = (r.validation?.detail?.hard_fails || []).map((x) => x.check);
  switch (ch.type) {
    case "hand": return { pass: null, detail: `hand check: ${ch.text}` };
    case "draft_not_contains": return draft === undefined ? na() : { pass: !draft.includes(ch.text), detail: `draft does not contain ${ch.text}` };
    case "draft_equals": return draft === undefined ? na() : { pass: draft.trim() === ch.text, detail: "draft is exactly the expected line" };
    case "outline_risk_flags_contain": {
      const o = r.outline ? parseOutline(r.outline.text).value : null;
      if (!o) return na();
      const want = ch.any.map((t) => t.toLowerCase());
      const flags = Array.isArray(o.risk_flags) ? o.risk_flags.filter((f) => typeof f === "string") : [];
      return { pass: flags.some((f) => want.some((t) => f.toLowerCase().includes(t))),
        detail: `a risk flag names the planted issue (contains one of ${ch.any.map((t) => JSON.stringify(t)).join(", ")})` };
    }
    case "no_soft_flag": return r.validation ? { pass: !soft.includes(ch.check), detail: `no soft flag ${ch.check}` } : na();
    case "no_hard_fail": return r.validation ? { pass: !hard.includes(ch.check), detail: `no hard fail ${ch.check}` } : na();
    case "re_line_ends_with_name": {
      if (draft === undefined) return na();
      const re = draft.split(/\r?\n/).map((l) => l.trim()).find((l) => l.startsWith("Re:"));
      return { pass: !!re && re.endsWith(c.inputs.name), detail: "the Re line ends with the exact applicant name" };
    }
    case "facts_block_no_lt": {
      const um = r[ch.stage]?.user_message;
      if (!um) return na();
      const f = factsBlock(um);
      return { pass: f !== null && !f.includes("<"), detail: `the ${ch.stage} case_facts block holds no <` };
    }
    case "user_message_contains": {
      const um = r[ch.stage]?.user_message;
      return um ? { pass: um.includes(ch.text), detail: `the ${ch.stage} user message contains ${JSON.stringify(ch.text)}` } : na();
    }
    default: return { pass: false, detail: `unknown check ${ch.type}` };
  }
}
const na = () => ({ pass: null, detail: "not reached" });

// --- Automatic metrics per case --------------------------------------------------------------------------------------
export function caseMetrics(c, r, outlineSchema) {
  const e = c.expected;
  const M = [];
  const add = (id, pass, value, detail = "", extra = {}) => M.push({ id, pass, value, detail, ...extra });
  const g = r.grounding;
  if (g) {
    const ok = g.allowed === e.grounding.allowed && g.gate_mode === e.grounding.gate_mode && g.reason === e.grounding.reason;
    add("G1", ok, { allowed: g.allowed, gate_mode: g.gate_mode, reason: g.reason });
    if (g.allowed === "true") {
      const keysOk = JSON.stringify(g.provision_keys) === JSON.stringify(g.citation_status_keys)
        && JSON.stringify(JSON.parse(g.provisions).map((p) => p.key)) === JSON.stringify(g.provision_keys);
      add("G2", keysOk && g.flags.includes("test_mode"), { keys: g.provision_keys.length, flags: g.flags });
    }
  } else {
    add("G1", false, null, "no grounding");
  }
  let outline = null;
  if (r.outline) {
    add("O1", r.outline.stop_reason === "end_turn", r.outline.stop_reason);
    const p = parseOutline(r.outline.text);
    const problems = p.error ? [p.error] : schemaProblems(p.value, outlineSchema);
    add("O2", problems.length === 0, problems.length, problems.slice(0, 5).join("; "));
    outline = p.value;
    if (outline && g) {
      const keys = (outline.grounds || []).map((x) => x.provision_key);
      add("O3", JSON.stringify(keys) === JSON.stringify(g.provision_keys), { grounds: keys.length, provided: g.provision_keys.length });
    }
    if (outline) {
      const want = [];
      const got = [];
      for (const k of ["inputs_contain_instructions", "facts_sufficient"]) {
        if (e[k] === null || e[k] === undefined) continue;
        want.push(`${k} ${e[k]}`);
        got.push(`${k} ${outline[k]}`);
      }
      add("O4", JSON.stringify(want) === JSON.stringify(got), got.join(", "));
      const labels = Object.entries(e.support || {});
      if (labels.length) {
        const by = Object.fromEntries((outline.grounds || []).map((x) => [x.provision_key, x.support]));
        const hits = labels.filter(([k, v]) => by[k] === v).length;
        add("O5", hits === labels.length, `${hits}/${labels.length}`, labels.filter(([k, v]) => by[k] !== v).map(([k, v]) => `${k} expected ${v}, got ${by[k]}`).join("; "));
      }
      const facts = fold(c.inputs.case_facts_lines.join("\n"));
      const items = (outline.grounds || []).flatMap((x) => x.facts_relied_on || []);
      const verbatim = items.filter((f) => facts.includes(fold(f))).length;
      add("O6", null, items.length ? `${verbatim}/${items.length}` : "0/0", "facts_relied_on found verbatim in case_facts");
    }
  }
  if (r.draft) {
    add("D1", r.draft.stop_reason === "end_turn", r.draft.stop_reason);
    const text = r.draft.text.trim();
    const outcome = text === NO_DRAFT.no_draft_facts ? "no_draft_facts" : text === NO_DRAFT.no_draft_instructions ? "no_draft_instructions"
      : text.startsWith("NO DRAFT PREPARED") ? "no_draft_other" : "letter";
    add("D2", outcome === e.outcome, outcome);
  } else if (r.grounding?.allowed === "true" && r.outline) {
    add("D2", e.outcome === "draft_failed", "draft_failed");
  } else if (r.grounding) {
    add("D2", e.outcome === "refused_at_grounding" && r.grounding.allowed === "false", r.grounding.allowed === "false" ? "refused_at_grounding" : "not drafted");
  }
  const v = r.validation;
  if (v && !v.void) {
    const hard = v.detail.hard_fails.map((x) => x.check);
    const letter = e.outcome === "letter";
    add("D3", v.verdict === e.verdict && (!letter || v.hard_fail_count === 0), v.verdict, hard.length ? `hard fails: ${[...new Set(hard)].join(", ")}` : "");
    const extra = v.detail.soft_flags.map((x) => x.check).filter((k) => !TEST_PAIR.includes(k));
    add("D4", extra.length === 0, extra.length, [...new Set(extra)].join(", "));
    const cited = [...new Set(v.detail.citations.map((x) => x.key))];
    if ((e.controlling_keys || []).length && letter) {
      const hit = e.controlling_keys.filter((k) => cited.includes(k)).length;
      add("D5", null, `${hit}/${e.controlling_keys.length}`, e.controlling_keys.filter((k) => !cited.includes(k)).map((k) => `missing ${k}`).join(", "),
        { hits: hit, of: e.controlling_keys.length });
      // Precision against the controlling keys, informational: citing another provided key is allowed (D6 holds the set).
      add("D10", null, `${hit}/${cited.length}`, cited.filter((k) => !e.controlling_keys.includes(k)).map((k) => `beyond the controlling keys: ${k}`).join(", "),
        { hits: hit, of: cited.length });
    }
    const bad = v.detail.citations.filter((x) => BAD_STATES.includes(x.state));
    add("D6", bad.length === 0, bad.length, bad.map((x) => `${x.key} ${x.state}`).join(", "));
    if (outline && r.draft) {
      const notSup = (outline.grounds || []).filter((x) => x.support === "not_supported").map((x) => x.provision_key);
      const subs = (sections(r.draft.text).Submissions || []).join("\n");
      const flagged = keysIn(subs, notSup);
      // Flagged for tier A and the tier B sample, never failed: the Submissions may answer a counter-consideration under it.
      add("D7", null, flagged.length, flagged.length ? `not_supported cited in Submissions: ${flagged.join(", ")}` : "", { flag: flagged.length > 0 });
    }
    const words = v.detail.words;
    add("D8", null, words, words === null || words === undefined ? "" : words < PROMPT_BAND[0] ? "below the prompt band" : words > PROMPT_BAND[1] ? "above the prompt band" : "inside the prompt band");
  } else if (v && v.void) {
    add("D3", false, "void", v.reason);
  }
  for (const ch of e.checks || []) {
    const res = caseCheck(ch, c, r);
    add("D9", res.pass, ch.type, res.detail);
  }
  const routes = r.predicted_routes || [];
  add("R1", routes.length === 1 && routes[0] === e.route, routes.join(","), routes.map((x) => ROUTE_NAMES[x]).join("; "));
  for (const s of ["outline", "draft"]) {
    if (!r[s]) continue;
    const u = r[s].usage || {};
    add("C1", null, { stage: s, input_tokens: u.input_tokens, output_tokens: u.output_tokens, usd: r[s].usd, latency_ms: r[s].latency_ms,
      output_share_of_max: u.output_tokens ? Number((u.output_tokens / r[s].max_tokens).toFixed(3)) : null });
  }
  return M;
}

// --- Summary and report -------------------------------------------------------------------------------------------------
const ratio = (h, n) => (n ? Number((h / n).toFixed(3)) : null);
// A per-case n/m metric (D5, D10) as the per-case list, the mean of the per-case ratios and the pooled count.
function nOfM(results, id) {
  const ms = results.flatMap((r) => (r.metrics || []).filter((m) => m.id === id).map((m) => ({ case_id: r.case_id, hits: m.hits, of: m.of, value: m.value })));
  const withN = ms.filter((m) => m.of > 0);
  const hits = ms.reduce((a, m) => a + (m.hits || 0), 0);
  const of = ms.reduce((a, m) => a + (m.of || 0), 0);
  return { per_case: ms.map((m) => `${m.case_id} ${m.value}`),
    mean: withN.length ? Number((withN.reduce((a, m) => a + m.hits / m.of, 0) / withN.length).toFixed(3)) : null,
    pooled: `${hits}/${of}`, pooled_rate: ratio(hits, of) };
}

export function summarize(results) {
  const byMetric = {};
  for (const r of results) {
    for (const m of r.metrics || []) {
      const s = (byMetric[m.id] ||= { pass: 0, fail: 0, flag: 0, info: 0 });
      if (m.pass === true) s.pass++;
      else if (m.pass === false) s.fail++;
      else if (m.flag) s.flag++;
      else s.info++;
    }
  }
  const usd = results.reduce((a, r) => a + (r.outline?.usd || 0) + (r.draft?.usd || 0), 0);
  const paid = results.filter((r) => r.outline);
  const tok = (s, k) => paid.reduce((a, r) => a + (r[s]?.usage?.[k] || 0), 0);
  const words = results.map((r) => r.validation?.detail?.words).filter((w) => Number.isInteger(w));
  return {
    cases: results.length,
    paid_cases: paid.length,
    errors: results.filter((r) => r.error).map((r) => ({ case_id: r.case_id, error: r.error })),
    metrics: byMetric,
    citation_recall: nOfM(results, "D5"),
    citation_precision_controlling: nOfM(results, "D10"),
    flagged: results.flatMap((r) => (r.metrics || []).filter((m) => m.flag).map((m) => ({ case_id: r.case_id, id: m.id, detail: m.detail }))),
    words: { n: words.length, min: words.length ? Math.min(...words) : null, max: words.length ? Math.max(...words) : null,
      in_prompt_band: words.filter((w) => w >= PROMPT_BAND[0] && w <= PROMPT_BAND[1]).length },
    tokens: { outline_in: tok("outline", "input_tokens"), outline_out: tok("outline", "output_tokens"),
      draft_in: tok("draft", "input_tokens"), draft_out: tok("draft", "output_tokens") },
    max_output_tokens: Math.max(0, ...paid.flatMap((r) => ["outline", "draft"].map((s) => r[s]?.usage?.output_tokens || 0))),
    usd_total: Number(usd.toFixed(4)),
    usd_per_paid_case: paid.length ? Number((usd / paid.length).toFixed(4)) : null,
  };
}

const cell = (m) => (m ? (m.pass === true ? "pass" : m.pass === false ? "FAIL" : m.flag ? "FLAG" : String(typeof m.value === "object" ? "" : m.value)) : "");

export function reportMd(run, results, summary) {
  const L = [];
  L.push(`# F-F14 run ${run.run_id}`, "");
  L.push(`Golden set ${run.golden_version} (digest ${run.golden_digest ? run.golden_digest.slice(0, 12) : "not recorded"}), ${summary.cases} cases (${summary.paid_cases} paid). Database ${run.database}. Outline ${run.versions.outline.stamp}, draft ${run.versions.draft.stamp}. Validator ${run.validator_version || "not reached"}. Snapshot of ${run.scenario_id} at version ${run.snapshot_version}.`, "");
  if (run.stopped_early) L.push(`**Stopped early:** ${run.stopped_early}. ${(run.cases_run || []).length} of ${(run.cases || []).length} cases ran.`, "");
  L.push(`Spend USD ${summary.usd_total} (${summary.usd_per_paid_case ?? "n/a"} per paid case). Tokens: outline ${summary.tokens.outline_in} in, ${summary.tokens.outline_out} out; draft ${summary.tokens.draft_in} in, ${summary.tokens.draft_out} out. Highest output on one call: ${summary.max_output_tokens} of 16000.`, "");
  const rc = summary.citation_recall;
  const pr = summary.citation_precision_controlling;
  L.push(`Citation recall against the controlling keys (D5): ${rc.pooled} pooled, mean per case ${rc.mean ?? "n/a"}. Precision against the controlling keys (D10, informational): ${pr.pooled} pooled, mean per case ${pr.mean ?? "n/a"}.`, "");
  if (run.committed_rows) L.push(`Committed rows after the run (fresh connection): ${Object.entries(run.committed_rows).map(([k, v]) => `${k} ${v}`).join(", ")}.`, "");
  L.push("## Metric counts", "", "| Metric | pass | fail | flag | info |", "|---|---|---|---|---|");
  for (const [k, s] of Object.entries(summary.metrics).sort()) L.push(`| ${k} | ${s.pass} | ${s.fail} | ${s.flag} | ${s.info} |`);
  L.push("", "## Cases", "", "| Case | Kind | G1 | O1 | O3 | O4 | O5 | D1 | D2 | Verdict | D4 | D5 | D6 | D7 | Words | Route (expected) | USD |", "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|");
  for (const r of results) {
    const get = (id) => (r.metrics || []).find((m) => m.id === id);
    const usd = ((r.outline?.usd || 0) + (r.draft?.usd || 0)).toFixed(4);
    L.push(`| ${r.case_id} | ${r.kind} | ${cell(get("G1"))} | ${cell(get("O1"))} | ${cell(get("O3"))} | ${cell(get("O4"))} | ${get("O5") ? get("O5").value : ""} | ${cell(get("D1"))} | ${get("D2") ? get("D2").value : ""} | ${r.validation?.verdict ?? ""} | ${get("D4") ? get("D4").value : ""} | ${get("D5") ? get("D5").value : ""} | ${get("D6") ? get("D6").value : ""} | ${cell(get("D7"))} | ${r.validation?.detail?.words ?? ""} | ${(r.predicted_routes || []).join(",")} (${r.expected_route}) | ${usd} |`);
  }
  const fails = results.flatMap((r) => (r.metrics || []).filter((m) => m.pass === false).map((m) => `- ${r.case_id} ${m.id}: ${m.detail || JSON.stringify(m.value)}`));
  L.push("", "## Failed metrics", "", ...(fails.length ? fails : ["None."]));
  L.push("", "## Flagged for tier A (not failed)", "", ...(summary.flagged.length ? summary.flagged.map((f) => `- ${f.case_id} ${f.id}: ${f.detail}`) : ["None."]));
  if (summary.errors.length) L.push("", "## Errors", "", ...summary.errors.map((e) => `- ${e.case_id}: ${e.error}`));
  L.push("");
  return L.join("\n");
}

// --- Hand-grading scaffold ----------------------------------------------------------------------------------------------
const isLetter = (r) => r.draft && !r.draft.text.trim().startsWith("NO DRAFT PREPARED");
const handChecks = (c) => (c?.expected?.checks || []).filter((ch) => ch.type === "hand");

// The fixed core of the tier B sample, from the golden set and never from a run's results, so two runs or two prompt
// versions are graded on the same letters: the first case in ID order of each category that expects a letter, and every
// case with a hand check (the traps no automatic metric can see: drawn facts, computed durations, self-employment
// counted, funds argued as met).
export function tierBCore(cases) {
  const core = new Set();
  const seen = new Set();
  for (const c of [...cases].sort((a, b) => (a.id < b.id ? -1 : 1))) {
    if (c.kind === "control" || c.expected?.outcome !== "letter") continue;
    if (!seen.has(c.category)) {
      seen.add(c.category);
      core.add(c.id);
    }
    if (handChecks(c).length) core.add(c.id);
  }
  return [...core].sort();
}

// The sample: the core letters, plus every letter with a red automatic metric (D3, D4 or O5 failed, or D7 flagged) as
// extra scrutiny. Versions are compared on the core.
export function tierBSample(results, cases) {
  const core = new Set(tierBCore(cases));
  const sample = new Set();
  for (const r of results.filter(isLetter)) {
    const red = (r.metrics || []).some((m) => (["D3", "D4", "O5"].includes(m.id) && m.pass === false) || (m.id === "D7" && m.flag));
    if (core.has(r.case_id) || red) sample.add(r.case_id);
  }
  return [...sample].sort();
}

const quote = (t) => (t ? t.replace(/\r\n/g, "\n").split("\n").map((l) => (l ? `> ${l}` : ">")).join("\n") : "> (empty)");
// Provision text printed under a tier B sentence that cites it (regulated-rag's side-by-side view). A longer text is
// shown once under Provided provisions and named under the sentence, so the reading view stays readable.
export const INLINE_PROVISION_CHARS = 800;

export function handgrade(run, results, cases) {
  const byId = Object.fromEntries(cases.map((c) => [c.id, c]));
  const core = tierBCore(cases);
  const sample = tierBSample(results, cases);
  const sheet = { grader: "", graded_at: "", run_id: run.run_id, golden_version: run.golden_version, golden_digest: run.golden_digest ?? null,
    instructions: "Fill grader and graded_at first. Values per eval/ff14/rubric.md. A hand check result is pass or fail. Leave tier D to the RCIC.",
    tier_b_core: core, tier_b_sample: sample, tier_a: [], tier_b: [], tier_c: [], tier_d: [], hand_checks: [] };
  const md = [];
  const rubric = fs.readFileSync(path.join(ROOT, "eval", "ff14", "rubric.md"), "utf8");
  md.push(`# F-F14 hand-grading, run ${run.run_id}`, "", "Reading view. Grades go in `handgrade.json` beside this file.", "",
    `Tier B core (fixed by the golden set): ${core.join(", ")}. Sample this run: ${sample.join(", ") || "none"}.`, "", rubric, "", "---", "");
  for (const r of results.filter((x) => x.draft)) {
    const c = byId[r.case_id];
    const outline = r.outline ? parseOutline(r.outline.text).value : null;
    const provisions = r.grounding?.provisions ? JSON.parse(r.grounding.provisions) : [];
    const provByKey = Object.fromEntries(provisions.map((p) => [p.key, p]));
    const keys = provisions.map((p) => p.key);
    const inSample = sample.includes(r.case_id);
    const flagged = (r.metrics || []).filter((m) => m.flag).map((m) => m.detail);
    md.push(`## ${r.case_id} (${c.kind}, ${c.stratum})`, "", `**What a correct answer covers:** ${c.expected.answer_summary}`, "");
    md.push(`**Automatic:** verdict ${r.validation?.verdict ?? "none"}, ${(r.metrics || []).filter((m) => m.pass === false).map((m) => m.id).join(", ") || "no failed metric"}${flagged.length ? `, flagged: ${flagged.join("; ")}` : ""}.`, "");
    const hands = isLetter(r) ? handChecks(c) : [];
    if (hands.length) {
      md.push("### Hand checks (record pass or fail under `hand_checks`)", "", ...hands.map((h) => `- ${h.text}`), "");
      for (const h of hands) sheet.hand_checks.push({ case_id: r.case_id, text: h.text, result: null, notes: "" });
    }
    md.push("### Case facts", "", quote(c.inputs.case_facts_lines.join("\n")), "");
    md.push("### Provided provisions", "");
    for (const p of provisions) md.push(`**${p.key}** (${p.purpose})`, "", quote(p.text), "");
    if (outline) {
      md.push("### Outline", "", `Thesis: ${outline.thesis}`, "", `inputs_contain_instructions ${outline.inputs_contain_instructions}, facts_sufficient ${outline.facts_sufficient}`, "");
      md.push("| Key | Requirement | Facts relied on | Support | Gap | Counter-consideration | Response |", "|---|---|---|---|---|---|---|");
      const esc = (s) => String(s ?? "").replace(/\|/g, "\\|").replace(/\n/g, " ");
      for (const gr of outline.grounds || []) {
        md.push(`| ${esc(gr.provision_key)} | ${esc(gr.requirement)} | ${esc((gr.facts_relied_on || []).join(" / "))} | ${esc(gr.support)} | ${esc(gr.gap)} | ${esc(gr.counter_consideration)} | ${esc(gr.response)} |`);
        if (isLetter(r)) sheet.tier_a.push({ case_id: r.case_id, provision_key: gr.provision_key, outline_support: gr.support, A1: null, A2: null, A3: null, notes: "" });
      }
      md.push("", `Risk flags: ${(outline.risk_flags || []).length ? "" : "none"}`, ...(outline.risk_flags || []).map((f) => `- ${f}`), "");
    }
    md.push(`### Draft${inSample ? ` (tier B ${core.includes(r.case_id) ? "core" : "red"} sample)` : ""}`, "");
    if (isLetter(r)) {
      const secs = sections(r.draft.text);
      md.push(quote((secs.head || []).join("\n")), "");
      for (const s of HEADINGS) {
        md.push(`**${s}**`, "");
        let n = 0;
        for (const line of secs[s] || []) {
          for (const t of splitSentences(line)) {
            md.push(`${s === "Introduction" ? "" : `${s[0]}${++n}. `}${t}`);
            if (!inSample || s === "Introduction") continue;
            for (const k of keysIn(t, keys)) {
              const p = provByKey[k];
              md.push(p.text.length <= INLINE_PROVISION_CHARS ? `   - cites ${k}: ${p.text.replace(/\s+/g, " ")}`
                : `   - cites ${k}: its text (${p.text.length} characters) is under Provided provisions`);
            }
          }
        }
        md.push("");
      }
      md.push(quote((secs.closing || []).join("\n")), "");
      if (inSample) for (const row of sentenceRows(r.case_id, r.draft.text, keys)) sheet.tier_b.push({ ...row, grade: null, error_class: null, notes: "" });
      sheet.tier_c.push({ case_id: r.case_id, C1: null, C2: null, C3: null, C4: null, notes: "" });
      sheet.tier_d.push({ case_id: r.case_id, legal_test: null, persuasive: null, nothing_material_missing: null, disposition: null, rcic_licence: "", notes: "" });
    } else {
      md.push(quote(r.draft.text), "");
    }
    md.push("---", "");
  }
  return { md: md.join("\n"), json: sheet };
}

const BLOCKING = ["invented_fact", "provision_misstated", "not_supported_argued"];

// Tier B statistics over a set of rows (merged rows dropped).
function tierBStats(rows) {
  const b = rows.filter((r) => r.grade !== "merged");
  const graded = b.filter((r) => [0, 1, 2].includes(r.grade));
  const zeros = graded.filter((r) => r.grade === 0);
  const byClass = (xs) => xs.reduce((a, r) => ((a[r.error_class || "unclassed"] = (a[r.error_class || "unclassed"] || 0) + 1), a), {});
  const faithful = graded.filter((r) => r.grade === 2).length;
  return { rows: b.length, graded: graded.length, not_applicable: b.filter((r) => r.grade === "n/a").length,
    ungraded: b.filter((r) => r.grade === null).length, faithful, faithfulness_rate: ratio(faithful, graded.length),
    grade0_by_class: byClass(zeros), grade1_by_class: byClass(graded.filter((r) => r.grade === 1)),
    blocking_zeros: zeros.filter((r) => BLOCKING.includes(r.error_class)).length };
}

// The filled gradesheet, summarized. Refuses a sheet with no grader or time. Tier B is reported over the fixed core
// (versions are compared there), over the whole sample, and per case.
export function summarizeGrades(sheet) {
  if (!sheet.grader || !sheet.graded_at) throw new Error("fill grader and graded_at before summarizing");
  const count = (rows, k) => rows.reduce((a, r) => ((a[r[k] ?? "ungraded"] = (a[r[k] ?? "ungraded"] || 0) + 1), a), {});
  const mean = (k) => {
    const v = sheet.tier_c.map((r) => r[k]).filter((x) => [0, 1, 2].includes(x));
    return v.length ? Number((v.reduce((a, x) => a + x, 0) / v.length).toFixed(2)) : null;
  };
  const core = sheet.tier_b_core || [];
  const sampled = [...new Set(sheet.tier_b.map((r) => r.case_id))].sort();
  const perCase = Object.fromEntries(sampled.map((id) => [id, tierBStats(sheet.tier_b.filter((r) => r.case_id === id))]));
  const misstated = {};
  for (const r of sheet.tier_b.filter((x) => [0, 1].includes(x.grade) && x.error_class === "provision_misstated")) {
    for (const k of r.cited_keys?.length ? r.cited_keys : ["no key cited"]) misstated[k] = (misstated[k] || 0) + 1;
  }
  const hc = sheet.hand_checks || [];
  return {
    grader: sheet.grader, graded_at: sheet.graded_at, run_id: sheet.run_id, golden_digest: sheet.golden_digest ?? null,
    tier_a: { rows: sheet.tier_a.length, A1: count(sheet.tier_a, "A1"), A2: count(sheet.tier_a, "A2"), A3: count(sheet.tier_a, "A3"),
      overstated: sheet.tier_a.filter((r) => r.A2 === "overstated").length },
    tier_b: {
      ...tierBStats(sheet.tier_b),
      core: { cases: core, missing: core.filter((id) => !sampled.includes(id)), ...tierBStats(sheet.tier_b.filter((r) => core.includes(r.case_id))) },
      red_additions: sampled.filter((id) => !core.includes(id)),
      per_case: perCase,
      provision_misstated_by_key: misstated,
    },
    tier_c: { letters: sheet.tier_c.length, C1: mean("C1"), C2: mean("C2"), C3: mean("C3"), C4: mean("C4") },
    hand_checks: { rows: hc.length, pass: hc.filter((h) => h.result === "pass").length, fail: hc.filter((h) => h.result === "fail").length,
      ungraded: hc.filter((h) => h.result !== "pass" && h.result !== "fail").length,
      failed: hc.filter((h) => h.result === "fail").map((h) => ({ case_id: h.case_id, text: h.text })) },
  };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [flag, dir] = process.argv.slice(2);
  if (flag !== "--summarize" || !dir) {
    console.error("usage: grade.mjs --summarize eval/ff14/runs/<run id>");
    process.exit(2);
  }
  try {
    const sheet = JSON.parse(fs.readFileSync(path.join(dir, "handgrade.json"), "utf8"));
    const out = summarizeGrades(sheet);
    fs.writeFileSync(path.join(dir, "handgrade_summary.json"), JSON.stringify(out, null, 2) + "\n");
    console.log(JSON.stringify(out, null, 2));
  } catch (e) {
    console.error(`grade.mjs: ${e.message}`);
    process.exit(1);
  }
}
