// F-F14: what the harness reproduces of the live Module F chain (scenario 7049689): the bound prompt versions, the
// snapshot checks, Make's routing predicted from the snapshot's own filters, and the price table.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalJson, sha256Hex } from "../law_load/load.mjs";
import { Refusal } from "./iml.mjs";

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
export const SCENARIO_ID = 7049689;
export const SNAPSHOT = "blueprints/module-f-drafting-chain__7049689.json";
export const STAGES = { outline: "drafting-chain.submission-letter-outline", draft: "drafting-chain.submission-letter-draft" };
export const STAGE_MODULE = { outline: 6, draft: 9 };
export const GROUNDING_MODULE = 4;
export const VALIDATOR_MODULE = 11;
export const GROUNDING_SP = '"ff13"."drafting_context"';

// Module 9's text as Make reads it (the draft).
const TXT9 = '{{first(map(9.content; "text"; "type"; "text"))}}';

const readJson = (rel) => JSON.parse(fs.readFileSync(path.join(ROOT, rel), "utf8"));

export function loadRegistry() {
  const list = readJson("ref/prompts.json").prompts;
  const bindings = readJson("ref/prompt_bindings.json").prompt_bindings;
  if (!Array.isArray(list) || !Array.isArray(bindings)) throw new Refusal("ref/prompts.json or ref/prompt_bindings.json has no list");
  return { list, bindings };
}

// One registered version, re-hashed. A template that does not hash to its template_sha256 never runs.
export function registeredVersion(registry, stage, version) {
  const v = registry.list.find((p) => p.stage === stage && p.version === version);
  if (!v) throw new Refusal(`${stage}@${version} is not registered in ref/prompts.json`);
  const sha = sha256Hex(canonicalJson(v.template));
  if (sha !== v.template_sha256) throw new Refusal(`${stage}@${version} does not hash to its template_sha256`);
  return { stage, version, stamp: `${stage}@${version}`, model: v.model, template: v.template, template_sha256: sha };
}

// The versions to run: the bound ones for scenario 7049689 by default, or --versions outline@N,draft@M naming other
// registered versions of the same two stages.
export function versionsToRun(registry, spec) {
  const pick = {};
  for (const [kind, stage] of Object.entries(STAGES)) {
    const b = registry.bindings.find((x) => Number(x.scenario_id) === SCENARIO_ID && x.module_id === STAGE_MODULE[kind]);
    if (!b || b.stage !== stage) throw new Refusal(`no binding of module ${STAGE_MODULE[kind]} of ${SCENARIO_ID} to ${stage}`);
    pick[kind] = b.version;
  }
  const bound = { ...pick };
  if (spec) {
    for (const part of spec.split(",")) {
      const m = part.trim().match(/^(outline|draft)@([0-9]+)$/);
      if (!m) throw new Refusal(`--versions takes outline@N,draft@M, not ${part}`);
      pick[m[1]] = Number(m[2]);
    }
  }
  const one = (kind) => {
    const b = registeredVersion(registry, STAGES[kind], bound[kind]);
    return { ...registeredVersion(registry, STAGES[kind], pick[kind]), bound: pick[kind] === bound[kind],
      bound_version: { stamp: b.stamp, model: b.model, template_sha256: b.template_sha256 } };
  };
  return { outline: one("outline"), draft: one("draft") };
}

export function loadSnapshot() {
  const bp = readJson(SNAPSHOT);
  const manifest = readJson("blueprints/manifest.json");
  const entry = (manifest.scenarios || []).find((s) => Number(s.id) === SCENARIO_ID);
  const index = {};
  const walk = (flow) => {
    for (const m of flow || []) {
      index[m.id] = m;
      for (const r of m.routes || []) walk(r.flow);
    }
  };
  walk(bp.flow);
  return { bp, index, version: entry ? entry.current_version : null };
}

// --- The grounding and validator arguments, pinned ------------------------------------------------------------------
// The exact v8 mappers of module 4 (ff13.drafting_context) and module 11 (ff13.validate_draft), and the module 10 call
// row fields that feed validator arguments @09 to @16. db.mjs builds its argument lists from these tables through
// ARG_SOURCES, and snapshotProblems holds them equal to the snapshot, so a blueprint change to any argument refuses
// --check until this file and db.mjs change in a reviewed commit.
export const STAMP_MODULE = 10;
export const GROUND_ARGS = {
  "@01:text": "{{1.id}}",
  "@02:text": "{{var.scenario.executionId}}",
  "@03:text": "{{1.`Visa Code`}}",
  "@04:text": "{{1.`Document Code`}}",
  "@05:text": '{{if(1.`Synthetic Test Case`; "true"; "false")}}',
};
export const VALIDATE_ARGS = {
  "@01:text": "{{1.id}}",
  "@02:text": "{{var.scenario.executionId}}",
  "@03:text": "{{1.`Visa Code`}}",
  "@04:text": "{{1.`Document Code`}}",
  "@05:text": TXT9,
  "@06:text": "{{1.Name}}",
  "@07:text": "{{1.`Case Facts`}}",
  "@08:text": "",
  "@09:text": "{{10.`Model Requested`}}",
  "@10:text": "{{10.`Model Served`}}",
  "@11:text": "{{10.`Stop Reason`}}",
  "@12:text": "{{10.`Prompt Version`}}",
  "@13:text": "{{10.`Prompt SHA256`}}",
  "@14:text": "{{10.`Input Tokens`}}",
  "@15:text": "{{10.`Output Tokens`}}",
  "@16:text": "{{10.`Message ID`}}",
};
// Module 10 (System Logs create) fields read by the validator, by name, with their field IDs (audit/airtable_links.json)
// and what the record maps. A function gives the literal from the bound draft version.
export const STAMP_FIELDS = {
  "Model Requested": { fid: "fldq1y6OZLEAMYkPM", value: (b) => b.model },
  "Model Served": { fid: "fld7htgTc1MkVD1yo", value: () => "{{9.model}}" },
  "Stop Reason": { fid: "fldsahnEv0stTIhdv", value: () => "{{9.stop_reason}}" },
  "Prompt Version": { fid: "fldH5cTvDOJf8p5WP", value: (b) => b.stamp },
  "Prompt SHA256": { fid: "fld2U85K5YDzw8TzM", value: (b) => b.template_sha256 },
  "Input Tokens": { fid: "fldzWonoDyQIVi5pp", value: () => "{{9.usage.input_tokens}}" },
  "Output Tokens": { fid: "fldH27E3yx8cwGkGv", value: () => "{{9.usage.output_tokens}}" },
  "Message ID": { fid: "fld0ztD4t19YbrJLU", value: () => "{{9.id}}" },
};
// What the runner sends for each pinned expression: t is the transaction context (record, exec, visa, doc, flag), v
// the validator inputs from the draft call. An expression with no source refuses.
export const ARG_SOURCES = {
  "{{1.id}}": (t) => t.record,
  "{{var.scenario.executionId}}": (t) => t.exec,
  "{{1.`Visa Code`}}": (t) => t.visa,
  "{{1.`Document Code`}}": (t) => t.doc,
  '{{if(1.`Synthetic Test Case`; "true"; "false")}}': (t) => (t.flag ? "true" : "false"),
  [TXT9]: (t, v) => v.draft,
  "{{1.Name}}": (t, v) => v.name,
  "{{1.`Case Facts`}}": (t, v) => v.case_facts,
  "": () => "",
  "{{10.`Model Requested`}}": (t, v) => v.model_requested,
  "{{10.`Model Served`}}": (t, v) => v.model_served,
  "{{10.`Stop Reason`}}": (t, v) => v.stop_reason,
  "{{10.`Prompt Version`}}": (t, v) => v.prompt_version,
  "{{10.`Prompt SHA256`}}": (t, v) => v.prompt_sha256,
  "{{10.`Input Tokens`}}": (t, v) => v.input_tokens,
  "{{10.`Output Tokens`}}": (t, v) => v.output_tokens,
  "{{10.`Message ID`}}": (t, v) => v.request_id,
};

// The positional argument list for one stored procedure, in @NN order.
export function argList(table, t, v = {}) {
  return Object.keys(table).sort().map((k) => {
    const src = ARG_SOURCES[table[k]];
    if (!src) throw new Refusal(`no runner source for argument ${k} ${table[k]}`);
    return src(t, v);
  });
}

// Check R2's test rerun here, so a stale pull or an edited template is caught: modules 6 and 9 hold the bound mapper,
// module 4 is the grounding stored procedure and module 11 the validator, both with exactly the pinned arguments, and
// module 10 maps the validator's stamp fields as pinned. Returns a list of problems.
export function snapshotProblems(snapshot, versions) {
  const out = [];
  const g = snapshot.index[GROUNDING_MODULE];
  if (!g || g.module !== "postgres:StoredProcedure" || g.parameters?.spname !== GROUNDING_SP) out.push(`module ${GROUNDING_MODULE} is not ${GROUNDING_SP}`);
  else if (canonicalJson(g.mapper) !== canonicalJson(GROUND_ARGS)) out.push(`module ${GROUNDING_MODULE} arguments differ from GROUND_ARGS (update chain.mjs and db.mjs in a reviewed commit)`);
  const v = snapshot.index[VALIDATOR_MODULE];
  if (!v || v.module !== "postgres:StoredProcedure" || v.parameters?.spname !== '"ff13"."validate_draft"') out.push(`module ${VALIDATOR_MODULE} is not ff13.validate_draft`);
  else if (canonicalJson(v.mapper) !== canonicalJson(VALIDATE_ARGS)) out.push(`module ${VALIDATOR_MODULE} arguments differ from VALIDATE_ARGS (update chain.mjs and db.mjs in a reviewed commit)`);
  const s = snapshot.index[STAMP_MODULE];
  if (!s || s.module !== "airtable:ActionCreateRecord") {
    out.push(`module ${STAMP_MODULE} is not the call row create`);
  } else {
    for (const [name, f] of Object.entries(STAMP_FIELDS)) {
      const want = f.value(versions.draft.bound_version);
      if (s.mapper?.record?.[f.fid] !== want) out.push(`module ${STAMP_MODULE} ${name} (${f.fid}) does not map ${JSON.stringify(want)}`);
    }
  }
  for (const kind of ["outline", "draft"]) {
    const m = snapshot.index[STAGE_MODULE[kind]];
    if (!m || m.module !== "anthropic-claude:createAMessage") {
      out.push(`module ${STAGE_MODULE[kind]} is not a Claude module`);
    } else if (versions[kind].bound && canonicalJson(m.mapper) !== canonicalJson(versions[kind].template)) {
      out.push(`module ${STAGE_MODULE[kind]} mapper differs from ${versions[kind].stamp} (stale pull or unregistered edit)`);
    }
  }
  return out;
}

// --- Make routing, predicted -----------------------------------------------------------------------------------------
// The filters below are copied from the snapshot (v8, 2026-11-16) and a unit test holds them equal to it, so a later
// blueprint change the table misses fails the test. Routers: route heads in order, and the fallback index.
export const ROUTERS = {
  3: { heads: [4, 40], else: 1 },
  5: { heads: [6, 37], else: null },
  8: { heads: [9, 34], else: 1 },
  12: { heads: [13, 20, 24, 28, 31], else: 4 },
  13: { heads: [14, 17], else: 1 },
};
// A route head that runs and then continues into a router on the same flow.
const CONTINUES = { 4: 5, 6: 8, 9: 12, 13: 13 };
export const TERMINALS = [14, 17, 20, 24, 28, 31, 34, 37, 40];
export const ROUTE_NAMES = {
  14: "NO DRAFT, inputs read as instructions", 17: "NO DRAFT, facts", 20: "test Doc, pass with flags", 24: "production Doc",
  28: "validator reject", 31: "verdict fallback, Draft Failed", 34: "outline not end_turn, Draft Failed", 37: "grounding refused",
  40: "preconditions not met",
};
export const ROUTE_FILTERS = {
  4: { name: "Preconditions met (Name, RCIC of Record and Case Facts hold a non-space character)", conditions: [[
    { a: "{{1.`RCIC of Record`}}", b: "\\S", o: "text:pattern" }, { a: "{{1.`Case Facts`}}", b: "\\S", o: "text:pattern" },
    { a: "{{1.Name}}", b: "\\S", o: "text:pattern" }, { a: "{{1.`Document Code`}}", b: "SUBMISSION-LETTER", o: "text:equal" }]] },
  6: { name: "Grounding allowed", conditions: [[{ a: "{{4.allowed}}", b: "true", o: "text:equal" }]] },
  9: { name: "Outline ended with end_turn", conditions: [[{ a: "{{6.stop_reason}}", b: "end_turn", o: "text:equal" }]] },
  13: { name: "Draft is a NO DRAFT line", conditions: [[{ a: TXT9, b: "NO DRAFT PREPARED", o: "text:startwith" }]] },
  14: { name: "Inputs read as instructions", conditions: [[{ a: TXT9, b: "NO DRAFT PREPARED. The inputs", o: "text:startwith" }]] },
  20: { name: "Test mode, pass with flags", conditions: [[
    { a: TXT9, b: "NO DRAFT PREPARED", o: "text:notstartwith" }, { a: "{{9.stop_reason}}", b: "end_turn", o: "text:equal" },
    { a: "{{4.gate_mode}}", b: "test", o: "text:equal" }, { a: "{{11.review_note}}", b: "F-F13 TEST MODE", o: "text:startwith" },
    { a: "{{11.verdict}}", b: "pass_with_flags", o: "text:equal" }]] },
  24: { name: "Production mode, pass or pass with flags, client folder set", conditions: [
    [{ a: TXT9, b: "NO DRAFT PREPARED", o: "text:notstartwith" }, { a: "{{9.stop_reason}}", b: "end_turn", o: "text:equal" },
      { a: "{{4.gate_mode}}", b: "production", o: "text:equal" }, { a: "{{11.review_note}}", b: "F-F13 TEST MODE", o: "text:notstartwith" },
      { a: "{{11.verdict}}", b: "pass", o: "text:equal" }, { a: "{{1.`Drive Folder ID`}}", o: "exist" }],
    [{ a: TXT9, b: "NO DRAFT PREPARED", o: "text:notstartwith" }, { a: "{{9.stop_reason}}", b: "end_turn", o: "text:equal" },
      { a: "{{4.gate_mode}}", b: "production", o: "text:equal" }, { a: "{{11.review_note}}", b: "F-F13 TEST MODE", o: "text:notstartwith" },
      { a: "{{11.verdict}}", b: "pass_with_flags", o: "text:equal" }, { a: "{{1.`Drive Folder ID`}}", o: "exist" }]] },
  28: { name: "Validator reject, mode consistent", conditions: [
    [{ a: TXT9, b: "NO DRAFT PREPARED", o: "text:notstartwith" }, { a: "{{4.gate_mode}}", b: "test", o: "text:equal" },
      { a: "{{11.review_note}}", b: "F-F13 TEST MODE", o: "text:startwith" }, { a: "{{11.verdict}}", b: "reject", o: "text:equal" }],
    [{ a: TXT9, b: "NO DRAFT PREPARED", o: "text:notstartwith" }, { a: "{{4.gate_mode}}", b: "production", o: "text:equal" },
      { a: "{{11.review_note}}", b: "F-F13 TEST MODE", o: "text:notstartwith" }, { a: "{{11.verdict}}", b: "reject", o: "text:equal" }]] },
  37: { name: "Grounding refused", conditions: [[{ a: "{{4.allowed}}", b: "true", o: "text:notequal" }]] },
};

// The operand values Make would see, from the case and the results so far. Undefined means the module never ran.
export function operandValues({ inputs, grounding, outline, draft, validation }) {
  return {
    "{{1.`RCIC of Record`}}": inputs.rcic_of_record,
    "{{1.`Case Facts`}}": inputs.case_facts,
    "{{1.Name}}": inputs.name,
    "{{1.`Document Code`}}": inputs.document_code,
    "{{1.`Drive Folder ID`}}": undefined,
    "{{4.allowed}}": grounding?.allowed,
    "{{4.gate_mode}}": grounding?.gate_mode,
    "{{6.stop_reason}}": outline?.stop_reason,
    "{{9.stop_reason}}": draft?.stop_reason,
    [TXT9]: draft ? draft.text : undefined,
    "{{11.review_note}}": validation?.review_note,
    "{{11.verdict}}": validation?.verdict,
  };
}

function condition(c, values) {
  if (!Object.prototype.hasOwnProperty.call(values, c.a)) throw new Refusal(`route table: no value for operand ${c.a}`);
  const v = values[c.a];
  const s = v === undefined || v === null ? "" : String(v);
  switch (c.o) {
    case "text:equal": return s === c.b;
    case "text:notequal": return s !== c.b;
    case "text:startwith": return s.startsWith(c.b);
    case "text:notstartwith": return !s.startsWith(c.b);
    case "text:pattern": return new RegExp(c.b).test(s);
    case "exist": return s !== "";
    default: throw new Refusal(`route table: operator ${c.o} is not modelled`);
  }
}

export const filterPasses = (f, values) => !f || f.conditions.some((group) => group.every((c) => condition(c, values)));

// Every terminal route head Make would run, in order. Make runs every route whose filter passes, and the fallback only
// when no other route passed. A continuation stops where the module it needs never ran.
export function predictRoutes(values) {
  const out = [];
  const runRouter = (id) => {
    const r = ROUTERS[id];
    const taken = r.heads.filter((h, i) => i !== r.else && filterPasses(ROUTE_FILTERS[h], values));
    if (!taken.length && r.else !== null) taken.push(r.heads[r.else]);
    for (const h of taken) {
      if (TERMINALS.includes(h)) out.push(h);
      else if (h === 13) runRouter(13);
      else if (CONTINUES[h] !== undefined && stillRuns(h, values)) runRouter(CONTINUES[h]);
    }
  };
  runRouter(3);
  return out;
}

// A route continues past its head only when that module produced a result (grounding, outline or draft).
function stillRuns(head, values) {
  if (head === 4) return values["{{4.allowed}}"] !== undefined;
  if (head === 6) return values["{{6.stop_reason}}"] !== undefined;
  if (head === 9) return values["{{9.stop_reason}}"] !== undefined && values["{{11.verdict}}"] !== undefined;
  return true;
}

// --- Price ---------------------------------------------------------------------------------------------------------
// USD per million tokens, claude-api skill 2.1.325 model table (cached 2026-11-03): Opus 5.5 input 4, output 20, cache
// reads 0.20. Cache writes at 1.25 times input (5-minute TTL). inference_geo us at 1.1 times (decisions doc).
export const PRICING = {
  source: "claude-api skill 2.1.325, model table cached 2026-11-03",
  models: { "claude-opus-5-5": { input: 4, output: 20, cache_write: 5, cache_read: 0.2 } },
  us_geo_multiplier: 1.1,
};
// Measured on live run 3 (2026-11-15), per case, used for the projection until a run measures its own mean.
export const MEASURED_USD_PER_CASE = 0.27;

export function usageUsd(model, usage) {
  const p = PRICING.models[model];
  if (!p) throw new Refusal(`no price for ${model}`);
  if (!usage) return 0;
  const n = (k) => Number(usage[k] || 0);
  const usd = (n("input_tokens") * p.input + n("output_tokens") * p.output + n("cache_creation_input_tokens") * p.cache_write
    + n("cache_read_input_tokens") * p.cache_read) / 1e6;
  return usage.inference_geo === "us" ? usd * PRICING.us_geo_multiplier : usd;
}

// The most a call can cost: the input at about 2 characters per token (well above the real count) and every output
// token max_tokens allows, at the us multiplier. --max-usd stops before a call whose bound would pass the cap.
export function worstCaseUsd(body) {
  const p = PRICING.models[body.model];
  if (!p) throw new Refusal(`no price for ${body.model}`);
  const chars = body.system.length + body.messages.reduce((a, m) => a + m.content.length, 0)
    + (body.output_config?.format ? JSON.stringify(body.output_config.format).length : 0);
  return ((Math.ceil(chars / 2) * p.input + body.max_tokens * p.output) / 1e6) * PRICING.us_geo_multiplier;
}
