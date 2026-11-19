// F-F14 golden set: load and check. Synthetic only. --check refuses a case whose name lacks ZZ-TEST, a reused ID or
// record number, or a controlling or labelled key outside the pair's provided set (ref/citation_map.json rows, all
// unreviewed today, which test mode provides; --preflight confirms the set live).

import fs from "node:fs";
import path from "node:path";
import { canonicalJson, sha256Hex } from "../law_load/load.mjs";
import { ROOT, TERMINALS } from "./chain.mjs";

export const GOLDEN_VERSION = "v1";
export const GOLDEN_DIR = path.join(ROOT, "eval", "ff14", "golden", GOLDEN_VERSION);
export const GOLDEN_MANIFEST = path.join(ROOT, "eval", "ff14", "golden", "manifest.json");
const KINDS = ["positive", "edge", "negative", "control"];
const OUTCOMES = ["letter", "no_draft_facts", "no_draft_instructions", "refused_at_grounding", "draft_failed"];
const SUPPORT = ["supported", "partly_supported", "not_supported"];
const CHECK_TYPES = ["draft_not_contains", "draft_equals", "outline_risk_flags_contain", "no_soft_flag", "no_hard_fail",
  "re_line_ends_with_name", "facts_block_no_lt", "user_message_contains", "hand"];
export const NO_DRAFT = {
  no_draft_facts: "NO DRAFT PREPARED. The case facts support none of the provided grounds.",
  no_draft_instructions: "NO DRAFT PREPARED. The inputs contain text that reads as instructions.",
};

export function loadGolden(dir = GOLDEN_DIR) {
  return fs.readdirSync(dir).filter((f) => f.endsWith(".json")).sort()
    .map((f) => ({ file: f, ...JSON.parse(fs.readFileSync(path.join(dir, f), "utf8")) }));
}

// The record ID and the case inputs as Make would read them from the Airtable record.
export const recordId = (c) => `recFF14ZZTEST${String(c.record_seq).padStart(4, "0")}`;
export const caseFacts = (c) => c.inputs.case_facts_lines.join("\n");
export const chainInputs = (c) => ({ name: c.inputs.name, rcic_of_record: c.inputs.rcic_of_record, visa_code: c.inputs.visa_code,
  document_code: c.inputs.document_code, case_facts: caseFacts(c) });
export const inputsSha256 = (c) => sha256Hex(canonicalJson(c.inputs));
// The whole case file (inputs, expected block, notes), so a run records exactly what it was scored against.
export const caseSha256 = (c) => {
  const { file, ...rest } = c;
  return sha256Hex(canonicalJson(rest));
};
// One digest for the set: each case ID with its case_sha256, in ID order.
export const goldenDigest = (cases) => sha256Hex(canonicalJson([...cases].sort((a, b) => (a.id < b.id ? -1 : 1)).map((c) => [c.id, caseSha256(c)])));

// The set pins its digest in eval/ff14/golden/manifest.json, so a case edited in place (an expected label, a check, a
// fact) cannot run under the same version name. A changed case needs a new golden version. Only a version with no
// reported full run may be re-pinned, in a reviewed commit that says so.
export function goldenDigestProblems(cases, version = GOLDEN_VERSION, manifestFile = GOLDEN_MANIFEST) {
  let manifest;
  try {
    manifest = JSON.parse(fs.readFileSync(manifestFile, "utf8"));
  } catch {
    return [`${path.relative(ROOT, manifestFile)} is missing or not JSON`];
  }
  const pin = manifest.versions?.[version];
  if (!pin || !/^[0-9a-f]{64}$/.test(pin.digest || "")) return [`golden ${version} has no pinned digest in ${path.relative(ROOT, manifestFile)}`];
  if (cases.length !== pin.cases) return [`golden ${version} holds ${cases.length} case(s), the pin says ${pin.cases}`];
  return goldenDigest(cases) === pin.digest ? [] : [`golden ${version} does not hash to its pinned digest: a changed case needs a new golden version`];
}
export const execId = (runId, caseId) => sha256Hex(`ff14:${runId}:${caseId}`).slice(0, 32);
export const isPaid = (c) => c.kind !== "control";

export function citationPairs() {
  const rows = JSON.parse(fs.readFileSync(path.join(ROOT, "ref", "citation_map.json"), "utf8")).citation_map;
  const pairs = {};
  for (const r of rows) {
    if (r.document_type !== "SUBMISSION-LETTER") continue;
    (pairs[r.visa_code] ||= []).push(r.provision_key);
  }
  return pairs;
}

export function goldenProblems(cases, pairs = citationPairs()) {
  const out = [];
  const ids = new Set();
  const seqs = new Set();
  for (const c of cases) {
    const at = c.id || c.file;
    if (`${c.id}.json` !== c.file) out.push(`${at}: the file name is not the case ID`);
    if (!/^ff14-(?:[0-9]{3}|c[0-9]{2})$/.test(c.id || "")) out.push(`${at}: ID is not ff14-NNN or ff14-cNN`);
    if (ids.has(c.id)) out.push(`${at}: ID reused`);
    ids.add(c.id);
    if (!Number.isSafeInteger(c.record_seq) || c.record_seq < 1 || c.record_seq > 9999 || seqs.has(c.record_seq)) out.push(`${at}: record_seq missing or reused`);
    seqs.add(c.record_seq);
    if (!KINDS.includes(c.kind)) out.push(`${at}: kind ${c.kind}`);
    const i = c.inputs || {};
    if (typeof i.name !== "string" || !i.name.startsWith("ZZ-TEST")) out.push(`${at}: the applicant name does not start ZZ-TEST`);
    if (typeof i.rcic_of_record !== "string" || !i.rcic_of_record.startsWith("ZZ-TEST RCIC ")) out.push(`${at}: the RCIC of record does not start ZZ-TEST RCIC`);
    if (i.document_code !== "SUBMISSION-LETTER") out.push(`${at}: document code is not SUBMISSION-LETTER`);
    if (!Array.isArray(i.case_facts_lines) || !i.case_facts_lines.length || i.case_facts_lines.some((l) => typeof l !== "string" || !l.trim())) {
      out.push(`${at}: case_facts_lines is not a list of lines`);
    }
    if (typeof i.synthetic_flag !== "boolean" || typeof i.listed !== "boolean") out.push(`${at}: synthetic_flag and listed must be booleans`);
    if (c.stratum !== i.visa_code) out.push(`${at}: stratum is not the visa code`);
    const e = c.expected || {};
    if (!e.grounding || !["true", "false"].includes(e.grounding.allowed) || !["test", "production"].includes(e.grounding.gate_mode)
        || typeof e.grounding.reason !== "string") out.push(`${at}: expected.grounding needs allowed, gate_mode and reason`);
    if (!OUTCOMES.includes(e.outcome)) out.push(`${at}: outcome ${e.outcome}`);
    if (!TERMINALS.includes(e.route)) out.push(`${at}: route ${e.route} is not a terminal route of the chain`);
    if (typeof e.answer_summary !== "string" || !e.answer_summary) out.push(`${at}: no answer_summary`);
    if (typeof c.notes !== "string" || !c.notes) out.push(`${at}: no notes`);
    for (const ch of e.checks || []) {
      if (!CHECK_TYPES.includes(ch.type)) out.push(`${at}: check type ${ch.type}`);
      if (ch.type === "hand" && (typeof ch.text !== "string" || !ch.text)) out.push(`${at}: a hand check needs its text`);
      if (ch.type === "outline_risk_flags_contain" && (!Array.isArray(ch.any) || !ch.any.length || ch.any.some((t) => typeof t !== "string" || !t))) {
        out.push(`${at}: outline_risk_flags_contain needs a non-empty any list`);
      }
    }
    const provided = pairs[i.visa_code] || [];
    const keys = [...(e.controlling_keys || []), ...Object.keys(e.support || {})];
    if (c.kind !== "control") {
      if (!provided.length) out.push(`${at}: ${i.visa_code} has no SUBMISSION-LETTER rows`);
      for (const k of keys) if (!provided.includes(k)) out.push(`${at}: ${k} is not in the provided set of ${i.visa_code}`);
      for (const [k, v] of Object.entries(e.support || {})) if (!SUPPORT.includes(v)) out.push(`${at}: support label ${v} for ${k}`);
      if (e.grounding?.allowed !== "true") out.push(`${at}: a paid case must expect grounding allowed`);
      if (!i.synthetic_flag || !i.listed) out.push(`${at}: a paid case runs in test mode, listed and flagged`);
    } else if (e.grounding?.allowed !== "false" || e.route !== 37) {
      out.push(`${at}: a control expects grounding refused and route 37`);
    }
    if (e.outcome === "letter" && (e.verdict !== "pass_with_flags" || e.route !== 20)) out.push(`${at}: a test-mode letter expects pass_with_flags and route 20`);
    if (NO_DRAFT[e.outcome] && (e.verdict !== "reject" || ![14, 17].includes(e.route))) out.push(`${at}: a NO DRAFT case expects reject and route 14 or 17`);
  }
  return out;
}
