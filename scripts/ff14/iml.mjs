// F-F14: the registered Make "Create a Prompt" mappers turned into Messages API requests.
//
// Two closed lists, both from specs/F-F14-evaluation-harness.md:
//   MAPPINGS      the seven Make IML expressions the bound drafting-chain templates use, matched on exact text.
//                 Anything else refuses. The runner never evaluates IML in general.
//   mapper keys   each mapper key becomes one request field by a fixed rule, and an unknown key refuses.
// API facts (claude-api skill 2.1.325, shared/ and typescript/): effort sits in output_config and Opus 5.5 defaults to
// medium, so the registered effort is always sent. output_config.format is the structured output parameter
// (output_format is deprecated). Opus 5.5 rejects thinking disabled, budget_tokens, sampling parameters and forced
// tool_choice with a 400. Server-side fallbacks are deliberately absent (specs/F-F10-prompts.md, model pin P2).

import { canonicalJson, sha256Hex } from "../law_load/load.mjs";

export class Refusal extends Error {}
// Stops the whole run, not only the case: an API error that would repeat, a leftover row, a lost database connection.
export class Fatal extends Error {}

// Audit P2 and P4 (audit_blueprints.CLAUDE_MODELS, CLAUDE_MIN_MAX_TOKENS).
export const CLAUDE_MODELS = { "claude-opus-5-5": 16000, "claude-haiku-5-5": 2048 };
export const EFFORTS = ["low", "medium", "high", "xhigh", "max"];

const lt = (s) => {
  if (typeof s !== "string") throw new Refusal("a mapped value is not text");
  return s.replace(/</g, " less than ");
};

// The first content block of type text, found by type and never by position (Opus returns thinking blocks first).
// Make's first(map(N.content; "text"; "type"; "text")) gives empty text when there is none.
export function firstText(message) {
  const b = (message?.content || []).find((x) => x && x.type === "text");
  return b ? b.text : "";
}

// Expression (exact text inside {{ }}) -> value from the case context.
//   ctx.inputs      { name, rcic_of_record, visa_code, document_code, case_facts }
//   ctx.provisions  the provisions text column of ff13.drafting_context, byte for byte
//   ctx.outline     the outline response message (stage 2 only)
export const MAPPINGS = {
  'replace(1.`Case Facts`; "/</g"; " less than ")': (ctx) => lt(need(ctx.inputs?.case_facts, "Case Facts")),
  'replace(1.Name; "/</g"; " less than ")': (ctx) => lt(need(ctx.inputs?.name, "Name")),
  'replace(1.`RCIC of Record`; "/</g"; " less than ")': (ctx) => lt(need(ctx.inputs?.rcic_of_record, "RCIC of Record")),
  "1.`Visa Code`": (ctx) => need(ctx.inputs?.visa_code, "Visa Code"),
  "1.`Document Code`": (ctx) => need(ctx.inputs?.document_code, "Document Code"),
  "4.provisions": (ctx) => need(ctx.provisions, "4.provisions"),
  'replace(first(map(6.content; "text"; "type"; "text")); "/</g"; " less than ")': (ctx) => {
    if (!ctx.outline) throw new Refusal("the draft template maps the outline, and no outline response is given");
    return lt(firstText(ctx.outline));
  },
};

function need(v, what) {
  if (typeof v !== "string") throw new Refusal(`no value for ${what}`);
  return v;
}

// Every {{ ... }} of a string, in order, with the text around it. Refuses a stray }}, a nested {{ and an unclosed {{.
export function scanMappings(text) {
  const parts = [];
  let i = 0;
  while (i < text.length) {
    const open = text.indexOf("{{", i);
    const plain = open === -1 ? text.slice(i) : text.slice(i, open);
    if (plain.includes("}}")) throw new Refusal("a stray }} outside a mapping");
    parts.push({ text: plain });
    if (open === -1) break;
    const close = text.indexOf("}}", open + 2);
    if (close === -1) throw new Refusal("a {{ with no closing }}");
    const expr = text.slice(open + 2, close);
    if (expr.includes("{{")) throw new Refusal("a nested {{ inside a mapping");
    parts.push({ expr });
    i = close + 2;
  }
  return parts;
}

export function fillString(text, ctx) {
  return scanMappings(text).map((p) => {
    if ("text" in p) return p.text;
    const fn = Object.prototype.hasOwnProperty.call(MAPPINGS, p.expr) ? MAPPINGS[p.expr] : null;
    if (!fn) throw new Refusal(`unknown mapping {{${p.expr}}}, add it to MAPPINGS in a reviewed commit with a test`);
    return fn(ctx);
  }).join("");
}

export const expressionsOf = (text) => scanMappings(text).filter((p) => "expr" in p).map((p) => p.expr);

const MAPPER_KEYS = new Set(["model", "effort", "system", "messages", "metadata", "thinking", "container", "max_tokens", "tool_choice", "outputFormat"]);
const isEmptyObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v) && Object.keys(v).length === 0;

// The registered template (a whole Make module mapper) and the case context -> the Messages API request body.
export function buildRequest(template, ctx) {
  if (!template || typeof template !== "object" || Array.isArray(template)) throw new Refusal("the template is not an object");
  for (const k of Object.keys(template)) {
    if (!MAPPER_KEYS.has(k)) throw new Refusal(`mapper key ${k} is not on the closed list`);
  }
  const { model, effort, system, messages, thinking, outputFormat } = template;
  if (!Object.prototype.hasOwnProperty.call(CLAUDE_MODELS, model)) throw new Refusal(`model ${JSON.stringify(model)} is not a pinned Claude model`);
  if (typeof system !== "string" || !system.length) throw new Refusal("system is not text");
  if (system.includes("{{") || system.includes("}}")) throw new Refusal("system holds a mapping");
  if (!EFFORTS.includes(effort)) throw new Refusal("effort is missing or not a known level");
  if (canonicalJson(thinking) !== canonicalJson({ type: "adaptive" })) throw new Refusal("thinking is not exactly adaptive");
  const mt = typeof template.max_tokens === "number" ? template.max_tokens
    : typeof template.max_tokens === "string" && /^[0-9]+$/.test(template.max_tokens) ? Number(template.max_tokens) : NaN;
  if (!Number.isSafeInteger(mt) || mt < CLAUDE_MODELS[model]) throw new Refusal(`max_tokens must be an integer of at least ${CLAUDE_MODELS[model]} on ${model}`);
  for (const k of ["metadata", "container", "tool_choice"]) {
    if (k in template && !isEmptyObject(template[k])) throw new Refusal(`${k} is set, only an empty object is dropped`);
  }
  if (!Array.isArray(messages) || messages.length !== 1) throw new Refusal("messages must hold exactly one item");
  const m = messages[0];
  if (!m || canonicalJson(Object.keys(m).sort()) !== canonicalJson(["content", "inputType", "role"]) || m.role !== "user" || m.inputType !== "single"
      || typeof m.content !== "string") {
    throw new Refusal("the message must be one single user text item");
  }
  const outputConfig = { effort };
  if (!outputFormat || typeof outputFormat !== "object") throw new Refusal("outputFormat is missing");
  if (outputFormat.type === "json_schema") {
    if (canonicalJson(Object.keys(outputFormat).sort()) !== canonicalJson(["schema", "type"])) throw new Refusal("outputFormat json_schema holds other keys");
    if (typeof outputFormat.schema !== "string" || outputFormat.schema.includes("{{")) {
      throw new Refusal("the json_schema schema must be JSON text with no mapping (P7)");
    }
    let schema;
    try {
      schema = JSON.parse(outputFormat.schema);
    } catch {
      throw new Refusal("the json_schema schema text does not parse");
    }
    if (!schema || typeof schema !== "object" || Array.isArray(schema)) throw new Refusal("the json_schema schema is not an object");
    outputConfig.format = { type: "json_schema", schema };
  } else if (outputFormat.type === "text") {
    if (Object.keys(outputFormat).length !== 1) throw new Refusal("outputFormat text holds other keys");
  } else {
    throw new Refusal(`outputFormat type ${JSON.stringify(outputFormat.type)} is not text or json_schema`);
  }
  return {
    model,
    max_tokens: mt,
    system,
    messages: [{ role: "user", content: fillString(m.content, ctx) }],
    thinking: { type: "adaptive" },
    output_config: outputConfig,
  };
}

export const requestSha256 = (body) => sha256Hex(canonicalJson(body));
