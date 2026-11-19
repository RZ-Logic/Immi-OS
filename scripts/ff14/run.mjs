#!/usr/bin/env node
// F-F14 (X-38): the offline Module F evaluation harness. Design: specs/F-F14-evaluation-harness.md.
//
//   node scripts/ff14/run.mjs --check                      registry, bindings, snapshot, golden set, mapping table. No network
//   node scripts/ff14/run.mjs --dry-run [--cases a,b] [--show <id>]
//                                                          --check, then grounding on PGlite (committed migrations, law/,
//                                                          ref/) and both requests built per case, printed without secrets.
//                                                          No API call, no live database
//   node scripts/ff14/run.mjs --preflight [--cases a,b]    --check, then every case's grounding on the live database in a
//                                                          rolled-back transaction. No Claude call
//   node scripts/ff14/run.mjs --run [--max-usd 12] [--cases a,b] [--versions outline@N,draft@M] [--db pglite]
//                                                          the evaluation. Writes eval/ff14/runs/<UTC timestamp>/
//   node scripts/ff14/run.mjs --check|--dry-run|--run --arms A0,A1,A2 --exemplars eval/x32/overlay/v1.json --versions draft@N
//                                                          X-32 arms (scripts/ff14/x32.mjs), one outline per case and a
//                                                          draft per arm. Writes eval/x32/runs/<UTC timestamp>/. Without
//                                                          --arms nothing below changes
//
// Secrets (ANTHROPIC_API_KEY, SUPABASE_DB_URL, SUPABASE_DB_PASSWORD, SUPABASE_DB_CA) come from the repo .env through the
// loader's one parser and are never printed, logged or written. Every file write is checked for them first. The runner
// refuses to start when ANTHROPIC_LOG is set or ANTHROPIC_BASE_URL names another host. No Make run, no Airtable record.

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import Anthropic from "@anthropic-ai/sdk";
import { sha256Hex } from "../law_load/load.mjs";
import {
  GROUNDING_MODULE, MEASURED_USD_PER_CASE, PRICING, ROOT, SCENARIO_ID, loadRegistry, loadSnapshot, operandValues, predictRoutes,
  snapshotProblems, usageUsd, versionsToRun, worstCaseUsd,
} from "./chain.mjs";
import { committedRows, ground, lawSources, leftoverRecords, liveClient, lostError, pgVersion, readSecrets, validate } from "./db.mjs";
import {
  GOLDEN_VERSION, caseSha256, chainInputs, execId, goldenDigest, goldenDigestProblems, goldenProblems, inputsSha256, isPaid, loadGolden,
  recordId,
} from "./golden.mjs";
import { caseMetrics, handgrade, reportMd, summarize } from "./grade.mjs";
import { Fatal, MAPPINGS, Refusal, buildRequest, expressionsOf, firstText, requestSha256 } from "./iml.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const RUNS = path.join(ROOT, "eval", "ff14", "runs");
const EXPECTED_VALIDATOR = "F-F13.2+F-F10";
const DRY_OUTLINE = { content: [{ type: "text", text: "[DRY RUN: the outline response text goes here]" }] };

export function parseArgs(argv) {
  const modes = ["--check", "--dry-run", "--preflight", "--run"].filter((m) => argv.includes(m));
  const opts = { mode: modes[0], cases: null, versions: null, maxUsd: 12, db: "live", show: null };
  const takes = { "--cases": "cases", "--versions": "versions", "--max-usd": "maxUsd", "--db": "db", "--show": "show",
    "--arms": "arms", "--exemplars": "exemplars" };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (modes.includes(a)) continue;
    if (!(a in takes) || i + 1 >= argv.length) throw new Refusal(`unknown or incomplete argument ${a}`);
    opts[takes[a]] = argv[++i];
  }
  if (modes.length !== 1) throw new Refusal("usage: run.mjs --check | --dry-run | --preflight | --run [--max-usd N] [--cases a,b] [--versions outline@N,draft@M] [--db pglite]");
  opts.maxUsd = Number(opts.maxUsd);
  if (!(opts.maxUsd > 0)) throw new Refusal("--max-usd must be a positive number");
  if (!["live", "pglite"].includes(opts.db)) throw new Refusal("--db is live or pglite");
  if (opts.db === "pglite" && opts.mode !== "--run") throw new Refusal("--db pglite goes with --run (--dry-run always uses PGlite)");
  if (opts.cases) opts.cases = opts.cases.split(",").map((s) => s.trim()).filter(Boolean);
  // X-32: --arms and --exemplars are set only when given, so the options of every other run are what they were.
  if (opts.exemplars !== undefined && opts.arms === undefined) throw new Refusal("--exemplars goes with --arms");
  if (opts.arms !== undefined && (opts.mode === "--preflight" || opts.db !== "live" || opts.show !== null)) {
    throw new Refusal("--arms goes with --check, --dry-run or --run on the live database, without --show");
  }
  return opts;
}

// --- Secrets ---------------------------------------------------------------------------------------------------------
export function secretValues(env) {
  const vals = [env.ANTHROPIC_API_KEY, env.SUPABASE_DB_PASSWORD, env.SUPABASE_DB_URL, env.SUPABASE_DB_CA];
  if (env.SUPABASE_DB_CA) vals.push(path.resolve(env.SUPABASE_DB_CA));
  return vals.filter((v) => typeof v === "string" && v.length >= 8);
}

export function guardText(text, secrets) {
  for (const s of secrets) if (text.includes(s)) throw new Fatal("refused to write or print output that holds a secret value");
  return text;
}

export function writeGuarded(file, value, secrets) {
  const text = typeof value === "string" ? value : JSON.stringify(value, null, 2) + "\n";
  guardText(text, secrets);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, text, { encoding: "utf8", flag: "wx" });
}

const scrub = (msg, secrets) => secrets.reduce((m, s) => m.split(s).join("[redacted]"), String(msg));

// The client always gets an explicit base URL, so the environment cannot redirect a request carrying the key. A base
// URL in the environment that names another host still refuses, since it shows a proxy setup this runner would bypass
// without saying so. ANTHROPIC_LOG refuses, since SDK logging could print request headers.
export function envGuard(e) {
  const base = e.ANTHROPIC_BASE_URL;
  if (base && base.replace(/\/+$/, "") !== "https://api.anthropic.com") throw new Refusal("ANTHROPIC_BASE_URL names a host other than https://api.anthropic.com. Unset it");
  if (e.ANTHROPIC_LOG) throw new Refusal("ANTHROPIC_LOG is set. Unset it, the runner logs no request");
}

// --- Check -----------------------------------------------------------------------------------------------------------
export function check({ versionsSpec = null, casesFilter = null } = {}) {
  const problems = [];
  const registry = loadRegistry();
  const versions = versionsToRun(registry, versionsSpec);
  const snapshot = loadSnapshot();
  problems.push(...snapshotProblems(snapshot, versions));
  for (const kind of ["outline", "draft"]) {
    const t = versions[kind].template;
    for (const expr of expressionsOf(t.messages?.[0]?.content || "")) {
      if (!Object.prototype.hasOwnProperty.call(MAPPINGS, expr)) problems.push(`${versions[kind].stamp}: unknown mapping {{${expr}}}`);
    }
  }
  let cases = loadGolden();
  problems.push(...goldenProblems(cases), ...goldenDigestProblems(cases));
  const digest = goldenDigest(cases);
  if (casesFilter) {
    const unknown = casesFilter.filter((id) => !cases.some((c) => c.id === id));
    if (unknown.length) problems.push(`--cases names unknown cases: ${unknown.join(", ")}`);
    cases = cases.filter((c) => casesFilter.includes(c.id));
  }
  // Every request builds with placeholder provisions, so a template the closed lists refuse fails here, before any spend.
  for (const c of cases.filter(isPaid)) {
    try {
      buildRequest(versions.outline.template, { inputs: chainInputs(c), provisions: "[]" });
      buildRequest(versions.draft.template, { inputs: chainInputs(c), provisions: "[]", outline: DRY_OUTLINE });
    } catch (e) {
      problems.push(`${c.id}: ${e.message}`);
    }
  }
  return { problems, registry, versions, snapshot, cases, digest };
}

// --- Request shapes for --dry-run ------------------------------------------------------------------------------------
export function requestShape(body) {
  const fmt = body.output_config.format;
  return {
    model: body.model,
    max_tokens: body.max_tokens,
    thinking: body.thinking,
    output_config: { effort: body.output_config.effort, ...(fmt ? { format: { type: fmt.type, schema_keys: Object.keys(fmt.schema.properties || {}) } } : {}) },
    system: { chars: body.system.length, sha256: sha256Hex(body.system) },
    messages: body.messages.map((m) => ({ role: m.role, chars: m.content.length, sha256: sha256Hex(m.content),
      head: m.content.slice(0, 160), tail: m.content.slice(-160) })),
    other_keys: Object.keys(body).filter((k) => !["model", "max_tokens", "thinking", "output_config", "system", "messages"].includes(k)),
    request_sha256: requestSha256(body),
  };
}

// --- Claude calls ----------------------------------------------------------------------------------------------------
export function anthropicClient(apiKey, extra = {}) {
  if (!apiKey) throw new Refusal("ANTHROPIC_API_KEY is not set in .env");
  return new Anthropic({ apiKey, baseURL: "https://api.anthropic.com", maxRetries: 0, timeout: 600000, logLevel: "off", ...extra });
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// One stage. maxRetries is 0 in the SDK, so every retry is visible here: 429, 5xx and connection errors at most twice
// with backoff. Any other API error stops the run (a request-shape or key problem repeats on every case). Before every
// attempt, budget.reserve refuses a call whose worst case would pass --max-usd.
export async function callStage(client, body, budget) {
  const attempts = [];
  for (let attempt = 0; attempt < 3; attempt++) {
    budget.reserve(worstCaseUsd(body));
    const t0 = Date.now();
    try {
      const msg = await client.messages.create(body);
      return { msg, latency_ms: Date.now() - t0, attempts };
    } catch (e) {
      const retryable = e instanceof Anthropic.APIConnectionError || e instanceof Anthropic.RateLimitError
        || (e instanceof Anthropic.APIError && Number(e.status) >= 500);
      attempts.push({ error: e?.constructor?.name || "Error", status: e?.status ?? null, request_id: e?.requestID ?? null });
      if (retryable && attempt < 2) {
        await sleep(2000 * 2 ** attempt);
        continue;
      }
      if (e instanceof Anthropic.APIError) throw new Fatal(`Anthropic ${e.constructor.name} ${e.status ?? ""} request ${e.requestID ?? "unknown"}`);
      throw e;
    }
  }
  throw new Fatal("unreachable");
}

function stageRecord(version, body, call) {
  const m = call.msg;
  const usage = JSON.parse(JSON.stringify(m.usage || {}));
  return {
    stamp: version.stamp, template_sha256: version.template_sha256, model_requested: body.model, max_tokens: body.max_tokens,
    request_sha256: requestSha256(body), user_message: body.messages[0].content,
    model_served: m.model, message_id: m.id, request_id: m._request_id ?? null, stop_reason: m.stop_reason,
    stop_details: m.stop_details ?? null, usage, usd: Number(usageUsd(m.model, usage).toFixed(6)), latency_ms: call.latency_ms,
    content_types: (m.content || []).map((b) => b.type), text: firstText(m), retries: call.attempts,
  };
}

export function makeBudget(maxUsd) {
  return {
    spent: 0,
    reserve(bound) {
      if (this.spent + bound > maxUsd) throw new Fatal(`stopped before a call: spent USD ${this.spent.toFixed(4)} plus this call's worst case USD ${bound.toFixed(4)} would pass --max-usd ${maxUsd}`);
    },
    add(usd) {
      this.spent += usd;
    },
  };
}

// --- One case --------------------------------------------------------------------------------------------------------
export async function runCase({ c, runId, versions, db, claude, budget, outlineSchema }) {
  const record = recordId(c);
  const exec = execId(runId, c.id);
  const inputs = chainInputs(c);
  const tx = { record, exec, visa: c.inputs.visa_code, doc: c.inputs.document_code, flag: c.inputs.synthetic_flag, listed: c.inputs.listed };
  const r = { case_id: c.id, kind: c.kind, category: c.category, stratum: c.stratum, record_id: record, exec_id: exec,
    inputs_sha256: inputsSha256(c), case_sha256: caseSha256(c), expected_route: c.expected.route, grounding: null, outline: null, draft: null, validation: null,
    predicted_routes: [], metrics: [], error: null };
  try {
    r.grounding = await ground(db, tx);
    if (r.grounding.allowed === "true" && isPaid(c)) {
      const ob = buildRequest(versions.outline.template, { inputs, provisions: r.grounding.provisions });
      const oc = await callStage(claude, ob, budget);
      r.outline = stageRecord(versions.outline, ob, oc);
      budget.add(r.outline.usd);
      if (r.outline.stop_reason === "end_turn") {
        const db2 = buildRequest(versions.draft.template, { inputs, provisions: r.grounding.provisions, outline: oc.msg });
        const dc = await callStage(claude, db2, budget);
        r.draft = stageRecord(versions.draft, db2, dc);
        budget.add(r.draft.usd);
        const u = r.draft.usage;
        r.validation = await validate(db, tx, r.grounding, {
          draft: r.draft.text, name: inputs.name, case_facts: inputs.case_facts, model_requested: r.draft.model_requested,
          model_served: r.draft.model_served, stop_reason: r.draft.stop_reason, prompt_version: versions.draft.stamp,
          prompt_sha256: versions.draft.template_sha256, input_tokens: String(u.input_tokens), output_tokens: String(u.output_tokens),
          request_id: r.draft.message_id,
        });
      }
    }
  } catch (e) {
    if (e instanceof Fatal) {
      r.error = e.message;
      r.fatal = true;
    } else if (db.lost) {
      r.error = lostError(db).message;
      r.fatal = true;
    } else {
      r.error = `${e?.code ? `SQLSTATE ${e.code} ` : ""}${e?.message || e}`;
    }
  }
  r.predicted_routes = predictRoutes(operandValues({ inputs, grounding: r.grounding, outline: r.outline, draft: r.draft,
    validation: r.validation && !r.validation.void ? r.validation : null }));
  r.metrics = caseMetrics(c, r, outlineSchema);
  return r;
}

// The cases in order. A Fatal case result, or a stop request between cases (Ctrl-C), ends the loop, and the caller then
// proves nothing persisted and writes the run files for the cases that ran.
export async function runLoop({ cases, runId, versions, db, claude, budget, outlineSchema, stop = { requested: false }, onCase = () => {} }) {
  const results = [];
  let validatorVersion = null;
  let stopped = null;
  for (const c of cases) {
    if (stop.requested) {
      stopped = "stop requested (Ctrl-C) before the next case";
      break;
    }
    const r = await runCase({ c, runId, versions, db, claude, budget, outlineSchema });
    const vv = r.validation?.detail?.validator_version;
    if (vv) {
      if (validatorVersion && vv !== validatorVersion) {
        r.error = `validator version changed mid-run (${validatorVersion} then ${vv})`;
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
    const dirty = execFileSync("git", ["status", "--porcelain", "--", "scripts/ff14", "eval/ff14/golden", "ref", "blueprints", "supabase"], { cwd: ROOT }).toString().trim();
    return { head, clean: dirty === "" };
  } catch {
    return { head: null, clean: false };
  }
}

const sdkVersion = () => JSON.parse(fs.readFileSync(path.join(HERE, "node_modules", "@anthropic-ai", "sdk", "package.json"), "utf8")).version;

// --- Modes -----------------------------------------------------------------------------------------------------------
async function main(argv) {
  const opts = parseArgs(argv);
  envGuard(process.env);
  const chk = check({ versionsSpec: opts.versions, casesFilter: opts.cases });
  if (opts.arms !== undefined) {
    // X-32: the arms check their problems themselves (an X-32 draft template maps the exemplar, which check() does not know).
    const { armsMain } = await import("./x32.mjs");
    return armsMain(opts, chk, { secretValues, guardText, writeGuarded, anthropicClient, makeBudget, callStage });
  }
  const paid = chk.cases.filter(isPaid).length;
  console.log(`check: ${chk.cases.length} case(s), ${paid} paid, outline ${chk.versions.outline.stamp}, draft ${chk.versions.draft.stamp}, snapshot of ${SCENARIO_ID} version ${chk.snapshot.version}`);
  if (chk.problems.length) {
    for (const p of chk.problems) console.log(`  problem: ${p}`);
    return 1;
  }
  if (opts.mode === "--check") {
    console.log("check: clean");
    return 0;
  }
  const outlineSchema = JSON.parse(chk.versions.outline.template.outputFormat.schema);

  if (opts.mode === "--dry-run") {
    const { pgliteClient } = await import("./pglite.mjs");
    const db = await pgliteClient();
    try {
      for (const c of chk.cases) {
        const tx = { record: recordId(c), exec: execId("dryrun", c.id), visa: c.inputs.visa_code, doc: c.inputs.document_code,
          flag: c.inputs.synthetic_flag, listed: c.inputs.listed };
        const g = await ground(db, tx);
        const out = { case: c.id, record: tx.record, grounding: { allowed: g.allowed, gate_mode: g.gate_mode, reason: g.reason, provision_keys: g.provision_keys } };
        if (g.allowed === "true" && isPaid(c)) {
          const ob = buildRequest(chk.versions.outline.template, { inputs: chainInputs(c), provisions: g.provisions });
          const dbody = buildRequest(chk.versions.draft.template, { inputs: chainInputs(c), provisions: g.provisions, outline: DRY_OUTLINE });
          out.outline_request = requestShape(ob);
          out.draft_request = requestShape(dbody);
          out.worst_case_usd = Number((worstCaseUsd(ob) + worstCaseUsd(dbody)).toFixed(4));
          if (opts.show === c.id) out.full = { outline_user: ob.messages[0].content, draft_user: dbody.messages[0].content };
        }
        console.log(JSON.stringify(out, null, 2));
      }
      const rows = await committedRows(db, chk.cases.map(recordId), chk.cases.map((c) => execId("dryrun", c.id)));
      console.log(`dry run: no API call made. PGlite rows left after rollback: ${JSON.stringify(rows)}`);
    } finally {
      await db.end();
    }
    return 0;
  }

  const env = readSecrets(path.join(ROOT, ".env"));
  const secrets = secretValues(env);
  const live = opts.db === "live";
  const out = (s) => console.log(scrub(guardText(s, secrets), secrets));
  let db;
  if (live) {
    db = await liveClient(env);
  } else {
    const { pgliteClient } = await import("./pglite.mjs");
    db = await pgliteClient();
  }
  const runId = new Date().toISOString().replace(/[-:]/g, "").replace(/\.\d+Z$/, "Z");
  const used = { records: chk.cases.map(recordId), execs: chk.cases.map((c) => execId(runId, c.id)) };
  let exit = 0;
  // Proof that nothing persisted: a fresh connection (live) counts committed rows for every record and execution ID used,
  // and reads the law sources there too, so the proof and run.json survive a lost run connection.
  const proveNothingPersisted = async () => {
    let committed;
    let law = null;
    if (live) {
      const fresh = await liveClient(env);
      try {
        committed = await committedRows(fresh, used.records, used.execs);
        law = await lawSources(fresh);
      } finally {
        await fresh.end();
      }
    } else {
      committed = await committedRows(db, used.records, used.execs);
      law = await lawSources(db);
    }
    const any = Object.values(committed).some((n) => n > 0);
    out(`${any ? "ALARM: committed rows found" : "committed rows after rollback (fresh connection)"}: ${JSON.stringify(committed)}`);
    return { committed, law };
  };
  try {
    // A committed harness record from an earlier run refuses the whole run before any case or spend.
    const left = await leftoverRecords(db);
    if (left.length) throw new Fatal(`ref.test_records holds ${left.length} committed harness record(s) from an earlier run (${left.join(", ")}). Stop and investigate before any run`);
    if (opts.mode === "--preflight") {
      let bad = 0;
      for (const c of chk.cases) {
        const g = await ground(db, { record: recordId(c), exec: execId(runId, c.id), visa: c.inputs.visa_code, doc: c.inputs.document_code,
          flag: c.inputs.synthetic_flag, listed: c.inputs.listed });
        const want = c.expected.grounding;
        const ok = g.allowed === want.allowed && g.gate_mode === want.gate_mode && g.reason === want.reason
          && (g.allowed !== "true" || JSON.stringify(g.provision_keys) === JSON.stringify(g.citation_status_keys));
        const keysOk = (c.expected.controlling_keys || []).every((k) => g.provision_keys.includes(k));
        if (!ok || !keysOk) bad++;
        out(`${c.id} ${ok && keysOk ? "ok" : "MISMATCH"}: allowed ${g.allowed}, ${g.gate_mode}, ${g.reason}, ${g.provision_keys.length} key(s)`);
      }
      const { committed } = await proveNothingPersisted();
      exit = bad || Object.values(committed).some((n) => n > 0) ? 1 : 0;
      return exit;
    }

    // --run
    const claude = anthropicClient(env.ANTHROPIC_API_KEY);
    const budget = makeBudget(opts.maxUsd);
    out(`run ${runId}: ${paid} paid case(s), projected USD ${(paid * MEASURED_USD_PER_CASE).toFixed(2)} at the measured ${MEASURED_USD_PER_CASE} per case, cap --max-usd ${opts.maxUsd}${live ? "" : ", PGLITE (development only, not a reported result)"}`);
    const dir = path.join(RUNS, runId);
    const started = new Date().toISOString();
    // Ctrl-C once: finish the current case, then prove and write. A second Ctrl-C ends the process (rows stay safe, the
    // server aborts an open transaction, but the proof and run files are lost).
    const stop = { requested: false };
    process.once("SIGINT", () => {
      stop.requested = true;
      console.log("ff14: stop requested, finishing the current case, then the proof and the run files. Ctrl-C again to abort");
    });
    const { results, validatorVersion, stopped } = await runLoop({
      cases: chk.cases, runId, versions: chk.versions, db, claude, budget, outlineSchema, stop,
      onCase: (r, c) => {
        if (r.error) r.error = scrub(r.error, secrets);
        writeGuarded(path.join(dir, "cases", `${c.id}.json`), r, secrets);
        const fails = r.metrics.filter((m) => m.pass === false).map((m) => m.id);
        out(`${c.id}: grounding ${r.grounding?.allowed ?? "none"}, outline ${r.outline?.stop_reason ?? "-"}, draft ${r.draft?.stop_reason ?? "-"}, verdict ${r.validation?.verdict ?? "-"}, route ${r.predicted_routes.join(",") || "-"} (expected ${c.expected.route}), USD ${((r.outline?.usd || 0) + (r.draft?.usd || 0)).toFixed(4)}${fails.length ? `, failed ${fails.join(" ")}` : ""}${r.error ? `, error: ${r.error}` : ""}`);
      },
    });
    if (stopped) {
      exit = 1;
      out(`run stopped early: ${scrub(stopped, secrets)}`);
    }
    const { committed, law } = await proveNothingPersisted();
    if (Object.values(committed).some((n) => n > 0)) exit = 1;
    const git = gitState();
    const run = {
      run_id: runId, started, ended: new Date().toISOString(), database: live ? "live Supabase (owner role, rolled back)" : "PGlite (development only)",
      git_head: git.head, git_clean: git.clean, runner: "scripts/ff14/run.mjs", sdk: { "@anthropic-ai/sdk": sdkVersion(), pg: pgVersion() },
      scenario_id: SCENARIO_ID, snapshot_version: chk.snapshot.version, grounding_module: GROUNDING_MODULE,
      versions: Object.fromEntries(["outline", "draft"].map((k) => [k, { stamp: chk.versions[k].stamp, template_sha256: chk.versions[k].template_sha256, bound: chk.versions[k].bound }])),
      validator_version: validatorVersion, validator_version_expected: EXPECTED_VALIDATOR,
      law_sources: law, golden_version: GOLDEN_VERSION, golden_digest: chk.digest, cases: chk.cases.map((c) => c.id),
      cases_run: results.map((r) => r.case_id), stopped_early: stopped ? scrub(stopped, secrets) : null, pricing: PRICING,
      max_usd: opts.maxUsd, spent_usd: Number(budget.spent.toFixed(6)), committed_rows: committed, exit,
    };
    const summary = summarize(results);
    const hg = handgrade(run, results, chk.cases);
    writeGuarded(path.join(dir, "run.json"), run, secrets);
    writeGuarded(path.join(dir, "summary.json"), summary, secrets);
    writeGuarded(path.join(dir, "report.md"), reportMd(run, results, summary), secrets);
    writeGuarded(path.join(dir, "handgrade.md"), hg.md, secrets);
    writeGuarded(path.join(dir, "handgrade.json"), hg.json, secrets);
    out(`run ${runId} done: spent USD ${budget.spent.toFixed(4)}, committed rows ${JSON.stringify(committed)}, results in ${path.relative(ROOT, dir)}`);
    if (validatorVersion && validatorVersion !== EXPECTED_VALIDATOR) out(`note: validator version ${validatorVersion}, expected ${EXPECTED_VALIDATOR}`);
    return exit;
  } finally {
    await db.end();
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (e) => {
      const env = (() => {
        try {
          return readSecrets(path.join(ROOT, ".env"));
        } catch {
          return {};
        }
      })();
      const msg = e instanceof Refusal || e instanceof Fatal ? e.message : `${e?.code ? `SQLSTATE ${e.code} ` : ""}${e?.name || "Error"}: ${e?.message || e}`;
      console.error(`ff14: ${scrub(msg, secretValues(env))}`);
      process.exit(1);
    },
  );
}
