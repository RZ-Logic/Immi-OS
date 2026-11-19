#!/usr/bin/env node
// Gives ff13_make (F-F13.1, the role Make's PostgreSQL connection logs in as) a fresh random password, then proves
// it works through the pooler. Run it to set the first password and again to rotate one.
//
//   node scripts/law_load/make_role.mjs
//
// The password is generated here, sent to Postgres only as a SCRAM-SHA-256 verifier (log_statement=ddl logs
// ALTER ROLE, so a plain password would land in the database log), and copied to the Windows clipboard for
// Rizwan to paste into the Make connection. It is never printed, written to disk or kept. Clear the clipboard
// afterwards, and turn off clipboard history (Win+V) first if it is on. A rotation breaks the old Make connection
// until the new password is pasted there.
//
// The admin connection is load.mjs's: the repo .env, TLS verified against SUPABASE_DB_CA. The probe connects as
// ff13_make through the same pooler, checks it can execute the validator, the F-F10 grounding call and the X-32 ranker and
// cannot read law.provisions, the ledger, the groundings, the selections, the test record list or the TEST seed list,
// and writes nothing (a validator, grounding or ranker call would add a permanent append-only row).

import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import pg from "pg";
import { readEnv, connectionConfig } from "./load.mjs";

const ROLE = "ff13_make";
const VALIDATOR = "ff13.validate_draft(text,text,text,text,text,text,text,text,text,text,text,text,text,text,text,text)";
const DRAFTING_CONTEXT = "ff13.drafting_context(text,text,text,text,text)";
const RANK_EXEMPLARS = "ff13.rank_exemplars(text,text,text,text,text,text)";
// Read probes that must be refused (42501). None of them writes.
const DENIED = ["law.provisions", "ff13.validations", "ff13.groundings", "ff13.selections", "ref.test_records", "ref.exemplar_test_seeds",
  "ref.exemplar_tags"];

// RFC 5802 / RFC 7677, the format Postgres stores (src/common/scram-common.c).
export function scramVerifier(password, salt = crypto.randomBytes(16), iterations = 4096) {
  const salted = crypto.pbkdf2Sync(Buffer.from(password, "utf8"), salt, iterations, 32, "sha256");
  const hmac = (key, msg) => crypto.createHmac("sha256", key).update(msg).digest();
  const stored = crypto.createHash("sha256").update(hmac(salted, "Client Key")).digest();
  const server = hmac(salted, "Server Key");
  return `SCRAM-SHA-256$${iterations}:${salt.toString("base64")}$${stored.toString("base64")}:${server.toString("base64")}`;
}

function toClipboard(text) {
  const r = spawnSync("clip", [], { input: text, shell: false });
  if (r.error || r.status !== 0) throw new Error("could not copy to the clipboard (clip.exe), nothing changed in Make");
}

async function main() {
  const local = process.env.LAW_LOAD_LOCAL === "1";
  const { caPath, ...admin } = connectionConfig(readEnv(), { local });
  // The pooler names a tenant by suffix: postgres.<ref> becomes ff13_make.<ref>. A direct or local host has none.
  const dot = admin.user.indexOf(".");
  const user = dot > 0 ? `${ROLE}${admin.user.slice(dot)}` : ROLE;
  // base64url of 24 random bytes: 32 characters, about 192 bits, nothing a URL or a form would mangle.
  const password = crypto.randomBytes(24).toString("base64url");

  const a = new pg.Client(admin);
  await a.connect();
  try {
    const [r] = (await a.query("SELECT rolname FROM pg_roles WHERE rolname = $1", [ROLE])).rows;
    if (!r) throw new Error(`${ROLE} does not exist, run load.mjs --push first`);
    // The verifier is base64 and $ : only, so it cannot break out of the literal. ALTER ROLE takes no parameters.
    const v = scramVerifier(password);
    if (!/^SCRAM-SHA-256\$4096:[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+$/.test(v)) throw new Error("verifier malformed");
    await a.query(`ALTER ROLE ${ROLE} LOGIN PASSWORD '${v}'`);
    console.log(`PASS  ${ROLE}: LOGIN set with a new SCRAM-SHA-256 verifier`);
  } finally {
    await a.end().catch(() => {});
  }

  // The database now holds this password, so it goes to the clipboard before the probe: a failed probe must never
  // lose a password the role already has (measured 2026-11-13, a second run's password was set and never copied).
  if (local) {
    console.log("INFO  local rehearsal, clipboard skipped");
  } else {
    toClipboard(password);
    console.log("PASS  password copied to the clipboard");
  }

  // The shared pooler checks new logins against the credentials it cached, so right after a rotation it can answer
  // 28P01 for the correct new password (Supabase KB, "Supavisor error: password authentication failed after password
  // rotation", measured 2026-11-13). The probe retries that one error for up to five minutes.
  const ATTEMPTS = 21;
  const WAIT_MS = 15000;
  let result = 1;
  for (let attempt = 1; attempt <= ATTEMPTS; attempt++) {
    const p = new pg.Client({ ...admin, user, password });
    try {
      await p.connect();
      const q = async (sql, params) => (await p.query(sql, params)).rows[0];
      const me = await q("SELECT current_user AS u");
      const ex = await q("SELECT has_function_privilege($1, 'EXECUTE') AS h", [VALIDATOR]);
      const dc = await q("SELECT has_function_privilege($1, 'EXECUTE') AS h", [DRAFTING_CONTEXT]);
      const rk = await q("SELECT has_function_privilege($1, 'EXECUTE') AS h", [RANK_EXEMPLARS]);
      const denied = [];
      for (const t of DENIED) {
        try {
          await p.query(`SELECT 1 FROM ${t} LIMIT 1`);
        } catch (e) {
          if (e.code === "42501") denied.push(t);
        }
      }
      const ok = me.u === ROLE && ex.h && dc.h && rk.h && denied.length === DENIED.length;
      console.log(`${ok ? "PASS" : "FAIL"}  probe as ${user} through ${admin.host}:${admin.port}${local ? "" : ", TLS verified"}: ` +
        `current_user ${me.u}, EXECUTE on the validator ${ex.h ? "yes" : "no"}, on drafting_context ${dc.h ? "yes" : "no"}, ` +
        `on rank_exemplars ${rk.h ? "yes" : "no"}, ` +
        `denied on ${denied.join(", ") || "nothing"} (expected ${DENIED.join(", ")})`);
      result = ok ? 0 : 1;
      break;
    } catch (e) {
      if (e.code === "28P01" && attempt < ATTEMPTS) {
        console.log(`WAIT  probe ${attempt}: the pooler still checks the previous password (28P01), retrying in ${WAIT_MS / 1000} s`);
        await new Promise((r) => setTimeout(r, WAIT_MS));
        continue;
      }
      console.log(`FAIL  probe as ${user}: ${e.code || ""} ${e.message}`.trim());
      if (e.code === "28P01") {
        console.log("INFO  the database holds the copied password and the pooler has not picked it up after five minutes. " +
          "Do not run this again (that rotates it). Save the Make connection later with the same password");
      }
      break;
    } finally {
      await p.end().catch(() => {});
    }
  }
  if (result === 0 && !local) {
    console.log("PASS  paste the password into the Make PostgreSQL connection, then clear the clipboard");
  }
  console.log(`INFO  Make connection: host ${admin.host}, port ${admin.port}, database ${admin.database}, user ${user}, Encrypt Yes, Reject Unauthorized Yes`);
  return result;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().then((code) => process.exit(code), (e) => {
    console.error(`error: ${e.message}`);
    process.exit(2);
  });
}
