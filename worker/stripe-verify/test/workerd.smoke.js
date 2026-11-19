// Runs the Worker inside workerd (wrangler unstable_dev) with test-only secrets and real
// Stripe-signed requests. The listener host does not resolve, so a request that passes
// verification ends in 502 (listener unreachable). The Worker's own log lines prove which
// path each request took: "forward of evt_smoke failed" means the signature was accepted
// and the forward was attempted, "verification failed" means it was refused.
// (A captured 200 forward needs Miniflare's outboundService. The Miniflare 5 beta bundled
// with wrangler 4.151 changed its options schema, so the forward payload is pinned by the
// unit tests in worker.test.js instead.)
import assert from "node:assert/strict";
import Stripe from "stripe";
import { unstable_dev } from "wrangler";

const SECRET = "wh" + "sec_" + "smoke0123456789abcdefABCDE";
const seen = [];
const write = process.stdout.write.bind(process.stdout);
const ewrite = process.stderr.write.bind(process.stderr);
process.stdout.write = (c, ...a) => { seen.push(String(c)); return true; };
process.stderr.write = (c, ...a) => { seen.push(String(c)); return true; };
const restore = () => { process.stdout.write = write; process.stderr.write = ewrite; };

const worker = await unstable_dev("src/index.js", {
  experimental: { disableExperimentalWarning: true },
  logLevel: "log",
  vars: {
    STRIPE_WEBHOOK_SECRET: SECRET,
    MAKE_LISTENER_URL: "https://listener.invalid/hook",
    MAKE_API_KEY: "smoke-key",
    STRIPE_LIVEMODE: "false",
    FORWARD_EVENT_TYPES: "invoice.paid",
    STRIPE_WEBHOOK_IPS: "",
  },
});
let results;
try {
  const payload = JSON.stringify({ id: "evt_smoke", object: "event", type: "invoice.paid", livemode: false, created: 1,
                                   data: { object: { id: "in_smoke", object: "invoice", description: "étape 名前" } } });
  const post = (body, sig) => worker.fetch("/", { method: "POST", headers: { "stripe-signature": sig }, body });
  const sign = (p, secret = SECRET) => Stripe.webhooks.generateTestHeaderString({ payload: p, secret });
  const other = payload.replace("invoice.paid", "customer.created");
  results = { valid: (await post(payload, sign(payload))).status };
  await new Promise((r) => setTimeout(r, 300));
  results.validForwarded = seen.join("").includes("forward of evt_smoke failed");
  results.validVerifyLogged = seen.join("").includes("verification failed");
  results.tampered = (await post(payload.replace("in_smoke", "in_other"), sign(payload))).status;
  results.wrongSecret = (await post(payload, sign(payload, SECRET + "x"))).status;
  results.get = (await worker.fetch("/")).status;
  results.ignoredType = (await post(other, sign(other))).status;
} finally {
  await worker.stop();
  restore();
}
console.log(JSON.stringify(results));
assert.deepEqual(results, { valid: 502, validForwarded: true, validVerifyLogged: false, tampered: 400, wrongSecret: 400, get: 405, ignoredType: 200 });
console.log("workerd smoke: PASS");
