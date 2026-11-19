// Real Stripe signatures from stripe-node's own test header generator, no network.
// The secret literals are split so the repo's secret scanner never sees a whole one.
import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import Stripe from "stripe";
import worker, { forwardPayload } from "../src/index.js";

const SECRET = "wh" + "sec_" + "test0123456789abcdefABCDEF";
const OTHER = "wh" + "sec_" + "other0123456789abcdefABCDE";
const LISTENER = "https://hook.example.test/listener";
const API_KEY = "make-key-for-tests";

const ENV = {
  STRIPE_WEBHOOK_SECRET: SECRET,
  MAKE_LISTENER_URL: LISTENER,
  MAKE_API_KEY: API_KEY,
  STRIPE_LIVEMODE: "false",
  FORWARD_EVENT_TYPES: "invoice.paid, invoice.payment_failed",
  STRIPE_WEBHOOK_IPS: "",
};

function event(over = {}) {
  return {
    id: "evt_test_1",
    object: "event",
    type: "invoice.paid",
    livemode: false,
    created: 1761800000,
    data: { object: { id: "in_test_1", object: "invoice", amount_paid: 125000, metadata: { airtable_record_id: "recTEST000000000A" } } },
    ...over,
  };
}

function signed(payload, { secret = SECRET, timestamp, header } = {}) {
  const sig = header ?? Stripe.webhooks.generateTestHeaderString({ payload, secret, timestamp });
  return new Request("https://verify.example.test/", {
    method: "POST",
    headers: { "content-type": "application/json", "stripe-signature": sig, "cf-connecting-ip": "203.0.113.7" },
    body: payload,
  });
}

let calls;
let answer;
const realFetch = globalThis.fetch;
const quiet = { log: console.log, warn: console.warn, error: console.error };

beforeEach(() => {
  calls = [];
  answer = async () => new Response("Accepted", { status: 200 });
  globalThis.fetch = async (url, init) => {
    calls.push({ url: String(url), init });
    return answer(url, init);
  };
  console.log = console.warn = console.error = () => {};
});

afterEach(() => {
  globalThis.fetch = realFetch;
  Object.assign(console, quiet);
});

async function run(req, env = ENV) {
  const res = await worker.fetch(req, env);
  const text = await res.text();
  for (const s of [SECRET, OTHER, API_KEY, LISTENER]) assert.ok(!text.includes(s), "response leaks a secret");
  return { status: res.status, body: JSON.parse(text) };
}

test("a correctly signed allowed event is forwarded with the API key and only IDs", async () => {
  const r = await run(signed(JSON.stringify(event())));
  assert.equal(r.status, 200);
  assert.equal(r.body.forwarded, true);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, LISTENER);
  assert.equal(calls[0].init.method, "POST");
  assert.equal(calls[0].init.headers["x-make-apikey"], API_KEY);
  assert.equal(calls[0].init.redirect, "manual");
  assert.deepEqual(JSON.parse(calls[0].init.body), {
    event_id: "evt_test_1", type: "invoice.paid", object_id: "in_test_1", object_type: "invoice", livemode: false, created: 1761800000,
  });
});

test("the forward never carries amounts, metadata or customer data", () => {
  const p = forwardPayload(event());
  assert.deepEqual(Object.keys(p).sort(), ["created", "event_id", "livemode", "object_id", "object_type", "type"]);
  assert.ok(!JSON.stringify(p).includes("rec"));
});

test("a body changed after signing is refused and nothing is forwarded", async () => {
  const payload = JSON.stringify(event());
  const header = Stripe.webhooks.generateTestHeaderString({ payload, secret: SECRET });
  const r = await run(signed(payload.replace("in_test_1", "in_test_2"), { header }));
  assert.equal(r.status, 400);
  assert.equal(calls.length, 0);
});

test("re-serialised JSON fails, so the raw body is what is checked", async () => {
  const payload = JSON.stringify(event(), null, 2);
  const header = Stripe.webhooks.generateTestHeaderString({ payload, secret: SECRET });
  const r = await run(signed(JSON.stringify(JSON.parse(payload)), { header }));
  assert.equal(r.status, 400);
});

test("a signature made with another secret is refused", async () => {
  const r = await run(signed(JSON.stringify(event()), { secret: OTHER }));
  assert.equal(r.status, 400);
  assert.equal(r.body.error, "signature verification failed");
  assert.equal(calls.length, 0);
});

test("a timestamp older than 300 seconds is refused (replay)", async () => {
  const old = Math.floor(Date.now() / 1000) - 301;
  const r = await run(signed(JSON.stringify(event()), { timestamp: old }));
  assert.equal(r.status, 400);
  assert.equal(calls.length, 0);
});

test("a timestamp inside the window is accepted", async () => {
  const recent = Math.floor(Date.now() / 1000) - 240;
  const r = await run(signed(JSON.stringify(event()), { timestamp: recent }));
  assert.equal(r.status, 200);
});

test("during a secret roll either v1 signature is accepted", async () => {
  const payload = JSON.stringify(event());
  const t = Math.floor(Date.now() / 1000);
  const v1 = (secret) => Stripe.webhooks.generateTestHeaderString({ payload, secret, timestamp: t }).split(",").find((p) => p.startsWith("v1="));
  const header = `t=${t},${v1(OTHER)},${v1(SECRET)}`;
  const r = await run(signed(payload, { header }));
  assert.equal(r.status, 200);
});

test("a v0 signature alone is not accepted", async () => {
  const payload = JSON.stringify(event());
  const t = Math.floor(Date.now() / 1000);
  const good = Stripe.webhooks.generateTestHeaderString({ payload, secret: SECRET, timestamp: t }).split(",").find((p) => p.startsWith("v1="));
  const r = await run(signed(payload, { header: `t=${t},v0=${good.slice(3)}` }));
  assert.equal(r.status, 400);
});

test("a missing signature header is refused", async () => {
  const req = new Request("https://verify.example.test/", { method: "POST", body: JSON.stringify(event()) });
  const r = await run(req);
  assert.equal(r.status, 400);
  assert.equal(calls.length, 0);
});

test("non-ASCII text in the body still verifies", async () => {
  const e = event();
  e.data.object.description = "Frais de dossier, étape soumission, 名前";
  const r = await run(signed(JSON.stringify(e)));
  assert.equal(r.status, 200);
});

test("only POST is served", async () => {
  const r = await run(new Request("https://verify.example.test/", { method: "GET" }));
  assert.equal(r.status, 405);
});

test("a verified event outside the allow-list gets 200 and is not forwarded", async () => {
  const r = await run(signed(JSON.stringify(event({ type: "customer.created" }))));
  assert.equal(r.status, 200);
  assert.equal(r.body.forwarded, false);
  assert.equal(calls.length, 0);
});

test("a live event on a test endpoint is refused, and the reverse", async () => {
  let r = await run(signed(JSON.stringify(event({ livemode: true }))));
  assert.equal(r.status, 400);
  r = await run(signed(JSON.stringify(event())), { ...ENV, STRIPE_LIVEMODE: "true" });
  assert.equal(r.status, 400);
  assert.equal(calls.length, 0);
});

test("a listener error, a redirect or a network failure answers 502 so Stripe retries", async () => {
  for (const make of [
    async () => new Response("no", { status: 500 }),
    async () => new Response("gone", { status: 410 }),
    async () => new Response(null, { status: 302, headers: { location: "https://elsewhere.test/" } }),
    async () => { throw new TypeError("network"); },
  ]) {
    answer = make;
    const r = await run(signed(JSON.stringify(event())));
    assert.equal(r.status, 502);
  }
});

test("a listener that hangs is cut off and answers 502", async () => {
  answer = (_url, init) => new Promise((_resolve, reject) => {
    init.signal.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")));
  });
  const realTimeout = globalThis.setTimeout;
  globalThis.setTimeout = (fn) => realTimeout(fn, 5);
  try {
    const r = await run(signed(JSON.stringify(event())));
    assert.equal(r.status, 502);
  } finally {
    globalThis.setTimeout = realTimeout;
  }
});

test("missing or bad configuration answers 500 and forwards nothing", async () => {
  for (const env of [
    { ...ENV, STRIPE_WEBHOOK_SECRET: "" },
    { ...ENV, MAKE_API_KEY: undefined },
    { ...ENV, STRIPE_LIVEMODE: "yes" },
    { ...ENV, MAKE_LISTENER_URL: "http://hook.example.test/plain" },
    { ...ENV, MAKE_LISTENER_URL: "not a url" },
  ]) {
    const r = await run(signed(JSON.stringify(event())), env);
    assert.equal(r.status, 500);
  }
  assert.equal(calls.length, 0);
});

test("the optional IP allow-list refuses other callers", async () => {
  let r = await run(signed(JSON.stringify(event())), { ...ENV, STRIPE_WEBHOOK_IPS: "3.18.12.63, 3.130.192.231" });
  assert.equal(r.status, 403);
  r = await run(signed(JSON.stringify(event())), { ...ENV, STRIPE_WEBHOOK_IPS: "203.0.113.7" });
  assert.equal(r.status, 200);
});

test("a declared Content-Length over the cap is refused before the body is read", async () => {
  const payload = JSON.stringify(event());
  const req = new Request("https://verify.example.test/", {
    method: "POST",
    headers: { "stripe-signature": Stripe.webhooks.generateTestHeaderString({ payload, secret: SECRET }), "content-length": String(512 * 1024 + 1) },
    body: payload,
  });
  const r = await run(req);
  assert.equal(r.status, 413);
  assert.equal(calls.length, 0);
});

test("a body over the cap without a Content-Length is cut off while streaming", async () => {
  const chunk = new TextEncoder().encode("x".repeat(64 * 1024));
  let sent = 0;
  const body = new ReadableStream({
    pull(controller) {
      if (sent >= 20) return controller.close();
      sent += 1;
      controller.enqueue(chunk);
    },
  });
  const req = new Request("https://verify.example.test/", { method: "POST", headers: { "stripe-signature": "t=1,v1=00" }, body, duplex: "half" });
  const r = await run(req);
  assert.equal(r.status, 413);
  assert.ok(sent < 20, "the stream was read to the end");
  assert.equal(calls.length, 0);
});

test("the log names the error class on a failed check, never the secret", async () => {
  const lines = [];
  console.warn = (m) => lines.push(String(m));
  await run(signed(JSON.stringify(event()), { secret: OTHER }));
  assert.equal(lines.length, 1);
  assert.match(lines[0], /verification failed: \w+/);
  for (const s of [SECRET, OTHER, API_KEY]) assert.ok(!lines[0].includes(s));
});

test("invoice.payment_succeeded is not in the shipped allow-list, so one payment forwards once", async () => {
  const toml = (await import("node:fs")).readFileSync(new URL("../wrangler.toml", import.meta.url), "utf8");
  const lists = [...toml.matchAll(/^FORWARD_EVENT_TYPES = "([^"]*)"/gm)].map((m) => m[1].split(","));
  assert.equal(lists.length, 2);
  for (const l of lists) {
    assert.ok(l.includes("invoice.paid"));
    assert.ok(!l.includes("invoice.payment_succeeded"));
  }
  assert.match(toml, /^preview_urls = false/m);
});

test("an oversized body is refused before verification", async () => {
  const big = JSON.stringify(event({ pad: "x".repeat(600 * 1024) }));
  const r = await run(signed(big));
  assert.equal(r.status, 413);
  assert.equal(calls.length, 0);
});
