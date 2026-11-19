// Immi-OS Stripe webhook verifier (F-H9, option A3, specs/F-H9-options.md).
//
// Stripe POSTs every event here. The Worker checks the Stripe-Signature header against the
// raw body with Stripe's own library (HMAC-SHA256, 300 s tolerance), and forwards only the
// IDs to the Make listener hook, which needs the Make webhook API key (header x-make-apikey).
// The listener re-fetches the object from Stripe before it writes anything, so nothing but
// IDs crosses this hop, and the Worker holds no Stripe API key.
//
// Stripe retries only on a non-2xx answer (live mode, up to 3 days, sandbox a few hours). So
// the Worker answers 2xx only once Make has accepted the forward, and 502 when Make did not,
// so a Make outage shorter than the retry window loses no payment event. Longer outages are
// recovered from the Events API (README, Recovery).
//
// Secrets (wrangler secret put, never in the repo or wrangler.toml):
//   STRIPE_WEBHOOK_SECRET  the endpoint's whsec_ signing secret
//   MAKE_LISTENER_URL      the Make listener hook URL (a bearer secret, hard rule 4)
//   MAKE_API_KEY           the API key on that hook
// Vars (wrangler.toml):
//   STRIPE_LIVEMODE        "true" or "false": events of the other mode are refused
//   FORWARD_EVENT_TYPES    comma-separated allow-list, other verified events get 200 and are dropped
//   STRIPE_WEBHOOK_IPS     optional comma-separated allow-list of caller IPs (docs.stripe.com/ips)

import Stripe from "stripe";

const TOLERANCE_SECONDS = 300;
const MAX_BODY_BYTES = 512 * 1024;
const FORWARD_TIMEOUT_MS = 10000;
const crypto = Stripe.createSubtleCryptoProvider();

function reply(status, body) {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

// The body as text, read with a running byte count, so a body without Content-Length (or
// with a false one) is cut off at the cap instead of buffered in full. null means too large.
async function readCapped(request, cap) {
  if (!request.body) return "";
  const reader = request.body.getReader();
  const chunks = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > cap) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(size);
  let at = 0;
  for (const c of chunks) {
    bytes.set(c, at);
    at += c.byteLength;
  }
  return new TextDecoder().decode(bytes);
}

function list(value) {
  return String(value || "").split(",").map((s) => s.trim()).filter(Boolean);
}

function config(env) {
  const missing = ["STRIPE_WEBHOOK_SECRET", "MAKE_LISTENER_URL", "MAKE_API_KEY", "STRIPE_LIVEMODE", "FORWARD_EVENT_TYPES"]
    .filter((k) => !env[k]);
  if (!["true", "false"].includes(String(env.STRIPE_LIVEMODE))) missing.push("STRIPE_LIVEMODE (true or false)");
  if (missing.length) return { missing };
  let url;
  try {
    url = new URL(env.MAKE_LISTENER_URL);
  } catch {
    return { missing: ["MAKE_LISTENER_URL (not a URL)"] };
  }
  if (url.protocol !== "https:") return { missing: ["MAKE_LISTENER_URL (must be https)"] };
  return {
    secret: env.STRIPE_WEBHOOK_SECRET,
    listener: url.toString(),
    apiKey: env.MAKE_API_KEY,
    livemode: env.STRIPE_LIVEMODE === "true",
    types: new Set(list(env.FORWARD_EVENT_TYPES)),
    ips: new Set(list(env.STRIPE_WEBHOOK_IPS)),
  };
}

// The only fields the listener gets. It fetches the object from Stripe by ID, so amounts,
// metadata and customer details never travel through this hop.
export function forwardPayload(event) {
  const obj = (event.data && event.data.object) || {};
  return {
    event_id: event.id,
    type: event.type,
    object_id: obj.id || null,
    object_type: obj.object || null,
    livemode: event.livemode === true,
    created: event.created,
  };
}

export default {
  async fetch(request, env) {
    if (request.method !== "POST") return reply(405, { error: "method not allowed" });
    const cfg = config(env);
    if (cfg.missing) {
      // A deploy without its secrets. 500 makes Stripe retry while Rizwan fixes it.
      console.error(`stripe-verify: configuration incomplete: ${cfg.missing.join(", ")}`);
      return reply(500, { error: "not configured" });
    }
    if (cfg.ips.size) {
      const ip = request.headers.get("cf-connecting-ip") || "";
      if (!cfg.ips.has(ip)) return reply(403, { error: "caller not allowed" });
    }
    const declared = Number(request.headers.get("content-length") || 0);
    if (declared > MAX_BODY_BYTES) return reply(413, { error: "payload too large" });
    const signature = request.headers.get("stripe-signature");
    if (!signature) return reply(400, { error: "missing signature" });

    // The raw body, read once as text. Parsing before the check would break the HMAC.
    const raw = await readCapped(request, MAX_BODY_BYTES);
    if (raw === null) return reply(413, { error: "payload too large" });

    let event;
    try {
      event = await Stripe.webhooks.constructEventAsync(raw, signature, cfg.secret, TOLERANCE_SECONDS, crypto);
    } catch (err) {
      // Never echo the reason to the caller: it would help a forger tune the request. The
      // class alone goes to the log, so a Thin-payload destination (a plain Error after a
      // valid signature) can be told apart from a bad signature.
      console.warn(`stripe-verify: verification failed: ${(err && err.constructor && err.constructor.name) || "unknown"}`);
      return reply(400, { error: "signature verification failed" });
    }
    if (event.livemode !== cfg.livemode) {
      console.warn(`stripe-verify: ${event.id} livemode ${event.livemode} refused on a livemode ${cfg.livemode} endpoint`);
      return reply(400, { error: "wrong mode" });
    }
    if (!cfg.types.has(event.type)) {
      // Verified but not ours. 200 so Stripe does not retry an event nobody will handle.
      return reply(200, { received: true, forwarded: false });
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), FORWARD_TIMEOUT_MS);
    let res;
    try {
      res = await fetch(cfg.listener, {
        method: "POST",
        headers: { "content-type": "application/json", "x-make-apikey": cfg.apiKey },
        body: JSON.stringify(forwardPayload(event)),
        redirect: "manual",
        signal: controller.signal,
      });
    } catch (err) {
      console.error(`stripe-verify: forward of ${event.id} failed: ${err && err.name}`);
      return reply(502, { error: "listener unreachable" });
    } finally {
      clearTimeout(timer);
    }
    if (res.status < 200 || res.status >= 300) {
      console.error(`stripe-verify: listener answered ${res.status} for ${event.id}`);
      return reply(502, { error: "listener refused" });
    }
    console.log(`stripe-verify: forwarded ${event.id} ${event.type}`);
    return reply(200, { received: true, forwarded: true });
  },
};
