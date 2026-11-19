# immios-stripe-verify

The Cloudflare Worker for F-H9 option A3 (`specs/F-H9-options.md`). Stripe sends every webhook event here. The Worker checks the `Stripe-Signature` header against the raw body with Stripe's own library (HMAC-SHA256, 300 second tolerance, every `v1` signature during a secret roll). It then forwards only the IDs to the Make listener hook with the hook's API key (`x-make-apikey`).

The listener re-fetches the invoice from Stripe before it writes anything, so amounts, metadata and customer details never cross this hop. The Worker holds no Stripe API key.

There are two Workers from one codebase: `immios-stripe-verify-test` (top level of `wrangler.toml`) and `immios-stripe-verify-live` (`--env live`). Each has its own signing secret, listener URL and Make API key, so test credentials never reach the live listener.

## What it answers

| Case | Status | Stripe retries |
|---|---|---|
| Signature valid, allowed type, Make accepted (2xx) | 200 | No |
| Signature valid, type not in `FORWARD_EVENT_TYPES` | 200, not forwarded | No |
| Missing or bad signature, timestamp older than 300 s | 400 | Yes, and the endpoint shows failures |
| Test event on a live Worker or the reverse | 400 | Yes |
| Caller IP not in `STRIPE_WEBHOOK_IPS` (when set) | 403 | Yes |
| Body over 512 KB (declared or streamed) | 413 | Yes |
| Make answered non-2xx, redirected, timed out (10 s) or was unreachable | 502 | Yes |
| A secret or var is missing | 500 | Yes, until it is set |

A 200 from the Worker means Make queued the event, not that the listener processed it. Processing failures inside Make are the listener's job (error handlers and the Logger).

Stripe retries live events for up to 3 days and sandbox events 3 times over a few hours (docs.stripe.com/webhooks). If deliveries keep failing for several days, Stripe disables the endpoint and stops sending, new events included, until someone re-enables it. See Recovery.

## Configuration

Secrets, set per Worker with `npx wrangler secret put <NAME>` (add `--env live` for live), never in the repo or `wrangler.toml`:

- `STRIPE_WEBHOOK_SECRET`: the endpoint's signing secret from the Stripe Dashboard
- `MAKE_LISTENER_URL`: the Make listener hook URL (a bearer secret, hard rule 4)
- `MAKE_API_KEY`: the API key on that hook

Vars in `wrangler.toml`: `STRIPE_LIVEMODE`, `FORWARD_EVENT_TYPES` (the Invoice events, without `invoice.payment_succeeded`, which Stripe sends together with `invoice.paid` for the same payment) and `STRIPE_WEBHOOK_IPS` (optional second-layer caller allow-list). Version preview URLs are off, so after a secret roll no old version stays callable with the old secret. Workers Logs are on.

## Preconditions

1. The Make listener scenario exists (F-H9, `specs/F-H9-stripe-payment-listener.md`, created inactive through `scripts/make_create.py`), with its duplicate gate on the Stripe event ID and Sequential processing on. The Worker forwards a redelivered event again, so the gate is what stops a second release. The listener re-fetches the event from Stripe, so a forged event ID gets nowhere.
2. F-H1 has switched Financial Guardrail to Stripe Invoices, so there are `invoice.*` events to receive.

## Deploy the test Worker (Rizwan)

1. `cd worker/stripe-verify`, then `npm ci`.
2. `npx wrangler login` with the Cloudflare account that hosts velocyt.ca.
3. `npx wrangler deploy`. The Worker answers 500 until its secrets exist, which is safe because Stripe retries.
4. Stripe Dashboard in test mode, Developers, Webhooks, Add destination: the `workers.dev` URL from step 3, payload style **Snapshot** (a Thin destination sends events the Worker cannot parse, logged as a verification failure), and exactly the events in `FORWARD_EVENT_TYPES`. Copy the signing secret.
5. `npx wrangler secret put STRIPE_WEBHOOK_SECRET`, then `MAKE_LISTENER_URL` and `MAKE_API_KEY`. Paste each value at the prompt, never on the command line. The Make API key is a new key made for this hook only, never the Pending Call or Logger key.
6. Test (F-H11) on test records: `stripe trigger invoice.paid`. The Worker's Logs (dashboard, Observability) show `forwarded evt_...`, and the listener's hook history shows one call with only IDs. Send the same event again from the Dashboard ("Resend") and check that the listener's duplicate gate stops it.

## Deploy the live Worker (after F-H11 passes)

1. Cloudflare dashboard, velocyt.ca zone, Security, WAF, custom rule: block requests to host `stripe-hook.velocyt.ca` unless `ip.src` is in Stripe's webhook IP list (https://docs.stripe.com/ips, webhooks section). Optionally add a rate-limiting rule. A WAF block happens before the Worker runs, so junk traffic cannot use up the Free plan's 100,000 requests a day, a limit shared by every Worker on the account. The live Worker has `workers_dev = false`, so this hostname is its only address.
2. `npx wrangler deploy --env live`. This creates the `stripe-hook.velocyt.ca` custom domain.
3. Stripe Dashboard in live mode: add a destination at `https://stripe-hook.velocyt.ca/`, payload style Snapshot, the same events. Copy the live signing secret.
4. `npx wrangler secret put STRIPE_WEBHOOK_SECRET --env live` with the live secret, then `MAKE_LISTENER_URL --env live` and `MAKE_API_KEY --env live`.
5. Turn on Stripe's failing-endpoint email for the account and route it to systems@velocyt.ca.

To roll a signing secret: roll it in the Stripe Dashboard (both secrets sign for up to 24 h), then `wrangler secret put STRIPE_WEBHOOK_SECRET` (with `--env live` for live) inside that window.

## Recovery

After a Make outage longer than the retry window, or when the failing-endpoint email arrives:

1. Re-enable the endpoint in the Stripe Dashboard if Stripe disabled it.
2. List the events that were not delivered: List Events with `delivery_success=false` and the types in `FORWARD_EVENT_TYPES` (events stay listable for 30 days).
3. Resend each one from the Dashboard or with `stripe events resend <event id>`. The listener's duplicate gate makes a resend of an already processed event harmless.

A failure inside the listener (a Logger alert from a Stripe Payment Listener module) is a different case: the event reached Make, its marker row exists, and a resend is stopped by the duplicate gate. Resolve the incomplete execution in Make instead (runbook in `specs/F-H9-stripe-payment-listener.md`). With Sequential processing on, an unresolved one holds every later event in the queue.

## Tests

- `npm test`: 23 tests with real Stripe signatures (stripe-node's test header generator), no network.
- `npm run smoke`: runs the Worker inside workerd through wrangler and sends it signed requests. Its log proves a valid signature reaches the forward step.

Not measured: CPU time per request against the Workers Free limit of 10 ms. HMAC over a small body plus one fetch should fit, and I/O wait does not count as CPU time. The invocation logs record CPU time, so check them after the first test events.

Versions are pinned exact: stripe 22.6.2 and wrangler 4.151.0, both at least two weeks old when chosen (2026-10-30).
