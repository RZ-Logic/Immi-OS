<h1 align="center">
  <img src="./assets/immi-os-banner.png" alt="Immi-OS. From first inquiry to verified payment" width="100%" />
</h1>

<p align="center">
  <strong>Operations automation for Canadian immigration consulting firms:<br/>intake and voice screening, follow-up, policy monitoring and reactivation, client support, contracts,<br/>payment gating, submission drafting and interview preparation.<br/>The AI handles volume and first drafts. The licensed consultant (RCIC) keeps every legal judgment and every sign-off.</strong>
</p>

<p align="center">
  <a href="./LICENSE.txt"><img src="https://img.shields.io/badge/License-Proprietary-555555?style=for-the-badge" alt="License: Proprietary"/></a>
  <a href="https://www.make.com"><img src="https://img.shields.io/badge/Built_with-Make.com-6D00CC?style=for-the-badge&logo=make&logoColor=white" alt="Built with Make.com"/></a>
  <a href="https://airtable.com"><img src="https://img.shields.io/badge/Client_Data-Airtable-18BFFF?style=for-the-badge&logo=airtable&logoColor=white" alt="Client data: Airtable"/></a>
  <a href="https://supabase.com"><img src="https://img.shields.io/badge/Reference_Data-Supabase_Canada-3FCF8E?style=for-the-badge&logo=supabase&logoColor=white" alt="Reference data: Supabase, Canada"/></a>
  <a href="https://www.anthropic.com"><img src="https://img.shields.io/badge/Models-Claude_Opus_%26_Haiku-D97757?style=for-the-badge&logo=anthropic&logoColor=white" alt="Models: Claude Opus and Haiku"/></a>
  <img src="https://img.shields.io/badge/Legal_Sign--off-RCIC_Only-2A9D4A?style=for-the-badge" alt="Legal sign-off: RCIC only"/>
  <img src="https://img.shields.io/badge/Status-Pre--activation-E07B00?style=for-the-badge" alt="Status: pre-activation"/>
</p>

<p align="center">
  <a href="#-current-state-november-2026">Current State</a> •
  <a href="#-why-it-is-interesting">Why It Is Interesting</a> •
  <a href="#-the-market">Market</a> •
  <a href="#-one-clients-journey">Journey</a> •
  <a href="#-business-impact-modelled">Impact</a> •
  <a href="#-modules">Modules</a> •
  <a href="#-engineering-properties">Engineering Properties</a> •
  <a href="#-roadmap">Roadmap</a> •
  <a href="#-technology-stack">Stack</a> •
  <a href="#-what-is-in-this-repository">Repository</a> •
  <a href="./prompt.md">Prompts</a>
</p>

---

## 📂 [View System Prompts & Prompt Governance](./prompt.md)

---

## 📍 Current State (November 2026)

Measured on the latest pull of the live Make account and stated plainly:

| Area | State |
| :--- | :--- |
| **Make scenarios** | 21 scenarios in scope, all built, all passing the repo's static audit on the latest pull. |
| **Running in production** | 2 of 21: the shared error Logger and the Daily API Cost Audit. Every other scenario is inactive until its test runs on dedicated test records pass. The consultant activates each one by hand, one at a time. |
| **Submission drafting (Module F)** | Built and tested end to end on synthetic records, in test mode only. Production drafting stays closed until a licensed RCIC signs the citation rows. Today 0 of 35 visa-type and document pairs are open. |
| **Payments (Module H)** | Built and tested in Stripe test mode. Live keys are not switched on. Milestone billing and trust-account handling are an open design decision. |
| **Models** | Anthropic only. Claude Opus 5.5 drafts submissions and grades mock interviews. Claude Haiku 5.5 runs the eight high-volume calls. No OpenAI model remains. |

The figures below the line are the design target. Nothing in this README claims production results the system has not produced yet.

---

## 💡 Why It Is Interesting

- **The law is grounded, not recalled.** Every provision of IRPA and IRPR is indexed from the official Justice Canada XML into Postgres. The drafter gets the exact provision text it may cite, and a deterministic validator checks every citation in the draft against that index before anyone sees it.
- **The AI never disqualifies anyone.** The voice screener can only sort a lead into VIP, Nurture, Call Later or Do Not Call. Disqualification is a manual decision by staff, and every automated status decision writes a trace with its evidence and the call ID.
- **Every AI call is traceable.** Each Claude prompt is an immutable, hashed version in a registry. Every call writes a row stamped with the prompt version, its SHA-256, the model requested and served, the stop reason and the token counts.
- **The live system is audited like code.** The private repo of record holds snapshots of every Make scenario and an auditor that checks them for error handling, webhook authentication, secrets, mapping bugs, model pinning, Stripe idempotency and status-write integrity. Changes reach Make only through a guarded push script that refuses anything the audit does not close cleanly.
- **Deterministic where it matters.** Retainer agreements come from a vetted template, not a language model. Legal documents need the same output every time.

---

## 👥 Who This Is For

- Licensed Canadian immigration consultants (RCICs) and firms handling 50+ active files
- Practices that screen, follow up and draft by hand and want those hours back
- Firms that want submission work gated on payment
- Operators who need a traceable record of what the AI did, with which prompt and which model

---

## 🧭 The Market

The market is contested. Several purpose-built RCIC platforms already ship AI-assisted intake, drafting help, CICC-aligned audit trails and Canadian data residency. Being early is not an edge.

Where Immi-OS differs:
- **Front-office revenue automation.** Voice screening within minutes of an inquiry, policy-driven reactivation of past leads, and payment-gated progression.
- **A grounded drafting pipeline.** Verbatim statute text in, deterministic citation validation out, and a mandatory RCIC review before any draft leaves the firm.

Where it is behind: client records live in Airtable, so Canadian residency for client data is not a claim Immi-OS can make today. The law index, reference tables and prompt registry already sit in Postgres in Canada (Central).

---

## 🔄 One Client's Journey

```
┌──────────────────────────────────────────────────────────────────────────┐
│                                                                          │
│   One lead, inquiry to approval (the designed path once activated):      │
│                                                                          │
│     INQUIRY            ← Gmail watch, Claude Haiku extracts the fields   │
│       │                                                                  │
│       ├─ VIP CALL      ← job offer or CRS 500+, called on the same run   │
│       └─ SCREENER CALL ← every other lead, one dial per 15-minute run    │
│       │                                                                  │
│     OUTCOME            ← VIP, Nurture, Call Later or Do Not Call.        │
│                          The AI never disqualifies anyone.               │
│     RETAINER           ← staff set Send Contract, filled from a template │
│     DRAFT              ← two Claude Opus stages, every citation checked  │
│     RCIC SIGN-OFF      ← the licensed consultant reviews and decides     │
│     PAYMENT GATE       ← Stripe invoice locks the file until it is paid  │
│     MOCK INTERVIEW     ← Bland officer call, Opus scorecard to staff     │
│     APPROVED           ← one HeyGen video, sent once the render is done  │
│                                                                          │
│   Every step writes a System Logs row. Every failure goes through the    │
│   shared Logger: one Error row and one Slack alert carrying IDs only.    │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

1. **Inquiry:** A prospect emails the firm. Claude Haiku extracts the details into Airtable. A lead with a job offer or a CRS score of 500 or more is VIP.
2. **Voice screening:** VIP leads get an instant email and a call from the Bland VIP agent on the same run. Other leads queue for the screener agent. The screener asks about the job offer and CRS score and ends in VIP, Nurture, Call Later or Do Not Call.
3. **Follow-up:** Claude Haiku summarizes the call for the consultant. VIP leads get a booking link. Nurture leads get a short CRS improvement guide. Do Not Call leads get nothing further.
4. **Retainer:** Staff set the lead to Send Contract. The retainer is generated from a vetted Google Docs template and emailed. The signed PDF reply is filed and the lead advances.
5. **Drafting:** Staff start the drafting chain. Claude Opus outlines and then drafts the submission letter from the case facts and the exact IRPA and IRPR text it was given. The validator checks every citation. The draft lands in a staff-only folder as Draft Ready - Pending Review. The RCIC reviews, edits and decides.
6. **Payment gate:** The consultant marks the file Ready for Submission. With a balance outstanding, the system issues a Stripe invoice and locks the file. The paid invoice releases it.
7. **Interview prep:** A Bland voice agent plays a skeptical visa officer in a short pressure interview. Claude Opus grades the transcript into a risk scorecard for the consultant.
8. **Approval:** When a file is marked Approved, Claude writes a short script and HeyGen renders a congratulation video from the consultant's avatar, emailed once the render completes.
9. **Reactivation:** When a policy change lands, the Market Watchdog drafts a campaign. Once a person sets it Active, matching past leads get an email and, on a North American number, a call.

---

## 📌 Business Impact (modelled)

Modelled estimate for a single senior partner at full activation. It has not been measured yet, because the system is not live.

| Module Category | Task Automated | Weekly Savings | Annual Value |
| :--- | :--- | :--- | :--- |
| **Admin & Intake** | Screening calls, data entry, status emails | 10 Hours | $75,000 |
| **Production** | Submission letter first drafts | 5 Hours | $37,500 |
| **Sales Operations** | Contract sending, filing and onboarding | 2 Hours | $15,000 |
| **Service Delivery** | Mock interview coaching and prep | 3 Hours | $22,500 |
| **Finance** | Invoicing and payment gating | 2 Hours | $15,000 |
| **TOTAL** | **Full system at activation** | **22 Hours** | **$165,000** |

---

## 🧩 Modules

Make.com orchestrates every scenario. Airtable is the system of record for client data. Postgres (Supabase, Canada Central) holds only non-client reference data: the law index, citation mappings, visa types, the prompt registry and the drafting validator's ledger.

### 📥 Module A: Intake & Voice Screening

- **One intake channel today:** a Gmail watch on the firm's intake inbox, polled every 15 minutes. Claude Haiku extracts the structured fields with a JSON schema. The older web-form and Facebook intake scenarios are disabled.
- **Two Bland voice agents:** a VIP agent that calls VIP leads on the same run, and a screener agent that a batch caller dials one lead per 15-minute run. A non-VIP lead with an empty queue gets its first call within about 30 minutes (inferred from the schedules), and longer with a backlog.
- **Four outcomes, no rejection:** the screener ends in VIP, Nurture, Call Later or Do Not Call. The status write behind it accepts only those four values, and anything else lands in a traced fallback with a ledger row and an alert. Disqualification is a manual staff decision that triggers a polite rejection email.
- **Consistent VIP rule:** the extraction step and the screener use the same rule, a job offer or a CRS score of 500 or more.
- **Duplicate protection:** a repeated post-call delivery for the same call is detected and skipped, so a client never gets a second email or text.

### 🌱 Module B: Follow-up & Nurture

- **Single-touch follow-up by outcome:** VIP leads get a text and an email with a booking link. Nurture leads get a short CRS guide that Claude Haiku writes from a fixed tip list, which the RCIC approves before activation. When the model does not finish its answer, the lead gets a plain follow-up email instead of a cut-off guide.
- **The Pivot:** when a caller asks a legal question, the agent says it is an AI assistant and offers a strategy call with the senior consultant instead of answering. Disclosure and escalation are built into the conversation, which matters in a regulated profession.
- **Not built yet:** multi-step drip sequences with cadenced re-engagement are on the roadmap.

### 📡 Module C: Market Watchdog & Reactivation

- **RSS ingestion:** the Watchdog reads a news feed every 15 minutes. Claude Haiku rates urgency, category and target industry, and writes a short outreach script.
- **A producer and a consumer with a human gate:** High-urgency items become Campaign rows in Draft. Campaign Launcher acts only on a campaign a person sets Active, so news never triggers outreach on its own.
- **Audience:** leads in the campaign's industry (or every lead for a General campaign) that are ready for outreach, created in the last 180 days, never Disqualified or Do Not Call, capped at 50 per activation. Matching is by industry today. Matching on CRS, age and education is planned.
- **Delivery:** every matched lead gets an email. Leads with a valid North American number also get a Bland call that uses the campaign script.

### 💬 Module D: Client Support & Approval Videos

- **Two-stage filter:** Claude Haiku first decides whether an inbound email is a status request from an existing client. Only those reach the lookup and the second Claude Haiku call, which drafts the reply from the client's current stage and the consultant's notes. Spam, pitches and new leads stop at the first, cheaper call.
- **Approval videos:** when a file is marked Approved, a 15-minute poll picks it up, Claude Haiku writes a short script and HeyGen renders the consultant's avatar. The email goes out only after the render reports completed with a video URL, and each client gets one video.
- **Cost:** zero marginal staff time. Each HeyGen render has a per-video compute cost passed through to the firm.
- **Honest gap:** replies go out after an automatic completeness check, not after a human review. A pre-send QA gate for these replies is on the roadmap.

### 📝 Module E: Contracts & Onboarding

- **Deterministic by design:** the retainer is generated from a vetted Google Docs template with the client's details filled in. No language model writes any part of the agreement.
- **Send:** setting a lead to Send Contract generates the retainer, emails it and files it to the lead's Drive folder, or the firm's shared folder when the lead has none.
- **Receive:** a Gmail watch picks up replies with a PDF attachment and a contract keyword in the subject, never the firm's own sent mail. The PDF is checked, filed to the firm's signed-contracts folder, attached to the lead's record, and the lead advances.
- **Not built yet:** filing each signed copy into the client's own folder, and verifying the signature itself.

### ⚖️ Module F: Submission Drafting

```
┌──────────────────────────────────────────────────────────────────────────┐
│                                                                          │
│   Module F drafting chain:                                               │
│                                                                          │
│     CASE FACTS + VISA CODE + DOCUMENT TYPE                               │
│       │                                                                  │
│       ▼                                                                  │
│     GROUNDING          ← Postgres returns mapped provisions, verbatim.   │
│       │                  Production: RCIC-signed mappings only.          │
│       ▼                                                                  │
│     OUTLINE            ← Claude Opus, JSON schema: plan, risk flags,     │
│       │                  weak grounds                                    │
│       ▼                                                                  │
│     DRAFT              ← Claude Opus, cites only the text it was given   │
│       │                                                                  │
│       ▼                                                                  │
│     VALIDATOR          ← deterministic, every citation checked against   │
│       │                  the IRPA and IRPR index and the grounding set   │
│       ▼                                                                  │
│     REVIEW TRAIL       ← Google Doc in a staff-only folder, review row   │
│       │                  with verdict, flags and the document hash       │
│       ▼                                                                  │
│     DRAFT READY - PENDING REVIEW  ──►  the RCIC edits, signs or rejects  │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

- **Grounding first:** a Postgres function returns the provisions mapped to the client's visa type and document type, with their verbatim text. In production only RCIC-signed mappings count. Unreviewed candidate mappings are allowed only for records registered as synthetic tests.
- **Two Claude Opus stages:** an outline stage returns a structured plan with risk flags and weak grounds, then a drafting stage writes the letter from the case facts and the provided text only. Opus uses adaptive thinking with a large output budget.
- **Deterministic validation:** every citation in the draft is checked against the law index and against the provisions the drafter was given. The verdict, risk flags and a hash of the document are written to a review trail.
- **Human sign-off:** the draft lands in a staff-only Google Drive folder with the status Draft Ready - Pending Review. Nothing is sent to a client. The RCIC reviews and decides.
- **Scope today:** submission letters, for 17 supported visa codes. Letters of explanation and study plans come next. A recorded RCIC sign-off step and an exemplar library of consented, de-identified past submissions are built in the repo and not live yet.
- **Law kept current:** a monthly check compares the index with the Justice Laws consolidation. The index was last reloaded after the IRPR amendment of 2026-10-23.
- **Measured quality:** an evaluation harness ran the chain on a synthetic case set and met its automatic bar. The human grading of those drafts is still open.

### 🎙️ Module G: Interview Simulator

- **The call:** when staff mark a client Ready to Call, a Bland voice agent plays a skeptical visa officer in a short pressure interview, with question sets for study, spousal and visitor applications.
- **The grade:** after the call, Claude Opus grades the transcript into a risk score, a verdict and an analysis on the client's record for the consultant. Nothing is sent to the client.
- **Today and next:** V1 is a single-call grader. A rubric library per visa type, case-file questions and a multi-stage grader are designed and not built.

### 💳 Module H: Payments & Cost Control

Three separate functions:
- **Payment gate:** when the consultant marks a file Ready for Submission with a balance due, the system checks the client's email format, creates or finds the Stripe customer, issues a Stripe invoice with an idempotency key and the lead's record ID and billing milestone in its metadata, emails the hosted invoice link and locks the file.
- **Payment listener:** a Cloudflare Worker verifies Stripe's signature and forwards only the event and invoice IDs. The listener re-fetches the invoice from Stripe, marks the lead Paid in Full, and the gate releases the file.
- **Daily API cost audit:** the one scenario besides the Logger that runs in production. It totals the previous day's AI and voice spend from the ledger and posts it to Slack.
- **Open:** today the gate charges one balance. Milestone billing and trust-account handling wait on a decision and a review by counsel.

### 🛡️ Module I: Governance, Ledgers & Audit

- **The shared Logger:** every external call in every scenario has an error handler that is one Logger call followed by its directive (Break, Resume or Ignore). The Logger writes an Error row to System Logs and posts a Slack alert that carries IDs only, never client data.
- **Two ledgers:** System Logs is the synchronous event log, with success rows, error rows and one stamped row per Claude call. The Voice AI Ledger holds the price of every Bland call.
- **Post-call reconciliation:** four webhook receivers take Bland's post-call notice, re-fetch the call from Bland rather than trusting the request, act only on a call that ended and has not been reconciled, and write its cost once, linked to the System Logs row of that call.
- **Authenticated webhooks:** every Make webhook either requires an API key or re-fetches what it was told from the source.
- **Honest limits:** this is not zero data loss. If the Logger answers with an HTTP error, that entry is lost without an alert. If the call to the Logger fails outright, the calling run ends, and a webhook-triggered scenario deactivates. Both risks are documented.
- **The repo audit:** the auditor reads each scenario snapshot and fails on a missing handler, an unauthenticated webhook, a credential literal, a mapping to a field that does not exist, an unpinned model, a Stripe call without an idempotency key, a status write without a trace, and many more rules learned from real bugs. The latest pull passes it in full.

### 📊 Module J: Operations Dashboard

- **Today:** a Softr dashboard over Airtable shows API spend, tasks automated and a searchable execution log.
- **Not built yet:** pipeline velocity, conversion rates and sampled QA review of AI output. Module F already has a mandatory pre-release review. The broader QA workflow is planned on a new dashboard after Module F reaches production.

---

## 🧱 Engineering Properties

| Property | Implementation |
|----------|---------------|
| **Human sign-off on legal work** | Every Module F draft stops at Draft Ready - Pending Review in a staff-only folder. Interview scorecards go to the consultant, never the client. |
| **Grounded citations** | The drafter cites only provision text it was given, and a deterministic validator checks every citation against the IRPA and IRPR index. |
| **No automated rejection** | The AI sorts leads into four outcomes and never disqualifies. Each automated status decision writes its evidence and call ID. |
| **Traceable AI calls** | Hashed, immutable prompt versions. Each call is stamped with prompt version, hash, models requested and served, stop reason and tokens. |
| **Payment-gated progression** | A file locks behind a Stripe invoice and releases only on a signature-verified, re-fetched paid event. |
| **Logged failures** | Every external call has a handler that logs to System Logs and alerts Slack with IDs only. Known gaps are documented, not hidden. |
| **Duplicate safety** | Idempotency keys on Stripe calls, duplicate-delivery gates on webhooks, and one-video-per-client flags. |
| **Audited changes** | Scenario snapshots in git, a static audit on every pull, and a guarded push path that refuses changes the audit does not accept. |

---

## 🚀 Roadmap

- **Production drafting:** a named RCIC signs the citation mappings and the recorded sign-off step goes live.
- **Exemplar library:** consented, de-identified past submissions selected by visa type and document type for argument structure and firm voice. Semantic ranking is added only once a category holds enough exemplars and the evaluation shows a gain.
- **The statute is never vectorized.** Citation grounding stays deterministic and curated in V1 and V2. Retrieval applies only to exemplars, never to the law.
- **Milestone billing and trust accounting** once the model is decided and reviewed by counsel.
- **Operations dashboard** with pipeline views and sampled pre-send QA for client emails.
- **Interview simulator V2:** case-file questions, all 17 visa codes and a rubric-grounded grader.
- **Nurture sequences**, more policy feeds and multi-variable campaign matching.
- **Multi-firm deployment:** per-firm client data, with the shared reference data already separated from client data.

Immi-OS augments the consultant. Legal judgment, advice and sign-off stay with the licensed RCIC, as Section 91 of IRPA requires.

---

## 🔌 Technology Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| Orchestration | Make.com | Scenarios, webhooks, routing, error handling |
| Client data | Airtable | Leads, files, campaigns, System Logs and Voice AI Ledger |
| Reference data | Postgres (Supabase, Canada Central) | IRPA and IRPR index, citation mappings, visa types, prompt registry, validator ledger |
| Language models | Anthropic Claude (Opus 5.5, Haiku 5.5) | Drafting and grading on Opus, extraction, triage, replies and scripts on Haiku |
| Voice AI | Bland.ai | Screening agents, reactivation calls, mock interviews |
| Video AI | HeyGen | Approval videos from the consultant's avatar |
| Messaging | Gmail, Twilio, Slack | Client email, follow-up text, staff alerts |
| Documents | Google Docs and Drive | Retainers and draft submissions |
| Payments | Stripe, Cloudflare Workers | Invoices, signature-verified payment events |
| Dashboard | Softr | Operations view |
| Governance | Python and Node tooling in this repo | Snapshots, static audit, guarded pushes, prompt registry, law index |

---

## 📁 What Is in This Repository

This public copy carries the governance tooling and public reference data. The live scenario snapshots, the database migrations, the internal audit records and specs, and the client-facing prompts stay in the private repo of record.

| Path | Contents |
|------|----------|
| `scripts/` | Read-only snapshot pull, the static auditor, the guarded push and create scripts, the secret scanner, the prompt registry tool, the IRPA and IRPR index builder and loader, and the drafting evaluation harness |
| `tests/` | Unit tests for the audit rules and push guards. Most read the private snapshots and audit inputs, so they do not run on their own |
| `worker/stripe-verify/` | The Cloudflare Worker that verifies Stripe signatures and forwards IDs only |
| `law/` | The IRPA and IRPR provision index built from the Justice Canada XML |
| `ref/` | Public reference data: supported visa types, document types and sections, and the IRCC vocabulary |
| `.githooks/` | The pre-commit secret scan |

*Immi-OS is a proprietary commercial system developed by Velocyt Consulting. To request a demonstration or discuss deployment for your firm, please reach out directly.*

📍 *Engineered in Mississauga, Ontario, Canada.*
