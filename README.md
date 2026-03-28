# 🍁 Immi-OS: Autonomous Business Operating System for Immigration Consultants

*An enterprise-grade, AI-driven ecosystem designed specifically for Canadian immigration consultants. Immi-OS acts as an active "digital employee" that monitors the market, prepares clients for high-stakes interviews, enforces financial compliance, and drafts legal documentation.*

---

## 📂 [View System Prompts & Logic Architecture](./prompt.md)

---

## Who This Is For

- Licensed Canadian immigration consultants (RCICs) and law firms handling 50+ active case files
- Practices that rely on manual intake screening, legal drafting, and client communication — and want to reclaim 20+ hours per week
- Firms that need strict financial compliance guardrails (no submission without payment confirmation)
- Operators who require a transparent, auditable trail for every AI-generated output — critical for legal liability

---

## Architecture at a Glance

Immi-OS is a 15-scenario automation ecosystem orchestrated by Make.com with Airtable as the centralized relational database. OpenAI powers the cognitive layer — intake screening, legal drafting, news analysis, and interview coaching. Bland.ai handles real-time voice interactions (lead qualification, mock interviews). Stripe enforces financial compliance through webhook-gated state progression. Softr provides the executive dashboard and QA audit interface. Every scenario writes to an immutable Shadow Ledger, and a database-first architecture ensures zero data loss even during full API outages.

---

## Example: One Client's Journey

A single client flowing through the complete system:

1. **Lead Capture:** A prospect submits a web form. Data is instantly sanitized and written to Airtable → Status: **"New Lead"**
2. **AI Voice Screening:** Within 120 seconds, Bland.ai calls the prospect, conducts a dynamic eligibility interview, and returns a transcript. GPT-4.0 analyzes it → Status: **"VIP"** (immediate pathway + budget confirmed). Slack alert fires to the Senior Partner.
3. **Auto-Onboarding:** The system generates a customized Retainer Agreement and emails it immediately. The prospect signs and returns the PDF → Status: **"Review Contract"**. The signed document is auto-filed to Google Drive.
4. **Legal Drafting:** Immi-OS extracts all intake data, applies IRPA-compliant reasoning, and generates an 80% complete Submission Letter in Google Docs → Status: **"Draft Ready"**. The consultant reviews and finalizes.
5. **Financial Compliance:** The consultant marks the file "Ready for Submission." The system checks the balance, detects $2,500 outstanding, and issues a Stripe invoice automatically. The file is **locked** from progressing until `payment_intent.succeeded` is received → Status: **"Paid"**
6. **Interview Prep:** Before a scheduled CBSA interview, Bland.ai calls the client and conducts a 20-minute aggressive mock interview. GPT generates a Risk Scorecard flagging hesitation on financial questions → Status: **"Interview Prepped"**
7. **Submission & Celebration:** File is submitted. When IRCC approves, a HeyGen video avatar of the consultant congratulates the client by name → Status: **"Approved"**
8. **Market Reactivation:** Six months later, IRCC drops CRS requirements. The system queries sleeping leads, finds this client's spouse now qualifies, and triggers an outbound email + Bland.ai call → new case file opened automatically.

Every step above generates a Shadow Ledger entry. If any step fails, the error handler intercepts it, parks the payload, and fires a Slack alert.

---

## 📌 Executive Summary & Business Impact

By replacing manual administrative, drafting, and coaching work with intelligent automation, Immi-OS delivers significant measurable financial value. The system is designed to allow a single Senior Partner to handle the caseload of a two-person team.

| Module Category | Task Automated | Weekly Savings | Annual Value |
| :--- | :--- | :--- | :--- |
| **Admin & Intake** | Screening calls, Data entry, FAQ emails | 10 Hours | $75,000 |
| **Production** | Legal Document Drafting (First Pass) | 5 Hours | $37,500 |
| **Sales Operations** | Contract Sending, Filing & Onboarding | 2 Hours | $15,000 |
| **Service Delivery** | Mock Interview Coaching & Prep | 3 Hours | $22,500 |
| **Finance** | AR Collections & Compliance checks | 2 Hours | $15,000 |
| **TOTAL** | **Full System Automation** | **22 Hours** | **$165,000+** |

---

## 🏗️ Core Modules & Architecture (Deep Dive)

Immi-OS is orchestrated primarily via Make.com and utilizes a centralized Airtable database for relational design and view-based triggers. Below is the technical breakdown of the core modules that power the ecosystem.

*(Click to expand any section for architectural details)*

<details>
<summary><b>Module A: Multi-Channel Intake & Screening</b></summary>

* **Omni-Channel Capture:** Aggregates incoming leads via Webhook (from Softr/Webflow forms) and Mailhook (parsing raw email bodies). Data is instantly sanitized, formatted, and pushed to a centralized Airtable Leads table.

* **AI Voice Screening (Bland.ai):** An automated trigger fires a POST request to the Bland.ai API within 120 seconds of lead capture. The AI agent, armed with the lead's name and native language, conducts a dynamic qualification interview to verify eligibility constraints (Age, Education, Job Offer).

* **Transcript Analysis & Dynamic Tagging:** Upon call completion, the webhook payload (containing the full transcript) is routed through GPT-4.0 via Make.com. The LLM extracts key data points and updates the Airtable record with a definitive status tag:

    * *VIP:* Lead possesses an immediate pathway and budget. Triggers an urgent Slack ping to the Senior Partner.
    * *Nurture:* Lead lacks a specific requirement (e.g., IELTS score is 0.5 too low). Routed to targeted education.
    * *Disqualified:* No mathematical pathway exists under current IRPA guidelines.

</details>

<br>

<details>
<summary><b>Module B: Intelligent Nurture & Education</b></summary>

* **Conditional Logic Routing:** The system doesn't just send generic newsletters. Make.com reads the exact "missing variable" identified by GPT-4.0 in Module A and routes the lead into a highly specific drip sequence.

* **The "Nurture" Path:** If a lead needs a higher language score, they receive automated IELTS prep resources. If they need a job, they receive Canadian resume templates. This keeps the firm top-of-mind while the lead improves their profile, requiring zero consultant hours.

* **The "Disqualified" Path:** The system generates a polite, personalized rejection email explaining exactly why they do not qualify, attaching general resources. This protects the firm's brand reputation while completely shielding the consultant from time-wasting follow-ups.

<img src="./Assets/Bland-AI_conversational_pathway.png" width="100%" alt="Bland AI Pathway">

</details>

<br>

<details>
<summary><b>Module C: Market Watchdogs (News & Reactivation)</b></summary>

* **Real-Time Monitoring:** Custom automations scrape official immigration news and policy updates.

* **Heuristic AI Analysis:** OpenAI analyzes each news update to assign a Priority Level and categorize the impact (e.g., "CRS Score Drop," "New STEM Draw").

* **Active Reactivation Logic (The Database Query):** If the news is positive, Make.com triggers a search within the "Sleeping Leads" Airtable view, querying for profiles that mathematically match the new, lowered criteria.

* **The Wake-Up Trigger:** Matches immediately trigger a multi-channel sequence: an urgent Email AND a personalized Bland.ai outbound call stating, *"Good news, the IRCC requirements just changed and your profile is now eligible for submission."*

</details>

<br>

<details>
<summary><b>Module D: Automated Customer Service (CS)</b></summary>

* **Intent Recognition Routing:** When an existing client sends an email, Make.com routes the text to OpenAI to classify the intent (e.g., Status Update, Document Missing, General Question).

* **Status Inquiries:** For status inquiries, the system searches the client's specific Airtable record, extracts the current stage (e.g., "Awaiting Biometrics"), and drafts a highly accurate, personalized response.

* **Milestone Celebrations (HeyGen API):** When a file status shifts to "Approved," Make.com fires a webhook to HeyGen. It passes the client's name and visa type as variables to render a photorealistic Video Avatar of the consultant congratulating them, creating a premium client experience at zero marginal time cost.

<img src="./Assets/Make - Customer_Support_Bot_for_existing_client.png" width="100%" alt="Make.com Support Workflow">

</details>

<br>

<details>
<summary><b>Module E: The "Closer" & Auto-Onboarding</b></summary>

* **Solving Contract Friction:** Eliminates delays in sending agreements and the administrative clutter of manually filing signed PDFs.

* **The Pitch:** Once a lead is "Qualified," the system automatically generates the customized Retainer Agreement and emails it immediately.

* **The Listener:** The system monitors the inbox for replies with the subject "Retainer Agreement."

* **The Filer:** When the signed PDF arrives, the system validates the attachment, auto-saves it to the client's dedicated Google Drive folder, and updates the Airtable status to "Review Contract."

* **Impact:** Reduces "Speed-to-Contract" to near zero, increasing conversion rates while eliminating 100% of document filing work.

</details>

<br>

<details>
<summary><b>Module F: AI Legal Drafting Assistant</b></summary>

* **The Production Bottleneck:** Legal drafting (Study Plans, Submission Letters) traditionally consumes 1-2 hours of deep work per client.

* **Structured Prompt Chaining:** Immi-OS utilizes a multi-step GPT-5.2 Pro architecture. First, it extracts all factual data from the client's intake forms. Next, it applies IRPA-compliant reasoning to structure the argument. Finally, it drafts the narrative.

* **Output & Impact:** The system generates a highly formatted, 80% complete first draft directly into a Google Doc, allowing the consultant to bypass the "blank page" and focus strictly on high-level legal strategy and final review.

</details>

<br>

<details>
<summary><b>Module G: AI Visa Interview Simulator</b></summary>

* **The Feature:** A specialized Bland.ai voice agent configured with a strict, low-latency "IRCC / CBSA Officer" persona, designed to interrupt and pressure-test clients.

* **The Workflow:** While most Canadian applications are paper-based, targeted interviews (like Spousal Sponsorships) and Port of Entry (airport) examinations are incredibly high-stakes. Prior to landing or an official summons, the system calls the client and conducts a dynamic 20-minute aggressive roleplay simulation based on their specific case file.

* **The JSON Risk Scorecard:** Post-call, the transcript is analyzed by GPT-5.2 pro to generate a strict JSON output evaluating the client's performance (e.g., flagged hesitation on financial questions, contradictory relationship timelines). This provides the consultant with targeted coaching data, replacing hours of manual prep time.

</details>

<br>

<details>
<summary><b>Module H: Smart Financial Compliance</b></summary>

* **State-Locked Progression:** System progression is intrinsically tied to billing status. When a consultant marks a file as "Ready for Submission" in Airtable, a webhook checks the client's financial balance.

* **Automated Collections:** If an outstanding balance is detected, Make.com automatically generates and issues a Stripe invoice to the client.

* **The Guardrail:** The system locks the file from moving to the final "Submitted" stage until the payment_intent.succeeded webhook is received from Stripe, guaranteeing 100% payment compliance and eliminating awkward consultant-client money conversations.

</details>

<br>

<details>
<summary><b>Module I: System Governance (The "Shadow Ledger" & Failsafes)</b></summary>

* **The Problem with Black Boxes:** Standard automations fail silently during API timeouts, resulting in lost data and broken client journeys.

* **The Immutable Shadow Ledger:** A universal logging system engineered across all Make.com scenarios. Every single execution, whether a success or failure, is recorded into a centralized, immutable Airtable database. This tracks the exact payload, the AI prompt, the generated output, and the precise timestamp.

* **Failsafe Routing & Redundancy:** Implemented advanced Make.com error handlers (Break, Commit, Ignore, Resume). If a third-party API crashes, the system intercepts the RuntimeError, prevents data loss, securely parks the payload, and triggers an urgent Slack alert containing the error trace for manual resolution.

* **Impact:** Achieves true enterprise-grade reliability, ensures zero data loss during API outages, and maintains a 100% transparent audit trail.

</details>

<br>

<details>
<summary><b>Module J: Executive Dashboard & Quality Assurance</b></summary>

* **The CFO Command Center (Softr):** A secure, role-based web UI built on top of the Airtable base. It visualizes real-time pipeline velocity, conversion rates, and total API spending across the entire automation ecosystem.

* **The 5% QA Audit Protocol:** To ensure AI hallucinations do not reach the client, the dashboard features a purpose-built QA interface. It forces the Senior Partner to randomly sample 5% of all AI-generated emails and legal drafts, displaying the underlying prompt alongside the output to guarantee strict legal and tonal compliance.

</details>

---

## 🛡️ Enterprise-Grade Properties

| Property | Implementation |
|----------|---------------|
| **Zero data loss** | Database-first safeguard — all incoming client payloads are committed to Airtable before any logic execution begins. If the automation engine is offline, data waits in the queue and is processed sequentially upon recovery. |
| **State-locked progression** | File advancement is gated by external confirmations — Stripe payment webhooks must succeed before submission, signed PDFs must be validated before onboarding proceeds. No state transition without verification. |
| **Immutable audit trail** | The Shadow Ledger records every execution across all 15 scenarios — payload, AI prompt, generated output, timestamp, and outcome. Records are append-only for forensic-grade traceability. |
| **Failsafe error routing** | Advanced Make.com error handlers (Break, Commit, Ignore, Resume) intercept RuntimeErrors, park payloads safely, and fire immediate Slack alerts. Zero silent failures. |
| **AI output guardrails** | The 5% QA Audit Protocol forces random sampling of all AI-generated legal drafts and client communications. The Senior Partner reviews the underlying prompt alongside the output to catch hallucinations before they reach clients. |
| **Financial compliance** | Stripe webhook-gated billing ensures 100% payment collection before file submission. Eliminates accounts receivable aging entirely. |
| **Human override points** | Legal drafts require consultant review and finalization. AI-generated interview scorecards are advisory, not autonomous. No fully autonomous actions on high-stakes legal operations. |
| **Auto-recovery** | When Make.com is restored after an outage, the system automatically fetches unhandled records from the Airtable queue and processes them sequentially, maintaining correct chronological order for legal filings. |

---

## 🏗️ Architecture & Fault Tolerance

Immi-OS is engineered with a **Database-First Safeguard** to ensure 100% data integrity for high-stakes legal documentation.

* **Persistent Queueing (Airtable):** Unlike standard webhooks that "fire and forget," Immi-OS utilizes Airtable as an ACID-compliant staging layer. All incoming client payloads are committed to a permanent record before any logic execution begins.
* **Asynchronous Processing (Make.com):** Automation scenarios are triggered via record monitoring rather than direct HTTP POST requests. This decoupled architecture ensures that if the automation engine is offline, the client data is never dropped — it simply waits in the queue.
* **Auto-Recovery & Sequential Replay:** Once the processing service (Make) is restored, it automatically fetches unhandled records from the Airtable queue and processes them sequentially, maintaining the correct chronological order for legal filings.
* **Multi-Stage Validation:** Every node in the 15-scenario ecosystem contains custom error-handling logic (Break/Resume) to prevent silent failures during PDF generation or compliance checks.

---

## ⚙️ Production Considerations

- **Orchestration:** Make.com handles all scenario execution, webhook routing, and error handling across 15 interconnected scenarios
- **Database:** Airtable serves as the centralized relational database with view-based triggers, relational lookups, and role-based access control
- **Secrets Management:** All API keys (OpenAI, Bland.ai, Stripe, HeyGen) stored as Make.com connection credentials — never hardcoded in scenario logic
- **Rate Limits:** Make.com operations are throttled per plan tier. At scale, scenarios are partitioned by module to distribute execution load. Bland.ai concurrent call limits are managed via queue-based dispatching
- **QA & Compliance:** The Softr-based 5% audit protocol provides ongoing quality assurance. All AI-generated legal content is flagged for human review before client delivery
- **Scaling:** The modular architecture allows individual modules to be deployed independently. A firm handling 200+ active cases can partition intake, drafting, and compliance into separate Make.com organizations with shared Airtable access

---

## 🚀 Future Vision & Roadmap (V2.0)

* **Implementation of RAG (Retrieval-Augmented Generation):** Transitioning from prompt chaining to a Vector Database (e.g., Pinecone) containing the firm's successful past submissions and the Immigration and Refugee Protection Act (IRPA). Enabling the AI to cite specific case law and mimic the Senior Partner's writing style with high precision.

* **The "Consultant Replacement" Model:** By automating legal research and precedent retrieval via RAG, the system will evolve from a "Digital Secretary" to a "Digital Junior Associate." Strategic goal: Reduce the required headcount of junior consultants by 50%, allowing the firm to scale via technology rather than payroll.

* **Firm-Specific Writing Style Cloning:** Extend the vector database beyond IRPA citations to include each firm's past successful submission letters. The AI learns to replicate the Senior Partner's exact tone, argumentation structure, and phrasing patterns — producing drafts that read like the consultant wrote them, not a generic LLM.

* **Multi-Firm White-Label SaaS:** Architect Immi-OS as a deployable platform. Each firm receives their own Airtable base, Make.com organization, and Softr portal while sharing the same scenario templates. Deploy once, customize per firm — transitioning from selling consulting services to selling a product.

* **Predictive Compliance Scoring:** A risk assessment layer that scores each active case file on likelihood of approval based on historical outcome data. Cases below a configurable threshold are flagged for senior review before submission, reducing rejection rates and protecting the firm's approval record.

* **Multilingual Client Communication Layer:** Extend AI prompts to generate all client-facing communications (emails, status updates, celebration messages) in the client's preferred language while maintaining all internal records in English. The consultant operates in English; the client receives Mandarin, Punjabi, French, or Arabic.

---

## Technology Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| Orchestration | Make.com | Complex scenario execution, webhooks, JSON routing, error handling |
| Database | Airtable | Relational design, view-based triggers, Shadow Ledger, persistent queueing |
| Intelligence | OpenAI (GPT-4.0 / GPT-5.2 Pro) | News analysis, legal drafting, transcript analysis, risk scoring |
| Voice AI | Bland.ai | Lead screening calls, mock visa interview simulations |
| Video AI | HeyGen | Personalized milestone celebration videos |
| Communications | Twilio | SMS notifications and alerts |
| Payments | Stripe API | Webhook-gated invoicing and payment compliance |
| Presentation Layer | Softr | Executive dashboard, client portals, QA audit interface |

*Note: Immi-OS is a proprietary commercial system developed by Velocyt Consulting. To request a live demonstration of the architecture or discuss custom AI automation deployment for your firm, please reach out directly.*

📍 *Engineered in Mississauga, Ontario, Canada.*
