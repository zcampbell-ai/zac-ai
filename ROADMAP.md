# Zac AI Roadmap

## Purpose
Build the full Zac AI architecture incrementally, with useful,
verified results at every phase.

ARCHITECTURE.md defines the full scope.
SECURITY.md governs permissions and data handling.
DECISIONS.md records meaningful architectural decisions.
This roadmap defines implementation order, not a reduction in scope.

## Current Position
Phase 0 is in progress.
Implementation has not yet been verified.

## Tracking Rules
- [ ] means incomplete or not yet verified.
- [x] means completed and verified.
- Update this file as work is verified.
- Document blockers and the next concrete step.
- Do not mark a capability complete merely because code exists.
- Future phases remain planned until their prerequisites are met.
- Record changes to phase order or scope in DECISIONS.md.
- Do not silently substitute providers or commit to a technology stack.
- Verify current provider capabilities before choosing models or APIs.

## Phase Completion Requirements
For each phase:
- Demonstrate the intended behavior.
- Run relevant tests, including failure and permission cases.
- Document configuration and operation.
- Preserve source provenance and trust boundaries where applicable.
- Verify recovery or rollback appropriate to the change.
- Record remaining limitations and meaningful decisions.

## Phase 0 - Project Foundation
- [x] Create and clone the private zac-ai GitHub repository.
- [x] Populate CLAUDE.md.
- [x] Populate ARCHITECTURE.md.
- [x] Populate SECURITY.md.
- [x] Populate and verify ROADMAP.md.
- [x] Populate and verify DECISIONS.md.
- [x] Populate and verify README.md.
- [x] Inspect existing files and repository status.
- [x] Configure Git exclusions for secrets, private data, logs, and backups.
- [x] Review and commit the foundation documents.
- [x] Verify the foundation is backed up to the private repository.
- [x] Install and authenticate Claude Code on the Mac Studio.
- [x] Verify Claude Code reads and follows the project instructions. (Initial read-only review passed; this does not establish enforcement of every security policy.)
- [ ] Give Claude Code one bounded initial implementation task.

## Phase 1 - Local Runtime and Safety Foundation
- [ ] Inventory Mac Studio hardware and existing software.
- [x] Select and document the initial implementation stack. (D020: Python,
  `uv`, FastAPI, Pydantic v2)
- [x] Create a minimal, runnable application with health checks. (D020;
  verified via `uv run pytest`, `uv run ruff check`, `uv run mypy src`, and a
  manual `GET /health` check against a `127.0.0.1`-only server)
- [x] Establish development and production configuration separation. (D021:
  explicit `Environment` enum with exactly `development`/`production`,
  fail-safe on any other value, `.env.development` read only in development
  mode, production defaults unchanged and conservative; verified via
  automated tests and a manual run in each mode)
- [ ] Establish secrets management: `.env.development` is allowed for
  development/test secrets only; real production/runtime secrets use
  macOS Keychain; no plaintext `.env.production` file is used for real
  production secrets. Enforce PERSONAL_/BRAINSTORM_/SHARED_
  trust-boundary access in code, and apply centralized redacted
  logging. (D017)
- [ ] Add a lightweight local secret-scanning safeguard before any real
  credential is introduced. (D017)
- [ ] Implement personal and Brainstorm trust boundaries.
- [ ] Implement data classification and policy enforcement.
- [ ] Implement the initial action gateway with writes denied by default.
- [ ] Add automated checks for boundary and permission enforcement.
- [ ] Establish private access and document service startup and shutdown.
- [ ] Create an initial backup and verify restoration across all
  three recovery lanes (D017, D018): code/docs (Lane A, tested now),
  Zac State/database (Lane B, tested once canonical Zac State exists,
  with separate encryption keys per trust boundary), and secrets
  escrow (Lane C, tested once the first real approved credential
  exists in Keychain and the password manager - never create a
  credential solely to run this test). A successful Lane A restore
  drill alone does not satisfy this item; it remains incomplete until
  Lane B and Lane C have each been tested under those conditions.
- [x] Install Ollama and benchmark local models on real Zac AI tasks: a fast
  model, a stronger everyday model, a stronger reasoning model, and a coding
  model (evaluation only; not yet wired into canonical state, memory, or model
  routing). (D019)
- [x] Record local-model benchmark results and hardware fit as a decision in
  DECISIONS.md. (D019)

## Phase 2 - Canonical State, Memory, and Evidence
- [ ] Define schemas for all first-class entities in ARCHITECTURE.md.
- [ ] Implement Zac State and Brainstorm State.
- [ ] Support working, state, historical, and procedural memory.
- [ ] Preserve versioned state and temporal history.
- [ ] Store sources, timestamps, confidence, and contradictory evidence.
- [ ] Implement identity resolution with uncertain-match handling.
- [ ] Define retention, correction, export, and deletion behavior.
- [ ] Validate using synthetic data before connecting private sources.

## Phase 3 - Read-Only Integrations and Events
- [ ] Confirm Phase 1 secrets management, redacted logging, and a verified backup/restore are complete before connecting any live Gmail, Slack, Salesforce, or ClickUp account.
- [ ] Choose and document the first useful read-only integration.
- [ ] Implement a reusable connector and normalized event interface.
- [ ] Support deduplication, incremental sync, retries, and sync status.
- [ ] Preserve source permissions, provenance, and processing status.
- [ ] Add Gmail.
- [ ] Add Google Calendar.
- [ ] Add Google Drive.
- [ ] Add Slack.
- [ ] Add Fireflies.
- [ ] Add ClickUp.
- [ ] Add Salesforce.
- [ ] Verify each integration independently before adding the next.
- [ ] Ensure retrieved content cannot grant permissions or issue commands.

## Phase 4 - Chief of Staff and First Useful Workflows
- [ ] Implement the Chief of Staff control plane.
- [ ] Assemble relevant context from canonical state and evidence.
- [ ] Implement commitment extraction, ownership, dates, and status.
- [ ] Track open loops, decisions, overdue items, and follow-ups.
- [ ] Implement Urgent, Important, FYI, and Noise prioritization.
- [ ] Produce a source-backed daily briefing.
- [ ] Process meetings into draft decisions, commitments, and actions.
- [ ] Run workflows in shadow mode and compare with Zac's decisions.
- [ ] Measure missed items, false positives, and usefulness.

## Phase 5 - Model Routing and Shared Text Interface
- [ ] Implement a replaceable model-provider interface.
- [ ] Integrate the fast local model benchmarked in Phase 1 into the replaceable model-provider interface.
- [ ] Integrate the stronger local model benchmarked in Phase 1 into the replaceable model-provider interface.
- [ ] Add approved OpenAI and Anthropic provider adapters.
- [ ] Route by privacy, quality, latency, cost, tools, and availability.
- [ ] Add caching, usage accounting, budget alerts, and limits.
- [ ] Verify fallback behavior never weakens privacy restrictions.
- [ ] Provide manual text chat with shared state and source references.
- [ ] Support private access from laptop, phone, and browser.
- [ ] Keep optional ChatGPT and Slack interfaces replaceable.

## Phase 6 - Approvals and Verified Actions
- [ ] Create the approval and action interface.
- [ ] Show the exact proposed action, destination, and relevant evidence.
- [ ] Enforce risk levels and authorization centrally.
- [ ] Bind approval to the specific action being executed.
- [ ] Prevent duplicate execution and handle expired or changed actions.
- [ ] Log approvals, denials, execution, failures, and verification.
- [ ] Enable selected writes only after explicit authorization.
- [ ] Verify outcomes and support rollback where available.
- [ ] Keep high-risk actions subject to explicit human approval.

## Phase 7 - Specialist Workforce and Brainstorm Artifacts
- [ ] Add Communications workflows.
- [ ] Expand Meeting workflows.
- [ ] Add Sales / CRM workflows.
- [ ] Add Project / Delivery workflows.
- [ ] Add Research / Strategy workflows.
- [ ] Add Personal Admin workflows.
- [ ] Add Technical / Builder workflows, including Claude Code use.
- [ ] Add Artifact workflows.
- [ ] Build Brainstorm facts, standards, and exemplar libraries.
- [ ] Generate proposals, SOWs, decks, case studies, and reports.
- [ ] Evaluate factual support, pricing, brand, scope, and legal language.
- [ ] Keep specialist coordination behind the Chief of Staff interface.
- [ ] Evaluate OpenClaw only as an optional, replaceable component.

## Phase 8 - Voice and Interface Continuity
- [ ] Verify current voice-provider availability, quality, and cost.
- [ ] Evaluate the architecture's initial voice preference and alternatives.
- [ ] Implement voice through a replaceable provider interface.
- [ ] Share state, history, tools, routing, and permissions with text.
- [ ] Support interruption and reliable conversation continuity.
- [ ] Require explicit approval for sensitive actions initiated by voice.
- [ ] Verify useful voice access on desktop and mobile.

## Phase 9 - Evaluation, Feedback, and Selective Autonomy
Evaluation begins in earlier phases; this phase expands it.
- [ ] Establish independent evaluation for important outputs and actions.
- [ ] Track approvals, rejections, edits, ignored suggestions, and outcomes.
- [ ] Build scorecards for time saved, quality, failures, cost, and value.
- [ ] Benchmark routing and workflows against representative examples.
- [ ] Define measurable reliability criteria for each autonomous workflow.
- [ ] Enable only explicitly authorized, narrowly scoped autonomy.
- [ ] Provide pause controls and permission revocation.
- [ ] Allow proposed improvements through tests, review, and staging.
- [ ] Require human approval before production self-improvement changes.
- [ ] Prohibit self-expansion of security rules or permissions.

## Phase 10 - Future Sources and Publishing
- [ ] Add iMessage/SMS with explicit sensitive-data controls.
- [ ] Add X/Twitter and other approved social intelligence sources.
- [ ] Evaluate optional Muse and other replaceable intelligence providers.
- [ ] Add LinkedIn research, drafting, evaluation, approval, and publishing.
- [ ] Add optional HeyGen script, video, review, and publishing workflows.
- [ ] Preserve Zac's voice, source evidence, and publishing permissions.
- [ ] Track content outcomes without making providers canonical memory.

## Phase 11 - Recovery, Hardening, and Broader Brainstorm Use
Backups and operational checks begin in Phase 1 and continue throughout.
- [ ] Test recovery from Mac Studio failure and database corruption.
- [ ] Test credential rotation and model-provider replacement.
- [ ] Verify reproducible infrastructure and restorable knowledge.
- [ ] Test replacement of orchestration components.
- [ ] Review performance, observability, retention, and ongoing costs.
- [ ] Document routine operations and incident recovery.
- [ ] Define role-based access for broader Brainstorm use.
- [ ] Explore Sales, Delivery, Engineering, and Leadership intelligence.
- [ ] Verify Zac's personal data never becomes company-wide by default.

## Next Concrete Step
Inventory Mac Studio hardware and existing development tools using read-only checks before selecting the implementation stack.
