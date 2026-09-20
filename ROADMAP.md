# Zac AI Roadmap

## Purpose
Build the full Zac AI architecture incrementally, with useful,
verified results at every phase.

ARCHITECTURE.md defines the full scope.
SECURITY.md governs permissions and data handling.
DECISIONS.md records meaningful architectural decisions.
This roadmap defines implementation order, not a reduction in scope.

## Current Position
Phase 0 and Phase 1 are complete (see the Phase 1 completion audit,
DECISIONS.md D016-D025). Phase 2 (Canonical State, Memory, and Evidence)
has not yet started; D026 (Zac State v1 storage foundation) is under
architecture review before any Phase 2 implementation begins.

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
- [x] Give Claude Code one bounded initial implementation task. (Satisfied
  repeatedly since: D020-D025 were each a single, bounded, reviewed
  implementation task.)

## Phase 1 - Local Runtime and Safety Foundation
- [x] Inventory Mac Studio hardware and existing software. (D016: read-only
  inventory recorded in D016's Context - Apple M4 Max, 16 CPU cores, 40 GPU
  cores, 64GB memory, ~911GB free storage.)
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
- [x] Add a lightweight local secret-scanning safeguard before any real
  credential is introduced. (D017, D022: Gitleaks via Homebrew, blocking
  `.githooks/pre-commit` via `core.hooksPath`; verified via a clean
  full-history scan, an isolated block-test, and a clean staged-diff scan)
- [x] Implement personal and Brainstorm trust boundaries. (D023:
  `src/zacai/policy.py`, `TrustBoundary`/`evaluate_access`; verified via
  automated tests)
- [x] Implement data classification and policy enforcement. (D023:
  `DataClassification`/`Destination`/`AccessRequest`/`PolicyDecision` in
  `src/zacai/policy.py`; the HIGHLY_RESTRICTED+EXTERNAL hard-deny rule is
  implemented and tested, but this only covers the external-transmission
  case - storage/retention/logging-specific classification rules remain
  future work)
- [x] Implement the initial action gateway with writes denied by default.
  (D024: `src/zacai/gateway.py`, `ActionType`/`ActionRequest`/
  `GatewayDecision`/`evaluate_gateway`; calls `evaluate_access` first and
  unconditionally, so a D023 policy denial can never be overridden;
  external/state-changing writes default to REQUIRE_APPROVAL, and
  credential, permission, production, financial, and bulk-delete actions
  are hard-denied in v1 with no approval path yet; verified via automated
  tests)
- [x] Add automated checks for boundary and permission enforcement. (D024:
  `tests/test_gateway.py` proves policy-deny precedence cannot be
  overridden, drafts are non-executing and structurally separate from
  sends, writes require approval by default, dangerous/unsupported
  actions are denied even hypothetically approved, and every `ActionType`
  is classified into exactly one outcome)
- [x] Establish private access and document service startup and shutdown.
  (D025: `deploy/com.zacai.service.plist` LaunchAgent template,
  `scripts/service-install.sh`/`service-uninstall.sh`/`service-status.sh`,
  and a new `assert_safe_bind_host()` guard in `src/zacai/main.py` that
  refuses to start unless bound to `127.0.0.1`; README documents the full
  start/stop/restart/status/health/log workflow; verified via automated
  tests. Live installation and operational verification on the Mac
  Studio are complete: the LaunchAgent is installed and running, `lsof`
  confirmed it listens only on `127.0.0.1:8000`, and `launchctl kickstart
  -k` (restart) and `launchctl bootout` (clean stop, no auto-restart) were
  both verified; Tailscale remote access and log rotation remain future
  work)
- [ ] Create an initial backup and verify restoration across all
  three recovery lanes (D017, D018): code/docs (Lane A, tested now),
  Zac State/database (Lane B, tested once canonical Zac State exists,
  with separate encryption keys per trust boundary), and secrets
  escrow (Lane C, tested once the first real approved credential
  exists in Keychain and the password manager - never create a
  credential solely to run this test). A successful Lane A restore
  drill alone does not satisfy this item; it remains incomplete until
  Lane B and Lane C have each been tested under those conditions.
  Status: Lane A is complete; Lane B and Lane C are deferred by design,
  not incomplete work - Lane B cannot exist before Phase 2 creates
  canonical Zac State, and Lane C cannot be tested without a real
  approved credential, which must not be created solely to run this
  test (see RECOVERY.md). This item correctly stays open and does not
  block starting Phase 2 - Phase 2 is the prerequisite Lane B is
  waiting on.
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
Complete the D026 architecture review for Zac AI's Phase 2 Zac State v1
storage and schema foundation (database choice, boundary-storage design,
minimal first entity slice, temporal/versioning and provenance design)
before any Phase 2 implementation begins.
