# Zac AI Decision Log

## Purpose
Preserve architectural decisions, their reasons, and their consequences.
Prevent future builders from silently changing the agreed direction.

These initial decisions come from Zac's planning conversation and
the established CLAUDE.md, ARCHITECTURE.md, and SECURITY.md.

Accepted means the direction is agreed, not that implementation is complete.

## Decision Process
- Record meaningful architectural decisions before implementing them.
- Use Proposed, Accepted, Rejected, or Superseded as the status.
- Distinguish verified facts from assumptions.
- Explain alternatives and tradeoffs for new technical choices.
- Do not treat a proposed decision as authorization.
- Preserve old decisions when superseded and link to their replacements.
- Never record credentials or secrets here.
- Security and permission changes remain subject to SECURITY.md.

## D001 - Zac AI Owns Canonical AI State
Status: Accepted

Decision:
Zac AI owns its durable AI state, memory, history, workflows,
permissions, and agent definitions.

Reason:
The system must survive changes in models, interfaces, and vendors.

Consequences:
ChatGPT, Claude, local models, and other providers are replaceable.
Connected business systems retain their own authoritative records.
Zac AI retains source references and reconciles its derived state.

## D002 - Mac Studio Is the Initial Compute Node
Status: Accepted

Decision:
Use the Mac Studio as the initial always-on private compute node.

Reason:
Provide a persistent foundation for local processing and orchestration.

Consequences:
Verify hardware capacity before choosing local models.
Document service operation, backups, and recovery.
Prefer private networking; do not expose local services publicly.

## D003 - Personal and Brainstorm Data Have Separate Boundaries
Status: Accepted

Decision:
Maintain logical separation and explicit permissions for personal
and Brainstorm data.

Reason:
Personal access must not imply company access, or vice versa.

Consequences:
Apply boundaries to storage, retrieval, agents, routing, and interfaces.
Future company-wide access must not expose Zac's personal information.

## D004 - State Must Preserve Evidence and History
Status: Accepted

Decision:
Maintain source-backed state, first-class entities, identity resolution,
and temporal history.

Reason:
Important conclusions must be explainable and correctable.

Consequences:
Retain provenance, timestamps, confidence, and relevant contradictions.
Do not silently merge uncertain identities or overwrite important history.

## D005 - Chief of Staff Coordinates Specialist Work
Status: Accepted

Decision:
Use the Chief of Staff as the primary control plane for priorities,
context, delegation, approvals, and specialist workflows.

Reason:
Zac should interact with useful outcomes without managing many agents.

Consequences:
Specialists operate within shared policies and permissions.
Creating an agent does not grant additional access or autonomy.

## D006 - Integrations Start Read-Only
Status: Accepted

Decision:
Begin new integrations with read-only access unless explicitly
authorized otherwise.

Reason:
Validate understanding and reliability before enabling external effects.

Consequences:
Treat retrieved content as untrusted data.
Add writes deliberately through the central action gateway.
Never expand integration permissions silently.

## D007 - External Actions Use a Central Approval Gateway
Status: Accepted

Decision:
Route external actions through central permission and approval checks.

Reason:
Make action authority consistent, reviewable, and auditable.

Consequences:
Progress from observation to drafts, approved actions, and narrowly
authorized autonomy.
High-risk actions always require explicit human approval.
Log important actions and verify their outcomes.

## D008 - Model Routing Is Replaceable and Policy-Aware
Status: Accepted

Decision:
Support fast local, stronger local, OpenAI, Anthropic, and future
providers through replaceable interfaces.

Reason:
Balance privacy, quality, latency, cost, and tool capability.

Consequences:
Measure performance on actual Zac AI workflows.
Do not assume a provider is approved for every data classification.
Fallbacks must not weaken privacy or permission restrictions.
Specific models remain undecided until availability and fit are verified.

## D009 - Text and Voice Are Equal First-Class Interfaces
Status: Accepted

Decision:
Text and voice share canonical state, history, tools, permissions,
agents, and model routing.

Reason:
Zac should be able to move between interfaces without losing context.

Consequences:
Voice providers remain replaceable and do not own canonical memory.
The architecture's GPT-Live-1 reference is an initial preference,
not a verified API selection or implementation commitment.
Verify current availability, quality, and cost before choosing a provider.
Retain Gemini Live, ElevenLabs, and future providers as alternatives.

## D010 - OpenClaw Is Optional and Replaceable
Status: Accepted

Decision:
OpenClaw may be evaluated as an orchestration component.

Reason:
An orchestration framework must not become an irreplaceable dependency.

Consequences:
Adoption is not yet decided.
Do not keep canonical identity, business logic, or history solely
in OpenClaw-specific formats.

## D011 - Build Incrementally and Verify Before Expanding
Status: Accepted

Decision:
Follow ROADMAP.md in bounded, useful phases.

Reason:
Reduce complexity and verify value before increasing scope or autonomy.

Consequences:
Use relevant tests, evaluator review, staging, and shadow mode.
Record evidence before marking capabilities complete.
Keep changes focused, observable, and reversible where practical.

## D012 - Self-Improvement Requires Controlled Promotion
Status: Accepted

Decision:
The system may propose improvements but must validate them before
production deployment.

Reason:
Improvement must not bypass security or human control.

Consequences:
Follow Builder -> Tests -> Evaluator -> Staging/Shadow
-> Human approval -> Production.
Do not allow unrestricted changes to permissions, credentials,
approval rules, security boundaries, or critical infrastructure.

## D013 - Brainstorm Artifacts Use Facts, Standards, and Exemplars
Status: Accepted

Decision:
Maintain separate libraries for company facts, approved standards,
and strong examples.

Reason:
Proposals and other artifacts need consistent, supported content.

Consequences:
Evaluate source support, accuracy, pricing, brand, scope,
and legal/commercial language before use.

## D014 - Recovery and Value Measurement Are Core Requirements
Status: Accepted

Decision:
Build recoverability, operational visibility, and value measurement
into the system from the beginning.

Reason:
The system must remain useful and recoverable as dependencies change.

Consequences:
Back up code, configuration, and state; store secrets separately.
Test restoration and document recovery.
Track quality, failures, time saved, local usage, and cloud costs.
Optimize total value rather than minimum API spending alone.

## D015 - Future Scope Remains Part of the Architecture
Status: Accepted

Decision:
Preserve future iMessage/SMS, social intelligence, optional Muse,
LinkedIn publishing, optional HeyGen, and broader Brainstorm use.

Reason:
Early implementation should support the long-term direction
without trying to build everything immediately.

Consequences:
Implement these capabilities in later roadmap phases.
Evaluate provider capabilities and permissions before adoption.
Publishing requires approval unless explicitly authorized otherwise.
Broader Brainstorm use requires role-based access.

## D016 - Initial Technology Stack and Early Local Model Evaluation
Status: Accepted
Date: 2026-09-18

Context:
A read-only inventory of the Mac Studio (Apple M4 Max, 16 CPU cores -
12 Performance and 4 Efficiency, 40 GPU cores, 64GB memory, and
approximately 911GB free storage) confirmed ample hardware headroom
for local inference. Homebrew, Python, uv, Node.js/npm, PostgreSQL,
pgvector, Docker, Ollama, MLX, OpenClaw, Tailscale, and Claude Code
were evaluated against Apple Silicon performance, security,
simplicity, vendor replaceability, local AI capability, future
event-driven integrations, temporal/source-backed memory, model
routing, and backup/disaster recovery, as required before selecting
the Phase 1 implementation stack.

Decision:
Sequence the v1 stack as follows:

Install now:
- Homebrew
- uv

Already installed/configured:
- Tailscale
- Claude Code
- Apple Command Line Tools
- Git

Install early, immediately after the basic Phase 1 development
foundation is in place:
- Ollama
- One fast local model
- One stronger local model
This early work is a benchmark only. Ollama and the chosen local
models do not become canonical architecture and do not own system
state. Integrating them into the model router remains a Phase 5
activity, informed by this early benchmark.

Install later, when justified by the relevant implementation phase:
- Python, managed through uv
- PostgreSQL
- pgvector
- MLX

Do not install yet:
- Node.js/npm
- Docker
- OpenClaw

Alternatives considered:
Leaving all local-model evaluation at its original Phase 5 placement
was rejected because local inference is a core design goal of Zac AI
and real local performance and quality should be benchmarked early
rather than assumed. Installing Docker now to run Ollama or
PostgreSQL in containers was rejected for v1; on a single always-on
node, native Homebrew services are simpler and avoid the overhead of
Docker Desktop's Linux virtual machine on Apple Silicon. Adopting
OpenClaw now was rejected; it remains an optional, later, replaceable
orchestration component per D010. Installing Python directly through
Homebrew was rejected in favor of managing it through uv, which can
provision an exact interpreter version on demand without pre-empting
the still-open application language and framework decision.

Reasons and tradeoffs:
Homebrew and uv are foundational, low-risk, and reversible, and they
unblock later steps without pre-committing to unresolved Open
Decisions. Tailscale and Claude Code are already in place and satisfy
SECURITY.md's private-networking guidance and the Phase 1 private-
access task. Early Ollama and local-model benchmarking trades a small
amount of near-term simplicity for earlier evidence on a core design
goal, while deliberately withholding state ownership and model-router
integration so that vendor and model replaceability are preserved.
PostgreSQL, pgvector, and MLX wait for the phases that actually need
them, keeping the running surface minimal. Node.js/npm, Docker, and
OpenClaw are withheld because nothing in the current or next phase
requires them, and installing them now would guess at still-open
decisions or add unnecessary services.

Security and data implications:
This decision only sequences tooling installation; no live personal
or Brainstorm data is processed by it. Ollama and local models run
entirely on-device with no external network exposure, consistent
with SECURITY.md's preference for local processing. Tailscale ensures
no service is exposed to the public internet. Data classification,
trust boundaries, and approval requirements are unchanged. Secrets
management, redacted logging, and a verified backup and restore must
be completed before any live Gmail, Slack, Salesforce, or ClickUp
account is connected.

Consequences:
Ollama and its models are evaluated early but remain outside
canonical state, memory, and the model router until Phase 5 formally
integrates them. ROADMAP.md Phase 1 gains explicit local-model
benchmarking steps; Phase 5 is reworded to integrate the Phase 1
benchmark results rather than evaluate from zero; Phase 3 gains an
explicit gate requiring secrets management and a verified backup and
restore before any live Gmail, Slack, Salesforce, or ClickUp
connection. PostgreSQL, pgvector, MLX, Node.js/npm, Docker, and
OpenClaw remain undecided or deferred; none are authorized for
installation by this decision. Zac AI continues to own canonical
state and history; personal and Brainstorm trust boundaries, source
provenance, temporal memory, security and approval gates, and
model/vendor replaceability (D001, D003, D004, D007, D008, D010) are
unchanged by this decision.

Verification:
Confirm that only Homebrew and uv are installed as an immediate
result of this decision. When Ollama and the two local models are
later installed, confirm they are reachable only through localhost or
Tailscale, never a public interface. Confirm Phase 5 work references
and builds on the Phase 1 benchmark rather than repeating evaluation
from scratch. Confirm no live Gmail, Slack, Salesforce, or ClickUp
connection is made until the Phase 3 gate is checked off and
verified.

Approval or source:
Zac Campbell, architecture review conversation, 2026-09-18.

Supersedes:
None. Extends D002 (Mac Studio Is the Initial Compute Node) and D008
(Model Routing Is Replaceable and Policy-Aware) by sequencing their
implementation; does not change the substance of either decision.

## D017 - Secrets and Configuration Management Approach (v1)
Status: Accepted
Date: 2026-09-18

Context:
Phase 1 requires establishing secrets management and redacted logging
before any live integration is connected (ROADMAP.md Phase 1; Phase 3
gate). DECISIONS.md listed secrets storage implementation as an open
decision. An architecture review evaluated environment variables,
.env files, macOS Keychain, encrypted storage, and dedicated secrets
managers against SECURITY.md and CLAUDE.md: never commit secrets to
Git, never hardcode them in source, keep Personal and Brainstorm
credentials logically separable, distinguish development from
production/runtime configuration, and avoid granting Claude Code or
other agents automatic access to every secret.

Decision:
Adopt a three-tier, env-var-based secrets and configuration model
for v1:
- Tier 0: versioned, non-secret configuration (ports, feature flags,
  model names, log levels) in committed config files that reference
  secret names only, never values.
- Tier 1: local development and test secrets in a gitignored
  `.env.development` file. Development credentials only; never used
  for production/runtime secrets.
- Tier 2: real production/runtime secrets stored in macOS Keychain,
  read into process environment variables only at service startup by
  a small loader. No plaintext `.env.production` file will hold real
  credentials.

Every secret name carries a trust-boundary prefix: PERSONAL_,
BRAINSTORM_, or SHARED_. Boundary access is enforced in code through
a config-loader accessor that checks a secret's prefix against the
caller's declared boundary, not by naming convention alone.
Centralized logging redaction removes values matching secret-like
key names and common token shapes before anything is written to a
log or surfaced to Zac. Secrets recovery is documented and tested
separately from the Git code backup and any database backup.
Keychain is treated as the current implementation of a replaceable
secrets-provider interface, so it can be swapped for a dedicated
secrets manager later without changing application code.

No real credentials or Keychain entries are created by this
decision. They will be added only when a specific approved
integration requires them. A lightweight local secret-scanning
safeguard will be added to Phase 1 before any real credential is
introduced; CI-enforced scanning is deferred.

Alternatives considered:
A plaintext .env.production file for real credentials was rejected:
it would leave production secrets unencrypted at rest and readable
by any process or tool, including Claude Code, with file access,
undermining the requirement that agents not automatically gain
access to every secret. A dedicated secrets manager (Vault, Doppler,
1Password Connect, AWS/GCP Secrets Manager) was rejected for v1 as
unjustified infrastructure for a single always-on node with a single
operator; it remains available later without an architecture change
because the application only ever depends on environment variables,
not on Keychain specifically. Relying on naming convention alone,
without code-enforced boundary checks, was rejected because a
convention can be silently bypassed. Deferring secret-scanning
entirely was rejected; a lightweight local safeguard is cheap enough
to add before real credentials exist, though CI enforcement can
wait.

Reasons and tradeoffs:
Keychain gives OS-level encryption at rest and requires an explicit,
visible retrieval action rather than an incidental file read, which
better satisfies the requirement that agents not automatically see
every secret. This adds a small amount of implementation work, a
loader script, and is macOS-specific, but only at the retrieval
layer; the application itself remains portable because it only
consumes environment variables. Building the security rails, that
is boundary enforcement, redaction, a recovery plan, and a scanning
safeguard, before any real credential exists trades a small delay in
connecting integrations for confidence that the rails work before
anything sensitive depends on them.

Security and data implications:
No live personal or Brainstorm data or credentials are introduced by
this decision. Data classification, trust boundaries (D003), and
approval requirements in SECURITY.md are unchanged. This decision
specifies the mechanism by which SECURITY.md's existing rule to use
environment variables or an approved secrets mechanism is satisfied
for v1, and clarifies that macOS Keychain is the approved mechanism
for production/runtime secrets.

Consequences:
ROADMAP.md Phase 1 gains an explicit item to add a lightweight local
secret-scanning safeguard before any real credential is introduced,
and clarifies that production secrets use Keychain rather than a
.env.production file. SECURITY.md is updated to name Keychain as the
approved v1 mechanism for production secrets, to require code-
enforced boundary access, and to require secrets recovery to be
tested separately from code and database backup. No files, Keychain
entries, or software are created or installed by this decision
itself; those remain separate, later steps gated on an approved
integration actually needing credentials.

Verification:
Confirm no .env.production file or real credential exists until a
specific approved integration requires one. Confirm any secret
ultimately introduced is named with a PERSONAL_, BRAINSTORM_, or
SHARED_ prefix and is only reachable through the boundary-checked
accessor. Confirm centralized log redaction is in place and tested
before any real credential is introduced. Confirm a lightweight
local secret-scanning safeguard is installed and run before any real
credential is introduced. Confirm secrets recovery is documented and
tested separately from code and database backup/restore.

Approval or source:
Zac Campbell, architecture review conversation, 2026-09-18.

Supersedes:
None. Resolves the "Secrets storage implementation" item from the
Open Decisions list.

## D018 - Backup and Recovery Architecture (v1)
Status: Accepted
Date: 2026-09-18

Context:
ARCHITECTURE.md ("Disaster Recovery") and SECURITY.md ("Backups and
Recovery") require recoverable code, state, and configuration, with
secrets stored and recovered separately from code and database
backups. D014 established recovery and value measurement as a core
v1 requirement. D017 already established macOS Keychain as the v1
production/runtime secret store. An architecture review designed the
concrete backup/recovery model for the Mac Studio, at a point where
no canonical Zac State/database yet exists and no real Keychain
credential yet exists.

Decision:
Adopt a three-lane recovery model, each lane independently
restorable so that recovering one never depends on recovering
another:

- Lane A - Code and documentation: Git plus the private GitHub
  repository. Already continuously off-device; no new mechanism
  needed. `RECOVERY.md` documents the model and manual rebuild
  procedure and is itself versioned under Lane A.
- Lane B - Zac State / database (Phase 2+, does not exist yet):
  scheduled local dump plus a client-side encrypted off-device copy.
  Personal and Brainstorm state must be encrypted with separate keys
  once those stores hold sensitive data; a single shared key across
  both trust boundaries is not permitted. Daily dump with a small
  rolling retention window (for example 7 daily plus 4 weekly) is the
  intended frequency once Lane B exists. The specific off-device
  storage destination is deferred (see Open Decisions) until closer
  to when canonical Zac State is created.
- Lane C - Secrets escrow: the existing password manager, decided
  this session as the v1 off-device escrow for whatever is in macOS
  Keychain. No separate encrypted secrets archive is built. No
  Keychain export/import automation is built yet. Neither the
  password manager nor Keychain is populated with any Zac AI
  credential until a specific approved integration requires it,
  unchanged from D017.

A successful Lane A restore drill (cloning the GitHub repository)
validates Lane A only. It does not, by itself, satisfy the Phase 1
"create an initial backup and verify restoration" requirement. That
requirement remains incomplete until canonical Zac State exists and
Lane B restoration has actually been tested, and until the first real
approved credential exists and Lane C recovery has actually been
tested. A credential must never be created solely to run a recovery
test.

Client-side encryption is required before any off-device copy leaves
the Mac Studio, with the decryption key held separately from the
encrypted data itself. `age` is the currently preferred candidate
tool for this encryption, but it is not installed and not adopted as
a final tool choice by this decision, so the architecture is not
locked to a specific tool before Lane B or Lane C actually require
one.

No credentials, Keychain entries, password-manager entries, backup
files, or software installs are created by this decision itself.

Alternatives considered:
A separate encrypted secrets archive for Lane C was considered and
rejected in favor of the existing password manager, which avoids
duplicate infrastructure and manual key management for something the
password manager already does. Automating Keychain export/import now
was rejected as premature, since no real secret exists yet to
protect. A single shared encryption key across the Personal and
Brainstorm boundaries for Lane B was rejected because it would let
access to one boundary's backup expose the other's data, which would
violate D003. Choosing the Lane B off-device destination now was
rejected as premature, since no canonical Zac State exists yet to
determine realistic size or access-pattern requirements; deferring
avoids guessing. Committing to `age`, or any specific encryption
tool, now was rejected to keep the architecture tool-agnostic until
Lane B or Lane C actually require encryption.

Reasons and tradeoffs:
Reusing the existing password manager for Lane C avoids new
infrastructure and manual encrypted-file upkeep, at the cost of
depending on that vendor for secrets recovery. This is acceptable
because Keychain remains the primary v1 runtime store and the
password manager is only an off-device escrow of values, not logic
or canonical state, consistent with vendor-independence principles.
Separate encryption keys per trust boundary for Lane B add minor
key-management overhead later but are necessary to prevent a
boundary violation at the backup layer. Deferring the Lane B
destination and the encryption tool choice trades some near-term
architectural completeness for avoiding premature commitments before
real requirements are known.

Security and data implications:
No live personal or Brainstorm data, credentials, or backups are
created by this decision. Data classification and trust boundaries
(SECURITY.md, D003) directly shape Lane B's per-boundary
encryption-key requirement. Highly Restricted secrets continue to
default to local storage in Keychain, with the password manager
serving only as an off-device escrow, consistent with SECURITY.md's
Highly Restricted handling.

Consequences:
`RECOVERY.md` is created describing the three-lane model and the
manual rebuild procedure. ROADMAP.md's Phase 1 backup/restore item is
reworded so that Lane A success alone is not mistaken for the full
requirement, and so that Lane C testing waits for the first real
approved credential rather than requiring one to be created for the
test. DECISIONS.md's Open Decisions list narrows its backup entry to
the Lane B off-device storage destination, since the lane model,
schedule, retention pattern, and Lane C location are now decided. No
Keychain entries, password-manager entries, backup files, or software
installs happen as a result of this decision.

Verification:
Confirm `RECOVERY.md` exists and accurately describes the three
lanes and rebuild steps. Confirm no backup files, Keychain entries,
password-manager entries, or installed encryption tooling exist as
an immediate result of this decision. Confirm the Phase 1
backup/restore roadmap item remains unchecked until Lane B has been
tested against real Zac State and Lane C has been tested against a
real approved credential. Confirm any future Lane B implementation
uses separate encryption keys per trust boundary. Confirm no
credential is ever created solely to run a recovery test.

Approval or source:
Zac Campbell, architecture review conversation, 2026-09-18.

Supersedes:
None. Extends D014 (Recovery and Value Measurement Are Core
Requirements) and D017 (Secrets and Configuration Management
Approach) by defining the concrete backup/recovery model and Lane
C's chosen location; does not change the substance of either.

## D019 - Initial Local-Model Benchmark and Provisional Role Assignments
Status: Accepted
Date: 2026-09-18

Context:
ROADMAP.md Phase 1 required installing Ollama and benchmarking one fast local
model and one stronger local model on real Zac AI tasks, building on the tooling
sequence D016 established (Ollama installed early, models evaluated before any
canonical-state or model-router integration). On the Mac Studio (Apple M4 Max,
64GB unified memory), four models were installed and benchmarked in one pass
rather than two, since MLX-servable options made a reasoning-tier and a
coding-tier model equally cheap to test alongside the originally planned fast and
stronger models: qwen3.5:0.8b, qwen3.5:9b-mlx, qwen3.8:27b-mlx, and
qwen3-coder:30b.

Decision:
Record the following benchmark results and provisional role assignments:

1. qwen3.5:0.8b - ~229 tokens/sec generation. Appropriate for very lightweight
   routing, tagging, classification, and simple extraction. Not appropriate for
   nuanced reasoning or high-stakes work.
2. qwen3.5:9b-mlx - ~70 tokens/sec generation; with thinking disabled, completed
   an inbox-triage task in ~1.5 seconds. Strong candidate for the default
   everyday local worker: routine summaries, classification, extraction, and
   normal agent work. Thinking should generally be disabled for simple workflows
   to reduce latency and unnecessary output.
3. qwen3.8:27b-mlx - roughly 36-58 tokens/sec depending on workload. Suitable as
   the stronger local reasoning tier for business analysis. Observed limitation:
   invented an unsupported "2-week paid discovery" detail in one benchmark run.
   Must remain subject to source grounding, structured-output checks, and
   evaluator safeguards (ARCHITECTURE.md Section 18, Evaluator Layer) before its
   output is trusted or acted upon.
4. qwen3-coder:30b - roughly 100-110 tokens/sec on coding benchmarks. Appropriate
   for local software engineering: prototype scaffolding, code generation,
   refactoring, tests, and implementation drafts. Observed limitation: some
   architecture, security, and prototype-design choices still require human
   review. Must not bypass Zac AI security rules (SECURITY.md) or ship
   production code without review and evaluation.

Keep all four models installed for now. Stop downloading additional models for
now. Do not make Ollama or any individual model canonical. These are provisional
role assignments based on current benchmarks, not permanent choices; Zac AI will
route between models through a replaceable provider/model-router interface (D008)
once Phase 5 formally integrates them. Data classification (SECURITY.md) - not
cost or model quality - continues to determine which cloud providers may receive
sensitive data; DeepSeek's hosted API is specifically not approved as a default
provider for confidential Brainstorm or personal data. Approved cloud escalation
beyond the existing OpenAI/Anthropic pattern remains a separate, later decision.
New local models should be benchmarked against repeatable Zac AI workloads before
replacing an incumbent in any of the four roles above.

Alternatives considered:
Limiting this benchmark to exactly the two models the Phase 1 item named (one
fast, one stronger) was rejected: MLX made a reasoning-tier and a coding-tier
model similarly cheap to evaluate in the same hardware pass, and earlier evidence
on likely-needed roles reduces rework later. Giving qwen3.8:27b-mlx or
qwen3-coder:30b unrestricted autonomous responsibility on the strength of this
benchmark was rejected: both showed concrete limitations (an invented detail; and
architecture/security choices needing review) that must be caught by the existing
evaluator and review safeguards (ARCHITECTURE.md Sections 18-19) rather than
trusted outright. Treating this benchmark as sufficient to wire any of these
models into canonical state, memory, or the model router now was rejected; that
integration remains Phase 5's job per D008 and the Phase 1/Phase 5 split already
recorded in D016 and ROADMAP.md.

Reasons and tradeoffs:
Benchmarking four models in one pass gives broader early evidence at low
incremental cost on hardware already provisioned under D016, at the cost of a
slightly larger provisional surface to track before Phase 5. Keeping role
assignments provisional and explicitly outside canonical state and model routing
preserves model and vendor replaceability (D001, D008) while letting later phases
build on measured performance instead of assumptions.

Security and data implications:
No live personal or Brainstorm data was processed by this benchmark; all four
models ran locally on-device with no external network exposure, consistent with
SECURITY.md's preference for local processing. Data classification and trust
boundaries (SECURITY.md, D003) are unchanged. This decision reaffirms that
model-quality or cost findings do not override SECURITY.md's data-classification
rule: DeepSeek's hosted API is not approved as a default provider for
confidential Brainstorm or personal data, independent of its cost or quality.

Consequences:
ROADMAP.md Phase 1's two local-model-benchmark items are marked complete, the
first reworded to name the four models actually benchmarked instead of "one fast
... one stronger." Phase 5's existing wording ("Integrate the fast local model
benchmarked in Phase 1" / "the stronger local model benchmarked in Phase 1") is
unchanged in substance; this decision identifies which specific models
provisionally fill those two roles, plus two additional provisional roles
(reasoning tier, coding tier) Phase 5 or Phase 7 may draw on for reasoning- or
coding-oriented workflows. No canonical state, memory, or model-router code
changes result from this decision.

Verification:
Confirm all four named models remain installed and no additional models are
installed until a new benchmarking decision authorizes it. Confirm no canonical
state, memory, or model-router code references these models yet (Phase 5
remains open). Confirm DeepSeek's hosted API is not configured as a provider
anywhere in the codebase.

Approval or source:
Zac Campbell, local-model benchmark on Mac Studio, 2026-09-18.

Supersedes:
None. Extends D016 (benchmarks the Ollama and local models it sequenced for
installation) and D008 (informs, but does not implement, model routing).

## D020 - Initial Application Language and Framework (v1)
Status: Accepted
Date: 2026-09-19

Context:
D016 sequenced Python (managed via `uv`) as a runtime to install "later, when
justified," but explicitly left "the still-open application language and
framework decision" unresolved. ROADMAP.md Phase 1's next unchecked items were
"Select and document the initial implementation stack" and "Create a minimal,
runnable application with health checks." DECISIONS.md's Open Decisions list
still carried "Application language and framework" as unresolved. An
architecture review evaluated Python+FastAPI, Python with another lightweight
framework (Litestar, Flask, Sanic), and TypeScript/Node.js against: AI/model
integration, async/event-driven workflows, strong typing/schema validation,
local model access via Ollama now with replaceable providers later, future
Gmail/Slack/Drive/Fireflies/ClickUp/Salesforce connectors, temporal/source-backed
state, future PostgreSQL/pgvector, security/testability, simple single-node
deployment, ease of use by Claude Code and future coding agents, observability,
the ability to evolve into the full ARCHITECTURE.md system without a rewrite,
minimal operational complexity, novice-friendly maintenance, and vendor
neutrality. A Plan-agent review of the resulting recommendation, cross-checked
against ARCHITECTURE.md, SECURITY.md, ROADMAP.md, SECRETS.md, and D016/D017,
confirmed the stack choice and identified one scoping adjustment (folded into
this decision): ROADMAP.md Phase 1 lists secrets management (boundary-checked
access and centralized redacted logging, D017) as its own item alongside
"create a minimal app," not as a later phase, so the v1 milestone was scoped to
include both.

Decision:
Adopt Python, managed via `uv`, with FastAPI as the application framework and
Pydantic v2 as the schema/validation layer, for Zac AI's first runnable
application and going forward as the default backend stack until a specific
later phase justifies otherwise.

Implement the Phase 1 minimal milestone as:
- `src/zacai/main.py`: a FastAPI app exposing `GET /health` (status, version,
  UTC timestamp), with no external calls, no secrets, and no model calls.
- `src/zacai/config.py`: a Tier-0 settings loader (`pydantic-settings`, reading
  only non-secret configuration - host, port, log level, environment) and a
  boundary-checked secrets accessor (`get_secret`) that enforces the
  PERSONAL_/BRAINSTORM_/SHARED_ prefix in code per SECRETS.md/D017, even though
  no real secret exists yet.
- `src/zacai/logging_config.py`: structured JSON logging to stdout with a
  redaction function that strips secret-like key/value pairs and bearer tokens
  before anything is emitted, wired so that uvicorn's own request/lifecycle
  logs also flow through it (`log_config=None`) rather than bypassing it.
- Automated tests for the health endpoint, for the secrets accessor's
  boundary enforcement (matching, absent, and cross-boundary/unprefixed
  lookups, using only fake test values), and for logging redaction (fake
  password/token values, asserting they never appear unredacted in emitted
  output).
- README.md documents local install/run/test commands.

Deliberately deferred, not part of this decision: any Ollama or model-provider
integration, any database, any live external integration, the standalone
local secret-scanning safeguard (ROADMAP.md's separate Phase 1 item), Zac
State, and Node.js/npm/Docker/OpenClaw (unchanged from D016).

Alternatives considered:
Python with another lightweight framework (Litestar, Flask, Sanic) was
rejected: FastAPI's native Pydantic integration doubles as the future
entity/event schema layer ARCHITECTURE.md Section 4 calls for, its
auto-generated OpenAPI will help the future approval/action interface (Phase
6) and multiple clients (Phase 5), and it has the deepest representation in
coding-agent training data among the async Python options, which measurably
helps Claude Code and future agents work on this codebase reliably.
TypeScript/Node.js was rejected: the AI/local-model ecosystem (Ollama clients,
structured-output tooling) is deepest in Python, which the project needs
regardless of what serves the API; adding Node as a second runtime would
increase operational complexity on a single-operator, single-node system; and
D016 already declined to install Node/npm with no new justification having
appeared. No other language was found genuinely superior against the stated
priorities. A bare Starlette app or no framework at all was considered for the
literal health-check milestone but rejected as saving nothing meaningful
today while giving up the Pydantic/OpenAPI/WebSocket benefits above -
FastAPI's dependency-injection machinery is opt-in and unused by a
single-route app, so it does not add the operational complexity a "framework"
label might suggest.

Reasons and tradeoffs:
Python was already required for AI/local-model work, so FastAPI adds one
focused dependency rather than a second language or runtime. Building the
boundary-checked secrets accessor and redacted logging now, before any real
secret exists, trades a small amount of near-term scope for having the
security rails verified and tested before anything sensitive depends on them -
consistent with how D017 and D018 built their rails ahead of real credentials
and real state. Wiring uvicorn's own logs through the same redaction path
(`log_config=None`) trades uvicorn's default log formatting for a single,
centrally-redacted logging path, avoiding a gap where the framework's own
request logs could bypass SECURITY.md's redaction requirement once real
requests carry sensitive data.

Security and data implications:
No live personal or Brainstorm data, credentials, or Keychain entries are
introduced by this decision. The boundary-checked accessor and redaction
function were exercised only against fake, clearly-not-real test values in
automated tests - never a real credential. Data classification and trust
boundaries (SECURITY.md, D003) are unchanged. The application binds to
`127.0.0.1` only by default (verified manually), consistent with SECURITY.md's
private-networking requirement; Tailscale-only remote access is unaffected by
this decision.

Consequences:
ROADMAP.md Phase 1's "Select and document the initial implementation stack"
and "Create a minimal, runnable application with health checks" items are
marked complete, verified by a passing test suite (`uv run pytest`), a clean
lint pass (`uv run ruff check`), a clean type-check pass (`uv run mypy src`),
and a manual health-check/localhost-binding verification. The Phase 1 secrets
management item is not marked complete: the boundary-checked accessor and
redacted logging it requires now exist and are tested, but the macOS Keychain
loader for real production/runtime secrets does not exist yet and remains
gated on a specific approved integration actually needing a credential, per
D017. DECISIONS.md's Open Decisions list drops "Application language and
framework." "Database and search/retrieval technologies" and "Event transport
and workflow execution mechanism" remain open and undecided by this decision.

Verification:
Confirm `uv run pytest`, `uv run ruff check .`, and `uv run mypy src` all pass.
Confirm `uv run zacai` binds only to `127.0.0.1` (checked via `lsof`), never a
public interface. Confirm `curl http://127.0.0.1:8000/health` returns a 200
with status/version/timestamp. Confirm the running server's own logs (not just
directly-called application code) are emitted as redacted JSON. Confirm no
real credential, Keychain entry, `.env.production` file, or other secret was
created by this decision (`git status` / `git diff --check` clean, only the
files listed above added or modified).

Approval or source:
Zac Campbell, architecture review conversation, 2026-09-19.

Supersedes:
None. Resolves the "Application language and framework" item from the Open
Decisions list. Extends D016 (completes its deferred framework choice), D017
(implements the boundary-checked accessor and redacted logging it specified),
and D008/D001 (keeps model/vendor replaceability intact - this decision only
selects a web/schema layer, never a model provider or orchestration
framework).

## D021 - Development/Production Runtime Mode Separation
Status: Accepted
Date: 2026-09-19

Context:
D017 defined the secrets/configuration tiers (Tier 0 non-secret config, Tier 1
`.env.development` for dev/test secrets, Tier 2 macOS Keychain for real
production/runtime secrets) but never specified how a running Zac AI process
determines which tier or mode it is actually in, or what happens if that
determination is missing or wrong. D020's `Settings.environment` field was a
free-form, unvalidated string that had no effect on behavior: any value was
accepted, and `.env.development` was read unconditionally regardless of the
declared environment. An architecture review (design-only pass, then approved
implementation) identified this as a real gap ahead of introducing any real
data or credentials: a production run had no way to guarantee it would never
read a developer's local dotenv file, and an invalid or mistyped environment
value had no defined failure behavior.

Decision:
Make the runtime environment explicit, strictly typed, and fail-safe, and
make dotenv-file selection a single, environment-aware code path:

- Add `zacai.config.Environment`, a `str, Enum` with exactly two values:
  `development` and `production`. `Settings.environment` is typed as
  `Environment`, defaulting to `Environment.DEVELOPMENT`. Any other value
  (a typo, an empty string, `"staging"`, etc.) fails Pydantic validation
  when `Settings` is constructed - the application does not start.
- Remove the static `env_file=".env.development"` from `Settings.model_config`
  entirely. The only place that decides whether a dotenv file is read is a
  new `_select_env_file(raw_environment: str) -> str | None` function:
  it returns `".env.development"` only for an exact `"development"` match,
  and `None` for everything else, including invalid values - so an invalid
  value loads nothing and then fails through `Settings` validation, rather
  than silently falling back to some default behavior.
- `get_settings()` reads the raw `ZACAI_ENVIRONMENT` value from the real
  process environment (defaulting to `"development"` when absent), passes
  the result of `_select_env_file` as `Settings(_env_file=...)`, and lets
  `Settings` validate the same raw value into the `Environment` enum.
- `main.py` logs the resolved environment (`settings.environment.value`) at
  startup through the existing centralized, redacted structured-logging path
  - not sensitive, but makes the active mode auditable from the logs.
- Tier-0 defaults (`host=127.0.0.1`, `port=8000`, `log_level=INFO`) are
  unchanged and identical in both modes. No `.env.production` file is
  introduced or referenced anywhere.

Deliberately out of scope: wiring `get_secret()` to actually read
`.env.development`. Tracing the existing code confirmed `get_secret()` only
ever reads real `os.environ` (or an injected test mapping); because
pydantic-settings' dotenv loader never mutates `os.environ`, nothing in
`.env.development` is currently visible to `get_secret()` at all. This is a
pre-existing gap from D020, not something this decision closes - closing it
now, with no real dev/test credential yet to justify it, would be exactly the
kind of building-ahead-of-need D016/D017 already reject. It remains
documented, separate secrets-management work for when a specific approved
integration actually needs a development credential (see SECRETS.md's
credential-adding procedure).

Alternatives considered:
Keeping `environment` as a free-form string and validating it manually inside
`get_settings()` was rejected: it would duplicate validation logic in two
places (a manual check plus whatever `Settings` itself does) and would not
give the same fail-closed guarantee an enum-typed Pydantic field gives for
free. Making `.env.production` a real, loadable file path (even if never
populated) was rejected: SECRETS.md and D017 already prohibit a real
credential in a plaintext `.env.production` file, and giving it a code path
at all would invite exactly that mistake later. Defaulting an absent
`ZACAI_ENVIRONMENT` to `"production"` (fail toward the more restrictive mode)
was considered and rejected in favor of defaulting to `"development"`: on
this single-operator project, nothing unsafe happens if a manually-started
run is accidentally in development mode, whereas an unset variable silently
behaving like production could later matter once production-only behavior
(real Keychain secrets, live integrations) actually exists; requiring an
explicit `ZACAI_ENVIRONMENT=production` to opt into that mode is the more
conservative choice today. Wiring `get_secret()` to `.env.development` now
was considered and rejected per the "deliberately out of scope" note above.

Reasons and tradeoffs:
An enum-typed field gets fail-safe validation from Pydantic itself rather
than hand-written checks, and collapses "what counts as a valid environment"
into one declaration. Centralizing dotenv-file selection in one function
(`_select_env_file`) means there is exactly one place that can be audited or
tested for the property "production never reads a dev file" that the review
identified as the actual risk, rather than that guarantee depending on
`model_config` staying correct forever. Logging the resolved mode adds a
trivial amount of log volume in exchange for an operator being able to
confirm from `curl`/log output alone which mode a given run is actually in,
which directly serves SECURITY.md's "fail safely and request approval when
uncertain" posture applied to configuration rather than just to actions.

Security and data implications:
No real credential, Keychain entry, `.env.development`, or `.env.production`
file was created by this decision or its implementation. The application was
manually verified to bind to `127.0.0.1` only in both development and
production mode. A temporary `.env.development`-shaped file was created only
inside pytest's isolated `tmp_path` fixtures to test that production ignores
it and development reads it - never in the project's real working directory,
and never containing anything but a fake, non-secret port number. Data
classification and trust boundaries (SECURITY.md, D003) are unchanged; this
decision only changes which non-secret Tier-0 configuration source is
consulted and how invalid environment input is handled.

Consequences:
ROADMAP.md Phase 1's "Establish development and production configuration
separation" item is marked complete, verified by a passing test suite
(`uv run pytest`), a clean lint pass (`uv run ruff check`), a clean type-check
pass (`uv run mypy src`, with the `pydantic.mypy` plugin now enabled so mypy
understands `Settings`' pydantic-settings-specific constructor), and a manual
run of the application in both development and production mode confirming
correct logging and continued `127.0.0.1`-only binding. The separate Phase 1
"Establish secrets management" item remains unchecked: the macOS Keychain
loader for real production/runtime secrets still does not exist, and
`get_secret()` still does not read `.env.development`, both unchanged by this
decision and gated on a specific approved integration actually needing a
credential, per D017.

Verification:
Confirm `uv run pytest`, `uv run ruff check .`, and `uv run mypy src` all
pass. Confirm `Settings(environment="staging")` (or any value other than
`"development"`/`"production"`) raises a `pydantic.ValidationError`. Confirm
`ZACAI_ENVIRONMENT=production uv run zacai` binds only to `127.0.0.1` (via
`lsof`) and logs `"starting in production mode"`; confirm the same for
`ZACAI_ENVIRONMENT=development` (and for the variable being absent, which
must behave identically to explicit `development`). Confirm no
`.env.production` file exists anywhere in the repository. Confirm no real
credential, Keychain entry, or live integration was introduced
(`git status` / `git diff --check` clean, only the files this decision
describes added or modified).

Approval or source:
Zac Campbell, architecture review conversation, 2026-09-19.

Supersedes:
None. Extends D017 (implements explicit, fail-safe environment/tier
selection that D017 assumed but never specified) and D020 (refines the
`Settings.environment` field D020 introduced as a free-form string).

## D022 - Local Secret-Scanning Safeguard
Status: Accepted
Date: 2026-09-19

Context:
D017 required "a lightweight local secret-scanning safeguard before any real
credential is introduced," explicitly deferring CI-enforced scanning, but
never chose a mechanism. ROADMAP.md Phase 1 lists this as its own item. An
architecture review (design-only pass, then approved implementation)
evaluated Gitleaks, detect-secrets, a hand-rolled regex script, and a bare
(untracked) git hook against: catching common secret shapes, working fully
locally with no external service calls, low operational complexity, being
easy for Claude Code and future coding agents to respect, not requiring real
secrets to test, and being reproducible on a replacement Mac. The review
initially specified Gitleaks' `protect`/`detect` subcommands, but the
installed version (8.30.1, via Homebrew) does not have those commands at all
- `gitleaks --help` shows only `git`, `dir`, `stdin`, `completion`, and
`version`. `gitleaks git --help` confirms `--staged` as the current
supported staged-diff scan flag ("scan staged commits (good for
pre-commit)"), so the hook uses `gitleaks git --staged`, not the
deprecated/removed form.

Decision:
Adopt Gitleaks, installed via Homebrew, run from a committed, versioned hook,
blocking commits by default:

- `brew install gitleaks` (8.30.1 at the time of this decision).
- `.gitleaks.toml`: extends Gitleaks' default ruleset (`[extend]
  useDefault = true`) with no allowlist entries. A full-history scan
  (`gitleaks git --redact --config .gitleaks.toml .`, 9 commits, ~227KB)
  and a staged-diff scan of this decision's own new files both came back
  clean against the default ruleset alone - including against the existing
  fake test fixtures in `tests/test_config.py` and
  `tests/test_logging_config.py` (`fake-personal-value-123`,
  `hunter2-fake-password`, `sk-fake-1234567890abcdef`, etc.), none of which
  triggered a finding. No allowlist entry was needed or added. Should a real
  false positive appear later, the required order is: (1) a trailing
  `gitleaks:allow` comment on the exact matching line, (2) only if that is
  not possible, a narrow, commented `[[rules]]`/regex or path entry in
  `.gitleaks.toml`. Excluding an entire file or disabling a detector
  wholesale is not permitted by this decision.
- `.githooks/pre-commit`: a committed, executable shell script running
  `gitleaks git --staged --redact --config .gitleaks.toml .`. `--redact`
  keeps any matched secret value out of terminal output even locally. The
  script's exit code is Gitleaks' own, so any finding blocks the commit.
- `git config core.hooksPath .githooks`: a local, per-clone Git setting (not
  committed, not pushed, does not touch remotes, authentication, or SSH)
  that points Git's hook lookup at the versioned directory above instead of
  the untracked, unreproducible `.git/hooks/`.
- The safeguard blocks commits by default, effective immediately, rather
  than running as an optional manual check. `git commit --no-verify` remains
  available as git's own escape hatch for a genuine emergency; it is not a
  documented or recommended part of the normal workflow.

Alternatives considered:
detect-secrets was rejected: it would add a Python dev dependency and an
ongoing `.secrets.baseline` file that must be regenerated and re-audited as
the repo grows, more operational overhead than a stateless binary scan for a
single-operator project. A hand-rolled regex script was rejected: the
failure mode that matters here is a missed real secret, and Gitleaks'
maintained ruleset is more broadly tested than anything reasonable to write
and maintain in this repo. A bare, uncommitted `.git/hooks/pre-commit` was
rejected: `.git/hooks/` is not tracked by Git, so it would silently not
exist after a fresh clone or on a replacement Mac, failing the requirement
that this be reproducible; the `pre-commit` framework was considered as an
alternative way to solve that same reproducibility problem but rejected as
heavier than needed (its own Python install, YAML config, and a per-clone
`pre-commit install` step) for one check, when a committed hooks directory
plus `core.hooksPath` solves the same problem with one config line and no
new dependency. Manual-only (non-blocking) operation was rejected: relying
on remembering to run a scan recreates exactly the gap this safeguard exists
to close, and the repo is small and currently clean, which is the cheapest
possible time to turn on a blocking check.

Reasons and tradeoffs:
A static Homebrew binary keeps this entirely outside the application's own
dependency tree (`pyproject.toml`/`uv.lock` are untouched), consistent with
D016's preference for native Homebrew tools over added frameworks. Blocking
by default trades a small chance of an unexpected block for closing the gap
immediately rather than leaving an unenforced rail in place; the allowlist
order (inline comment first, narrow config entry only if necessary, never a
blanket exclusion) keeps any future false-positive handling itself
auditable rather than quietly widening what the safeguard ignores.
`core.hooksPath` being a per-clone setting is an inherent limitation shared
by every git-hook approach, including the `pre-commit` framework's own
install step; it is mitigated by documenting the one-time setup in
README.md and RECOVERY.md rather than by a heavier mechanism.

Security and data implications:
No real credential, Keychain entry, or live integration was created or
connected. Gitleaks makes no network calls; verification (full-history scan,
an isolated temporary-repo proof that a fake AWS-key-shaped string is
blocked, and a staged non-secret scan of this decision's own files) used
only fake, obviously-not-real values, and the temporary proof repository was
created outside this project and deleted immediately after the test - no
fake-secret content was ever staged or committed in this repository. `git
config core.hooksPath` is local only; it is never pushed and does not
change any remote, authentication, or SSH configuration. `--redact` is used
on every invocation so a real accidental secret, if one were ever caught,
would not itself be printed to the terminal or captured in shell history.

Consequences:
ROADMAP.md Phase 1's "Add a lightweight local secret-scanning safeguard
before any real credential is introduced" item is marked complete, verified
by a clean full-history scan, a successful isolated block-test, and a clean
staged-diff scan of this decision's own files. Every future commit in this
repository (once each clone has run the one-time setup) is scanned before it
can be created. CI-enforced scanning remains explicitly deferred, unchanged
from D017.

Verification:
Confirm `gitleaks version` reports 8.30.1 or later and that `gitleaks
--help` still exposes a staged-diff scan flag under whichever subcommand is
current at the time; do not assume the `git --staged` form persists forever
across major Gitleaks versions without checking. Confirm `gitleaks git
--redact --config .gitleaks.toml .` over the full repository history reports
no leaks. Confirm a fake-secret-shaped commit is blocked in an isolated,
disposable repository (never in this one). Confirm `git config
core.hooksPath` resolves to `.githooks` in this repository. Confirm no real
credential, Keychain entry, `.env.development`, or `.env.production` file
exists as a result of this decision.

Approval or source:
Zac Campbell, architecture review conversation, 2026-09-19.

Supersedes:
None. Extends D017 (implements the secret-scanning safeguard D017 required
but left unspecified).

## D023 - Trust-Boundary and Data-Classification Policy Layer
Status: Accepted
Date: 2026-09-19

Context:
ARCHITECTURE.md Section 16 and SECURITY.md require Personal/Brainstorm
logical separation, four data-classification levels (Public, Internal,
Confidential, Highly Restricted), and rules such as "Highly Restricted
information should not automatically be sent to external model providers."
D003 already decided that access from one boundary into another must be
deliberate and authorized. Until this decision, the only implemented piece
of this was `zacai.config.TrustBoundary`, scoped narrowly to enforcing a
PERSONAL_/BRAINSTORM_/SHARED_ prefix on secret *names* (D017/D020) - a
secret-naming check, not a general data-access decision. No entity, agent,
model router, or action gateway exists yet (all later phases), so this
decision builds the policy layer those will consult later, independent of
all of them, ahead of any real Personal or Brainstorm data being
introduced. An architecture review (design-only pass, then approved with
two security clarifications) evaluated the minimum v1 model needed.

Decision:
Add `src/zacai/policy.py` as the single source of truth for trust-boundary
and data-classification access decisions:

- `TrustBoundary` moves here as its canonical definition (values unchanged:
  PERSONAL, BRAINSTORM, SHARED). `zacai.config` imports and re-exports it
  (`from zacai.policy import TrustBoundary`), so `get_secret()` and every
  existing `from zacai.config import TrustBoundary` import keep working
  unchanged - verified by `config_module.TrustBoundary is
  zacai.policy.TrustBoundary` in the test suite.
- `DataClassification`: PUBLIC, INTERNAL, CONFIDENTIAL, HIGHLY_RESTRICTED -
  directly from SECURITY.md's existing four levels.
- `Destination`: LOCAL, EXTERNAL - whether handling a request would keep
  data on-system or send it to an external destination (e.g. a cloud model
  provider). This is independent of trust boundary: no `TrustBoundary`
  value means "the cloud," so the "don't send Highly Restricted externally"
  rule needed its own axis.
- `AccessRequest` (frozen Pydantic model): `data_boundary`,
  `data_classification`, `requestor_boundaries: frozenset[TrustBoundary]`,
  `destination`. An invalid value for any enum field fails Pydantic
  validation at construction - fail-closed, matching the `Environment`
  pattern from D021 - rather than reaching a decision function in an
  ambiguous state.
- `PolicyDecision` (frozen Pydantic model): `allowed: bool`, `reason: str`.
  `reason` is always populated, allow or deny, so every decision is
  self-explanatory in a log line on its own.
- `evaluate_access(request) -> PolicyDecision`: exactly two checks, both
  must pass:
  1. If `data_classification is HIGHLY_RESTRICTED` and
     `destination is EXTERNAL`: deny. This is a **hard deny with no
     override inside this module** (see the architecture principle below).
  2. Else if `data_boundary not in requestor_boundaries`: deny, naming the
     missing boundary. Otherwise: allow.
  This one function is what a future model router (Phase 5) and a future
  Action/Approval Gateway (Phase 6) are both meant to call - the access
  question does not differ by caller.

SHARED policy invariant (security clarification, binding on this and all
future policy work): SHARED means data that genuinely belongs to neither
Personal nor Brainstorm exclusively (e.g. Zac AI's own operational data).
It is independently authorized, never a combination of or bridge between
the other two:
- PERSONAL authorization does not imply SHARED.
- BRAINSTORM authorization does not imply SHARED.
- PERSONAL + BRAINSTORM authorization does not imply SHARED.
- SHARED authorization grants no PERSONAL or BRAINSTORM access.
SHARED must never be used to relabel mixed or provenance-bearing data to
sidestep this check; such data must keep its actual source boundary. All
five invariants above have a dedicated automated test
(`tests/test_policy.py`). Deciding whether a given entity genuinely
deserves the SHARED label is a data-classification/entity-tagging decision
made elsewhere (not yet built); this module only enforces access once data
is already labeled.

HIGHLY_RESTRICTED + EXTERNAL architecture principle (security
clarification, binding on this and all future policy/gateway work): policy
determines whether an operation is permitted at all. A future Action/
Approval Gateway (Phase 6, ARCHITECTURE.md Section 10) may impose further
restrictions or require human approval on top of an otherwise-permitted
operation, but it does not, and must not, override a policy denial produced
by `evaluate_access`. There is no override parameter or bypass path
anywhere in this module. Changing the HIGHLY_RESTRICTED+EXTERNAL rule
itself would require its own future, explicit security/architecture
decision - never an ordinary runtime approval.

No entity, agent, model router, or action gateway is created by this
decision. No database is chosen. No real Personal or Brainstorm data,
credential, or Keychain entry was created; `tests/test_policy.py` uses only
synthetic fixtures.

Alternatives considered:
Keeping `TrustBoundary` defined only in `config.py` and having `policy.py`
import it from there was considered and rejected: `policy.py` is now the
broader authority on trust boundaries, and `config.py`'s secret-name check
is one narrow consumer of that vocabulary, not its owner. Modeling denial as
a raised exception (extending `BoundaryError`) was rejected: an
access-denied outcome is an expected, everyday business decision a caller
needs to branch on (log it, surface it, try a narrower request), not a
programmer error - a first-class `PolicyDecision` return value fits that
better than exception-based control flow. Adding an `explicit_override`
flag to `AccessRequest` for the Highly-Restricted-external case (to model
SECURITY.md's "unless explicitly authorized for that specific use" clause)
was proposed initially and explicitly rejected on review: it would let any
caller flip a boolean to bypass the deny, which is exactly the override
path the security clarification above forbids. That future exception path,
if ever pursued, would need its own explicit, later architecture decision -
not a parameter added quietly here. Gating same-boundary/local access by
classification level (e.g. requiring extra approval for Confidential data
even within its own boundary) was considered and deferred: SECURITY.md ties
its concrete classification rule specifically to external transmission, and
inventing additional restrictions beyond what is specified would exceed
"keep the implementation minimal."

Reasons and tradeoffs:
Collapsing the boundary rule to a single set-membership check
(`data_boundary in requestor_boundaries`) rather than writing separate
same-boundary/SHARED/cross-boundary branches makes SHARED's lack of special
treatment structural rather than a matter of remembering not to special-case
it, and makes the empty-authorization case ("missing/unknown boundary")
fall out for free with no extra code. Making the HIGHLY_RESTRICTED+EXTERNAL
rule a hard deny with no in-module override trades away a convenience (a
one-off legitimate exception must go through a not-yet-built approval
mechanism rather than a flag here) for the stronger, auditable guarantee
that this module's answer to "is this permitted at all" cannot be
quietly bypassed by whichever future component calls it.

Security and data implications:
No real Personal or Brainstorm data, credential, or Keychain entry was
created. All 17 new tests use synthetic fixtures only. This decision adds a
policy-decision capability but does not yet gate any real code path (no
model router or action gateway calls `evaluate_access` yet) - its value at
this stage is that the rules, invariants, and their tests exist and are
verified before anything real depends on them.

Consequences:
ROADMAP.md Phase 1's "Implement personal and Brainstorm trust boundaries"
and "Implement data classification and policy enforcement" items are marked
complete, verified by `uv run pytest` (45 passed, including all 17 new
policy tests and all pre-existing tests unmodified), a clean `uv run ruff
check .`, and a clean `uv run mypy src`. Future work (Phase 5 model
routing, Phase 6 action gateway, Phase 7 agents) must call
`evaluate_access` rather than re-implementing boundary or classification
logic, and must not add an override path around the HIGHLY_RESTRICTED+
EXTERNAL deny without its own explicit decision.

Verification:
Confirm `uv run pytest`, `uv run ruff check .`, and `uv run mypy src` all
pass. Confirm `zacai.config.TrustBoundary is zacai.policy.TrustBoundary`.
Confirm each of the five SHARED invariants above has a passing, explicitly
named test. Confirm HIGHLY_RESTRICTED+EXTERNAL is denied even when the
requestor is fully authorized for the matching boundary, and that
HIGHLY_RESTRICTED+LOCAL and CONFIDENTIAL+EXTERNAL are both allowed under
the same same-boundary authorization (proving the ceiling is specific, not
blanket). Confirm no real Personal or Brainstorm data, credential, or
Keychain entry exists as a result of this decision.

Approval or source:
Zac Campbell, architecture review conversation, 2026-09-19.

Supersedes:
None. Extends D003 (implements the deliberate-and-authorized boundary
separation D003 required), D004 (decision reasons support explainability),
and D017 (generalizes the narrower secret-name `TrustBoundary` it
introduced into the broader data-access policy layer).

## D024 - Action/Approval Gateway (v1)
Status: Accepted
Date: 2026-09-19

Context:
ROADMAP.md Phase 1 left two open items directly addressed here: "Implement
the initial action gateway with writes denied by default" and "Add
automated checks for boundary and permission enforcement." ARCHITECTURE.md
Section 10 defines three action risk tiers (Low/Medium/High) and lists
sensitive-action examples (external email, deleting data, modifying
contracts, financial changes, spending money, modifying credentials,
publishing externally). SECURITY.md requires destructive, external, and
financial/credential/permission/production actions to be explicitly
approved, and defines the agent permission ladder (Read, Analyze,
Recommend, Draft, Act with approval, Selective autonomy). D007 already
decided that external actions route through a central approval gateway;
D023 built the policy layer that decision and this one both depend on, and
D023's own text explicitly reserved this exact hook: "a future Action/
Approval Gateway (Phase 6) may impose further restrictions or require
human approval on top of an otherwise-permitted operation, but it does
not, and must not, override a policy denial produced by `evaluate_access`.
There is no override parameter or bypass path anywhere in this module." An
architecture review (design-only pass, then approved with one
clarification on how REQUIRE_APPROVAL should be represented) evaluated the
minimum v1 model needed.

Decision:
Add `src/zacai/gateway.py`, downstream of and calling `zacai.policy.
evaluate_access` (D023), never modifying it:

- `ActionType` (23 members) enumerates the kinds of operations Zac AI may
  attempt: read/analyze/summarize/recommend, draft (non-executing, kept
  structurally separate from any send/publish type so no single flag can
  turn a draft into an executing send), external communication/publishing
  writes, CRM/task/calendar create/update/delete, a scoped single-file
  delete, and five actions considered too undesigned to leave at
  REQUIRE_APPROVAL: bulk/unscoped data deletion, spending money, modifying
  a credential, changing a permission, and modifying a production
  configuration.
- `ActionRisk` (LOW/MEDIUM/HIGH, ARCHITECTURE.md Section 10) is derived
  internally from the outcome an action receives (with `DELETE_FILE`
  overridden to HIGH despite remaining REQUIRE_APPROVAL, per SECURITY.md's
  "high-risk deletions" language) - never a field a caller can set.
- `GatewayOutcome`: `ALLOW` / `REQUIRE_APPROVAL` / `DENY`, a tri-state,
  never a boolean, so "not denied" and "does not execute now" are never
  conflated with each other or with a plain allow.
- `ActionRequest` (frozen Pydantic model): `action_type`, `access:
  AccessRequest` (D023's type, embedded rather than re-declared), and a
  `description` string used only for audit/logging, never parsed or
  branched on. It has no approval, override, or execute/dry-run field of
  any kind - locked in by a dedicated structural test.
- `GatewayDecision` (frozen Pydantic model): `outcome`, `reason: str`
  (always populated, mirroring `PolicyDecision.reason`), `risk`.
- `evaluate_gateway(request) -> GatewayDecision`: calls `evaluate_access
  (request.access)` first, unconditionally, with no parameter or code path
  that skips it. If policy denies, returns DENY immediately without
  consulting action-type classification at all. Only if policy allows does
  it classify `action_type` into exactly one of three fixed, disjoint,
  exhaustive sets (`_ALLOW_ACTIONS`, `_REQUIRE_APPROVAL_ACTIONS`,
  `_DENY_ACTIONS`) and return the matching outcome; an action type absent
  from all three (should be unreachable) fails closed to DENY.

REQUIRE_APPROVAL is a terminal result in this decision: it means execution
must stop and no action may occur until a future, separately designed
approval mechanism satisfies the requirement. This decision does not
design that mechanism - no `ApprovalRecord`, token, persistence, lookup
interface, expiry, or replay protection is introduced, and `evaluate_
gateway`'s signature gains no approval-related parameter. It records only
these binding invariants for whenever that mechanism is designed:
- An approval must never override a D023 policy DENY.
- An approval must never override a D024 hard DENY.
- Approval must eventually be bound to the specific action being
  authorized, not represented as a caller-controlled boolean.
- Approval must be auditable.
- Replay/stale-approval risks must be addressed when that system is
  designed.

No connector (Gmail, Slack, Salesforce, Calendar, ClickUp) is wired to
this gateway. No database, approval UI, or agent is created. No real
Personal or Brainstorm data, credential, or Keychain entry was created;
`tests/test_gateway.py` uses only synthetic fixtures.

Alternatives considered:
An `approval`/`override` field on `ActionRequest` was proposed and
rejected: it would recreate the exact shape of D023's rejected
`explicit_override` flag - a bypass a caller could simply set, whether or
not v1 code happened to read it. Pre-computing a `PolicyDecision` and
passing it into `evaluate_gateway` as a parameter (instead of calling
`evaluate_access` internally) was rejected: it would let a caller fabricate
an allow and skip policy entirely, defeating the "policy remains
authoritative" requirement. A boolean `GatewayDecision.outcome` (mirroring
`PolicyDecision.allowed`) was rejected in favor of a tri-state enum: a
boolean cannot represent REQUIRE_APPROVAL without conflating it with
either ALLOW or DENY. Designing an `evaluate_gateway(request,
approval_lookup=...)` API and an `ApprovalRecord`/token type now (so a
future approval mechanism would have less to build later) was proposed
during review and explicitly deferred: REQUIRE_APPROVAL is sufficient as a
terminal state for v1, and committing to an API shape before the approval
architecture (binding, replay/expiry protection, audit) is actually
designed risks constraining that later design or having to be reworked.
Leaving the five v1-hard-denied action types at REQUIRE_APPROVAL (matching
the brief's raw example list) was considered and rejected: with no
approval-binding/replay-prevention mechanism yet, REQUIRE_APPROVAL is not
a safe waiting room for actions that could defeat other controls
(credential/permission changes), cause irreversible loss with no verified
backup/restore yet (bulk delete - ROADMAP's backup-verification item is
still unchecked), or cause real monetary/production harm.

Reasons and tradeoffs:
Embedding D023's `AccessRequest` inside `ActionRequest` rather than
flattening its fields onto `ActionRequest` means `evaluate_gateway` calls
`evaluate_access(request.access)` with zero translation code, eliminating
any risk of a field-mapping bug silently changing policy semantics.
Classifying `ActionType` via three disjoint frozensets rather than a
single `dict[ActionType, GatewayOutcome]` makes "is every action type
classified, exactly once" a structural set-algebra assertion
(`test_all_action_types_are_classified`) rather than an implicit property
of a mapping's keys. Hard-denying five actions instead of leaving them at
REQUIRE_APPROVAL trades short-term flexibility (nothing can move them
forward even manually yet) for not building an approval mechanism with no
real binding or replay protection to rely on; this is reversible by a
future, explicit decision once that mechanism exists, per the recorded
invariants above.

Security and data implications:
No live connector, database, or UI is touched. Nothing added here causes
any real external send, spend, delete, credential change, or permission
change to occur - no code path anywhere calls a connector, and none is
wired. `reason` and `description` strings may echo caller-provided
content and should be passed through the existing `zacai.logging_config`
redaction path by any future caller that logs them.

Consequences:
ROADMAP.md Phase 1's "Implement the initial action gateway with writes
denied by default" and "Add automated checks for boundary and permission
enforcement" items are marked complete, verified by `uv run pytest` (143
passed, including 98 new gateway tests and all 45 pre-existing tests
unmodified), a clean `uv run ruff check .`, and a clean `uv run mypy src`.
Future work (Phase 4 agents, Phase 5 model routing, Phase 6 approvals)
must route attempted actions through `evaluate_gateway` rather than
re-implementing this classification, must not add an override path around
either the D023 policy check or the D024 `_DENY_ACTIONS` set without its
own explicit decision, and must extend `evaluate_gateway`'s signature only
additively (never by adding an approval field to `ActionRequest`) when the
approval mechanism is eventually designed.

Verification:
Confirm `uv run pytest`, `uv run ruff check .`, and `uv run mypy src` all
pass. Confirm every `ActionType` combined with a denied `AccessRequest`
returns DENY, including a LOW-risk type like `READ_DATA` under the
HIGHLY_RESTRICTED+EXTERNAL hard deny (proving action-type classification
never runs once policy denies). Confirm `MODIFY_CREDENTIAL` with an
allowed policy still returns DENY, not REQUIRE_APPROVAL. Confirm
`DRAFT_CONTENT` and `SEND_EMAIL` with identical descriptions return ALLOW
and REQUIRE_APPROVAL respectively. Confirm `ActionRequest`'s field set is
exactly `{action_type, access, description}`. Confirm `_ALLOW_ACTIONS`,
`_REQUIRE_APPROVAL_ACTIONS`, and `_DENY_ACTIONS` are pairwise disjoint and
their union equals every `ActionType` member. Confirm `git diff --check`
and `git status` show only `src/zacai/gateway.py` and
`tests/test_gateway.py` added, with `src/zacai/policy.py` unchanged.

Approval or source:
Zac Campbell, architecture review conversation, 2026-09-19.

Supersedes:
None. Extends D007 (External Actions Use a Central Approval Gateway) by
providing its first concrete implementation, and D023 (Trust-Boundary and
Data-Classification Policy Layer) by consuming `evaluate_access` as the
mandatory first step per D023's own forward-looking language, without
modifying `policy.py`'s public contract.

## D025 - Private Service Lifecycle and Startup/Shutdown (v1)
Status: Accepted
Date: 2026-09-19

Context:
ROADMAP.md Phase 1's last standalone open item was "Establish private
access and document service startup and shutdown." Until this decision,
running Zac AI meant a manual, foreground `uv run zacai` in a terminal,
stopped with Ctrl+C or a manual `kill` - nothing restarted it after a
crash, a reboot, or a login, and nothing in code enforced the
`127.0.0.1`-only binding D020 verified manually and D021 fixed as Tier-0's
default in both runtime modes. D016 already lists Tailscale as installed
and configured on the Mac Studio, satisfying the Phase 1 private-access
task "in principle," but the operational wiring of this specific FastAPI
service into an always-on, restart-on-failure process was still open.
SECRETS.md and D017 gate macOS Keychain-based production secret loading on
a specific, already-approved integration actually needing a credential -
none exists yet, so that loader is not built here, only identified as a
future integration point. An architecture review (design-only pass,
approved with four scope/security tightenings) evaluated the minimum v1
model needed.

Decision:
Add a native macOS `launchd` LaunchAgent (not a LaunchDaemon, not Docker or
another process manager) as the service-lifecycle mechanism, plus one new
code-level safety invariant:

- `assert_safe_bind_host(host)` (`src/zacai/main.py`), called in `run()`
  immediately before `uvicorn.run()`: a strict allowlist accepting only
  the literal `"127.0.0.1"`. Every other value - `"localhost"`, `"::1"`,
  `"0.0.0.0"`, `"::"`, a Tailscale/LAN/public address, an empty string, or
  any other hostname - raises `RuntimeError` and aborts startup before a
  socket is ever opened. This is purely additive: `Settings`,
  `_select_env_file`, and `Environment` validation in `config.py` are
  unchanged.
- `deploy/com.zacai.service.plist`: a committed **template**, not the real
  installed file, using `__ZACAI_REPO_PATH__`/`__ZACAI_LOG_DIR__`
  placeholders so no real username or absolute path is ever committed to
  version control. Key plist settings: `ProgramArguments` points at the
  venv's own `.venv/bin/zacai` by absolute path (launchd's minimal
  environment may not have `uv`/Homebrew on `PATH`); `EnvironmentVariables`
  sets only `ZACAI_ENVIRONMENT=production`, leaving host/port/log-level at
  Tier-0's own defaults; `RunAtLoad: true` (starts at login, not boot -
  see Alternatives); `KeepAlive: {SuccessfulExit: false}` (restarts on a
  crash, not after a deliberate `launchctl bootout`); `ThrottleInterval:
  10` (bounds crash-loop pacing); `StandardOutPath`/`StandardErrorPath`
  redirect the app's existing, unchanged stdout-only redacted-JSON log
  stream to `~/Library/Logs/zacai/` - no second logging system is built.
- `scripts/service-install.sh`, `scripts/service-uninstall.sh`,
  `scripts/service-status.sh`: user-space shell scripts (matching
  `.githooks/pre-commit`'s style) that render/manage the real plist and
  report status. `service-install.sh` deliberately does not itself run
  `launchctl bootstrap` - loading the service is a separate, deliberate
  command the operator runs themselves.
- README.md documents the full install/start/stop/restart/status/health/
  log-inspection/reboot-recovery/disable-autostart workflow in
  novice-readable terms.

This decision explicitly does **not**: configure or execute `tailscale
serve` or `tailscale funnel`, or any other Tailscale-configuration-changing
command; create `/etc/newsyslog.d/zacai.conf` or any other `sudo`/
system-wide change; build Keychain secret loading; change any firewall,
router, or network setting.

Live installation on the Mac Studio was subsequently approved and
completed: the rendered plist was loaded as a per-user LaunchAgent running
`/Users/brainstormzac/zac-ai/.venv/bin/zacai` from working directory
`/Users/brainstormzac/zac-ai` with `ZACAI_ENVIRONMENT=production` confirmed
in the live launchd environment; `lsof` confirmed the service listens only
on `127.0.0.1:8000`, with no `0.0.0.0`, LAN, Tailscale, or public interface
bound; `launchctl kickstart -k` and `launchctl bootout` were both exercised
successfully (see Verification below).

Alternatives considered:
A LaunchDaemon (root, system-wide, can start before login) was considered
and rejected in favor of a per-user LaunchAgent: a LaunchDaemon has no
access to a logged-in user's unlocked login keychain, which would directly
conflict with D017/SECRETS.md's already-chosen Tier-2 mechanism (reading
production secrets from the user's login keychain at service startup) the
first time a real credential is added - migrating from LaunchDaemon to
LaunchAgent later would be pure rework. Binding the app directly to the
Mac's Tailscale interface IP via `ZACAI_HOST` (instead of keeping it
`127.0.0.1`-only) was considered and rejected: it would make this specific
app's own socket the thing directly reachable tailnet-wide, so any bug in
this app's binding logic becomes a network-exposure bug, and it is the
configuration most likely to get "fixed" into `0.0.0.0` under
troubleshooting pressure; `tailscale serve` as a reverse proxy to the
unchanged loopback-only service is recorded as the approved future
direction instead, but is a separate, later decision to actually configure.
Building `/etc/newsyslog.d` log rotation now was proposed and deferred:
this milestone has no meaningful production log volume yet, and adding a
`sudo`-gated system-wide file was judged premature relative to the
already-approved boring v1 scope; it is recorded as an open operational
item that must be resolved before real log volume accumulates. Docker or
another process manager was rejected, consistent with D016's native-tooling
preference on a single always-on node.

Reasons and tradeoffs:
Starting the LaunchAgent at login rather than boot trades boot-time
availability (the service would otherwise come up even with nobody signed
in) for Keychain-readiness and mechanism simplicity; the Mac Studio is a
single-operator node that is expected to be logged into when in active
use, so this is judged an acceptable v1 tradeoff, reversible by a later,
explicit LaunchDaemon migration decision if boot-time availability without
login is ever actually needed. Making `assert_safe_bind_host` a strict
single-literal allowlist rather than a broader "is this loopback-shaped"
check trades flexibility (no `::1`, no bare `"localhost"`) for
unambiguity: a v1 with exactly one accepted value has no edge cases to
reason about later, and widening it is a deliberate, visible, future code
change rather than a silent gap.

Security and data implications:
No public internet exposure is introduced or enabled by this decision -
the app remains bound to `127.0.0.1` only, now enforced in code rather
than by convention alone, and no Tailscale-reachability command is run.
No real credential, Keychain entry, or production secret is created; no
`.env.production` file is introduced anywhere. The existing redacted
stdout logging path (D017) is reused unchanged; launchd's
`StandardOutPath`/`StandardErrorPath` are a passive file sink for output
that is already redacted before it is written. Log rotation is not yet
implemented - `~/Library/Logs/zacai/*.log` can grow unbounded until a
future decision adds `newsyslog` configuration; this is a known,
documented gap, not an oversight.

Consequences:
ROADMAP.md's "Establish private access and document service startup and
shutdown" item is marked fully complete: both the code/tooling/
documentation scope and live installation and operational verification on
the Mac Studio (loopback-only binding, clean restart, clean stop) are
done. Future work must route any change to the
app's bind address through `assert_safe_bind_host` rather than bypassing
it, must not configure `tailscale serve`/`funnel` without its own explicit
approval, must add log rotation before meaningful production log volume
accumulates, and - when a specific, approved integration first needs a
production credential (D017) - must implement the `_load_keychain_secrets`
integration point this decision identified but did not build, taking
advantage of the LaunchAgent's user-session Keychain access chosen here.

Verification:
Confirm `uv run pytest` (153 passed, including 10 new
`tests/test_main.py` cases), `uv run ruff check .`, and `uv run mypy src`
all pass. Confirm `assert_safe_bind_host` accepts only the literal
`"127.0.0.1"` and rejects `"localhost"`, `"::1"`, `"0.0.0.0"`, `"::"`, a
Tailscale-range address, a LAN address, a public address, an empty string,
and an arbitrary hostname. Confirm `git diff --check` is clean and
`git status` shows only `deploy/com.zacai.service.plist`,
`scripts/service-install.sh`, `scripts/service-uninstall.sh`,
`scripts/service-status.sh`, `src/zacai/main.py`, `tests/test_main.py`,
`README.md`, `ROADMAP.md`, and `DECISIONS.md` touched, with
`src/zacai/config.py`, `src/zacai/policy.py`, and `src/zacai/gateway.py`
unchanged. Confirm no `launchctl`, `tailscale`, or `sudo` command was run,
and no file was written outside this repository, during implementation.

Live verification is complete, performed by Zac Campbell on the Mac
Studio: the LaunchAgent loaded and `/health` returned
`{"status":"ok","version":"0.1.0",...}`; `lsof` confirmed listening only
on `127.0.0.1:8000`; structured JSON logs were present in
`~/Library/Logs/zacai/zacai.out.log` with `zacai.err.log` empty;
`launchctl kickstart -k` cleanly stopped the original process (PID 10573)
and started a new, healthy one (PID 10594); `launchctl bootout` unloaded
the LaunchAgent, stopped the health endpoint from responding, and `lsof`
confirmed nothing remained listening on port 8000 with no automatic
restart, after which the LaunchAgent was restored to its normal running
state. A duplicate `launchctl bootstrap` attempt made while the service
was already loaded returned `"Bootstrap failed: 5: Input/output error"`;
`launchctl print` at that moment confirmed the already-loaded instance was
healthy and unaffected, so this specific result reflected the service
already being loaded and running, not a service failure, and no root/sudo
workaround was used.

Approval or source:
Zac Campbell, architecture review conversation, 2026-09-19.

Supersedes:
None. Extends D016 (fulfills the private-access task Tailscale's
installation was said to satisfy "in principle"), D020 and D021 (keeps
their `127.0.0.1`-only, Tier-0-defaults, and `.env.development`/
`.env.production` invariants completely unchanged, now additionally
enforced in code), and D017/SECRETS.md (identifies, without building, the
future Keychain-loading integration point this LaunchAgent choice keeps
straightforward).

## D026 - Zac State v1 Storage Foundation (Person, Commitment, Source)
Status: Accepted
Date: 2026-09-19

Context:
ROADMAP.md Phase 2 ("Canonical State, Memory, and Evidence") requires
entity schemas, versioned/temporal history, and source-backed evidence
before any live connector is approved. DECISIONS.md's Open Decisions list
carried "Database and search/retrieval technologies" unresolved since
D016, which named PostgreSQL, pgvector, and MLX only as candidates to
"install later, when justified by the relevant implementation phase" -
that phase is Phase 2. D023 built the trust-boundary/data-classification
policy layer but explicitly declined to choose a database or address
storage representation ("No database is chosen" - D023 has no discussion
anywhere of columns, schemas, or separate databases). D024 flagged a
future need for a persisted, auditable `ApprovalRecord`. D018 requires
Personal and Brainstorm state to be backed up with separate encryption
keys, never a shared key across boundaries, once Lane B exists. An
architecture review (two design-only passes, each revised before
approval) evaluated the minimum v1 model needed.

Decision:
Add PostgreSQL 18 (`brew install postgresql@18`) as the v1 canonical
store, with pgvector deliberately not installed, plus:

- `src/zacai/db.py`: engine/session construction only, reading
  `Settings.database_url` (new Tier-0, non-secret field in
  `zacai.config`, default `postgresql+psycopg://127.0.0.1:5432/zacai_dev`
  - loopback-only, no embedded credential).
- `src/zacai/state.py`: the v1 schema - `source` (immutable provenance,
  never versioned), `person` and `commitment` (append-only, one row per
  `(entity_id, version)`), `person_head`/`commitment_head` (the one
  deliberate, mutable exception - a boundary plus a version pointer, no
  content), and typed `person_evidence`/`commitment_evidence` (not a
  generic polymorphic association table). `TrustBoundary`/
  `DataClassification` are reused unchanged from `zacai.policy` - never
  redefined here. Every boundary-scoped table carries `trust_boundary`
  `NOT NULL` with a database `CHECK` constraint (`Enum(...,
  native_enum=False, create_constraint=True)` - SQLAlchemy 2.0 changed
  this default to `False`, so it must be passed explicitly or no
  constraint is generated at all). `source`, `person`, and `commitment`
  each also carry `data_classification NOT NULL`, so a stored row already
  carries enough to reconstruct a D023 `AccessRequest` without chasing
  provenance first.
- Cross-boundary leakage is prevented by real composite foreign keys, not
  repository convention alone: `person_evidence`/`commitment_evidence`
  FK their `trust_boundary` to both the entity version and the `source`
  they cite; `commitment` FKs `(owner_person_id, trust_boundary)` to
  `person_head(entity_id, trust_boundary)`, so a commitment can only ever
  reference a person in its own exact boundary - SHARED is never a
  bridge. `person`/`commitment` also FK `(entity_id, trust_boundary)` to
  their own head table, and a head row's `trust_boundary` is set once at
  creation and never updated - making it structurally impossible for any
  version to be inserted with a different boundary than its entity's
  original one, even if the repository's own check were bypassed.
- Version allocation (`_allocate_version` in `state_repository.py`) is
  concurrency-safe using only ordinary PostgreSQL mechanisms - `INSERT
  ... ON CONFLICT DO NOTHING` followed by `SELECT ... FOR UPDATE` - never
  an unguarded `SELECT max(version) + 1`. One algorithm, not two, handles
  both a brand-new entity and an existing one: for two concurrent callers
  targeting the same not-yet-existing `entity_id`, Postgres blocks the
  second's `INSERT ... ON CONFLICT` on the first's uncommitted row until
  it resolves, after which the second's insert becomes a no-op and it
  proceeds to lock the now-existing row - fully serializing both cases
  with nothing but row-level locking, no advisory lock, no external lock
  service.
- `create_person`/`create_commitment` require at least one `SUPPORTS`
  evidence row per version and enforce a non-weakening classification
  invariant: a version's `data_classification` may never be less
  restrictive than any `SUPPORTS` evidence backing it (checked in the
  repository layer, inside the same transaction as the write - not a DB
  trigger, and not automatic propagation; a caller must still supply a
  classification, the repository only rejects one the evidence doesn't
  justify).
- `source`/`person`/`commitment`/`person_evidence`/`commitment_evidence`
  are append-only, enforced by a database trigger
  (`zacai_forbid_mutation()`) that raises on any `UPDATE` or `DELETE` -
  not a `REVOKE`, since a table's owner always bypasses `GRANT`/`REVOKE`
  on their own objects in PostgreSQL regardless of privileges granted
  away. `person_head`/`commitment_head` carry no such trigger - they are
  the one deliberate, named exception. Logical deletion is a normal new
  version with `status="RETRACTED"` (a tombstone), going through the
  identical version-creation path as any other change - never a physical
  `DELETE`, which the trigger forbids
  outright regardless.
- One Alembic migration (`alembic/versions/0001_initial_state_schema.py`)
  creates all seven tables plus the trigger function and its five
  triggers, hand-reviewed and edited after `--autogenerate` (which cannot
  infer the composite foreign keys or the trigger-based append-only
  enforcement).

Alternatives considered:
SQLite was rejected: its single-writer model becomes a near-term
bottleneck given Phase 3's seven connectors and Phase 4's Chief-of-Staff
process, and it has no path to vector search later, forcing a future
storage-engine rewrite rather than an additive extension. Installing
pgvector now was rejected: ARCHITECTURE.md has no vector/semantic-search
requirement anywhere, and Phase 2's own checklist has none either -
installing it now would be infrastructure with no consuming feature,
against D016's own "wait for the phase that needs it" principle.
PostgreSQL 16 was rejected in favor of 18 (the current stable major as of
this review, with a Homebrew formula on Apple Silicon): no dependency in
this v1 slice (plain tables, foreign keys, transactions; pgvector
deferred) pins to an older major. Separate schemas or separate databases
per trust boundary were rejected in favor of one database with mandatory
boundary columns: they would map cleanly onto D018's per-boundary backup
keys, but cost real foreign-key integrity across boundaries, triplicated
migrations, and multiple credential sets for a single novice maintainer -
a worse tradeoff than a small boundary-aware backup export step. A
generic polymorphic `evidence_link(entity_type, entity_id, version,
source_id)` table was rejected in favor of typed `person_evidence`/
`commitment_evidence` tables: a polymorphic discriminator column cannot
be enforced by a real foreign key the way a typed table can.
Advisory-lock-based concurrency was rejected in favor of `INSERT ON
CONFLICT` + `SELECT FOR UPDATE`: it achieves the same serialization using
only ordinary row locks already relied on elsewhere in this design, with
no hash-key-collision risk an advisory lock's integer key would
introduce. A single-column `owner_person_id` FK to `person.entity_id`
alone, deferring owner-boundary checking to the repository layer, was
rejected for the same "prefer database-enforceable constraints" reasoning
already applied to the evidence tables.

Reasons and tradeoffs:
Embedding a `trust_boundary` column directly on `person_head`/
`commitment_head` (rather than only on the versioned tables) is what
makes both the version-boundary-immutability FK and the
commitment-owner-boundary FK possible with an ordinary composite foreign
key - a small, deliberate schema addition in exchange for two real
database-level guarantees instead of two repository-layer conventions.
Checking the classification non-weakening rule in the repository layer
rather than a database trigger trades a small amount of enforcement
strength (a direct, ORM-bypassing SQL write could in principle violate it)
for avoiding a more complex piece of PL/pgSQL for a rule that is not
itself a simple column-level constraint (it spans version, evidence, and
source rows) - explicitly not addressed by automatic classification
propagation, which was out of scope by design. Making `person`/
`commitment` referencing `owner_person_id`/evidence non-version-pinned
(referencing the entity via its head row, not a specific version) avoids
forcing an unrelated re-versioning cascade every time a referenced
entity's own content changes for unrelated reasons.

Security and data implications:
No real Personal, Brainstorm, or Shared data was created by this
decision - `zacai_dev` contains only synthetic test fixtures (and a small
number of synthetic rows deliberately left behind by the two concurrency
tests, which cannot be deleted by design - the append-only trigger
applies to test cleanup attempts exactly as it does to any other write).
No credential was created; `Settings.database_url` has no embedded
password (local trust authentication via `127.0.0.1`). This decision does
not establish a precedent that a production database password belongs in
Tier-0 `Settings`: if a future PostgreSQL deployment ever requires
authentication, that credential must be loaded via `get_secret`/Keychain
(D017), never embedded in a committed or configured `database_url` value.
No pgvector,
embeddings, or full-text search was installed or added. The
`trust_boundary`/`data_classification` columns this decision adds are
what make a future `AccessRequest` reconstructible directly from a stored
row, without weakening or duplicating `zacai.policy`'s logic - D023's
`evaluate_access` and D024's `evaluate_gateway` are both unchanged by this
decision.

Consequences:
Phase 2 gains a real, tested storage foundation for exactly three
entities (Person, Commitment, Source) - not the full entity graph, not
identity resolution, and not a claim that ROADMAP.md's broader Phase 2
checklist items are complete. D018's Lane B backup design gains a
concrete mechanism to build next (a boundary-aware `COPY`-based export
per boundary, not yet implemented) rather than remaining purely
theoretical, and D026 records an explicit extension D018 itself did not:
`SHARED` requires its own separate backup encryption key, not just
Personal and Brainstorm, since D018 predates SHARED as a third,
independently-authorized boundary. Future work extending this schema
(Company, Task, Project, identity resolution, retention/export/deletion
behavior, any connector) must route through `zacai.state_repository`
rather than querying `zacai.state` tables directly, and must not weaken
the append-only trigger, the boundary-immutability FKs, or the
classification non-weakening check without its own explicit decision.

Verification:
Confirmed `uv run pytest` (195 passed, including 42 new D026 tests: 4 in
`tests/test_db.py`, 6 in `tests/test_state.py`, 32 in
`tests/test_state_repository.py`), a clean `uv run ruff check .`, a clean
`uv run mypy src`, and a clean `git diff --check`. Confirmed
`alembic upgrade head` / `alembic downgrade base` / `alembic upgrade
head` round-trips cleanly against `zacai_dev`, leaving exactly the seven
application tables plus `alembic_version`. Confirmed the append-only
triggers reject `UPDATE`/`DELETE` on `source`/`person`/`commitment`/
`person_evidence`/`commitment_evidence` while `person_head`/
`commitment_head` remain updatable. Confirmed both the first-version and
next-version concurrency tests produce sequential, non-duplicate versions
under real concurrent transactions. Confirmed the nine-combination
owner-boundary matrix and the SHARED-is-not-a-bridge boundary-leak tests
all pass, and that a raw SQL insert bypassing `state_repository` entirely
is still rejected by the relevant foreign key in each case. Confirmed
`git status` shows no live LaunchAgent, Tailscale, or credential change,
and that `src/zacai/policy.py` and `src/zacai/gateway.py` are unchanged.

Approval or source:
Zac Campbell, architecture review conversation, 2026-09-19.

Supersedes:
None. Extends D004 (source-backed, versioned state), D016 (resolves the
long-deferred "install later" candidacy of PostgreSQL, explicitly still
deferring pgvector), D018 (gives Lane B's per-boundary encryption
requirement a concrete storage shape to back up, and extends it to
explicitly cover SHARED), and D023 (consumes `TrustBoundary`/
`DataClassification` unchanged, and answers the storage-representation
question D023 explicitly left open, without modifying `policy.py`).

## Open Decisions
These choices have not yet been made:
- Database and search/retrieval technologies
- Local model runtime and specific models
- Cloud models and account configuration
- First read-only integration and its authorization method
- Event transport and workflow execution mechanism
- Lane B (Zac State/database) off-device storage destination (D018)
- Text interface implementation
- Voice provider and API
- Whether to adopt OpenClaw
- Workflow budgets and reliability thresholds for autonomy

Choose these incrementally, using evidence and the current roadmap.
Do not treat this list as permission to install or connect everything.

## Template for New Decisions
ID: D016 or the next unused number
Title:
Date:
Status: Proposed
Context:
Decision:
Alternatives considered:
Reasons and tradeoffs:
Security and data implications:
Consequences:
Verification:
Approval or source:
Supersedes:

## Next Concrete Step
Inventory Mac Studio hardware and existing development tools using read-only checks before selecting the implementation stack.
