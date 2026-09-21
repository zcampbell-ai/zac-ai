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

## D027 - Test Database Isolation
Status: Accepted
Date: 2026-09-19

Context:
D026's two concurrency tests must commit real, independent transactions
to exercise genuine PostgreSQL row-locking, so they cannot use the
rollback-based `db_session` fixture - they were writing directly into
`zacai_dev`. This left synthetic rows in the persistent development
database after every test run, requiring a manual `dropdb`/`createdb`
reset after D026 shipped. Normal test runs must never be able to mutate
`zacai_dev` again. An architecture review (design-only pass, then
approved with two safety additions - a tightened URL allowlist plus a
post-connect verification, and a cross-process advisory lock) evaluated
the minimum reliable fix.

Decision:
All database tests now run against a dedicated, disposable `zacai_test`
database - never `zacai_dev` - via `tests/conftest.py`:

- `assert_safe_test_database_url(url)`: a strict allowlist, checked
  field-by-field with a specific error per failure. `host` must be
  exactly `"127.0.0.1"` (rejects `"localhost"`, `"::1"`, any LAN/
  Tailscale/remote address); `database` must be exactly `"zacai_test"`
  (rejects `"zacai_dev"` or anything else); `port` must be omitted or
  exactly `5432`; the URL must carry no password. Run once per test
  session, before any connection is opened.
- `assert_connected_to_safe_test_database(reported_database)`: a second,
  independent check - defense in depth, not redundancy. After the first
  connection opens, `SELECT current_database()` is compared against the
  same literal. The URL string is validated pre-connect; this verifies
  what was *actually* connected to, catching anything a string alone
  couldn't (a connection alias, a DSN quirk, an unexpected driver
  default). It is a pure function taking a plain string, kept separate
  from the query itself so it is unit-testable without a live connection.
- A fixed PostgreSQL session-level advisory lock (`_TEST_SESSION_LOCK_KEY
  = 727027`, tied to "D027," documented as never to collide with a future
  key added elsewhere) serializes two concurrent `pytest` processes:
  `pg_try_advisory_lock` is attempted first for immediate feedback; on
  failure, a clear message is printed to stderr before falling back to
  the blocking `pg_advisory_lock`, so a second run waits and proceeds
  automatically rather than failing fast or corrupting the first run's
  reset. Held on one dedicated connection for the whole test session,
  released via `pg_advisory_unlock` at teardown. Test infrastructure
  only - no application code uses this lock, and it is unrelated to and
  never interacts with D026's own row-level concurrency mechanism
  (`INSERT ON CONFLICT` + `SELECT FOR UPDATE` in `state_repository.py`).
- The schema is reset once per test session - `alembic downgrade base`
  (skipped on a completely fresh database with no `alembic_version`
  table yet) then `alembic upgrade head` - run programmatically against
  the test URL, using the exact same migration file
  (`alembic/versions/0001_initial_state_schema.py`) that defines
  `zacai_dev`'s schema. No hand-built test tables exist anywhere.
- `db_session` (the existing SAVEPOINT-based rollback fixture) now binds
  to this test engine instead of `zacai.db.get_engine()`. The two D026
  concurrency tests now take a `test_session_factory` fixture parameter
  instead of importing `zacai.db.get_session_factory()` directly - there
  is no code path left, in any test, through which `zacai_dev` could be
  reached.
- `alembic/env.py` was corrected: it previously unconditionally
  overwrote `sqlalchemy.url` from `Settings.database_url` on every
  invocation, which would have silently redirected this test-session
  reset back onto `zacai_dev` regardless of what `tests/conftest.py` set
  programmatically. It now only falls back to `Settings.database_url`
  when no URL has already been explicitly configured (i.e. normal `uv
  run alembic ...` CLI usage against `zacai_dev`/production is
  unaffected; a caller that has already called `config.set_main_option`
  is left alone).
- `tests/test_db.py`'s two `session_scope()` tests (a `zacai.db` function
  that otherwise always resolves `Settings.database_url`) monkeypatch
  `zacai.db`'s module-level singletons and `get_settings` for the
  duration of one test each, redirecting them at the already-validated
  test engine, so `session_scope()` itself is genuinely exercised without
  ever opening a connection to `zacai_dev`.

Alternatives considered:
A temporary, per-test database (`CREATE DATABASE` per test function) was
rejected: real catalog-level database creation is not free, and churning
through one per test adds meaningful cost and complexity for a benefit
the existing rollback fixture already provides to every test that doesn't
need real concurrency. Rollback/SAVEPOINT isolation alone, with no
separate database at all, was rejected as the *complete* answer (though
it remains exactly right for ordinary tests): it cannot exercise real
concurrent-transaction locking, since two "connections" nested under one
enclosing transaction share the same MVCC snapshot and never actually
contend for a lock the way two independently-committed transactions do -
the two concurrency tests specifically need what only a real, separate
database provides. Failing fast on lock contention (`pg_try_advisory_lock`
alone, no fallback) was rejected in favor of try-then-block: failing fast
forces a manual retry for what is normally an accidental double-launch,
where waiting and proceeding automatically is the friendlier default, as
long as the wait is clearly announced rather than silent. A Docker-based
or otherwise external disposable database was rejected as unnecessary and
explicitly excluded - the same local Postgres 18 instance already serving
`zacai_dev` can just as easily own a second, empty database.

Reasons and tradeoffs:
Checking each URL field individually rather than one combined condition
trades a few extra lines for immediate diagnosability - a misconfigured
test environment names exactly which field is wrong, matching this
project's established fail-closed, specific-error style (D021, D025).
Splitting `assert_connected_to_safe_test_database` into a pure,
string-only function rather than inlining the query result comparison
allows it to be unit-tested directly, the same reasoning already applied
to `assert_safe_bind_host` (D025) and the classification/boundary checks
in `state_repository.py` (D026). Fixing `alembic/env.py`'s
unconditional-overwrite behavior, rather than working around it from
`tests/conftest.py` alone, was necessary, not optional - the review
process itself caught that the original code would have silently
defeated this entire decision.

Security and data implications:
No real Personal, Brainstorm, or Shared data was created by this
decision. `zacai_dev` remained empty and at Alembic head across
repeated verification runs, confirmed by direct row-count queries before
and after. No credential was created; the test database URL carries none,
enforced by the guard itself. No pgvector, embeddings, or full-text
search was touched. D026's application storage semantics
(`zacai.state`, `zacai.state_repository`, the migration file) are
completely unchanged by this decision - only test infrastructure was
added or modified.

Consequences:
Future contributors and agents writing database tests must use the
`db_session` or `test_session_factory` fixtures from `tests/conftest.py`
- never `zacai.db.get_engine()`/`get_session_factory()` directly in a
test - or risk the guard rejecting the run outright rather than silently
touching `zacai_dev`. `zacai_test` is disposable by design: it is reset
at the start of every test session, so nothing about its contents between
runs needs to be tracked, backed up, or treated as meaningful. Any future
database test file must be added to this same fixture-based pattern
rather than constructing its own engine.

Verification:
Confirmed `uv run pytest` (218 passed, including 23 new D027 tests: the
URL-guard cases, the post-connect-checker cases, and the real-engine
integration test in `tests/test_conftest_safety.py`, plus updated tests
in `tests/test_db.py` and the two D026 concurrency tests in
`tests/test_state_repository.py`), a clean `uv run ruff check .`, and a
clean `uv run mypy src`. Confirmed `zacai_dev`'s seven state tables held
zero rows both before and after two consecutive full `uv run pytest`
runs, and that `alembic current` against `zacai_dev` remained `0001
(head)` throughout - proving isolation empirically, not just by code
inspection. Confirmed `zacai_test`'s row count did not accumulate across
the two runs (reset to zero and repopulated identically each time by the
concurrency tests), proving the per-session reset actually resets.
Performed the one manual verification: two processes contending for the
real advisory lock via the actual `_acquire_test_session_lock`/
`_release_test_session_lock` functions - the first acquired immediately,
the second printed the documented waiting message and blocked for
approximately the remaining hold time before acquiring, proving the lock
genuinely serializes two concurrent owners rather than allowing a
concurrent reset. `git diff --check` clean.

Approval or source:
Zac Campbell, architecture review conversation, 2026-09-19.

Supersedes:
None. Extends D026 (fixes the one operational gap its own concurrency
tests introduced - direct, uncontrolled writes to `zacai_dev`) without
changing any of D026's application storage semantics, and follows the
same fail-closed, specific-error pattern D025's `assert_safe_bind_host`
established.

## D028 - Zac State Lane B Backup and Restore (v1)
Status: Accepted
Date: 2026-09-19

Context:
D018 already decided Lane B's shape - client-side encryption before any
off-device copy leaves the Mac Studio, separate encryption keys per
trust boundary, `age` as the preferred-but-unadopted candidate tool - but
deferred building or testing it until canonical Zac State existed. D026
created that state; D027 established the disposable, purpose-named
test-database pattern this decision reuses for `zacai_restore_test`.
RECOVERY.md's own text states Lane B "must be tested once canonical Zac
State exists" - it now does. D018 also predates D023's SHARED boundary,
naming separate keys only for "Personal and Brainstorm." An architecture
review (two design-only passes, the second adding three safety
corrections - a streaming pipeline avoiding plaintext, an explicit
Lane B/Lane C distinction, and D027-style destructive-target protection)
evaluated the minimum reliable v1 mechanism.

Decision:
Add `src/zacai/backup_safety.py` and `src/zacai/backup.py`, plus a
`uv run zacai-backup` console script, implementing:

- **Adopts `age`** as Lane B's encryption tool (resolving D018's
  "preferred, not adopted" status), in key-file mode, with **three**
  separate keypairs - Personal, Brainstorm, and Shared - explicitly
  extending D018's "separate keys" requirement to cover the SHARED
  boundary it predates. Private identities are generated and escrowed by
  Zac himself; this decision creates no real key material.
- **A streaming export/encryption pipeline**
  (`export_boundary`/`export_boundary_stream`): for one trust boundary,
  every row across all seven `zacai.state` tables, in one fixed FK-safe
  order (`source` -> `person_head` -> `commitment_head` -> `person` ->
  `commitment` -> `person_evidence` -> `commitment_evidence`), is
  streamed via PostgreSQL `COPY ... TO STDOUT`, framed with a small
  length-prefixed format, and piped directly into an encryption
  subprocess's stdin. **No plaintext file is ever written to disk in the
  normal path** - the only file created is the final encrypted artifact,
  with mode `0600` set atomically at creation (`O_CREAT | O_EXCL`, not a
  permissions fix applied after the fact), removed automatically if
  anything fails partway through. Each table is buffered in memory
  (never on disk) before framing - the appropriate "smallest reliable"
  choice at Zac AI's actual v1 data scale, named explicitly as a scope
  limit, not an oversight; true chunked disk-avoiding streaming for an
  arbitrarily large single table is a distinct future revision only if
  data volume ever actually demands it.
- **A matching streaming restore pipeline**
  (`restore_boundary`/`restore_boundary_stream`): a decryption
  subprocess's stdout is read frame-by-frame, in the exact same fixed
  order, straight into `COPY ... FROM STDIN` - restoring all seven
  tables without any plaintext ever touching disk either. Restoring
  frames out of the recorded order raises immediately rather than
  silently violating a foreign key.
- **Lane B key escrow is explicitly distinguished from Lane C.** The
  three private identities need two independently recoverable copies -
  local (outside this repository, restrictive permissions) and the
  existing password manager. Reusing the password manager as this
  escrow location is a **location reuse of an already-existing off-device
  store, not a functional dependency on Lane C** - it does not mark Lane
  C implemented or tested. Lane C remains entirely, separately deferred
  until a real, approved application credential exists in Keychain.
  Private identities are never committed, logged, embedded in a script,
  passed as CLI key material directly (`age -i <path>` only), or stored
  beside the artifact they decrypt as its only recovery copy.
- **`assert_safe_restore_target_url`/`assert_connected_to_safe_restore_database`**
  (`backup_safety.py`): a D027-style fail-closed guard, hardcoded to the
  single literal `zacai_restore_test` (host `127.0.0.1`, port omitted or
  `5432`, no password) - checked pre-connect via the URL string and
  post-connect via a live `SELECT current_database()`. Distinct from,
  and never confusable with, D027's own `zacai_test` guard.
- **Two-connection, fixed-constant destructive orchestration**
  (`recreate_restore_test_database`/`drop_restore_test_database`):
  PostgreSQL cannot drop a database while connected to it, so these
  functions connect to the always-present `postgres` maintenance
  database (itself validated by `assert_safe_admin_url`, pre- and
  post-connect) to issue `DROP`/`CREATE DATABASE zacai_restore_test`,
  where the target name is a **module constant, never a function
  parameter** - there is no code path by which a caller could redirect
  either function to a different database. `upgrade_restore_test_schema`
  then connects directly to `zacai_restore_test` (validated the same way)
  and runs the exact same Alembic migration `zacai_dev`/`zacai_test` use
  - no hand-built restore-test schema.
- **Local fast-recovery backup**: a plain, unencrypted `pg_dump -Fc` of
  the whole `zacai_dev` database remains a separate, local-only,
  explicitly non-Lane-B safety net (not built by this decision's
  automated tooling - documented as a manual operator step).
- **Off-device destination remains explicitly open**, unchanged from
  D018 - this decision's mechanism is destination-agnostic by design and
  does not invent one.
- **Manual only for v1** - no `launchd`/cron scheduling. Automating an
  unproven mechanism risks silently automating a broken backup, which is
  worse than no backup; scheduling is a distinct, later decision once
  manual drills have succeeded repeatedly.

Alternatives considered:
Writing plaintext CSV files to a temp directory and encrypting them
afterward was proposed initially and rejected on review: it makes
"delete it afterward" the primary security control for real Personal/
Brainstorm/Shared content, rather than never creating it. A per-test
temporary database for restore drills was rejected in favor of one
fixed, dedicated `zacai_restore_test`: D027's `zacai_test` already
demonstrates that a single, purpose-named disposable database, reset
deterministically, is simpler than provisioning one per run. Reusing
`zacai_test` itself for restore drills was rejected: it would conflate
pytest's own disposable sandbox with a distinct, human-driven
verification exercise. Passphrase-mode `age` encryption was rejected in
favor of key-file mode: passphrases block unattended/scriptable
encryption and have no escrow story as clean as a key file. Naming a
specific off-device destination (e.g. a particular cloud drive) now was
rejected as premature invention beyond what D018 itself deferred.
Advisory-lock-style protection for the destructive restore-test path was
considered and rejected in favor of URL validation plus live
verification plus fixed constants: D027's advisory lock solves a
different problem (two concurrent *pytest sessions*), not "can a caller
redirect a DROP DATABASE to the wrong target," which fixed constants
solve more directly.

Reasons and tradeoffs:
Buffering each table's CSV in memory rather than building true
constant-memory chunked streaming trades some theoretical scalability
for a materially simpler v1 implementation, appropriate at Zac AI's
actual personal/small-business data scale; this is a named, deliberate
limit, not a gap discovered later. Hardcoding the restore-test database
name as a module constant rather than accepting it as a parameter (even
an "internal" one) trades a small amount of flexibility for eliminating
an entire class of "what if a caller passes the wrong name" bugs before
they can exist. Validating both the fixed administrative connection
(`postgres`) and the restore-test connection, even though neither is
ever influenced by external input, is a self-check against a future
accidental edit to either constant, not a defense against an adversarial
caller.

Security and data implications:
No real Personal, Brainstorm, or Shared data was created by this
decision. No credential or real `age` key material was generated by
Claude - Zac generates and escrows the three identities himself. No
plaintext backup artifact was left on disk by any successful export in
testing (verified directly). `zacai_dev` was never connected to by any
automated test in this decision - all automated verification ran against
`zacai_test` (source) and `zacai_restore_test` (target), consistent with
D027's own invariant; `zacai_dev`'s row counts were confirmed unchanged
(zero) before and after, via a separate manual check outside the test
suite. Reusing the password manager for Lane B key escrow does not
change Lane C's status in any way (see Decision, above).

Consequences:
Lane B gains a real, drill-tested mechanism; RECOVERY.md documents it in
place of the prior "does not exist yet" status. ROADMAP's backup/restore
item still is not fully complete - Lane C remains separately deferred,
and running Lane B for real against `zacai_dev` (rather than synthetic
`zacai_test` data) is a distinct, later, explicitly-approved step, since
`zacai_dev` currently holds no real data to back up. Future work adding
scheduled automation must reuse `zacai.backup`'s existing functions
rather than re-implementing export/restore logic, and must not weaken
the streaming-only export path, the three-key-per-boundary requirement,
or the fixed-constant restore-target protection without its own explicit
decision.

Verification:
Confirmed `uv run pytest` (261 passed, including 34 new
`tests/test_backup_safety.py` guard tests and 9 new
`tests/test_backup.py` pipeline tests), a clean `uv run ruff check .`,
and a clean `uv run mypy src`. Confirmed a full drill end-to-end using a
no-op passthrough command in place of `age` (proving the framing/
streaming/FK-order logic independent of whether `age` is installed):
export from `zacai_test`'s synthetic data, `recreate_restore_test_database`
+ `upgrade_restore_test_schema` + `restore_boundary` into
`zacai_restore_test`, confirming the restored rows match the source
exactly, contain only the exported boundary, and that the append-only
trigger survives a fresh Alembic-built schema in the restore-test
database. Confirmed the exported artifact is created with mode `0600`
and that no other file exists in its output directory after a successful
export, and that a failed encryption command leaves no partial file
behind. Confirmed `recreate_restore_test_database`/
`drop_restore_test_database` accept no parameters at all (a structural
test, not just a behavioral one). Confirmed `zacai_restore_test` does not
exist after the test suite completes (dropped by the drill test's own
cleanup), and confirmed `zacai_dev` held zero rows in all seven state
tables both before and after the full test run, via a manual check
outside pytest.

Approval or source:
Zac Campbell, architecture review conversation, 2026-09-19.

Supersedes:
None. Extends D018 (adopts `age`, builds the mechanism D018 deferred, and
explicitly extends its "separate keys" requirement to cover SHARED),
D023 (the boundary this decision was missing), D026 (backs up exactly
the schema D026 created, without any schema change), and D027 (reuses
its disposable-database pattern for `zacai_restore_test` and its
fail-closed URL-guard style for the new restore-target protection).

## D029 - Zac State Entity Model Expansion (v1)
Status: Accepted
Date: 2026-09-21

Context:
D026 established Zac State's v1 storage foundation for exactly three
entities - Person, Commitment, Source. ARCHITECTURE.md names People,
Companies, Projects, Opportunities, Commitments, Decisions, and Meetings
as first-class entities; D026 explicitly deferred all but the first two.
Phase 2 requires the entity graph to grow toward that list before any
connector is approved. An architecture review evaluated nine candidate
entities (Company, Project, Task, Decision, Meeting, Event, Opportunity,
Message, Document) against ARCHITECTURE.md's list and against D026's
established patterns (versioned head+version tables for mutable-history
entities, typed evidence tables, composite-FK boundary enforcement,
append-only triggers), and went through two further design-review
rounds - each revising the model before implementation - before
approval.

Decision:
Add four entities - Company, Project, Decision, Meeting - plus their
supporting association/evidence/retraction tables, extending
`src/zacai/state.py` and `src/zacai/state_repository.py` without
modifying `src/zacai/policy.py` or `src/zacai/gateway.py`:

- **Task, Opportunity, Event, Message, and Document remain deferred.**
  Task was rejected as redundant with the existing Commitment entity -
  D026's Commitment already models an owned, trackable obligation, and a
  separate Task table would either duplicate that shape or require an
  immediate reconciliation this decision has no need to force yet.
  Opportunity, Event, Message, and Document are connector-shaped
  entities - each is best modeled once a real connector (Salesforce,
  Google Calendar, Gmail/Slack, Google Drive) supplies actual field
  requirements, rather than guessing a schema now and reworking it after
  the first real integration lands, which would violate the "read-only
  first, and don't build ahead of the phase that needs it" reasoning
  D016 and D026 already established.
- **Company and Project are versioned, head-based entities** -
  `company`/`company_head`/`company_evidence` and
  `project`/`project_head`/`project_evidence` reuse D026's Person/
  Commitment pattern exactly: append-only version rows, a mutable head
  row holding only a boundary and a version pointer, typed (non-
  polymorphic) evidence tables, and the append-only trigger on every
  table except the two head tables. `project` requires a `company_id`
  (composite FK to `company_head`); no entity in this decision's scope
  requires a Project.
- **Decision and Meeting are immutable, event-like entities**, not
  versioned - a Decision or a Meeting is a fact about something that
  happened, not a mutable-over-time record the way Person or Commitment
  is. Each carries its own `trust_boundary` and `data_classification`
  and a `UNIQUE(id, trust_boundary)` constraint so other tables can FK
  to it by its exact boundary, but has no head table and no version
  column.
- **Person <-> Company uses a typed, append-only
  `person_company_relationship` table, not `person.company_id`.** A
  single FK column wrongly assumes one person has exactly one company
  relationship at a time; a real person can be a current employee, have
  a prior employment history at a different company, and simultaneously
  be an external contact at a third - all valid, all worth retaining.
  `person_company_relationship` carries no uniqueness constraint on
  `(person_id, company_id)`: multiple concurrent and multiple historical
  rows for the same pair are both expected. `relationship_kind`
  (`EMPLOYEE`/`CONTACT`/`OTHER`) is the smallest split that matters for
  Chief-of-Staff queries today, not an attempt to enumerate every
  professional relationship type.
- **`person_company_relationship` is independently classified and
  source-backed**, not inherited from either endpoint. It carries its
  own `trust_boundary NOT NULL` and `data_classification NOT NULL`
  (composite FKs pin its boundary to match both `person_head` and
  `company_head` exactly - SHARED is never a bridge between a PERSONAL
  person and a BRAINSTORM company), plus a required `source_id`
  (composite FK to `source`), since a relationship fact - e.g. a still-
  confidential departure - can be more sensitive than either party's own
  record and must never be asserted without a citation, matching every
  other content-bearing table in this schema.
- **Meeting supports multiple typed `meeting_source` rows** instead of a
  single `Meeting.source_id` column, for the same reason a meeting can
  have a calendar event, a transcript, a summary, a recording, notes,
  and follow-up material - not exactly one source document.
  `meeting_source` uses a role-based `source_role` enum
  (`CALENDAR_EVENT`/`TRANSCRIPT`/`SUMMARY`/`RECORDING`/`NOTES`/
  `FOLLOW_UP`), deliberately not `EvidenceStance` (`SUPPORTS`/
  `CONTRADICTS`) - a transcript doesn't "support" that a meeting
  happened the way a `Source` supports a claim about a Person; it is a
  piece of material the meeting produced, playing a specific role.
  `create_meeting` requires at least one `meeting_source` row at
  creation (mirroring D026's at-least-one-`SUPPORTS`-evidence rule);
  `add_meeting_source` appends more later.
- **Decision supersession and Decision/Meeting retraction are distinct
  mechanisms, not one.** Supersession (`decision.supersedes_decision_id`)
  means "this Decision was real, but a later real Decision replaces
  it" - both rows remain, both stay valid history. Retraction
  (`decision_retraction`/`meeting_retraction`) means "this record should
  never have been asserted, or is no longer valid as a fact" - a
  presence-based check in a separate table, never a mutated status
  column, since the original row can never change. `get_decision`/
  `get_meeting` exclude retracted records by default, with an explicit
  `include_retracted` override. Both retraction tables require a
  `source_id`, a `UNIQUE` constraint on their target's ID (one retraction
  per record), and their own `trust_boundary` matched by composite FK to
  the record they retract.
- **`decision.supersedes_decision_id` uses a `DEFERRABLE INITIALLY
  DEFERRED` composite foreign key**, not reliance on `decided_at`
  ordering, because timestamps can be equal, backfilled, or otherwise
  imperfect and cannot be trusted to guarantee a superseded Decision's
  row exists before the superseding one during a bulk restore. Deferring
  constraint validation to transaction commit means `restore_boundary_
  stream` - which already commits an entire boundary's restore in one
  transaction (fixed during D028) - restores a Decision supersession
  chain correctly regardless of row order, with zero changes to the
  restore pipeline itself.
- **All cross-entity links use exact trust-boundary composite foreign
  keys**, the same pattern D026 established: Project->Company,
  Commitment->Project, PersonCompanyRelationship->Person/Company/Source,
  Meeting->Project, MeetingSource->Meeting/Source,
  MeetingAttendee->Person, Decision->Project/Meeting/supersedes-target,
  DecisionRetraction/MeetingRetraction->Decision/Meeting/Source. Every
  one of these is enforced at the database level, not only in the
  repository layer - verified by raw-SQL backstop tests that bypass
  `state_repository` entirely.
- **Commitment gains a nullable `project_id`** (composite FK to
  `project_head`) - purely additive, does not change D026's owner-
  boundary semantics or any existing Commitment behavior.
- **D028's backup/restore pipeline is extended only by reviewed
  `TABLE_ORDER`/`_ORDER_BY` additions** in `src/zacai/backup.py` - all
  14 new tables added in FK-safe order; `export_boundary_stream`,
  `restore_boundary_stream`, the restore-target guards, and the two-
  connection destructive orchestration are all unchanged, exactly as
  D028 already made them generic over `TABLE_ORDER`.
- **Repository functions remain explicit and typed, not a generic
  entity/relationship framework**: `create_company`/`get_company`/
  `retract_company`, `create_project`/`get_project`/`retract_project`,
  `record_person_company_relationship`/`get_current_company_
  relationships`, `create_meeting`/`add_meeting_source`/`get_meeting`/
  `retract_meeting`, `create_decision`/`get_decision`/`retract_decision`.
  `_allocate_version`/`_advance_head` are generalized from a closed union
  of head-table types to `type[Base]`, since both functions only ever
  touch `.__table__` generically - a purely typing-level change with no
  behavior difference.
- One new Alembic migration (`0002_entity_model_expansion.py`) adds all
  14 tables plus the append-only trigger on every one of them except the
  two new head tables, and the `commitment.project_id` column/FK.
  Migration `0001` is unchanged.
- **No Task/Opportunity/Event/Message/Document implementation**, no
  connectors, no identity resolution, no pgvector, no model routing, no
  agents, and no real data were introduced by this decision.

Alternatives considered:
A single `person.company_id` column was rejected (see Decision, above) -
it structurally cannot represent concurrent or historical multi-company
relationships, which are common in practice (a board member, a former
employee now an external contact). A single `Meeting.source_id` column
was rejected for the same reason applied to `meeting_source`: a meeting
routinely has more than one piece of supporting material. A generic
polymorphic retraction/correction framework (one `retraction` table with
an entity-type discriminator) was rejected in favor of two small, typed
tables (`decision_retraction`, `meeting_retraction`), consistent with
D026's rejection of a generic polymorphic evidence table for the same
reason - a discriminator column cannot be enforced by a real foreign
key. Relying on `decision.decided_at` ordering to make self-referencing
FK restoration safe was rejected in favor of `DEFERRABLE INITIALLY
DEFERRED` (see Decision, above) - an ordering assumption is a latent bug
waiting for a backfilled or duplicate timestamp, while a deferred
constraint is enforced by Postgres itself with no ordering assumption at
all. Building Task, Opportunity, Event, Message, and Document now,
speculatively, was rejected as building ahead of the connector that
would supply their real shape - the same "wait for the phase that needs
it" reasoning D016 and D026 already established for pgvector.

Reasons and tradeoffs:
Giving `person_company_relationship` its own `data_classification`
column rather than deriving it from Person and Company on every read
trades a small amount of storage/write-time burden (the caller must
supply a classification explicitly) for avoiding a join-and-max
computation on every read and for correctly handling the case where the
relationship fact itself is more sensitive than either endpoint's own
record. Requiring `DEFERRABLE INITIALLY DEFERRED` only on the one FK
that actually needs it (`decision.supersedes_decision_id`), rather than
deferring every foreign key in the new schema, keeps the ordering
guarantee narrowly scoped to the one place a self-reference within a
single bulk restore transaction actually requires it. Choosing
presence-in-a-separate-table for retraction, rather than reusing
Person/Commitment's in-row `status="RETRACTED"` tombstone pattern, trades
a small amount of pattern consistency for correctness: Decision and
Meeting have no version column to attach a new tombstone version to, so
a separate presence-based table is the only option that never mutates
the original row.

Security and data implications:
No real Personal, Brainstorm, or Shared data was created by this
decision - `zacai_dev` was confirmed to hold zero rows in all 21
application tables both before and after this work, via a manual check
outside pytest, consistent with every prior decision's invariant. No
connector, credential, or identity-resolution logic was added. Every new
cross-entity reference is boundary-enforced by a real composite foreign
key, not repository convention alone, and this was verified both through
the repository layer (`RelatedEntityBoundaryMismatchError`) and through
raw-SQL backstop tests that insert directly against the schema,
bypassing `state_repository` entirely. `person_company_relationship`,
`decision_retraction`, and `meeting_retraction` all require a
`source_id`, so no relationship or retraction fact can be recorded
without a citation, consistent with D026's source-backing requirement
for `person`/`commitment`.

Consequences:
Zac State's entity graph now covers six of ARCHITECTURE.md's named
first-class entities (Person, Commitment, Source, Company, Project,
Decision, Meeting) - Task/Opportunity/Event/Message/Document remain
explicitly deferred until a real connector justifies their shape. D028's
backup/restore mechanism now covers the full expanded schema, proven by
an extended restore drill and a reversed-row-order Decision-supersession
test against the real, unmodified restore pipeline. Future work adding
Task, Opportunity, Event, Message, or Document must route through
`zacai.state_repository` with the same explicit-typed-function,
composite-FK-boundary, and append-only-trigger patterns established
here and in D026, and must not add a generic entity/relationship
abstraction without its own explicit decision. Future work must not add
`person.company_id` or `meeting.source_id` - both were explicitly
rejected in this decision and superseding that choice requires a new
decision, not a quiet schema edit.

Verification:
Confirmed `uv run pytest` (291 passed, including 28 new tests in
`tests/test_state_d029.py` and 2 new tests in `tests/test_backup.py`), a
clean `uv run ruff check .`, a clean `uv run mypy src`, and a clean `git
diff --check`. Confirmed `alembic upgrade head` applied migration `0002`
against `zacai_dev` (revision 0001 -> 0002), and confirmed a full
downgrade/upgrade round-trip (`0002` -> `0001` -> `0002`) leaves exactly
the expected table set at each step, with migration `0001` itself
unmodified (`git diff --stat` empty for that file). Confirmed the
extended backup/restore drill: a full Company -> Project -> Person ->
PersonCompanyRelationship -> Commitment -> Meeting -> Decision scenario
exported from `zacai_test` and restored into `zacai_restore_test` via
the real, unmodified pipeline, with all row counts and the append-only
trigger confirmed post-restore. Confirmed a Decision-supersession chain
restores correctly even with its two rows' export order physically
reversed, proving the `DEFERRABLE INITIALLY DEFERRED` constraint on
`fk_decision_supersedes_boundary` (verified via `psql` to have
`condeferrable=t, condeferred=t`) works as designed, using the real
`restore_boundary()` entry point, not a hypothetical. Confirmed
`zacai_dev` held zero rows in all 21 application tables both before and
after this work, via a manual check outside pytest.

Approval or source:
Zac Campbell, architecture review conversation, 2026-09-21.

Supersedes:
None. Extends D023 (every new table's boundary/classification columns
reuse `TrustBoundary`/`DataClassification` unchanged), D026 (reuses its
head+version, typed-evidence, append-only-trigger, and concurrency-safe
version-allocation patterns exactly, and generalizes its head-table
helpers), and D028 (extends its `TABLE_ORDER`/`_ORDER_BY` constants only,
with no change to its export/restore pipeline, restore-target guards, or
destructive-orchestration logic).

## D030 - First Read-Only Ingestion Architecture (Synthetic v1)
Status: Accepted
Date: 2026-09-21

Context:
Phase 2 (D026-D029) built canonical Zac State with a real, tested storage
foundation, but no live external source has ever written into it - every
row through D029 is synthetic test data. ROADMAP.md Phase 3 requires
choosing and documenting the first useful read-only integration before
any live account is connected, and Phase 2's own checklist requires
validating with synthetic data first. An architecture review compared
Fireflies, Google Calendar, Gmail, and Slack against Chief-of-Staff
value, clean mapping to D029's entities, source/provenance quality,
identity ambiguity, trust-boundary difficulty, idempotency, API
complexity, blast radius, and usefulness for validating Decision/
Commitment extraction. The review went through three further correction
rounds - each revising the design before implementation - covering raw
artifact storage, Source lineage, extraction-candidate review, ingestion-
run transaction semantics, classification elevation, and finally the
artifact/database transaction ordering and a real-ingestion hard gate.

Decision:
**Fireflies is selected as Zac AI's first read-only ingestion source.**
Google Calendar was the strongest alternative - its OAuth-verified
attendee emails are actually a cleaner identity signal than Fireflies' -
but it has no transcript content, so it cannot validate Decision/
Commitment extraction, the highest-value, least-proven capability on the
roadmap, and a personal/work mixed calendar reintroduces real per-item
boundary ambiguity Fireflies doesn't have (a single connected Fireflies
account has one deterministic boundary, matching SECURITY.md's own
Fireflies-under-Brainstorm placement). Gmail and Slack were rejected as
structurally premature: both require a `Message` entity this project has
not yet built, and both carry materially higher blast radius (Gmail
especially, given SECURITY.md's own HIGHLY_RESTRICTED examples routinely
appear in an inbox) than is appropriate for a first pipeline whose job is
proving the pipeline itself is safe, not maximizing day-one coverage.

**This decision implements synthetic ingestion infrastructure only.** No
real Fireflies credential, account, network call, real transcript, or
real LLM call has occurred or is introduced by this decision. Every test
uses hand-built, Fireflies-shaped fixture payloads and a caller-supplied
stub in place of a model call.

- **Raw artifact content lives behind a replaceable `ArtifactStore`
  abstraction (`src/zacai/ingestion/artifact_store.py`), never in a
  PostgreSQL `JSONB` column.** `Source.content_location` is opaque to
  the database - its meaning belongs entirely to whichever
  `ArtifactStore` implementation wrote it, so a future encrypted/
  object-storage backend requires only a new class satisfying the same
  `put`/`get` protocol, never a `Source` schema change.
  **`LocalFilesystemArtifactStore` is the only v1 backend** - local
  disk, content-addressed (identical bytes always resolve to the
  identical path), atomic writes (`tempfile` + `os.replace`, never a
  direct write to the final path), `0700`/`0600` permissions. No S3 or
  cloud/object storage exists yet.
- **`content_hash` is the SHA-256 of the *exact* bytes `ArtifactStore`
  stores** - one canonicalization function
  (`zacai.ingestion.artifact_store.canonical_bytes`) produces the bytes
  both hashed and written, so hashing and storage can never silently
  diverge from two independently produced serializations. The invariant
  `sha256(artifact_store.get(source.content_location)) ==
  source.content_hash` is enforced at write time (a read-after-write
  check before the database transaction even opens) and by dedicated
  tests.
- **`Source` gains `content_hash`, `content_location`, and
  `supersedes_source_id`** (additive, still immutable/append-only - no
  trigger change). A content revision - the same
  `(system, external_ref, trust_boundary)` arriving with a different
  `content_hash` - is a new, immutable row linked via
  `supersedes_source_id`, never a mutation. That FK is `DEFERRABLE
  INITIALLY DEFERRED`, the same mechanism and reasoning as
  `Decision.supersedes_decision_id` (D029), and was proved safe under a
  reversed-row-order restore drill exactly like D029's. The "current"
  revision of a lineage chain is structural - the one row nothing else's
  `supersedes_source_id` points to - never timestamp-based.
- **Artifact writes happen before the database transaction opens**,
  because the two systems cannot share one transaction. If the artifact
  write succeeds but the database transaction that would record its
  `Source` row later fails or rolls back, the result is a **safe,
  named, accepted "orphan artifact"**: a real, valid, correctly-hashed
  file with no `Source` row referencing it. This is deliberately
  preferred over the reverse ordering (which could leave a `Source` row
  pointing at bytes that were never actually written - real data loss
  disguised as success). **Automatic orphan-artifact garbage collection
  is deliberately deferred** - only an observability primitive
  (`is_artifact_referenced`) was built; a future reconciliation process
  is sketched, not implemented, and no filesystem rollback/delete-on-
  failure is attempted (deleting on one caller's failure could delete
  bytes a concurrent or retried caller legitimately still needs, since
  content-addressed storage is inherently shareable).
- **`ingestion_run` uses a three-transaction lifecycle**: `STARTED` is
  inserted and committed immediately, before any risky work begins; the
  data batch (Source/Meeting writes plus cursor advance) runs in its own
  transaction; the terminal `SUCCEEDED`/`FAILED` update runs in a third,
  fresh transaction opened after the data transaction has already
  resolved either way. This is what lets a rolled-back data transaction
  never erase the failure audit record - proved by a test that forces a
  real rollback and confirms the `FAILED` row survives it.
  **`ingestion_cursor` advancement is atomic with the data batch's own
  commit** - the cursor never advances on failure, verified directly.
- **Identity resolution is minimal and exact**: only a case-insensitive,
  same-trust-boundary exact match on `person.primary_email` links an
  attendee to an existing Person. Every other case - no email, no match,
  or an ambiguous match against more than one Person - is recorded in a
  new `unresolved_identity` table rather than guessed or merged. No
  company/project auto-association from meeting content exists.
- **Extraction creates candidates only** (`extraction_candidate`, a new
  immutable, typed table) - never a canonical Decision or Commitment
  directly. **LLM/model output is never itself canonical Zac State.**
  Promotion requires an explicit, separately-recorded human approval
  (`approve_extraction_candidate`) that routes through the *same*,
  unmodified `create_decision`/`create_commitment` repository functions
  every other write already uses, citing the candidate's original
  `Source` as real evidence. **Rejection remains auditable**: a
  `reject_extraction_candidate` call requires a reason and records an
  `extraction_candidate_review` row (`UNIQUE(candidate_id)` - one final
  review per candidate, the same presence-based pattern D029's
  `decision_retraction`/`meeting_retraction` already established) rather
  than silently discarding anything. Reprocessing a Source with a new
  model/prompt version creates an independent, coexisting candidate set
  via a fresh, non-unique `extraction_record` row; a retried *failed*
  attempt never duplicates a prior attempt's (empty) output.
- **Source classification elevation is append-only and strictly
  upward-only.** A new `source_classification_elevation` table (never
  mutating `Source.data_classification` itself) records that a Source is
  more sensitive than originally assumed; `elevate_source_classification`
  rejects any attempt to elevate to an equal or weaker classification,
  reusing the existing `_CLASSIFICATION_ORDER` unchanged. **The Source's
  *effective* classification - not only its original stored value - is
  now the binding one for every downstream evidence/access check**:
  `get_effective_source_classification` is the only correct way to ask
  how sensitive a Source currently is, and
  `_assert_classification_not_weaker_than_evidence` (D026) was updated to
  call it instead of reading the stored column directly, so an elevated
  Source's `HIGHLY_RESTRICTED` status correctly and automatically trips
  `evaluate_access`'s existing, unconditional external hard-deny with no
  change to `zacai.policy` at all.
- **`extraction_candidate` uses typed, first-class columns** (`
  description`, `owner_person_id`, `due_date`, `project_id`,
  `proposed_classification`, `confidence`) instead of the `proposed_
  fields` `JSONB` blob originally sketched during design review. This is
  recorded here as a deliberate implementation simplification, consistent
  with this schema's typed-evidence-over-generic-blob philosophy already
  established in D026/D029, with no loss of capability for the two
  candidate types (`DECISION`/`COMMITMENT`) this milestone supports.
- **D023/D024 semantics are entirely unchanged.** `zacai.policy` and
  `zacai.gateway` were not modified; a dedicated test asserts nothing
  under `src/zacai/ingestion/` ever imports `zacai.gateway` or references
  `ActionType`. Ingestion only ever writes through
  `zacai.state_repository`, exactly like every existing synthetic
  fixture.
- **Migration `0003` is the ingestion architecture migration** - hand-
  reviewed after `--autogenerate`, adds the `Source` additions and seven
  new tables, append-only triggers on all but the two deliberate mutable
  exceptions (`ingestion_cursor`, `ingestion_run` - joining `person_head`/
  `commitment_head`/`company_head`/`project_head`). Migrations `0001` and
  `0002` are untouched.
- **D028's backup/restore pipeline is extended only for the new
  PostgreSQL state** - `TABLE_ORDER`/`_ORDER_BY` gained the seven new
  tables and `Source`'s new columns in FK-safe order, with zero change to
  `export_boundary_stream`/`restore_boundary_stream` or the restore-
  target guards, exactly as D029's additions required no pipeline
  change.

**Real-ingestion hard gate**: no real Fireflies content may be ingested
until raw artifact backup/recovery has been designed, implemented,
encrypted before any off-device storage, separated by PERSONAL/
BRAINSTORM/SHARED boundary protections consistent with D018/D028, and
restored in a real drill in which every restored artifact satisfies
`sha256(restored_bytes) == Source.content_hash`. This is a blocking
prerequisite, not a recommendation - see RECOVERY.md's Lane B section,
updated by this decision to record it. The synthetic implementation this
decision approves is exempt from this gate, since it never stores real
content; a future, separate, explicitly-approved milestone is required
before any live Fireflies account is connected.

Alternatives considered:
See the Decision section for the full Fireflies-vs-Calendar-vs-Gmail-vs-
Slack comparison. A single `Meeting.source_id`/no-lineage design was
rejected in the first design round in favor of typed multi-source
provenance (already D029) and, for content revisions specifically, the
`supersedes_source_id` lineage mechanism, for the same "typed, not
generic" reasoning applied throughout. Storing raw artifacts directly in
`Source.raw_payload` as `JSONB` was rejected in the first design round in
favor of the `ArtifactStore` abstraction - keeping large/variable raw
content out of the hot relational schema and out of vendor lock-in.
Having extraction write directly to `create_decision`/`create_commitment`
was rejected in favor of the candidate/review layer - an LLM's own
confidence is not the same thing as canonical truth, and D030's "prefer
unresolved/reviewed over incorrectly merged" principle (already applied
to identity resolution) applies equally to extracted facts. Attempting
filesystem rollback or delete-on-failure for a failed artifact write was
considered and rejected - it introduces a new failure mode (the delete
itself can fail) and is actively dangerous under content-addressed
storage, where a "failed" caller's bytes may already be legitimately
relied on by a different, successful caller.

Reasons and tradeoffs:
Writing the artifact before opening the database transaction, rather
than the reverse, trades a small, accepted risk (a harmless orphan file
on a rolled-back write) for avoiding a much worse one (a `Source` row
that claims content exists when it never was durably written). Splitting
`ingestion_run`'s lifecycle into three transactions rather than one
trades a small amount of mechanical complexity for a guarantee that
matters specifically because it protects the failure case: an audit
record that only a *successful* write could produce would be useless for
diagnosing exactly the failures it exists to catch. Keeping
`extraction_candidate` on typed columns rather than a `JSONB` blob trades
a small amount of schema flexibility (a future third candidate type would
need its own columns) for full `mypy --strict` type safety and
consistency with every other table in this schema, appropriate given
this milestone supports exactly two candidate types.

Security and data implications:
No real Personal, Brainstorm, or Shared data was created by this
decision - `zacai_dev` was confirmed to hold zero rows in all 28
application tables both before and after this work. No real credential
was created; `BRAINSTORM_FIREFLIES_API_KEY` and
`ZACAI_ARTIFACT_STORE_ROOT` were added to `.env.example` as names only,
with no value, consistent with SECRETS.md. No network call, no real LLM
call, and no write-scope request exist anywhere in this milestone's code
or tests - verified both by inspection and by a dedicated test. The
local artifact store's root directory is covered by `.gitignore` as
defense in depth, and its own default (`var/artifacts`) never overlaps
with any secret-bearing path. `zacai.policy` and `zacai.gateway` are
byte-for-byte unchanged by this decision.

Consequences:
Zac AI now has a proven, tested (against synthetic data), read-only
ingestion architecture ready to receive its first real credential once
the real-ingestion hard gate above is satisfied - that gate, not this
decision, is what still blocks ROADMAP.md Phase 3's "Add Fireflies" item
from being marked complete. Future work adding a second connector should
reuse the same `ArtifactStore` protocol, the same candidate/review
extraction pattern, and the same three-transaction ingestion-run
lifecycle rather than inventing parallel mechanisms, and must not weaken
the append-only guarantees, the "unresolved rather than guessed" identity
rule, or the classification non-weakening/elevation invariants without
its own explicit decision. Raw artifact backup/recovery remains a
named, open, blocking gap - it must be designed and drill-tested before
any real content is ever written to the artifact store.

Verification:
Confirmed `uv run pytest` (338 passed: 291 pre-existing plus 47 new -
9 artifact-store, 28 repository-level, 8 pipeline-integration, 2
extended backup/restore), a clean `uv run ruff check .`, a clean
`uv run mypy src` (16 source files), and a clean `git diff --check`.
Confirmed `alembic upgrade head` applied migration `0003` against
`zacai_dev` (0002 -> 0003) and a full downgrade/upgrade round-trip
(0003 -> 0002 -> 0003) leaves exactly the expected table set at each
step, with migrations `0001`/`0002` themselves unmodified. Confirmed the
`fk_source_supersedes_boundary` constraint has `condeferrable=t,
condeferred=t` via `psql`, and that the append-only trigger exists on
every new content-bearing table except the two deliberate mutable
exceptions. Confirmed the extended backup/restore drill against
`zacai_restore_test` (all seven new tables restored with >=1 row,
append-only trigger still active post-restore) and the reversed-row-order
Source-lineage restore, both via the real, unmodified `restore_boundary()`
pipeline. Confirmed `zacai_dev` held zero rows in all 28 application
tables both before and after this work, via a manual check outside
pytest.

Approval or source:
Zac Campbell, architecture review conversation, 2026-09-21.

Supersedes:
None. Extends D018/D028 (the real-ingestion hard gate is a direct
extension of Lane B's per-boundary encryption requirement to artifact
content, not yet satisfied), D023 (every new boundary/classification
column reuses `TrustBoundary`/`DataClassification` unchanged; `evaluate_
access`'s HIGHLY_RESTRICTED+EXTERNAL hard-deny is exercised, not
modified), D024 (entirely untouched - verified by a dedicated test),
D026 (reuses its evidence/confidence mechanism unchanged for extraction
candidates, and its classification non-weakening check is updated, not
replaced, to consult effective classification), D028 (extends
`TABLE_ORDER`/`_ORDER_BY` only, reuses its restore-target guards and
disposable-database pattern unchanged), and D029 (reuses its
`supersedes_*`/`DEFERRABLE INITIALLY DEFERRED` self-FK pattern and its
retraction-table shape for candidate review and classification
elevation).

## D031A - Encrypted Raw Artifact Backup + Restore (Cryptographic/Synthetic Foundation)
Status: Accepted
Date: 2026-09-21

Context:
D030 built a real, tested (synthetic-only) ingestion architecture whose
raw artifacts live in a `LocalFilesystemArtifactStore` that D028's Lane B
mechanism never backs up - an explicit gap that hard-blocks any real
Fireflies ingestion (D030's real-ingestion hard gate). An architecture
review designed the smallest robust extension of Lane B needed to
protect those artifacts, split deliberately into D031A (cryptographic/
procedural foundation, this decision) and D031B (a real off-device
backend and a real drill, not built here). The review also found, while
reading D030's shipped code rather than its original design sketch, that
`LocalFilesystemArtifactStore` used a flat, unpartitioned local layout
with no trust-boundary segmentation at all - corrected here, before any
real artifact data existed to migrate.

Decision:
**D031A implements the cryptographic/synthetic foundation only - it does
not lift the real-ingestion hard gate.** No real off-device backend, no
real credential/key, and no real Fireflies data are introduced.

- **`LocalFilesystemArtifactStore` is corrected to be boundary-
  partitioned**: `<root>/<trust_boundary>/<hash[:2]>/<hash>.bin`,
  replacing D030's shipped flat layout. `ArtifactStore.put`/`get` now
  require an explicit `trust_boundary` parameter; `content_location`
  itself (and `location_for`) stays boundary-agnostic, so the boundary
  is never inferred from a path string or by scanning the filesystem -
  it must always be supplied by the caller, who already holds it from
  the `Source` row's own `trust_boundary` column. There is no cross-
  boundary fallback: `get` resolves strictly within the supplied
  boundary and raises if the file isn't there, even when an identical
  `content_location` string happens to exist under a different
  boundary - a rare content-hash coincidence that the old flat layout
  would have incorrectly shared as one physical file. This was a pure
  source-code correction with nothing to migrate, since no real artifact
  ever existed under the old layout.
- **`src/zacai/backup_artifacts.py`** (new) implements: `age`-encrypted,
  content-addressed backup objects (`<boundary>/<hash[:2]>/<hash>.age`,
  one per artifact, not one continuous D028-style stream, since
  artifacts are independent immutable blobs where per-object encryption
  gives incremental backup for free); an encrypted, per-boundary
  manifest (`content_hash`, `content_location`, `backup_object_key`,
  `size_bytes`, `ciphertext_sha256`, `backed_up_at`, plus
  `manifest_version`/`boundary`/`generated_at`); a `BackupObjectStore`
  protocol with `LocalDirectoryBackupStore` as the only v1
  implementation (a second local directory - proves the cryptographic/
  procedural pipeline only, explicitly never claimed as off-device
  durability); the backup, restore, and reconciliation algorithms below.
- **Backup only ever uses the public `age` recipient** - reusing D028's
  exact three existing per-boundary identities/recipients unchanged, no
  new key system. The private identity is never read, referenced, or
  required during a backup run; only restore needs it, supplied out-of-
  band exactly like D028's `--identity` flag. No key was generated,
  rotated, exposed, or otherwise touched by this decision.
- **Backup is driven entirely by `Source` rows, never by scanning the
  filesystem.** An artifact with no `Source` reference (an orphan,
  D030) is never backed up - it cannot be assigned a trust boundary for
  encryption without guessing.
- **The "already protected" check is a strengthened, four-part
  verification**, never a bare manifest-membership test: (A) a prior
  local record exists, (B) the backup object exists, (C) its size
  matches, (D) its ciphertext SHA-256 matches. Any failure triggers
  repair - re-verify the local plaintext
  (`sha256(local_bytes) == Source.content_hash`, preserved exactly, and
  always checked before any (re-)encryption), re-encrypt, atomically
  write and finalize the new object, read it back, verify size and
  ciphertext hash, and only then update the record. No object is
  decrypted during routine incremental backup - full plaintext
  verification is reserved for restore.
- **A local, plaintext manifest cache is kept purely as a same-run-to-
  run comparison baseline for the four-part check** - a real
  architectural necessity discovered during implementation: `age`
  encryption is non-deterministic (the same plaintext re-encrypted
  produces different ciphertext each time), so *some* durable baseline
  is required to detect ciphertext corruption without decrypting; reading
  it back from the *encrypted* off-device manifest would require the
  private identity, breaking backup's public-key-only property. This
  local cache is never uploaded and is never treated as the durable
  backup representation - only the encrypted manifest object written to
  the `BackupObjectStore` is. Losing the local cache is always safe: the
  next run simply finds no baseline for each hash and re-verifies/
  re-uploads everything, which costs extra work, never correctness.
- **`artifact_backup_run`** (new table, migration `0004`) mirrors
  `ingestion_run`'s exact `STARTED -> SUCCEEDED/FAILED` lifecycle (D030)
  - a mutable, operational-audit-only table, the seventh deliberate
  exception to this schema's append-only rule. **Never authoritative for
  whether an artifact is protected** - the encrypted manifest, valid only
  after the four-part check, is the sole source of truth. A crash may
  leave a row stuck at `STARTED`; this is an accepted, honest audit gap,
  never a false "backed up" signal, since protection status is never
  read from this table. A backup run is marked `FAILED` (not
  `SUCCEEDED`) if any artifact failed, even though the manifest still
  durably protects whatever did succeed - success requires zero
  unresolved errors.
- **Restore** targets a dedicated, non-production location, guarded by
  `assert_safe_restore_target` (fails closed if the target equals the
  live `ArtifactStore` root - adapted from D027/D028's fixed-target
  guard pattern for a filesystem, not a database, target). **Two-layer
  wrong-boundary rejection**: `age -d` fails outright for a non-matching
  identity, and the decrypted manifest's own `boundary` field is
  independently checked against the boundary requested. Every restored
  artifact's plaintext hash is verified against its expected
  `content_hash` - never silently accepted on mismatch.
- **Reconciliation** computes `verified`/`missing`/`unexpected` sets
  against an independently-supplied set of expected `Source.content_hash`
  values. A restore is successful only if `missing` is empty and no
  artifact failed verification; a non-empty `unexpected` set is always
  surfaced but does not by itself force failure - a regression signal to
  investigate, not automatically fatal.
- **Two real implementation bugs were found and fixed during this
  decision's own test-writing** (not merely designed around): a
  `RestoreOutcome.successful` property referenced a non-existent
  `self.missing` attribute instead of `self.reconciliation.missing`
  (caught by `mypy --strict`); and a missing local artifact
  (`ArtifactStore.get` raising `OSError`) was not originally caught as a
  per-item failure and would have crashed an entire backup run instead
  of being recorded and skipped - fixed by introducing
  `MissingLocalArtifactError` and catching it explicitly, then proven via
  a dedicated test and via encountering the exact scenario naturally
  through accumulated synthetic test data in `zacai_test`.

Alternatives considered:
Encrypting local artifacts at rest with the same per-boundary key used
for backup was considered and rejected: it would require the private
identity to live permanently on the Mac Studio to decrypt artifacts
during normal ingestion - a strictly worse posture than today, where
private identities only ever touch the machine during an actual restore
drill. Relying on FileVault (already enabled) for local-at-rest
protection, exactly matching the precedent already accepted for the live
`zacai_dev` Postgres data directory, was adopted instead - sufficient to
satisfy the real-ingestion gate; local-at-rest artifact encryption
remains a possible, explicitly non-required future defense-in-depth
improvement. Merging D031A's artifact backup format with D028's database
export format was considered and rejected in favor of two independent
mechanisms, preserving D018's "each lane independently restorable"
principle and the different growth shapes of a relational dump versus an
incremental, content-addressed object store. Deriving the manifest fresh
each run purely from `Source` rows and backup-store state (no local
cache at all) was considered and rejected once it became clear that
`age`'s non-deterministic encryption makes ciphertext hashes unstable
across runs without a persisted baseline - the local plaintext cache
(never the durable backup) is the smallest fix that preserves both
"encrypt the manifest" and "backup never needs the private key."

Reasons and tradeoffs:
Per-object encryption (one `age`-encrypted file per artifact) trades a
larger number of small backup objects for exactly the incremental/
idempotent backup behavior this decision requires - D028's single
continuous per-boundary stream would not allow skipping unchanged
artifacts without re-deriving the whole export. Keeping a local,
plaintext manifest cache trades a small, explicitly-scoped exception to
"minimize plaintext copies" for preserving a stronger, more important
property - that routine backup never needs the private `age` identity at
all; the cache's total loss is always safe, only ever costing repeat
work. Marking a backup run `FAILED` whenever any single artifact fails,
even though the manifest still correctly protects everything that
succeeded, trades a slightly alarming-looking audit trail for an honest
one - a partially-successful run must never look identical to a fully
successful one.

Security and data implications:
No real Personal, Brainstorm, or Shared data was created by this
decision - `zacai_dev` was confirmed to hold zero rows in all 29
application tables both before and after this work. No real credential
or key material was generated, rotated, exposed, or referenced - every
`age` identity used in testing is a throwaway keypair generated fresh
per test via `age-keygen`, verified (by a dedicated test) never to appear
in any error message this module produces. Backup itself never requires,
reads, or references a private identity at any point. `zacai.policy` and
`zacai.gateway` are byte-for-byte unchanged, and a dedicated test proves
`zacai.backup_artifacts` never imports `zacai.gateway` or references
`ActionType`. `src/zacai/backup.py` and `backup_safety.py` (D028) are
unchanged - no correctness problem was found requiring a change to
either.

Consequences:
Zac AI now has a drill-tested (against synthetic data only) mechanism
for encrypting and reconciling raw ingestion artifacts, ready to receive
a real off-device backend once D031B is designed and implemented - that
future decision, not this one, is what still blocks ROADMAP.md Phase
3's "Add Fireflies" item and the real-ingestion hard gate. Future work
choosing D031B's actual backend must satisfy the same `BackupObjectStore`
protocol without modification to `backup_artifacts.py`'s backup/restore/
reconciliation logic. Future connectors' artifact backup must reuse this
mechanism rather than inventing a parallel one, and must not weaken the
four-part protection check, the two-layer boundary rejection on restore,
or the "never claim protection without full verification" invariant
without its own explicit decision.

Verification:
Confirmed `uv run pytest` (373 passed: 338 pre-existing plus 35 new - 7
boundary-partitioning/isolation tests in `test_ingestion_artifact_store.py`,
28 in the new `test_backup_artifacts.py`), a clean `uv run ruff check .`,
a clean `uv run mypy src` (17 source files), and a clean
`git diff --check`. Confirmed `alembic upgrade head` applied migration
`0004` against `zacai_dev` (0003 -> 0004) and a full downgrade/upgrade
round-trip (0004 -> 0003 -> 0004) leaves exactly the expected table set
at each step, with migrations `0001`-`0003` themselves unmodified.
Confirmed a full synthetic drill end-to-end (real `age` encryption/
decryption with throwaway keys, not a `cat` passthrough): three synthetic
artifacts backed up, encrypted, and reconciled with zero
missing/unexpected/failures; separately, a leftover artifact from
accumulated test-session state (a different test's already-vanished
`tmp_path`) was correctly caught as a per-item backup failure and
correctly flagged as `missing` during restore reconciliation - real,
unstaged evidence the failure-handling behaves correctly under messy
conditions, not just the clean-path test. Confirmed `zacai_dev` held
zero rows in all 29 application tables both before and after this work.
**This drill proves cryptographic/procedural correctness only - it used
`LocalDirectoryBackupStore` (a second local directory), never a real
off-device destination, and does not and cannot demonstrate off-device
durability. The real-ingestion hard gate remains fully in place.**

Approval or source:
Zac Campbell, architecture review conversation, 2026-09-21.

Supersedes:
None. Extends D018/D028 (implements the artifact half of Lane B's
per-boundary encryption requirement, reusing its exact key hierarchy and
its "encrypt client-side before anything leaves the device" principle,
without yet satisfying the off-device requirement itself - that is
D031B), D023 (reuses `TrustBoundary` unchanged; boundary partitioning is
enforced structurally in `ArtifactStore`, not just checked), D027/D028
(reuses their fixed-target, fail-closed restore-guard pattern, adapted
for a filesystem target), and D030 (corrects
`LocalFilesystemArtifactStore`'s local layout before any real data
existed, and reuses its `ArtifactStore` protocol, `content_hash`/
`content_location` columns, and `ingestion_run`-style mutable-audit-table
pattern unchanged).

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
