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

## D031B - Real Off-Device Artifact Backup + Restore-Drill-Verified (Gate Satisfied)
Status: Accepted
Date: 2026-09-22

Context:
D031A built and drill-tested the cryptographic/procedural artifact
backup pipeline but explicitly could not demonstrate off-device
durability - it used a second local directory as its `BackupObjectStore`
implementation. The real-ingestion hard gate (D030/D031A) requires a
real off-device backend and a real, successful restore drill against it
before any live Fireflies connection may be approved. D031B closes this
gap in two phases: Phase 1 (already committed) added
`S3CompatibleBackupObjectStore`, a single `boto3`-based implementation
satisfying any S3-compatible provider (AWS S3, Cloudflare R2, Backblaze
B2) via an `endpoint_url` override, proven hermetically against `moto`
with zero changes needed to `backup_boundary`/`restore_boundary_artifacts`.
Phase 1 also hardened `restore_boundary_artifacts` to call its restore-
target safety check internally and unconditionally (`live_artifact_root`
is now a required parameter), rather than relying on a caller to invoke
`assert_safe_restore_target` separately. This decision records Phase 2:
the real drill itself.

Decision:
**A real off-device disaster-recovery drill for the BRAINSTORM boundary
was executed against a real Backblaze B2 bucket
(`zac-ai-brainstorm-backup`, endpoint `s3.us-east-005.backblazeb2.com`),
using the existing escrowed Brainstorm `age` identity (by path only,
`/Users/brainstormzac/.config/zacai/backup-keys/brainstorm.agekey`,
never opened/read/copied) and its known public recipient (supplied
directly by Zac Campbell, never re-derived from the private identity).
The drill passed every acceptance criterion. The real-ingestion hard
gate's artifact-backup/recovery precondition is satisfied for
BRAINSTORM.**

- Four uniquely-tagged synthetic BRAINSTORM `Source` rows and realistic
  transcript-shaped artifacts (~20KB each, clearly labeled synthetic, no
  real Fireflies/customer/connector data) were created in `zacai_test`
  for the drill. `zacai_test` already held 9 unrelated BRAINSTORM rows
  from prior test-session activity (a known, accepted consequence of
  `zacai_test` being a shared, session-lifetime database) plus 4 more
  left over from a first drill attempt that crashed on an unrelated
  script bug (see below) - all correctly and safely excluded from the
  backup (`MissingLocalArtifactError`, their local files long gone) and
  never uploaded. Acceptance was scoped to the drill's own tagged digest
  set throughout, exactly as D031A/D031B's repeated shared-database
  lesson requires, while still exercising the real, unscoped
  `backup_boundary`/reconciliation algorithms end-to-end.
- The real `backup_boundary()` call achieved `failed=0` for the drill's
  own 4 artifacts (13 unrelated historical failures, all expected and
  harmless - no B2 object created for any of them).
- Off-device durability was independently verified using a **separately
  constructed** `S3CompatibleBackupObjectStore`/`boto3` client instance
  (not the one `backup_boundary` used): each of the 4 encrypted objects
  and the encrypted manifest were confirmed to exist remotely with
  matching size, and were independently retrieved and hashed.
- D028's existing, unmodified `export_boundary`/`recreate_restore_test_database`/
  `upgrade_restore_test_schema`/`restore_boundary` functions restored the
  BRAINSTORM boundary's database state into `zacai_restore_test` (never
  `zacai_dev`/`zacai_test`), confirming the drill's 4 tagged `Source`
  rows landed correctly.
- The hardened `restore_boundary_artifacts()` restored all 4 artifacts
  from **real B2** into a brand-new, previously-unused local root,
  checked against the real, resolved `Settings().artifact_store_root` as
  `live_artifact_root`. Reconciliation against the D028-restored,
  tag-scoped `Source` set: `missing=0`, `unexpected=0`, all 4 verified,
  `successful=True`. Every restored artifact's `sha256` was independently
  re-checked against `Source.content_hash` outside the library's own
  reconciliation logic.
- **Wrong-boundary identity rejection was verified against the real
  BRAINSTORM manifest using the actual existing real Personal and
  Shared `age` identities** (D028's escrowed identities, referenced only
  by their existing paths -
  `/Users/brainstormzac/.config/zacai/backup-keys/personal.agekey` and
  `.../shared.agekey` - never opened, read, copied, or logged). The
  real, currently-stored BRAINSTORM manifest object was fetched from B2
  and `age_decrypt` was attempted against it with each identity in turn:
  both the real Personal and real Shared identities were correctly
  rejected (`DecryptionError`), and the real Brainstorm identity
  correctly succeeded, decrypting a manifest whose own `boundary` field
  reads `BRAINSTORM` with 4 entries. This is a strictly stronger result
  than this decision originally recorded (a throwaway synthetic keypair
  substituted for an unknown real identity, since no real Personal/
  Shared identity path was known to the drill at that time) - the paths
  were subsequently supplied by Zac Campbell and the check was re-run
  against them directly, with no other part of the drill re-executed and
  no B2 object modified or deleted.
- The restore was proven independent of the original local artifacts,
  the local plaintext manifest cache, and any same-machine backup
  directory: the local manifest cache file was deleted before a second
  restore was run into a second fresh root from real B2 alone, which
  still succeeded identically.
- Cleanup removed only drill-local resources: `zacai_restore_test`
  (via the existing guarded `drop_restore_test_database()`), all
  temporary local directories/files, and the temporary Keychain-sourced
  environment variables. No B2 objects were or could be deleted (the B2
  application key intentionally has no delete permission) - the drill's
  synthetic encrypted objects and manifest remain in the dedicated
  Brainstorm backup bucket, as expected and accepted.
- **One drill-script bug was found and fixed during execution** (not a
  bug in shipped library code): the drill script's first attempt placed
  the local plaintext manifest cache file directly under the shared OS
  temp root via `tempfile.mkstemp`, and `_save_local_manifest_cache`
  correctly (by design) attempts to `chmod` its containing directory to
  `0700` - which failed with `PermissionError` against a directory the
  script did not own. Fixed by giving the cache file (and the DB export
  artifact) their own dedicated, script-owned temp directories. No
  `zacai.backup_artifacts` code changed as a result; `age_encrypt`/
  `_verify_or_repair` had already run to completion for the drill's own
  4 artifacts before the crash, so real B2 uploads for that first
  attempt's tag likely already succeeded (content-addressed and
  overwrite-idempotent, so re-running under a new tag was always safe;
  its now-orphaned 4 `Source` rows remain in `zacai_test` as additional,
  harmless historical pollution, already accounted for above).

Alternatives considered:
Using `run_artifact_backup()` (the audit-wrapping function) instead of
calling `backup_boundary()` directly was considered and rejected for
this drill: `run_artifact_backup()` marks the entire `artifact_backup_run`
`FAILED` if any single artifact fails, which would have conflated the
drill's own unambiguous success with the expected, harmless failures of
13 unrelated historical rows with long-vanished local files - calling
`backup_boundary()` directly and scoping acceptance to the drill's own
tagged digests exercises the identical underlying algorithm without that
conflation. Guessing or inferring a path to an existing real Personal/
Shared identity (e.g. a sibling filename in the same directory as the
Brainstorm identity) was considered and rejected at the time the drill
first ran, in favor of a throwaway synthetic keypair, per the standing
instruction to stop and report rather than exceed what has been
authorized - the real paths were not guessed; they were subsequently
supplied explicitly by Zac Campbell in a follow-up instruction, at which
point the stronger real-identity check (recorded above) was run instead.

Reasons and tradeoffs:
Verifying off-device durability with a separately constructed client,
rather than trusting `backup_boundary`'s own upload call, trades a small
amount of duplicated network I/O for a materially stronger claim - the
whole point of a disaster-recovery drill is to not merely assume the
happy path held. Scoping every acceptance check to the drill's own
uniquely-tagged digest set, rather than asserting on `zacai_test`'s raw
aggregate state, is the same lesson this project has learned and
re-applied repeatedly (D031A's own test suite, D031B Phase 1's tests,
and now this real drill) - a shared, session-lifetime test database
makes unscoped aggregate assertions inherently fragile and is not itself
a defect to fix.

Security and data implications:
No real Personal, Brainstorm, or Shared data was created, read, or
transmitted - all drill content is clearly-labeled synthetic transcript
text. `zacai_dev` was confirmed to hold zero rows in all application
tables both before and after the drill. The real B2 credentials were
loaded from macOS Keychain into environment variables within a single
process, never printed or logged, and unset immediately after use in
the same shell invocation; they were never written to any file. The
private Brainstorm `age` identity was referenced only by its existing
path, passed only to the `age` subprocess; it was never opened, read,
copied, or logged, and its filesystem metadata (mode `0600`, size 189
bytes) was confirmed unchanged after the drill. No second copy of any
real private identity was created. `zacai.policy`, `zacai.gateway`, and
D028's `backup.py`/`backup_safety.py` are confirmed unchanged. No B2
object was or could be deleted, by design (the application key has no
delete permission) - this is an accepted, intentional asymmetry, not a
gap.

Consequences:
**The real-ingestion hard gate's artifact-backup/recovery precondition
is now satisfied for the BRAINSTORM trust boundary.** This does not
itself connect, authorize, or approve any live Fireflies account or any
other real connector - ROADMAP.md Phase 3's "Add Fireflies" item still
requires its own separate approval before any real credential, network
call, or content ingestion occurs. Future connectors ingesting into
other trust boundaries (PERSONAL, SHARED) must run and pass their own
equivalent real off-device drill before their own real-ingestion gates
can be considered satisfied - this decision satisfies BRAINSTORM only.

Verification:
Confirmed the real drill's 18-point acceptance criteria in full (B2
upload/verification, D028 DB restore, artifact restore, hash
verification, reconciliation, wrong-identity rejection, independence
from local state, cleanup, `zacai_dev` before/after counts). Confirmed
`uv run pytest -q` (395 passed), a clean `uv run ruff check .`, a clean
`uv run mypy src`, and a clean `git diff --check`, run immediately after
the drill with no code changes made as a result of it.

Approval or source:
Zac Campbell, real off-device disaster-recovery drill approval and
Brainstorm public recipient/Keychain item names, 2026-09-22; and a
follow-up instruction the same day supplying the real Personal/Shared
identity paths for the stronger wrong-boundary verification recorded
above.

Supersedes:
None. Completes D031A's deferred off-device requirement; extends D018/
D027/D028/D030/D031A unchanged.

## D032 - Core Intelligence Contracts (Synthetic v1)
Status: Accepted; implemented and independently reviewed
Date: 2026-10-02

Context:
D031B is the completed BRAINSTORM artifact-recovery checkpoint. Zac's
continuation instruction places Core Intelligence Contracts before the first
controlled read-only Fireflies connection. No prior D032 specification exists
in the repository or the resumed Claude engineering conversation. Zac explicitly
authorized developing this design from the existing architecture and proceeding
with local implementation. Architecture sections 3, 5, 10, 13 and 18 establish
canonical state, event metadata, centralized approvals, replaceable intelligence
and independent evaluation. This slice formalizes those interfaces without
implementing all later roadmap phases.

Decision:
- Add `src/zacai/intelligence/` with frozen, validated Pydantic contracts and
  integer version 1 envelopes for `ZacEvent`, `IntelligenceTask` and
  `IntelligenceResult`. Unknown fields/versions, naive timestamps, non-finite
  numbers, invalid limits, mixed-boundary references and weakened derived
  classification fail validation. Public assessment/result boundaries revalidate
  even existing model objects; unvalidated `model_copy` output is not trusted.
- `ZacEvent` is the single canonical in-memory event envelope: UUID identity,
  producer/type, UTC occurrence/observation timestamps, exact trust boundary,
  classification, source/hash provenance, related entity/version references,
  correlation/causation IDs, importance, confidence and processing status. v1
  covers content-addressed, source-backed events. It is not the deferred Event
  database entity, an event transport, an event log or a new canonical store.
- `EvidenceReference` carries `Source.id`, its immutable content hash, exact
  boundary and effective classification. `resolve_evidence_reference` reads via
  an additive boundary-filtered `state_repository.get_source` and the existing
  `get_effective_source_classification`; it never substitutes the original
  `Source.data_classification` for the classification-elevation mechanism.
  Unknown/unauthorized sources give an indistinguishable error. Old evidence
  snapshots are historical declarations; a future dispatcher must re-resolve
  current labels and verify artifacts immediately before sending content.
- Tasks carry explicitly untrusted context, required capabilities, instruction
  text, latency/estimated-cost/output limits and source-backed event metadata.
  Context references must exactly match event provenance. Authorization,
  credentials, runtime approval and security configuration are not task fields.
- Provider, model and runtime identities are separate. `ModelRoute` declares
  destination, capabilities, capacity, availability and cost/latency estimates;
  provider names never establish locality. `IntelligenceProvider` is a replaceable
  typed Protocol. No live adapter, credential loader or dispatcher is shipped.
- `ApprovedRouteRegistry` is an immutable host configuration object, separate
  from JSON contracts and with no JSON loader. Each registration binds a model/
  provider/runtime descriptor, its destination, permitted boundaries and
  permitted classifications. Only trusted host configuration may construct it.
  This is not a sandbox against hostile Python code or a runtime approval UI.
- `assess_routes` evaluates only registered routes against independent host
  authorization, per-route approvals and existing `evaluate_access`, plus
  capabilities, availability, input/output capacity, estimated cost and latency.
  It returns explicit exclusions; no eligible route is a terminal report.
  It does not rank, dispatch, retry, silently register providers or relax privacy
  on fallback. Text capacity is explicitly measured in characters and includes
  instruction/context text; serialized request overhead and token capacity must
  be checked by future adapters. Estimates are not measured costs or guaranteed
  latency, nor an enforceable spending cap or timeout.
- Results distinguish success/failure, findings/candidates, usage observations
  and execution proposals. Failure cannot carry partial proposals; errors use
  bounded typed codes rather than arbitrary exception text. Boundary validation
  checks task/route linkage, source IDs against supplied context, non-weakening
  classification and reported output limits. Source citation alone does not prove
  factual support; independent evaluation and human promotion remain required.
  Result linkage validation is not routing approval: a future dispatcher must
  dispatch/accept only routes present in its current EligibilityReport.eligible_routes.
  Entity references are declarations only; existence/boundary/version resolution
  remains future host work and is not established by contract validation.
- Execution proposals carry action type, target reference, description and
  evidence only. They cannot execute, approve, acquire credentials or modify
  state. Future execution must pass the central D023/D024 policy/gateway and a
  separately designed, action-bound approval mechanism.
- D030's `ExtractionFunction`/`CandidateProposal`, idempotency, transactional
  candidate recording and human promotion remain unchanged. These contracts are
  a general foundation for later capabilities; D032 does not yet rewire D030.

Alternatives considered:
A provider-specific agent framework, autonomous execution engine or full Phase 5
router was rejected as premature. Arbitrary mutable payload dictionaries were
rejected because they obscure validation and allow authority-bearing escape
hatches. Caller-supplied provider candidates or permissions inside task JSON were
rejected in favor of a separate host registry. A persistent Event table/event bus
was rejected: their storage/transport decisions remain deferred. Live model or
Fireflies calls were rejected for this slice; synthetic adapters suffice to test
contract interchangeability. Separate permanent design docs were rejected in
favor of this existing decision log and ROADMAP.md.

Reasons and tradeoffs:
Explicit contracts separate intelligence from state ownership and action
execution while preserving future provider/runtime replacement. Pydantic matches
the existing policy/gateway request convention. Immutable host registry objects
keep approval configuration outside retrieved content; they rely on trusted host
code rather than claiming cryptographic authority or sandboxing. v1's required
content hashes and exact single boundary intentionally limit supported events;
future operational/hashless or cross-boundary workflows need a deliberate
extension. Classification ordering matches existing state rules; access denial
semantics remain exclusively in `evaluate_access`.

Security and data implications:
Only synthetic fixtures are used. No real transcript, external model call,
Fireflies request, credential, bucket write, canonical-state promotion, proposed
action execution, schema migration, service restart or production configuration
change occurs. New database tests use D027's rollback `db_session`. D023 policy,
D024 gateway and D030 ingestion/extraction are unchanged. PERSONAL/SHARED live
recovery gates remain unsatisfied by D031B's BRAINSTORM-only drill.

Consequences:
A tested contract foundation is available before live ingestion. This does not
complete Phase 2's entire entity/memory model, Phase 5 production routing,
Phase 6 approvals or Phase 7 agents. Fireflies remains a separately scoped and
explicitly approved next milestone. Runtime credential loading/escrow, production
operations and complete recovery scheduling still require their own verification.

Verification:
Final implementation: 639 tests passed (395 existing plus 244 D032 cases),
Ruff clean, strict mypy clean across 22 source files, and git diff --check clean.
The new cases include the full 192-case boundary/authorization/classification/
destination matrix, restricted-data fallback rejection, hostile JSON validation,
canonical classification elevation and two interchangeable synthetic adapters.
Claude's independent design review identified canonical effective-classification
resolution and an explicit host registry as required corrections; both are
implemented. Claude reviewed the implementation in a fork of the existing
Zac AI engineering session and reported no blocking findings. Its non-blocking
notes on unresolved entity references and result validation versus route approval
are documented, and empty-boundary source access is explicitly tested. Staged
Gitleaks secret scan is clean. No production deployment or live access occurred.

Approval or source:
Zac Campbell, 2026-10-02: continue the existing build, retain Claude as independent
reviewer, and develop D032 from the existing architecture. This authorizes the
local design/implementation/test slice; it does not authorize live Fireflies,
production deployment, new credentials or expanded autonomy.

Supersedes:
None. Extends D001/D004/D008/D023/D024/D026/D030; preserves D031B and all
existing roadmap phases. Updates immediate sequencing to D032 before Fireflies.

## D032A - Provider-Neutral Connector Event Capability (Design Follow-Up)
Status: Accepted design direction; not implemented or live-enabled
Date: 2026-10-06

Context:
The owner supplied the MCP Events development and asked whether it belongs in
Caz AI. Official OpenAI documentation confirms webhook subscriptions in supported
ChatGPT Work/cloud and dot surfaces, using a draft protocol with delivery-control
limitations. This availability does not connect the local Caz host or any account.
The existing D032 ZacEvent v1 is a Source-backed declaration, not an event bus.

Decision:
- Preserve canonical Zac State, ZacEvent v1 and the existing roadmap order. Add
  an optional companion event capability to read connectors when first needed:
  discovery, authorized subscribe/refresh/unsubscribe, scoped external delivery
  ingestion, and polling/reconciliation fallback. These are design responsibilities,
  not new callable interfaces or a live service in this checkpoint.
- Route external delivery through authenticated, boundary-scoped ingress and the
  existing permitted Source/artifact pipeline before constructing a Source-backed
  ZacEvent. Policy/router/workflow admission remains outside connectors/agents.
  Signed delivery verifies transport origin, not current fact, model permission,
  owner approval, source access or execution authority. Re-resolve current rights.
- Keep durable subscription ownership/filter/status/expiry/revocation and sync
  cursors separate from canonical business memory and credentials. Gateway owns
  signing secrets and tokens. Namespace delivery IDs by provider/account/boundary,
  preserve IDs across retries, and distinguish external occurrence from host
  observation. Deduplicate and accept that delivery can be unordered or missed.
  Reconciliation uses authorized source reads and advances cursors only after
  accepted durable ingestion; define restart, retry, truncation and loop controls.
- MCP Events, native webhooks and provider push are replaceable transports. Poll
  or reconcile when delivery, replay or subscription health is incomplete. No
  protocol-wide perfect delivery or cost/latency improvement is assumed.
- Implement and measure with a needed connector after current protected context
  intake/recovery gates. Cover invalid signature, revoked access, duplicate/out-of-
  order deliveries, restart/expiry/gaps, PERSONAL/BRAINSTORM isolation and retries
  before live adoption. No public endpoint, cloud/private-data transfer, new
  credentials, subscription or account scope is authorized by this design note.

Sources and limits:
Verified 2026-10-06: [OpenAI MCP Events](https://developers.openai.com/plugins/build/mcp-events).
OpenAI currently supports webhook delivery from the draft; its integration does
not support polling, streaming, gap or terminated control notifications. Caz's
polling fallback would be owned by its connector host, independent of that feature.
Completed D032 remains unchanged. This extends Phase 3, not a competing milestone
sequence or claim that Caz has a production event bus.

## D033A - Selected Fireflies Transcript Wire Preparation (Offline Only)
Status: Accepted; offline implementation independently reviewed
Date: 2026-10-02

Context:
After D032, Zac selected one Brainstorm work meeting and confirmed it belongs to
his Fireflies account. The meeting identifier and link remain in the operator
conversation, not committed configuration. Selection establishes proposed scope,
not approval to obtain credentials, fetch real content or persist it. Official
Fireflies schemas differ from D030's fixtures: `dateString` is timezone-aware,
`participants` is a list of emails, `meeting_attendees` provides explicit names
and emails, and `sentences` supplies indexed speaker text. D030's normalized
artifact cannot by itself preserve the real response's observed source privacy.

Decision:
Add `zacai.connectors.fireflies_wire`, a pure offline adapter with a fixed
`transcript(id: $transcriptId)` query and variable-only ID binding. It requests
selected transcript text, explicit attendees, observed privacy, recording-owner
metadata and completion state; no account listing, mutation, audio/video or
model-generated summaries. Reply processing rejects GraphQL errors even with
partial data, unavailable/wrong transcript IDs, live/unfinished meetings, unknown
privacy values, naive timestamps, duplicate JSON fields/sentence indices,
invalid schema and responses over 2 MB. Failure messages are sanitized.

The prepared result retains exact original response bytes and their SHA-256,
plus a frozen typed representation. Its repr omits transcript/response content.
A separate D030-compatible normalized view orders sentences and maps only
explicitly named attendees; speaker names are never guessed into attendee email
identities. Unresolved metadata remains in the original response. No network,
credential, database or artifact write occurs. D030 is not rewired.

Alternatives considered:
Feeding a real response directly into the synthetic D030 parser was rejected as
schema-incompatible. Discarding the original reply after normalizing text was
rejected because it loses observed source metadata and exact-byte provenance.
A generic GraphQL client/account-wide sync was rejected as excessive first-trial
scope. Wiring live transport or production credentials before separately reviewed
host authorization/storage controls was rejected.

Security and data implications:
Only synthetic fixtures are exercised. Observed privacy and recording-owner
metadata are snapshots, not complete source ACLs or authentication of the API-key
owner. A future trusted host must bind the selected ID to human-approved scope,
verify account identity, enforce read-only requests and prevent credential leaks.
Original response bytes require their own canonical Source/provenance reference
and encrypted backup coverage; ingesting the normalized view alone is explicitly
insufficient. Live orchestration must verify all those prerequisites before use.
There is no shipped transport, live CLI, Keychain loader or live fetch in D033A.

Consequences:
The real-wire mapping is tested before real content is introduced. This does not
mark Phase 3 Add Fireflies or source-permission preservation complete. Next is a
bounded live-host design covering approval, credential handling/escrow, identity,
raw+normalized provenance and backup, followed by explicit live-access approval.

Verification:
667 tests pass (639 existing plus 28 new synthetic wire cases), Ruff and strict
mypy are clean across 24 source files, and git diff --check is clean. Claude
independently reviewed this slice and found no safety blocker. Its diagnostic
issue (specific sanitized failures caught by the generic ValueError handler) is
fixed and tested. Its numeric-overflow caveat is addressed with a finite JSON
float parser. Source processing readiness remains unverified live: is_live=false
plus nonblank sentences is a conservative snapshot check, not a claim that all
Fireflies processing is complete. Staged gitleaks secret scan is clean.

Approval or source:
Zac Campbell's continuation instruction and selection of a single account-owned
meeting, 2026-10-02. No live-content/credential authorization is inferred.
Official sources checked 2026-10-02:
- https://docs.fireflies.ai/graphql-api/query/transcript
- https://docs.fireflies.ai/schema/transcript
- https://docs.fireflies.ai/schema/meeting-attendee
- https://docs.fireflies.ai/schema/sentence
- https://docs.fireflies.ai/graphql-api/query/user

Supersedes:
None. Extends D030/D032 and preserves D031B's BRAINSTORM-only recovery gate.

## D033B - Account Identity and Linked Capture (Offline Only)
Status: Accepted; offline implementation independently reviewed
Date: 2026-10-02

Context:
Zac supplied the expected Fireflies login identity and asked to continue. No
credential or live content access is authorized yet. D033A retains exact replies
but D030 cannot preserve real-wire privacy/owner metadata through normalization.
The next live host therefore needs an account check and a provenance-preserving
capture path before its transport/credential/approval wiring is enabled.

Decision:
- Add a fixed `user { user_id email }` query, with no caller-selected user ID.
  Official Fireflies documentation states that omitting the ID returns the API
  key owner. The offline parser compares that identity to host-supplied expected
  email (ASCII case-insensitive; malformed/whitespace identities fail closed).
  It uses D033A's shared bounded strict GraphQL envelope parser. This is fixture
  validation, not evidence that any live credential has been authenticated.
- Add `capture_selected_transcript`, a single-writer, BRAINSTORM-only storage
  helper. Independent local access policy, aware capture timestamp, selected ID,
  expected account email and exact recording-owner ID/email must match before
  artifact writes. Host-supplied scope values never come from transcript text.
  Matching declarations do not issue approval or grant live-access authority.
- Persist three hash-verified artifacts and immutable Source rows: exact account
  reply, exact transcript reply, and a versioned normalized envelope containing
  both Source IDs/hashes and the D030-shaped payload. Each representation has its
  own external-reference namespace, preventing normalization from superseding
  the raw reply. Source capture time records observation; meeting occurrence time
  remains the source's actual meeting timestamp. D030's synthetic pipeline used
  the meeting timestamp for Source.captured_at; it remains unchanged, so consumers
  must not infer meeting occurrence from every Source.captured_at. Excerpts omit
  content.
- Link the raw and normalized Sources to an immutable Meeting as TRANSCRIPT
  evidence. Role alone cannot distinguish the two; Source.external_ref's typed
  namespace and the normalized envelope do. No enum/schema migration is added.
  Unlike D030's exact-email matching, all attendees remain unresolved in this
  first-trial helper; identity matching is a separate later workflow.
  The account Source is explicitly referenced by the normalized
  envelope, not mislabeled as meeting text. Keep every explicit attendee record
  as an unresolved reference, including email-only records. No inferred identity
  links, canonical Person merges or extraction/promotion occurs.
- Identical captures return the existing Meeting; changed raw privacy/content
  creates linked source revisions and a new immutable Meeting observation.
  These are source observations, not a completed cross-revision meeting identity
  resolver. Existing retracted meetings are not revived. Existing effective
  source/lineage and meeting labels must exactly match requested classification;
  any relabeling requires a separate review, so neither replay nor changed content
  silently weakens an elevated source.
- Artifact writes precede corresponding Source rows and are read back/hash
  checked. A DB savepoint rolls back partial capture rows even if a caller catches
  the error; callers own final transaction commit/rollback. Savepoint entry may
  flush a caller's pending unrelated rows, so live orchestration must use a fresh
  dedicated session. D030 orphan artifacts remain an accepted failure mode; no
  automatic deletion occurs. Normalized artifacts orphaned after rollback can
  cite rolled-back source UUIDs and must never be treated as canonical evidence.
- All three Source artifacts enter D031's existing boundary backup inventory.
  This establishes inventory coverage, not a completed backup or live restore
  drill for these captures. No backup upload is executed by this helper.

Security and data implications:
All tests use synthetic identities/content and the isolated `zacai_test` database.
No credentials, Keychain item, API call, transcript fetch, external model,
production database, service restart or production configuration is introduced.
No runtime CLI, network transport or approval implementation is shipped. This
module trusts approved host configuration and ordinary Python code; it is not a
sandbox against malicious Python callers. The selected private meeting identifier
and supplied login email remain in the operator conversation, not fixtures/config.

Live-host acceptance criteria (still pending):
Before loading credentials or sending either query, the trusted Mac Studio host
must record separately approved exact account/meeting scope, classification and
bounded one-run lifetime; permit no agent-controlled override or scheduler.
Credential setup must follow SECRETS.md, Keychain startup environment injection,
D017 boundary checking and Lane C escrow/recovery verification. Transport must
use fixed HTTPS `api.fireflies.ai/graphql`, reject redirects/proxy credential
forwarding, bound time/bytes and sanitize errors, with no listing/mutation/retry
expansion. It must verify the API-key owner before the selected meeting query,
confirm source processing/privacy observations, record durable run success/failure
without source text/secrets, commit canonical capture, then verify encrypted
state/artifact backup coverage before declaring trial success. Source ACLs remain
an observed privacy snapshot; full ACL enforcement and continuing synchronization
remain unresolved. No external model analysis is part of this first trial.

Alternatives considered:
Passing normalized text alone to D030 was rejected because it loses metadata.
Treating `transcript.user` as authentication was rejected: the key-owner identity
must be queried separately. Adding a general approval/token framework, replacing
D023/D024, creating a new Event store or altering production runtime was rejected
as premature. Broad account sync and implicit classification changes are rejected.

Verification:
699 tests pass (667 existing plus 32 new synthetic identity/capture cases),
Ruff and strict mypy are clean across 26 source files, and git diff --check is
clean. Claude independently reviewed the implementation and the final corrections
in the existing engineering-review session and reported no remaining blockers.
Its timestamp/role/artifact-ordering observations are documented; meeting time
is consistently normalized to UTC. Tests verify scope mismatch before writes,
idempotency, privacy revision lineage, effective classification protection,
retraction protection, all-three-artifact backup inventory coverage, rollback and
retry after DB/artifact failures, and sanitized errors. Staged Gitleaks is clean.
No live readiness, credential authentication or actual backup upload is claimed.

Approval or source:
Zac Campbell's instruction to continue local development and explicit contextual
confirmation of BRAINSTORM / CONFIDENTIAL, local source storage, encrypted
Brainstorm backup and no external model processing, 2026-10-02. This confirms the
trial data-handling choice; credential setup/live access still needs separate
bounded approval. No actual meeting content is stored in this development slice.
Official account-query source checked: https://docs.fireflies.ai/graphql-api/query/user

Supersedes:
None. Extends D033A/D030/D031 and preserves the existing roadmap and security gates.

## D033C - Scoped Operator Trial Host and Verified Recovery
Status: Accepted; local implementation independently reviewed
Date: 2026-10-02

Context:
Zac asked to continue after D033A/D033B and pushed those checkpoints. He explicitly
confirmed BRAINSTORM / CONFIDENTIAL, local capture, encrypted backup and no external
model processing. He also selected the existing Brainstorm B2 bucket as the
Lane B state-export destination, with a separate encrypted state prefix; this
selects a design, not a live-upload authorization. Credential setup/escrow and
live-source access still require separate bounded approval.

Decision:
- Add a narrow trusted-operator library host, not a public agent/HTTP tool, daemon
  or general Phase 6 approval UI. Persist a frozen versioned trial scope as a
  content-addressed USER_INSTRUCTION Source in BRAINSTORM/CONFIDENTIAL: UUID,
  exact expected email/meeting ID, human approval reference, explicit recovery
  evidence references and aware timestamps with at most a 15-minute admission
  window. No caller approval boolean or cross-boundary/classification override.
  Scope issuance records a human decision already made; it cannot authenticate a
  chat or perform password-manager verification. Trusted operator code alone may
  issue it after those checks. No actual approval has been issued in development.
- Serialize issuance with a PostgreSQL transaction advisory lock per scope UUID;
  identical issuance is idempotent, while revision under that UUID is rejected.
  Claim by locking the immutable Source row, verifying type/namespace/hash and
  canonical effective classification, checking for any prior matching run, then
  inserting STARTED and committing in that same transaction. Two simultaneous
  claimants are tested using real database connections; exactly one succeeds.
- Existing D023/D024 READ_DATA policy/gateway must allow the local capture.
  No hard denial is overridden. Recheck time and current effective approval
  classification before credential lookup, identity query, transcript query and
  capture. Approval expiry is an admission check, not forcible cancellation of
  in-flight I/O. Failed, crashed or expired-after-claim runs consume their grant;
  retries require a new human approval, not an automatic fallback.
- Read only the fixed macOS Keychain service
  `zacai-brainstorm-fireflies-api-key` for the approved account after claim and
  backup preflight. Fixed security binary/arguments contain no credential value;
  stdout stays in memory, stderr is suppressed and lookup failures are sanitized.
  Feed D017 get_secret through a short-lived startup environment mapping without
  modifying global os.environ. No Keychain creation/modification or escrow export
  is automated. SecretStr hides credential representations; Python memory is not
  claimed to be securely erased.
- Fixed direct TLS HTTPS reads go only to api.fireflies.ai/graphql, with normal
  certificate/hostname validation, HTTP/1.1 ALPN, no proxies/redirects/retries,
  no caller query/URL, no listing/mutation/audio/video/summary. Validate credential
  header characters before connecting; reject non-200 replies, unexpected media
  type/content encoding, and responses over 2 MB. A 20-second socket-operation
  timeout is not a hard total deadline or DNS/trickle-data cancellation guarantee.
  HTTP debug logging must stay disabled; no runtime entrypoint exposes debug mode.
- Verify the key-owner identity before requesting the selected transcript. Capture
  through D033B in a dedicated session; commit evidence before marking ingestion
  success. A later backup failure marks the run FAILED, preserving already
  committed sources/meeting and counts. Failures use fixed stage-specific sanitized audit codes;
  audit-write failure is explicitly reported. A crash can leave STARTED; no replay
  is allowed under that approval. No scheduler or external model is invoked.
- A required BackupProtector performs real preflight/protection, not a success
  boolean. BrainstormTrialProtector requires the same engine as the capture
  session factory and separately constructed write/verification object clients.
  Match operator recovery references and prove recipient/identity pairing via
  an age challenge. References remain operator attestations, not automatic proof
  of credential escrow or off-device durability.
- Run D031's full BRAINSTORM artifact backup inventory and require success.
  Independently fetch/decrypt/hash-check the four approval/account/raw/normalized
  artifacts. Export committed canonical BRAINSTORM state via D028 framing under
  REPEATABLE READ, encrypt in memory, upload to
  BRAINSTORM/state/<run-UUID>/<ciphertext-SHA256>.age, and independently fetch,
  compare ciphertext and decrypted-export hashes. Snapshot bytes are capped at
  64 MB; D028 may allocate an individual table before that buffer check, so this
  is not a process-wide memory cap. No plaintext export file is written.
- Return trial success only after protection evidence binds the current approval,
  run and all four committed source hashes. The host checks evidence linkage;
  actual ciphertext/cleartext verification occurs inside the concrete protector.
  State snapshot includes committed capture and its ingestion success audit.
  If later verification fails, canonical audit is FAILED; a previously uploaded
  snapshot may still contain the prior success state. Recovery operators must
  reconcile the latest run status rather than treating an old snapshot as a
  fresh trial-success receipt. State exports are immutable run-addressed objects,
  no automatic "latest" pointer or retention/deletion policy is introduced.

Alternatives considered:
No schema migration is needed for this narrow ledger because the Source lock
serializes claim plus run insertion, empirically concurrency-tested. A general
approval-token framework, agent issuance endpoint and parallel canonical store
were rejected as scope expansion. A new backup provider/bucket was rejected in
favor of Zac's selected existing B2 destination. Upload-only success and trusting
self-reported backup hashes were rejected in favor of independent remote reads
and authenticated decryption. Automatic retries would widen a one-attempt grant.

Security and data implications:
The host/transport/protector APIs are trusted Python seams, not defenses against
malicious Python code, DB administrators or compromised operator accounts. No
new service, CLI, agent capability or production configuration is installed.
Tests mock Keychain/HTTP, use isolated zacai_test, temporary age identities and
local object stores. No real credential, Fireflies request/transcript, B2 upload,
production database or real backup identity is accessed. Tests with local stores
prove behavior/crypto, not real off-device durability. Selected private meeting
ID/email remain outside committed fixtures. D031B's real recovery evidence stands.

Remaining live gates:
Obtain explicit scoped human approval covering account/meeting, Keychain lookup,
read-only queries, local CONFIDENTIAL capture and encrypted state/artifact uploads
into the selected existing Brainstorm B2 bucket; acknowledge consumed-on-attempt
retry behavior. Populate/escrow/recover the first required Fireflies credential
using SECRETS.md/Lane C, outside agents. Review actual host wiring: local database,
artifact root, public recipient/private identity, scoped B2 credentials and two
independent S3 clients. Confirm existing BRAINSTORM inventory is readable and all
source privacy/processing observations are appropriate. An operator launch/runbook
and real drill remain pending; no live-ready claim follows from tests alone.
Complete ACL preservation, recurring sync and external intelligence are deferred.

Verification:
741 tests pass (699 prior tests plus 42 new host/transport/protection cases),
Ruff and strict mypy are clean across 29 source files. Claude reviewed the design,
host implementation and concrete backup verifier independently and reported no
remaining blockers. The design's claim-race concern is resolved by same-transaction
locking and a real two-connection test. Crypto tests use throwaway age keys and
independent local stores; corrupt state readback, wrong identity, capacity limits,
expiry, mid-run classification elevation, replay, immutable scope and sanitized
failure audit paths are exercised. Tests remain synthetic, not a live drill.
Staged Gitleaks and git diff --check are clean. No live access is authorized.

Approval or source:
Zac Campbell, 2026-10-02: continued local build, contextual CONFIDENTIAL trial
choice, and explicit selection of the existing Brainstorm B2 bucket for encrypted
state backups. No live credential/access/upload authorization is inferred.
Official references: https://docs.python.org/3/library/http.client.html and
https://docs.fireflies.ai/fundamentals/authorization.

Supersedes:
None. Extends D017/D023/D024/D028/D031/D033A/D033B. Selects the previously open
BRAINSTORM Lane B off-device destination; PERSONAL/SHARED are unchanged.

### D033C operator verification — 2026-10-02

This records operational evidence after the offline implementation above;
it does not replace D033C's architecture or authorize broader access.

Zac explicitly approved the account-owned selected meeting as BRAINSTORM /
CONFIDENTIAL, local capture and encrypted state/artifact protection in the
existing Brainstorm B2 bucket, with no external AI processing. He confirmed
"saved and recovered" for the Fireflies credential in a 1Password Secure Note.
The Mac Keychain item was populated privately by the human; no credential value
was printed, committed, or passed as command-line key material.

The first approval was consumed and the run recorded FAILED at CREDENTIAL,
before any Fireflies request. The login Keychain was unlocked and the named
item existed, but background retrieval did not complete within ten seconds;
Zac reported no prompt appeared. No unsupported root-cause claim is made.
Zac then performed a visible Terminal lookup with stdout discarded and selected
Always Allow. This was a human Keychain access decision, not an agent ACL change.
He separately replied "approve retry" before a new approval Source and run
were created. The launcher's conversation reference retains the original scoped
approval reference; this entry records the fresh retry authorization explicitly.
No automatic retry or reuse of the first consumed approval occurred.

The second run SUCCEEDED: the account matched the approved owner, the fixed
selected transcript was captured, and one Meeting with linked original and
normalized evidence was committed. Local reconciliation found five Sources,
all BRAINSTORM / CONFIDENTIAL and all matching their artifact content hashes.
These comprise both approval records plus account reply, original transcript
and normalized envelope. The artifact backup audit recorded checked=5,
backed_up=5, failed=0. The concrete protector independently retrieved, decrypted
and hash-verified the successful run's four approval/evidence artifacts from
real B2 and independently verified the encrypted state snapshot's ciphertext
hash and decrypted plaintext equality. The state snapshot uses D028 framing
and a repeatable-read export of the same canonical database.

Before the current artifact manifest changed, the existing D031B encrypted
manifest was copied to the BRAINSTORM manifest-history prefix and independently
read back byte-for-byte. Existing drill objects were not deleted. The ignored
local trial receipt retains run IDs, remote object references and ciphertext
hash; no meeting content, private account/meeting identifiers or credentials
are included in this Git documentation.

Limits: this proves one controlled read-only capture and off-device encrypted
byte recovery, not a full database restore of the real snapshot, whole-Mac
recovery, broader source ACL preservation, recurring access or production model
routing. No Decision/Commitment extraction or promotion, external model call,
identity merging, scheduler or retention/deletion policy was enabled. The
next slice must preserve the existing Phase 3 order and determine Zac's useful
review output and permitted local processing before analyzing real content.

## D034 - Context-Aware Compact Meeting Review (Offline Foundation)

Date: 2026-10-02
Status: Implemented offline; live analysis and model/runtime selection pending

Context and decision:
Zac requested a short meeting summary that connects to the surrounding work,
followed by decisions and commitments, then risks and follow-ups. Output should
use concise, plain conversational language rather than long generic AI prose.
At his explicit request, a bounded ten-message sample of his sent mail was read
through the already connected Brainstorm Gmail account to establish a provisional
style baseline. Only his authored portions informed the baseline; quoted replies,
forwards and signatures are not style examples. The sample includes short replies
and longer formal messages; his explicit preference for brevity takes priority.
No email contents, addresses, message IDs or client facts enter Git or fixtures.
This read does not install a Gmail connector or ingest mail into canonical state.

The new vendor-neutral review proposal uses the unchanged D032 IntelligenceTask
and host-selected evidence roles. Every claim must quote the current meeting;
a claimed connection additionally requires a quote from host-supplied related
context. Exact character spans must match supplied context text. Unsupported
connection claims are rejected, and absence of an established connection is
shown explicitly. Source quotes remain in the structured proposal for future
on-demand evidence display instead of crowding the default preview.

The preview orders contextual summary, decisions/commitments, risks/follow-ups.
Initial display limits are 60 words for summary plus connection and 180 words
for the total preview, including owner/date labels, plus a 1,400-character cap
against oversized unbroken strings. The preview is visibly labeled Draft review.
Over-budget proposals fail
rather than silently discarding issues. Inferences are visibly marked Possible;
owner/date labels remain proposed and unknown action owners remain unconfirmed.
These are draft display labels, not canonical identity resolution or facts.

Security, limitations and scope:
The host must independently resolve authorized canonical evidence, verify current
effective classifications and content hashes, and supply relevant context.
Quote presence is structural evidence, not proof of semantic entailment, prior
chronology, agreement, identity, completeness or accurate prose. An evaluator
and human review remain necessary. Frozen declarations and quote checks do not
sandbox malicious Python hosts or neutralize prompt injection in a future model.
The renderer returns untrusted plain text; a future UI must escape it and expose
supporting quotes. No provider, local inference service, live analysis, retrieval,
dispatch, promotion, new canonical store, email send or source permission is
introduced. Real meeting text remains outside external AI systems, including the
engineering reviewer. Style imitation is not claimed validated from ten samples;
future outputs require Zac's feedback. Durable style memory belongs in Zac State,
not in a provider prompt history or this development document.

Approval or source:
Zac's explicit output order, contextual-summary requirement, concise writing
preference and instruction to read sent emails for style, 2026-10-02. This is an
extension of the existing Phase 3 evidence-review path toward Phase 4 context
assembly, not a replacement roadmap or authorization for recurring source access.
Local runtime selection and permitted real-content processing remain next steps.

Supersedes: None. Extends D030/D032/D033C.

Verification:
763 tests pass, including 22 new synthetic review cases. Ruff is clean and strict
mypy passes across 30 source files. Claude independently reviewed the review
contract and tests and found no blockers; overlap of current/related evidence,
fabricated quote spans, wrong task, classification downgrade, budget overflow and
forged declarations are covered. These checks prove structural behavior only;
no real-content summary quality, style fidelity or local model was evaluated.

## D034B - Canonical Review Context and Synthetic Local Evaluation

Date: 2026-10-02
Status: Implemented and synthetic-benchmark-verified; private dispatch deferred

Decision:
Build a read-only context assembler for explicitly selected canonical Meeting /
Source pairs, a provider-neutral generation seam with numbered evidence, and a
separate SHARED/PUBLIC-only local benchmark. Do not change Zac Event, canonical
storage, permissions, credential handling or later phase order. Canonical source
selection and route registration remain trusted host inputs, outside model JSON.

The assembler checks non-retracted meetings, exact source links, one boundary,
current effective labels, READ_DATA gateway outcomes, artifact SHA-256 integrity,
normalized v1 format/identity/date and raw/account dependency roles and hashes.
The raw dependency must be linked to the same Meeting. Labels propagate across
the selected meetings and their provenance dependencies. Context is bounded to
eight explicit meetings, 16,000 characters per text and 24,000 total, with no
silent truncation. Related meeting occurrence must precede the selected meeting;
that alone does not establish shared project or relevance. The caller owns the
read snapshot and must refresh classifications/provenance before future dispatch.
Only normalized Fireflies v1 decoding exists; no source discovery or Gmail /
ClickUp ingestion is introduced.

Generation returns prose plus opaque quote IDs. The host rebuilds the catalog,
rejects tampering/unknown/duplicate IDs, resolves exact spans and supplies canonical
task identity/classification itself. Model fields cannot change those values.
Generated FOLLOW_UP items are conservatively marked inferred by the host even
if the model says false. Declared inferred DECISION/COMMITMENT items are rejected.
Semantic agreement, completion, identity and date support still require evaluation;
correct citations are not a claim that a paraphrase is true.

The benchmark uses fixed 127.0.0.1:11434 requests and D032 host registry eligibility,
pinned installed digests, bounded serialized requests/responses, schema output,
think=false, no tools, temperature=0 and no retries/fallback/auto-pulls. It rejects
private-boundary or non-PUBLIC declarations before network I/O. Installed model
identity and remote-model metadata are checked; incomplete/late/over-budget,
tool-calling or unexpected-thinking responses are rejected. The socket timeout
is not a hard process deadline and a trusted loopback server is not a sandbox
against a malicious host or model service. No new private route is authorized.

Actual synthetic evaluation:
Ollama 0.34.2 was observed listening only on 127.0.0.1:11434. Existing D019 models
were used unchanged; no downloads, replacements or service configuration changes.
Three cases cover a follow-up with prior evidence, missing background, and an
injected instruction plus explicit absence of agreement/owner/date. Both models
passed all three final structural checks with the same refined prompt and host
logic. Manual comparison found persistent meaning errors in the 9B model: a
planned join fix became "Fixed", and an actual promise was misclassified as a
follow-up while a collective agreement became a commitment. The 27B model kept
the fix planned, distinguished agreements/promises, preserved missing background,
left unsupported owners/dates unassigned and ignored the injected instruction in
these cases. That is a provisional result from three small fixtures, not general
semantic correctness, completeness or style fidelity.

Final observed request latency (model call, not end-to-end workflow):
- qwen3.5:9b-mlx: 7.02 / 5.50 / 4.72 seconds; not admitted for real review use.
- qwen3.8:27b-mlx: 12.51 / 10.95 / 8.47 seconds; candidate for later local shadow evaluation.
The reusable `benchmarks/compact_meeting_review.py` contains only synthetic cases
and full public model digest pins. It prints result/usage records and writes no
state. Raw model output remains a proposal; structural pass is separate from
manual semantic assessment. Intermediate prompt refinements and rejected outputs
are not evidence of real-content readiness. No real transcript or email was
processed in these benchmarks, or provided to the independent engineering reviewer.

Contextual input and next step:
Zac clarified that this selected meeting likely recurs four times a week and
should relate to an existing client project/SOW in ClickUp. He does not know the
exact SOW name. Most current-client conversations concern existing projects or
new work, and clients can occasionally have multiple projects in flight.
The project/SOW should therefore be the context anchor; recurrence or customer
match alone must not create a link. Identify candidates, surface uncertainty and
require human confirmation. A transcript may touch several projects; do not force
all content onto one. Meeting.project_id is immutable in D029, so retroactive or
multiple-project associations need a separately reviewed append-only design,
not an in-place backfill. No association or ClickUp attachment has been written.
This requirement refines the existing evidence/context roadmap, not a competing plan.

Subsequent contextual clarification, 2026-10-02:
Read-only ClickUp inspection found an account, successive SOW records, and
explicit Project Tasks links to their delivery lists. Zac confirmed that the
selected work continued as one project while contracts/names changed over time.
Use a stable canonical Project identity as the context anchor; retain each SOW
and delivery list as distinct source records associated with that project. Do
not turn each contract into a separate Project or merge/overwrite ClickUp
records. Project identity does not make every historical fact current: preserve
source dates, contract scope and uncertainty about transitions, and select only
relevant background for each review. This human confirmation covers the
identified engagement, not every same-client contract. No canonical association
or source ingestion has been written. Private client names, task IDs and
commercial details are intentionally absent from this engineering checkpoint.


Verification:
810 tests pass, including 47 new canonical context/generation/transport cases;
Ruff is clean and strict mypy passes across 33 source files. DB tests remain in
guarded zacai_test and use synthetic replies/artifacts only. They cover hash-valid
forged dependencies/date, effective elevation of each lineage role, corrupt
artifacts, retracted/unlinked/future meetings, catalog tampering, quote IDs,
private dispatch denial before network, model pin/cloud rejection, serialized
capacity, response role/tools/thinking, late/incomplete output and no retries.
Claude's initial and final independent engineering reviews found no blockers.
Both reviews were limited to code, documentation and synthetic fixtures.

Approval or source:
Zac's continuation instruction and project/SOW context clarification, 2026-10-02;
D019 installed-model benchmarks and D030/D032/D033C/D034 contracts and policy.
Official API references checked 2026-10-02:
https://docs.ollama.com/api/chat,
https://docs.ollama.com/api/tags,
https://docs.ollama.com/capabilities/structured-outputs.

Supersedes: None. Extends D034 without enabling production routing or private inference.

## D034C - Reviewed Supplemental Meeting Project Context

Status: Implemented and verified in the synthetic test environment; live rollout pending.

Context:
Zac confirmed that a continuing project can span successive SOWs and delivery
lists, and asked to continue general Zac AI development rather than reconstruct
a particular client's project history. D029 already supplies stable Project
identities, immutable versions and source-backed ProjectEvidence. D034C extends
that model instead of treating a contract name or external list as a project ID.

Decision:
Add two typed canonical tables: MeetingProjectAssociation and its retraction.
Both are append-only, including database UPDATE/DELETE rejection triggers.
An association identifies the immutable Meeting, stable Project, exact project
version reviewed, boundary, classification and manual confirmation Source.
Multiple actual projects may relate to one meeting. Corrections append a
withdrawal and, if appropriate, a separately confirmed replacement assertion.
The original Meeting.project_id remains a separate historical anchor and is
never rewritten, silently superseded or merged by these APIs.

The trusted host must capture real human confirmation and separately authorize
state writes outside agents. Requiring a same-boundary MANUAL Source records
confirmation provenance; it is not proof of authorization or an approval token.
No model, connector title, customer-name match or source text can self-approve
an association. Existing versioned ProjectEvidence retains successive source
records; contract periods, alias matching and automatic retrieval are not added.

Repository behavior:
Association creation locks ProjectHead, then Meeting, within the caller's
transaction. It rejects missing/unauthorized/cross-boundary or retracted
endpoints, stale reviewed versions, non-manual confirmation, weak classification
and duplicate active associations. Withdrawal serializes on the Meeting and
remains available after endpoint retraction. Read APIs return supplemental IDs
and reviewed/current version numbers, never project contents or fetched artifacts.
A changed project version is visible for later re-review, not silently treated
as the version the human confirmed.

Effective read classification includes the association, current Meeting and all
its Sources, reviewed/current Project versions and their supporting evidence,
and confirmation Source, refreshing Source elevations on every read. Missing
permission, withdrawn links, retracted endpoints or disallowed classifications
produce no context. The caller must use a consistent snapshot and refresh
policy/evidence before dispatch. This API grants neither source access nor
private inference authority.

Verification:
837 tests pass, including 27 new synthetic association cases in guarded
zacai_test. These exercise actual migration/trigger/FK enforcement and schema/ORM parity, multi-project
context, version continuity, stale review, unchanged original meeting anchors,
append-only corrections, duplicate concurrent assertions, boundary denial,
manual-source requirements, sensitivity elevation including older project
evidence, and withdrawal after endpoint retraction. Ruff passes; strict mypy
passes across 33 source files. Claude independently reviewed the schema, repository, migration and synthetic
tests and found no blockers. His minor bool-version test suggestion is covered
by the final three invalid-version cases; schema/ORM parity is also tested.

Rollout and limits:
Migration 0005 is tested in zacai_test only. zacai_dev is not upgraded and no
real associations, ClickUp attachments, additional ingestion, model calls,
provider/runtime settings or credentials are changed. D034B's review assembler
is not yet wired to these supplemental links. Do not call the new APIs on a
production schema before the protected migration rollout. Context identity
alone does not establish temporal relevance or imply every old fact remains
current; that selection still belongs to the bounded evidence workflow.

Approval or source:
Zac's project-continuity clarification and instruction to continue general
Zac AI development, 2026-10-02; D026/D029/D030/D032/D034B state and policy contracts.

Delivery priority:
Zac reiterated that delivery quality, correct course and completing foundational
setup matter more than coding activity. Keep foundational changes tied to the
existing roadmap and the smallest demonstrable end-to-end workflow. Evaluate
source accuracy, contextual continuity, uncertainty, concise style and practical
usefulness with human feedback; structural tests alone do not demonstrate these.
Roadmap wording now distinguishes verified v1 foundations from broader unchecked
phase scope. Do not postpone useful shadow delivery to reconstruct a client's
entire historical contract structure.

Supersedes: None. Extends the existing roadmap without enabling private inference.

## D034D - Explicit Reviewed Project Evidence in Meeting Draft Context

Date: 2026-10-03
Status: Implemented, independently reviewed and synthetic tests verified; live rollout pending.

Context:
D034C provides canonical supplemental meeting/project associations. Zac asked
to continue foundational implementation toward useful delivered meeting reviews,
retaining the existing roadmap and Claude as independent engineering reviewer.
The next slice connects explicitly selected project evidence to the existing
canonical meeting assembler and draft quote catalog.

Decision:
Add an opt-in assemble_project_review_context host seam, preserving the existing
D034B assembler and Zac Event contract. The host selects one to three exact
association/Source pairs; it does not discover sources or match titles/customers.
Each primary association must be active, same-boundary, and still pin the current
reviewed Project version. The selected Source must SUPPORT that exact version.
Only explicitly selected, hash-verified MANUAL UTF-8 project artifacts are
decoded; no ClickUp API source decoder or automatic SOW ingestion is introduced.

Earlier selected meetings must have an active reviewed association to at least
one selected stable Project identity. Historical association version pins may
remain older than current, preserving continuity across contract changes; they
are not converted into present-day scope/status assertions. Shared identity is
not proof of topical relevance: explicit host relevance selection and semantic
evaluation remain required. A meeting may span several projects; overlap does
not attribute its entire transcript to every project.

All classification dependencies enter event provenance as metadata: used
association confirmations, supporting evidence for reviewed/current Project
versions, and all Sources linked to selected meetings. The host refreshes
effective classifications and existing LOCAL READ_DATA gateway checks. Only
selected transcript/project artifact text enters the model quote catalog;
confirmation and unselected historical evidence bodies are not fetched. A
confirmation Source cannot also be selected as project prose, even if cited by
ProjectEvidence; a regression case enforces this before any artifact reads.
Project EntityReferences retain stable UUIDs and reviewed version pins.
Every resulting draft claim still requires selected-meeting evidence; a
continuity claim additionally needs quoted background evidence. Generation
instructions explicitly warn that related contract records may be historical
and must not imply current facts or invented transition dates.

Limits:
At most eight explicit meetings, three projects and 64 combined provenance
Sources; selected project artifacts are capped at 16,000 bytes/8,000 characters,
with the existing 24,000-character combined context cap. Invalid UTF-8, NUL,
blank text, integrity failure, unsupported source types, stale or withdrawn
links and disallowed labels fail with fixed sanitized errors. No silent
truncation or fallbacks. Caller owns a consistent snapshot and must refresh
canonical evidence/policy before any future dispatch.

Verification:
862 tests pass, including 25 new synthetic canonical-to-draft integration cases
in guarded zacai_test. They verify exact Project versions/provenance, quoted
background reaching the compact preview, metadata-only confirmations, withdrawn
and stale links, unlinked meetings, old-version sensitivity elevation, boundary
denial, source corruption, invalid/oversized artifacts, contradictory evidence
exclusion, shared-source deduplication across distinct projects, duplicate
project identity rejection and inventory limits. Ruff passes; strict mypy passes across 34 source
files. These deterministic draft tests verify plumbing, not model semantics or
real-content readiness. Claude independently reviewed the initial implementation,
shared-source refinements and final role-isolation guard; all reviews found no
blockers. The final review confirmed that confirmation-source alias rejection
occurs before artifact reads and preserves shared-source behavior.

Local PUBLIC-only evaluation:
The reusable benchmark adds one invented continuing-project/across-contracts
case; no private source data is supplied. The pinned qwen3.8:27b-mlx initial
four-case run passed structural checks, but manual review found an overstatement
of "not agreed" as a nonexistent completion date. After uncertainty wording was
tightened, the final four-case run passed three cases; the new project case was
rejected for failing selected-meeting citation requirements. A separate manual
PUBLIC-only diagnostic confirmed that rejection; no automatic retry or relaxed
validation was added. The other cases remained around 8.03/10.93/12.45 seconds.
This is evidence of a remaining model-output weakness, not private-runtime
readiness or a reason to remove safeguards. Output evaluation and human feedback
remain required before promotion.

Rollout and limits:
No new schema migration; the new opt-in path depends on 0005, whose live rollout
is still pending. No production database changes, real project associations,
private inference, additional ingestion, external attachments, model downloads
or runtime configuration changes occur. MANUAL provenance and association
records do not authorize inference or writes. Canonical refresh, audit/evaluator
controls, protected migration rollout and bounded local shadow review remain
next, before real-output evaluation. Wider source ACL/recurring access and full
real-state restore gates remain open.

Approval or source:
Zac's continuation instruction, 2026-10-03; existing project-continuity and
delivery-quality requirements; D026-D034C canonical state/policy contracts.

Supersedes: None. Extends the existing roadmap without promoting private runtime use.

## D034E - Canonical Meeting Review Refresh Foundation

Date: 2026-10-03
Status: Implemented, independently reviewed and synthetic tests verified; live host pending.

The next bounded slice of the existing D034 workflow is a read-only refresh check.
Before a future dispatch, the host reassembles the exact selected meeting,
earlier meetings and optional reviewed project evidence through D034B/D034D,
using current host-supplied boundary/classification permissions. A changed or
unavailable canonical context rejects instead of relabeling an old request.
A 120-second maximum request age also rejects future/naive clocks; checking
again cannot renew the original observation time. This conservative development
limit is not an autonomy reliability threshold or a private-runtime approval.

The comparison binds context text/order, source hashes and effective labels,
metadata provenance, entity/version pins, evidence roles, event metadata,
capabilities and task/output limits. Only newly generated task/event/correlation
IDs and observation time are excluded from comparison. Unordered provenance,
entity inventories and capabilities are normalized; passage order is retained.
The quote catalog/instruction must still match the host-derived request.

The host must use a new consistent database read snapshot, without a stale ORM
identity map, and dispatch immediately after refreshing through separate gateway
and runtime controls. This library cannot establish that transaction lifecycle
or prevent a concurrent change after its read. Pending ORM writes are rejected
before querying to prevent accidental autoflush. Its content-free result is neither
an authorization token nor a persisted audit receipt. Source ACL preservation,
private model-route approval, durable audit/evaluator controls, protected schema
rollout and a full real-state restore drill remain unresolved as previously
tracked. No private model inference, schema migration or canonical writes occur.

Verification: 882 tests pass, including 20 new synthetic refresh tests covering
unchanged context, request/catalog changes, expiration/nonrenewal, revoked boundary
scope, meeting/project/link withdrawal, label elevation even when newly allowed,
selection/limit changes, project-path downgrade, pending-write rejection before
autoflush and artifact corruption with
sanitized errors. Ruff and strict mypy pass across 35 source files. These fixtures
verify refresh logic within guarded zacai_test; they do not establish a production
snapshot/dispatch lifecycle or semantic model-output quality. Claude independently
reviewed D034E and D035 and found no blockers; a separate final review of the
added autoflush guard also found no blockers. Claude reviewed the OCE ownership/roadmap decision;
source capability claims were verified through primary-source browsing by Codex,
not independently web-verified by the restricted Claude reviewer.

## D034F - Exact Draft Evaluation and Canonical Audit Foundation

Date: 2026-10-03
Status: Implemented, independently reviewed and synthetic tests verified; live host pending.

Continue the existing D034 workflow while Zac is away. He authorized independent
engineering and a nonblocking question log; QUESTIONS.md records future approvals
and delivery feedback without treating them as granted. No immediate question
blocks this synthetic foundation work.

Evaluation binds an exact structurally validated draft and full context/roles/task
identity to SHA-256 digests. The eight required criteria are factual support,
temporal context, agreements/promises, owners/dates, uncertainty, completeness,
concision and usefulness. Each has PASS/FAIL/UNREVIEWED; FAIL takes precedence over
unreviewed. All criteria must occur exactly once, and trusted reviewer/builder
UUID assignments must differ. These are host-assigned identities, not authenticated
by the schema. Changed draft/context or mismatched evaluation bindings reject.
No keyword-based grading or automatic correctness/approval threshold is introduced.
REVIEW_EVALUATION.md defines the rubric and its limits. The code checks bindings
and supplied judgments; an independent reviewer must actually assess semantics,
and Zac's delivery feedback remains essential.

Closed audit events record stage, task/run/event UUIDs, context/output digests,
host route identity where relevant and bound evaluation metadata. Evaluation
records must pass the exact draft/context check; the general stage audit API
rejects evaluation events to avoid bypassing that verification. Evaluation
outcomes must agree with judgments. Raw quotes, generated prose, backend errors,
email addresses and arbitrary reviewer notes have no payload field.

The trusted operator appends hash-verified artifacts and canonical MANUAL Sources
through the existing D030 ArtifactStore/Source mechanism, within exact boundaries
and labels. PostgreSQL transaction advisory locking serializes an audit UUID's
first insertion/retries within its boundary. Identical retries reuse the Source
and recheck artifact integrity; a changed payload cannot reuse the event UUID.
The caller owns commit. This is not a separate canonical store or a production
workflow state machine. Orphan artifacts on DB failure remain the existing D030
failure mode; no deletion or automatic cleanup is introduced. Audit Sources enter
the existing artifact inventory; this does not verify a live encrypted backup.

No private processing, model-route approval, source expansion, migration rollout,
production service activation or action/fact promotion occurs. PASS remains a
reviewed draft, not permission. Next build the fresh-snapshot operator host with
mandatory audit-before-dispatch, route/security checks, failure audit and a bounded
shadow result. Actual state recovery/rollout and exact private-processing scope
still require the separately tracked evidence and human decisions.

Verification: 915 tests pass, including 33 new synthetic evaluator/audit tests,
with Ruff and strict mypy passing across 37 source files. Coverage includes
incomplete/duplicate rubric inventories, builder/reviewer separation, exact output
and context binding, failure/unreviewed precedence, stage consistency, no prose
in artifacts, boundary denial, corruption, immutable retry identity and evaluation
API bypass rejection, evaluation retries and pending-write rejection before
autoflush. These fixtures do not grade actual model semantic quality
or prove the complete dispatch/backup lifecycle. Claude independently reviewed
the implementation and documentation and found no blockers. Its suggested
pending-write test was added, alongside evaluation retry coverage, and the final
915-test suite passed.

Zac then requested a stop at a good checkpoint and a summary. Work is paused at
this verified library checkpoint; no dispatch host or live workflow was started.
Further implementation waits for Zac to resume.

## D034G - Fresh-Snapshot Review Operator Host Foundation

Date: 2026-10-03
Status: Implemented and synthetic tests verified; production adapters pending.

Zac resumed and selected continued engineering/synthetic checks before a concrete
private trial proposal. This extends D034 without changing the roadmap or enabling
private processing. Claude remains an independent engineering reviewer.

The host requires explicit trusted authorization, runtime and protection adapters;
none has a permissive default or a production implementation in this slice.
Authorization preflight precedes artifact reads; the adapter must durably claim
exact one-shot authority and recheck revocation. The runtime must verify actual
locality, model pin and complete serialized capacity before its single generation
attempt. The protection adapter must verify recovery coverage of committed audit
Sources. Protocols and synthetic fakes are not operational approval evidence.

Canonical reads use fresh PostgreSQL REPEATABLE READ, READ ONLY transactions.
The operator commits REQUEST_PREPARED and DISPATCH_STARTED audits through the
existing Source/ArtifactStore seam before generation, checks exact local route
registration and gateway eligibility, and refreshes selected evidence before
and after dispatch and after protection. No snapshot stays open across model
work. Failure, invalid quotes, late output, changed evidence, revocation, failed
audit or failed protection releases no successful draft. There is no retry or
fallback. Valid output remains an unevaluated shadow draft, not promoted facts,
semantic PASS or execution permission. Exact context digest is shared with the
existing evaluator rather than duplicated.

Read-only structural preflight found the already selected transcript just above
the original 16,000-character cap. Increase per-meeting text to 18,000 characters,
retain the combined 24,000-character bound, and never truncate source text.
This is a bounded capacity adjustment, not source expansion or model approval;
complete serialized input capacity must still be checked by the runtime adapter.
Project evidence limits and quote limits are unchanged.

Tests use invented captures and mandatory fake adapters in guarded zacai_test.
Separate committed transactions prove audit visibility before generation and
freshness rejection after concurrent label/authority changes during generation
and during protection. Actual private runtime/authorization/protection adapters,
real state restore evidence, protected schema 0005 rollout and one-shot private
processing approval remain pending. Concurrent changes are checked at boundaries;
no global lock is claimed across dispatch. Recovery failures can leave durable
failure/audit Sources or D030 orphan artifacts; no automatic deletion occurs.

Zac also requested reuse of existing Claude app assets. A private source inventory
records Sales Agent templates/builders/brand references, distinguishes observed
links from Claude-reported status and keeps client material out of Git. Retrieve
and verify originals before creating replacements; Claude memory never becomes
canonical Zac State by default. Zac explicitly clarified that this material is
a starting point, subject to change; reported prior approval does not make it
current authoritative policy. No full-history import or commercial generation
was performed.

Verification: 935 synthetic tests pass, Ruff is clean and strict mypy passes
across 38 source files. Independent Claude review
found no blockers and identified missing post-protection coverage, now added.
Claude also independently reviewed the final size-boundary changes, both
post-protection tests and roadmap/question-log scope, and found no blockers.
REVIEW_HOST.md records adapter obligations and operational limits.

Zac subsequently clarified the long-term ingestion goal: available Claude and
ChatGPT conversations, memory and prior work, plus historical Fireflies meetings.
Record it inside the existing Phase 3 source-ingestion roadmap after the current
bounded review/recovery/private-trial gates. This does not reorder phases or
claim access/export completeness. Preserve historical source/date/version and
personal/business boundaries; old instructions/memory/drafts are evidence for
review, not automatically current authoritative rules. No broad capture or
private model processing was performed as part of this clarification.

Supersedes: D034B's per-meeting 16,000-character limit only. Extends D034E/D034F;
no production deployment, source permission or phase-order change.

## D034H - Shared Local Review Runtime and Exact Capacity Binding

Date: 2026-10-03
Status: Implemented and mocked/synthetic tests verified; actual tokenizer and
private authorization/protection remain pending. No runtime activated.

Continue D034 after D034G, reusing the existing loopback benchmark transport
rather than creating a second provider path. The benchmark retains its explicit
SHARED/PUBLIC-only guard and route eligibility checks. Shared payload/model/JSON/
response validation lives in local_review_runtime.py; no cloud endpoint, proxy,
redirect, model pull, tools or fallback path is added.

LocalReviewRuntime is an explicit trusted host adapter, not an approval mechanism.
Its mandatory local prompt token counter must match the exact model digest and
count the full rendered chat-template/schema prompt without sending evidence to
an inference or remote service. No actual tokenizer backend/default is shipped.
Serialized character/byte capacity and input plus reserved output token capacity
are checked before metadata requests. Runtime input usage must equal the trusted
preflight count, otherwise possible clipping/template mismatch discards output.
The fixed 8,192-token request context is retained from the benchmark; larger
context is not silently selected. No private source is forced through this cap.

Preflight sends only model-name metadata, binds exact payload/context/task identity
and clears stale binding on a failed new preflight. Generation requires that
binding, consumes the instance even on failure, checks exact single-name installed
model registration and remote flags before and after one chat call, then returns
only structurally parsed ReviewDraft. Usage stays absent on failure. Total adapter
latency includes metadata rechecks; socket timeouts and late-output rejection are
not an OS-enforced hard process-kill deadline. Host freshness/authority checks
still surround dispatch. Trusted server/model/tokenizer declarations do not prove
locality or integrity against a hostile host or configuration race. The adapter
cannot issue permission or replace canonical evidence, gateway or recovery checks.

Tests cover metadata-only preflight, changed/missing binding, a new task with the
same prose, replay, failed preflight invalidation, pre/post-generation pin changes,
ambiguous registrations, tokenizer pin/capacity/usage mismatch, malformed/late/
foreign/incomplete output, tools, safe diagnostics and bounded response/connection
closure. A mocked runtime integration proves the separate-transaction audit is
committed before chat dispatch through D034G. No actual model call, tokenizer
installation, private processing, schema rollout or service activation occurred.

Verification: 967 guarded synthetic tests pass, Ruff is clean and strict mypy
passes across 39 source files. Claude independently reviewed the adapter, shared
benchmark path, added failure/scope tests and documentation and found no blockers.
Its initial concern about absent boundary enforcement was reconciled against
D034G's existing host gateway/route checks and denied-scope integration tests;
no synthetic-only restriction was substituted for the authoritative gateway.
The first private trial still needs actual matching tokenizer evidence, durable
one-shot authorization, recovery verification, protected migration and exact scope
approval. Inspection also found the existing Lane B table inventory omits the new 0005
meeting/project association tables. RECOVERY.md records the required coverage,
legacy-restore/live-0004 compatibility and consistent export snapshot checks before
rollout. No backup code, live state, dump or off-device storage changed here.
These gates are engineering work and concrete decisions, not replaced
by a general permission grant or historical source-import goal.

Supersedes: None. Extends D034G; benchmark guard and canonical contracts preserved.

## D034I - Schema-Aware State Snapshots and Atomic Recovery

Date: 2026-10-03
Status: Implemented and synthetic recovery drills verified; actual state recovery
and protected production migration remain pending.

Continue the existing recovery gate after D034H. Inspection found that the fixed
D028 table inventory omitted D034C's two business tables and did not explicitly
establish one consistent export snapshot. Resolve these before private workflow
rollout without moving broader history ingestion ahead of the current gates.

New encrypted plaintext streams carry a v2 format marker, exact schema revision
and boundary. Fixed historical inventories support 0001..0005; newest inventory
includes association and retraction tables after their FK dependencies. The actual
schema selects the inventory, preserving 0004 export compatibility before rollout.
Unknown revisions reject rather than silently omit new state. Existing operational
artifact_backup_run exclusion remains; raw artifact manifests are independent.
Exports set REPEATABLE READ, READ ONLY as the first statement and read both schema
revision and all tables inside that same snapshot. One table's bytes are held in
memory at a time, unchanged from D028's subprocess encryption pipeline.

Restore supports versioned streams and exact historical 7/21/28-table legacy
inventories. Header column names must match known schema column sets; explicit
COPY columns preserve old Source/Commitment data across nullable additions.
No untrusted table/column text can become an arbitrary SQL identifier. Header
lines are capped at 256 bytes and table frames at 256 MiB; unsupported size fails
without truncation. Rows' parsed boundary values are checked in PostgreSQL after
COPY, against declared v2 boundary or one inferred legacy boundary, within the
same uncommitted transaction. Mixed pre-existing restore state also rejects.
The disposable target remains one-boundary recovery, not a live merge/import API.

All tables roll back on malformed/truncated/trailing/unknown input, wrong boundary,
failed decryption or interruption. Successful stream EOF is not decryption proof:
the wrapper now checks subprocess exit before raw DB commit. A decryptor emitting
a complete valid stream and then exiting nonzero leaves no committed rows. Export
subprocesses are reaped even when upstream export fails; partial artifact cleanup
remains D028's existing behavior. Destructive target guards are unchanged.
Legacy streams have no explicit schema marker, so EOF at a valid older inventory
is structurally ambiguous; encryption authentication and source backup identity
remain necessary. V2 removes that ambiguity for new backups. No plain export is
persisted in the normal encrypted path; passthrough test artifacts are synthetic.

Verification: synthetic integration tests use actual historical Alembic schemas
only in the fixed disposable drill database, restore populated old Source and
Commitment records into current schema, verify supplemental association/retraction
identity and version pins, and preserve immutable original Meeting.project_id.
A separately committed concurrent write after Source export is excluded from
later Person reads, and SHOW checks verify both isolation and read-only mode.
Additional cases cover clean EOF missing exactly the new tables, invalid lengths,
unknown revisions, trailing data, wrong/mixed boundaries and complete-stream
decryption failure with rollback. All 987 tests pass, Ruff is clean and strict
mypy passes across 39 source files. Claude independently reviewed the original
mechanism and final boundary/missing-table additions and documentation, and found
no blockers. Its missing-table suggestion was added as a regression test. No real data, model inference, credential recovery, upload or production
schema change occurred. Actual recovery and approved rollout remain next gates.

Supersedes: D028's new-export framing and snapshot isolation only. Existing legacy
formats remain readable; canonical state, raw artifact backup backend, boundary
keys and production rollout permissions are unchanged.

## D035 - OCE Evaluation Before Custom Production Agent Infrastructure

Date: 2026-10-03
Status: Evaluation gate accepted; no adoption or installation.

Zac requested an explicit OpenClaw Enterprise evaluation before building a
custom production multi-agent control plane. D032 and the first controlled
Fireflies ingestion already exist; preserve that completed sequence and continue
D034's bounded meeting workflow. Evaluate OCE when persistent-agent deployment
infrastructure is needed, before committing to custom production machinery.
This gate does not replace the Chief of Staff's product/workflow responsibilities.

The September 29 announcement describes a vendor-neutral, self-hosted platform
in pre-1.0 development. The architecture overview distinguishes implemented
capabilities from requirements: external access-gateway admission, workload API
authentication and general credential-free model mediation remain planned.
Dedicated Kubernetes execution still requires operator-configured node isolation;
namespace separation alone is insufficient. Native admin pilot commands are not
individually authorized/audited by OCC. These limits require deployment evidence,
not acceptance of broad security claims.

Evaluation must compare agent lifecycle, isolated execution, identity/RBAC,
audit/observability, provider/runtime portability and sandbox/policy boundaries.
Use synthetic data first. Check denied/revoked access, cross-boundary isolation,
credential exposure, missing audit evidence, runtime replacement and recovery,
as well as Mac Studio fit and operational/maintenance cost. Pin the evaluated
revision and distinguish working, experimental and planned capabilities. Record
adopt, defer or reject with evidence and an exit/replacement path; adoption is a
separate human decision, not a consequence of this roadmap item.

Zac State remains canonical business memory/state; OCE may own replaceable
infrastructure desired state only. Zac Events remain the integration contract.
Zac's approval/security/credential gateway stays authoritative outside agents;
OCE platform IAM may add restrictions but cannot bypass or replace that gateway.
Routing remains privacy/latency/cost/capability aware. No provider, runtime or
control plane gains ownership of canonical identity or irreplaceable logic.
No OCE installation, integration, permission expansion or private-data transfer
is authorized here. Claude remains the independent engineering reviewer.

Verified sources on 2026-10-03:
- [OpenClaw announcement](https://openclaw.ai/blog/openclaw-enterprise)
- [OCE architecture and implementation limits](https://github.com/openclaw/openclaw-enterprise/blob/main/docs/design.md)


## D034J - Canonical One-Shot Review Authority

Date: 2026-10-03
Status: Implemented and independently reviewed with synthetic evidence only

Continue D034's bounded review host by implementing its required authorization
adapter outside agents. Reuse canonical Source artifacts rather than adding a
second approval database or an enabled service.

Trusted operators can record a genuine human decision as a BRAINSTORM /
CONFIDENTIAL USER_INSTRUCTION Source. Consent binds exact selected evidence,
generation instructions and schema, local route, exact model digest and a window
of at most 15 minutes. Reassembled task/event IDs do not invalidate the evidence
binding; a durable MANUAL claim separately binds the actual run and full context.
Consent selection metadata must also match the prepared request.

PostgreSQL transaction locks serialize claims and revocations. Exactly one claim
commits before model dispatch; failed pre-claim checks do not consume authority.
Later failures consume the attempt. Human revocation is append-only and checked
again before releasing a draft. Corrupt evidence, expiry, replay, altered scope or
loss of recovery readiness fails closed with fixed diagnostics.

The recovery gate is mandatory and has no shipped production implementation.
Reference strings attest operator evidence; they do not establish actual recovery
or credential escrow. Registry eligibility, privacy permissions and the existing
gateway remain independent host checks. No historical conversation, imported
instruction, transcript or agent may issue current consent: review-consent,
review-claim and review-revocation namespaces are reserved for the trusted host.

Verification: 15 guarded authorization tests include two concurrent real database
claims, revocation during generation, changed evidence/selection, replay, expiry,
recovery loss, malformed artifacts and boundary backup inventory. Claude's
independent terminal review found no blockers. No actual consent, private model
call, production migration or expanded source access occurred. Actual tokenizer,
state/key recovery verification and audit protection remain prerequisites for a
concrete private trial proposal.


## D034K - Verified Offline Local Prompt Counting

Date: 2026-10-03
Status: Implemented and independently reviewed; PUBLIC-only conformance verified

Replace the invented D034H token counter with a narrow, explicit installed-model
adapter. The installed candidate manifest still matches the previously recorded
27B hash. Ollama is now 0.35.1; official versioned source establishes that this
safetensors model uses the built-in qwen3.8 renderer, rather than the generic
/api/show template alone.

OllamaQwenReviewTokenCounter hash-verifies the exact manifest and tokenizer/config
blobs, loads the local tokenizer in memory without model weights or downloads,
and reproduces only the supported system/user no-thinking review prompt. It
includes schema, message markers and assistant prefix, uses Go-compatible Unicode
whitespace rules and disables tokenizer padding/truncation. Unsupported payloads,
changed/missing files, model pins or renderer metadata reject. The optional
local-review dependency pins tokenizers 0.22.2; the lockfile preserves resolution.

The runtime calls the mandatory counter compatibility check before and after
generation. This backend permits only verified Ollama 0.35.1; an update requires
new source/conformance verification. Payloads explicitly disable server truncation
and context shifting. Existing complete input/output budgets, one-attempt dispatch,
usage equality, model pin, gateway and human consent remain unchanged.

Verification: 1,027 guarded tests pass; Ruff and strict mypy pass. A preliminary
PUBLIC invented probe matched 1,026 prompt tokens. The reproducible three-case
benchmark matched offline/runtime input counts exactly: continuing-project 1,211,
Unicode 1,076 and longer-input 2,706 tokens (approximately 13.3 / 11.7 / 19.0 seconds).
These prove observed compatibility for those cases, not universal tokenizer parity
or semantic review quality. Exact usage equality remains enforced per attempt.
No private source data, credentials, live consent or production migration was used.
Claude independently verified the narrow prompt bytes against the official
renderer source, confirmed the synthetic fixture and found no engineering blockers.
Real recovery/protection verification remains next before a private trial proposal.

Sources inspected:
- https://github.com/ollama/ollama/blob/v0.35.1/model/renderers/qwen35.go
- https://github.com/ollama/ollama/blob/v0.35.1/server/prompt.go
- https://github.com/ollama/ollama/blob/v0.35.1/mlxrunner/tokenizer/tokenizer_encode.go
- https://huggingface.co/docs/tokenizers


## D034L - Review Protection and Full Real-State Recovery

Date: 2026-10-03
Status: Implemented and independently reviewed; existing off-device state restore verified

Continue D034 by implementing its mandatory protection seam. The trusted
BrainstormReviewProtector validates exactly three committed canonical audit
stages plus the consent and durable claim. Source roles, hashes, current labels,
run/context/task bindings, route and prepared request digest must agree. It uses
the existing artifact backup mechanism, independently retrieves/decrypts required
artifacts, exports one boundary snapshot, encrypts it before upload to the existing
state prefix, independently reads it back and requires full database restoration.
No credential loader, infrastructure creation, service or automatic approval is added.

DisposableStateRestoreVerifier touches only zacai_restore_test. It refuses a
connected target, leases its own drill calls, restores the exact schema inventory,
verifies every row/field by deterministic CSV re-export and checks required Source
hashes. The shared backup parser validates original CSV columns, supported legacy
inventories and boundary purity; additional rows or omitted-table content reject.
The temporary database is dropped before success, including mid-restore failures.
Use an exclusive operator window; arbitrary administrative SQL and old independent
drill entrypoints do not participate in this new verifier's advisory lease.

Verification: 1,035 guarded tests pass; Ruff and strict mypy pass. Throwaway age
keys and independent local object clients exercise the actual protector through
the review host and full disposable restore. Corrupted artifact/state readback,
restore failure, unrelated runs and incomplete audits release no draft. An
identical-count/UUID field tamper is detected. Claude found no engineering blockers.
Synthetic stores do not establish off-device durability or production permission.

An existing approved D033C Brainstorm encrypted state snapshot was then retrieved
from real B2 with a newly constructed client, checked against its prior ciphertext
hash, authenticated-decrypted using the existing local identity, fully restored,
compared row/field-for-row/field, and removed. Four required committed Source hashes
also matched current read-only canonical metadata. Private proof and object/run
references remain outside Git. No canonical writes, uploads, connector calls,
private model processing or production migration occurred during this recovery.
This verifies that specific prior snapshot, not a current full-state backup,
credential escrow, whole-Mac recovery or all boundaries.

Zac then copied the Brainstorm backup key from 1Password and explicitly authorized
private recovery verification. The protected temporary outside-Git copy decrypted
the same real B2 snapshot; full row/field restore and required Source checks passed
again. The clipboard was cleared and the temporary key removed without displaying
key material or changing the original identity. This establishes recovery of that
backup identity, not recovery of every application credential.
Fresh protected migration, pre-context recovery/denial-audit host
wiring, exact reviewed project evidence and private trial consent remain separate
steps. No trial approval is requested from this checkpoint.

## D034M - Current-State Schema Upgrade and Rollback Rehearsal

Date: 2026-10-03
Status: Verified local preparation; live rollout remains pending

Continue D034 and the existing roadmap. Rehearse the exact populated 0004 ->
0005 transition before presenting a live decision, rather than relying only on
fresh-head schema tests or recovery of an older snapshot.

The explicit operator script scripts/rehearse_schema_rollout.py uses fixed
loopback database targets, read-only canonical transactions, a bounded in-memory
BRAINSTORM snapshot, the existing guarded disposable target and the same recovery
lease as D034L. It pins Alembic head to 0005 and applies the real migrations to
the disposable copy. No model, source connector, credential loading or remote
storage call is added. No plaintext export file is written; the recovered state
temporarily exists in PostgreSQL until cleanup.

Actual verification passed: restoration at 0004 produced an identical export;
upgrade to 0005 preserved every original field with both new association tables
empty; downgrade to 0004 produced an identical export again. The disposable
database was removed. Live schema remained 0004, with no canonical writes,
uploads or inference. A separate read-only inventory check found no canonical
PERSONAL/SHARED rows. Private receipt metadata is ignored by Git and mode 0600.

This verifies the current BRAINSTORM canonical inventory in the local rehearsal,
not fresh off-device protection, the excluded operational backup journal,
whole-Mac recovery or safe downgrade after new association evidence exists.
SCHEMA_ROLLOUT.md records those limits and the remaining procedure. The prior
1,035-test application baseline is unchanged; the new operator procedure was
validated by the actual disposable rehearsal and Ruff. Claude independently
reviewed the final procedure with no blockers. Two minor findings were resolved:
receipts now have unique locally dated filenames, and empty new tables are also
checked explicitly before rollback. The revised rehearsal passed again.
No approval decision is needed at tonight's stopping point.

Next finish pre-context recovery/denial auditing, prepare the reviewed exact live
operator procedure and ask Zac for the fresh protected schema rollout decision.
No private review consent or production migration authority is issued here.

## D034N - Pre-Context Recovery Gate and Durable Denials

Date: 2026-10-04
Status: Implemented and independently reviewed with invented state; live wiring pending

Implement the remaining recovery seam in the existing one-shot review host.
BrainstormReviewRecoveryGate requires an explicitly pinned current encrypted
checkpoint, a separately constructed verification client, local identity/public
recipient, the hash-pinned private receipt of prior independent key recovery and
the actual DisposableStateRestoreVerifier. No credential loader, upload, model
call, issuer, service or permissive default is introduced.

On every check, verify the prior receipt's permissions/hash and recovered-key
evidence, independently retrieve/decrypt its original object with the current
identity and test its recipient. Then independently retrieve the separate current
versioned checkpoint and required selected/dependency artifacts, check every hash,
restore the complete checkpoint, compare current business tables and every
original Source field, and verify required Sources in the recovered state. The
shared normalized decoder closes raw/account dependencies; canonical project
lookups close confirmation and supporting evidence. No IntelligenceTask or
ReviewContext is manufactured inside recovery, and no local selected artifact
is read before the gate succeeds. Backup plaintext is used only locally for
recovery and is not sent to a model.

Receipt/reference binding alone cannot establish readiness. The protected receipt
is trusted operator evidence of the prior independent password-manager exercise;
fresh cryptographic checks establish that the current key decrypts that same
object. This verifies backup age identity escrow/readiness, not B2 application-key
escrow, every application credential or automated password-manager access.
Local synthetic object clients still do not prove real off-device durability.

Additional Sources alone are allowed because consent/claim/audit records are
necessarily appended during the review. Required Sources must be restored;
every business row and original Source field still matches. Unrelated business
changes conservatively require a new checkpoint. No arbitrary authority prefix
is used to discard business records. A live 0004 revision cannot silently omit
association records present in a 0005 checkpoint. Post-run D034L protection
captures new authority/audit records separately, avoiding a circular precondition.

The host now commits a closed ReviewPreContextAudit when context preparation or
preflight fails. Its run UUID is the real host attempt allocated at entry; it
has no task ID, context/draft digest, selected Source IDs, backend text or grant.
BRAINSTORM/CONFIDENTIAL MANUAL metadata uses a separate committed transaction,
the existing Source/artifact inventory and gateway. Denied journal permission or
failed write/commit produces terminal audit-unavailable rather than false proof.
The canonical Zac Event contract is unchanged.

Verification: 1,055 tests pass, including 20 new guarded tests with actual
throwaway age encryption, independent local clients, full disposable restoration,
all five host recovery checks, required project evidence, changed fields with
equal hashes/UUIDs/counts, stale labels/business state, lost association tables,
denial visibility, no selected reads/model dispatch on recovery failure, and
failed journal commits/permissions. Ruff and strict mypy pass across 43 source
files. Claude found no code blockers. The complete private first-run scope and
performance remain untested; repeated remote restoration can exhaust the existing
120-second request lifetime and must not silently relax it.

No actual private recovery-gate invocation, live schema change, new B2 upload,
connector access or model processing occurred. Finish the exact live operator
procedure and excluded operational-journal recovery before requesting the fresh
protected rollout decision. Exact reviewed project evidence and private trial
scope remain separate. Do not repeat the already completed key recovery exercise.

## D034O - Protected Operator Rollout and Journal Recovery

Date: 2026-10-04
Status: Implemented, independently reviewed, explicitly approved and executed on 2026-10-04

Finish the exact operator procedure required by D034M/D034N. Preserve the
existing migration 0005 unchanged and target only the controlled Mac Studio
zacai_dev database. The proposed scope is one fresh encrypted BRAINSTORM state
and operational-journal backup to the existing B2 state prefix, independent
retrieval/full disposable restoration, then the exact additive 0004 -> 0005
upgrade. Two empty association/retraction tables are added; no reviewed project
records, new integrations, broader history or private inference are authorized.

Capture state and excluded artifact_backup_run journal in the same read-only
repeatable-read snapshot. Recover and compare every field before any live write
lock. Brief SHARE NOWAIT table locks then protect a READ COMMITTED freshness
check and the externally owned Alembic transaction. Any intervening canonical
or journal change, another boundary, active writer, expired approval or changed
code cancels the upgrade. Validation failures before commit roll back DDL;
ambiguous commits/receipt failures require investigation, not a downgrade.

The explicit Mac operator command defaults to proposal output only. Actual
execution requires an owner-only human-approved scope pinning clean code,
migration digest, exact database and at most 15 minutes. A durable private claim keyed to the stripped unique human approval reference
consumes that consent before credentials; the library creates an exclusive
STARTED receipt before remote actions, PREPARED only after recovery and APPLIED
only after commit. Failure is FAILED_OR_UNCONFIRMED. Keys stay in the existing
Mac Keychain/age identity path; no secrets are committed or printed. The host
disables SDK request retries. Remote orphan encrypted objects may remain.

Claude's design review corrected a material availability issue: write locks
must not span network recovery or disposable restoration. The revised design
performs those operations first and verifies freshness again under short locks.
The table pause still affects all writers, even with BRAINSTORM-only inventory.
The existing recovered-key proof is retained; no repeat key exercise is needed.
The exact procedure and proposed user scope are in SCHEMA_ROLLOUT.md.

Verification: actual throwaway age encryption, independent local object clients,
full disposable state/journal restoration, successful exact upgrade, transactional
post-DDL rollback, concurrent changes during lock-free retrieval, active writer
refusal, expired authority, corrupt retrieval, failed restoration, duplicate
attempt refusal, unknown final receipt status and default operator guards.
Final verification: 1,077 tests pass (two existing dependency deprecation
warnings); Ruff and strict mypy pass across 44 source files. Claude independently
reviewed the initial implementation with no blockers. A fresh failure-focused
review subsequently found three low-severity issues: equivalent approval replay,
initial receipt failure logging and ambient default-port redirection. All were
fixed with meaningful regression tests; explicit server/schema/inventory checks
address its two remaining assumptions. The fresh CLI trace confirmed 11 reads,
two searches and zero tool errors. Claude rechecked the corrections and found
no blockers. Actual read-only local metadata confirmed no unexpected public
CREATE grants in zacai_dev or zacai_test. Tests also caught and corrected
PostgreSQL inet text formatting in the new address guard.
The later explicitly approved one-shot operation completed successfully; see
the execution record below. No private-model operation has occurred.

### D034O approved execution — 2026-10-04

Approval/source: Zac's explicit chat response, "Yes please continue and approved,"
after the concrete scope and manual push request. The clean approved commit
6c831d1 was confirmed pushed before the trusted operator consumed one private
15-minute scope. No scope renewal or retry occurred.

Outcome: APPLIED at 2026-10-04T11:21:04Z. Two fresh age-encrypted BRAINSTORM
state/journal objects were uploaded to the existing B2 state prefix, independently
retrieved and fully restored/compared in the guarded disposable database. The
live database upgraded from 0004 to exactly 0005 in the protected transaction.
Every original canonical field and operational journal remained unchanged. Both
new association/retraction tables are empty. Independent read-only checks
confirmed receipt permissions/bindings, new constraints/triggers, health and
disposable cleanup. The operational journal still has one preserved row.

Private approval, consumed claim and APPLIED receipt remain Git-excluded and
owner-only; no private payload or key was exposed. No project evidence write,
private inference or new integration access occurred. The approved operation is
complete and its authority consumed. Next prepare exact reviewed project evidence
and then the distinct one-shot private-trial proposal under the existing D034
roadmap; newly added business evidence needs a fresh protected checkpoint.

## D034P - Concrete Review Operator Composition

Date: 2026-10-04
Status: Implemented and verified with invented state; private execution remains gated.

The trusted operator now composes canonical one-shot authorization, pre-context
recovery, the fixed-loopback runtime and post-run artifact/state protection.
Construction grants no authority and performs no I/O. An atomic single-attempt
guard prevents concurrent reuse; canonical claims also prevent replay through
new instances. Actual database identity and schema 0005 are checked before host
actions. Configuration remains trusted Python, not an isolation boundary against
a malicious caller modifying adapters.

The combined tests use actual age encryption, independent local object clients,
canonical consent/claims/audits and full disposable database restores. Invented
project evidence reaches the draft with its provenance intact. Tests verify
recovery before generation, audit commit before dispatch, post-run restoration,
replay denial, corrupted backups, wrong route/model/tokenizer, changed tokenizer,
bad usage, wrong actual target/schema, expiry and concurrent reuse.

Verification: 1,091 tests pass; Ruff and strict mypy pass across 45 source files.
Claude performed two fresh code-only adversarial reviews. The first identified
weak proof assertions and a thread-safety gap, now corrected. The second found
no blockers and further proof gaps; canonical binding-before-runtime, changed
tokenizer, wrong schema and consumed-claim checks were added. Wording was
corrected about trusted configuration. Test interception of transport/inventory
and the concurrency scheduling limit are explicit; tests do not claim hostile
Python isolation, production inventory coverage or real end-to-end latency.

No actual private inference, project write, consent issuer, enabled command or
service is added. Model/tokenizer transports are simulated in these composition
tests; D034K's PUBLIC real-tokenizer conformance is separate evidence. Six full
recovery stages may exhaust the existing 120-second request lifetime; expiry
fails closed without automatically widening consent or freshness. Live timing
and semantic/style evaluation require a separately scoped approved trial.

Approval/source: Zac authorized continued foundational engineering and routine
reviews/commits/pushes while available remotely. D034O's rollout authority is
consumed. Next prepare the exact source-backed project proposal, protect any new
business evidence and request the separate bounded private-trial decision.

## D034Q - Approved Case-Specific Project Context Recorded

Date: 2026-10-04
Status: Approved bounded metadata addition applied; fresh protection pending.

Zac approved the exact four-record context proposal and clarified that this
continuation is a rare engagement, not a standard for Brainstorm. One account
may have many projects; projects may have one or several SOWs or extensions.
Relationships must be reasoned from evidence and clarified case by case.
Historical examples help reasoning without becoming automatic authority.

The trusted local operation added one Company, one continuing Project, four
separate observed source metadata artifacts, one explicitly provisional project
brief and one scoped human confirmation Source. Five supporting ProjectEvidence
links and one append-only supplemental association bind only the selected
already-captured meeting. Every original row/field was compared and preserved;
historical Meeting.project_id remains unchanged. No contract bodies, commercial
values, unrelated projects, connector writes, uploads or model calls occurred.
Creation/update timestamps are source-record dates, not contract effective
periods. Observed signature fields do not verify signed terms.

The human approval and its case-specific limitation are recorded as provenance,
not as reusable execution permission. A deterministic operation marker prevents
blind replay. Private proposal and APPLIED receipt are owner-only and excluded
from Git. Independent read-only verification confirmed all expected row counts,
all 11 canonical artifact hashes and no leftover disposable restore database.

Zac also specified the interaction preference: when project ambiguity could
change the work, ask one quick targeted question before doing it. When a later
statement conflicts with an earlier decision, surface the conflict and ask
whether the decision changed. These are design/interaction requirements;
this operation does not claim an implemented autonomous learning system or
conflict detector. Specific examples remain scoped to their actual engagements.

Next: the prepared backup-only proposal protects the six new metadata artifacts
and all existing BRAINSTORM Sources, fresh schema-0005 state and operational
journal in the existing encrypted B2 destination, with independent full recovery.
It has not executed and needs distinct approval. Private model consent remains
separate, after current-state protection and concrete exact-trial scope.

Approval/source: Zac's explicit approval with the case-by-case correction, voice
clarifications and instruction to continue, all on 2026-10-04. Existing reviewed
D029/D034C repository write helpers; D034P verified composition foundation.

### D034Q approved fresh protection — 2026-10-04

Zac explicitly approved the recommended encrypted backup/recovery scope after
its concrete question. The bound single attempt completed at
2026-10-04T12:26:46Z: all 11 canonical BRAINSTORM Source artifacts were encrypted
and independently retrieved/hash-verified; fresh schema-0005 state and the
operational journal were encrypted into the existing B2 state prefix, retrieved
through a separate client and fully restored/compared. Original journal rows
were preserved plus the expected successful backup audit. Disposable cleanup
and the owner-only VERIFIED receipt were independently checked. The current
Project/association remain unchanged; both backup audit records are SUCCEEDED.
No model call, migration or source expansion occurred. This backup authority
is consumed and does not authorize the next private shadow review.

## D034R - Exact Quote Packing for Bounded Review Inputs

Date: 2026-10-04
Status: Implemented, reviewed and verified; private model consent pending.

Read-only local proposal preparation found a real integration limit: the selected
meeting has 248 nonblank passages and the approved project brief adds 11, beyond
the existing 250-entry catalog cap. Neither source content nor canonical state
was changed to force a fit. Host preparation now deterministically combines
successive passages within each source into exact original slices only when the
unpacked catalog exceeds 250. The 1500-character quote and 250-entry caps remain;
short catalogs retain their identities. No source boundary/role is merged, no
nonblank passage is dropped, and an irreducibly oversized catalog still rejects.
The request validator rebuilds the catalog and rejects forged quote tuples.

Verification: 1,097 tests pass; Ruff and strict mypy pass across 45 source files.
New invented-data regressions cover the actual 248+11 shape, Unicode/CRLF/blank
lines, exact offsets, complete passage coverage, 250/251 threshold, a span at
exactly 1500 characters, source-role/ID alignment, forged catalog rejection and
preserved oversized-input failure. Claude's fresh code-only review found no
confirmed packing defects; meaningful proof gaps were closed with regressions.
Canonical assemblers already reject duplicate/overlapping evidence roles; no
private source was exported to the independent engineering reviewer.

The concrete local proposal now contains 13 quote spans, 24,791 serialized
characters and 5,792 exact input tokens. The selected installed 27B model pin is
unchanged; its proposal permits at most 1,600 output tokens and 32,000 serialized
characters under the existing 64,000-byte/16,384-token runtime caps. This is the
proposed individual route scope, not a global runtime-limit increase. The
selected meeting and case-specific manual project brief are the only prose
inputs; nine canonical provenance Sources include metadata dependencies. There
are no earlier-meeting inputs. Deterministic preparation invoked no model and
made no canonical writes. Exact hashes/IDs are kept in the excluded private
meeting-review-proposal-2026-10-04.json. The request retains its 120-second
freshness lifetime and one-attempt semantics. Consent, audit records, encrypted
post-run state/artifact protection and a local unevaluated draft require the
separate concrete human decision before execution.

Approval/source: Zac's continued foundational engineering authorization; the
separately approved contextual addition and verified fresh recovery. No private
model approval has been granted by this engineering step.

## D034S - Real Local Attempt Rejected; Safe Diagnostics Added

Date: 2026-10-04
Status: One approved real attempt completed without a released draft; diagnostic retry not approved.

Zac approved one local shadow review using the selected meeting and the confirmed
case-specific project brief. The concrete operator made exactly one generation
call at pushed checkpoint 9710ea6. Runtime/model/token/completion checks returned
successfully, then evidence/compactness validation rejected the result. The
operator recorded REQUEST_PREPARED, DISPATCH_STARTED and DRAFT_REJECTED. The
50.06-second attempt released no draft and retained no raw failed response. Its
original exact validation reason cannot be reconstructed from the retained
metadata. The canonical consent/claim and private authority are consumed.

The necessary failed-attempt protection completed within that original approved
scope: all 16 Source artifacts and fresh encrypted BRAINSTORM state/journal were
retrieved, decrypted, fully restored and compared using a separate storage
client. Three backup runs now show SUCCEEDED; schema remains 0005, one project
and supplemental association remain, and disposable database count is zero.
No second generation, new business evidence or external AI transfer occurred.

ReviewHostError now carries an optional closed rejection-code enum only during
draft validation. Classification accepts exact built-in ValueError strings from
fixed public validator messages; unknown/schema/backend errors yield a fixed
unclassified code. Exception payloads and original source text are never
serialized by the operator. Existing fixed messages, canonical audit stages,
Zac Event contracts, authorization, freshness and compactness gates are unchanged.
Future codes do not retroactively identify the first attempt's cause.

Verification: all 1,101 tests pass, Ruff passes, and strict mypy passes across 45
source files. Invented-data checks exercise actual unknown-evidence and
compactness rejections, arbitrary/private error arguments, hostile exception
subclasses, and non-validation phases. Claude independently reviewed only the
host and tests and found no confirmed defects. It noted message-drift coverage
and Python exception-context caveats; the operator serializes only closed codes,
never exception chains. Fixed mappings were checked against current validators.

A new excluded diagnostic proposal is prepared from the protected 16-Source
checkpoint. Inputs/model/limits remain identical: two prose sources, no earlier
meetings, 13 exact quote spans, 5,792 input tokens, at most 1,600 output tokens,
120-second request freshness, and one attempt. Fresh filenames preserve the
first authority/receipt and prevent their reuse. Claude found an unpinned
recovered-key verification receipt and a double-read backup-proof gap in the
prepared launcher. The proposal now pins that receipt, uses one immutable backup
read, requires exactly one state object and checks private-file permissions.
Claude rechecked and confirmed the recovery-proof fixes, then identified a
dangling-symlink precheck gap. The output guard now uses lexists, verified with
an invented broken symlink, before authority consumption. The proposal includes
canonical consent/claim/audits and encrypted protection of either success or failed audits.
A successful local draft remains unevaluated until Zac assesses meaning/style.
Fresh specific human approval is required before that additional generation.
No broader ingestion, recurring access or later roadmap phase is advanced.

Approval/source: Zac's explicit local-review Yes; standing engineering authority
for safe diagnostics and invented tests. No automatic retry is authorized.

## D034T - Diagnosed Citation Failure; Host Role Guidance Clarified

Date: 2026-10-04
Status: Implemented, independently reviewed and verified; corrected private attempt pending.

Zac explicitly approved the one diagnostic retry at pushed checkpoint 091cb0d.
It made exactly one private local generation call and failed closed after 47.49
seconds with MISSING_MEETING_EVIDENCE. At least one output claim lacked a quote
from the selected meeting. The retained closed code does not identify which
claim/section failed. No private failed response was retained or draft released;
do not infer its wording or why the model chose those citations. That authority
is consumed, with no automatic private retry.

The approved protection remainder succeeded. All 21 Source artifacts plus fresh
encrypted BRAINSTORM state/journal were decrypted, fully restored and compared
through a separate storage client. Independent metadata checks confirm schema
0005, four SUCCEEDED backup runs and zero disposable databases. No new business
context, earlier meetings, source expansion or external AI transfer occurred.

The provider-neutral review request now explicitly lists host-assigned meeting
and related-context evidence IDs in its instruction. Every summary, continuity
and item must cite meeting evidence; continuity additionally cites related
context. The instruction explains that project context cannot replace meeting
support and forbids padding with unrelated citations. Only host-derived IDs and
fixed wording enter this guide; source text stays in the untrusted evidence
payload. Role lists remain accurate with reordered sources and exact-source
packing. Validators still enforce every existing quote/role/compactness rule;
no citation is injected or corrected after generation. Meaning is still evaluated
separately; a structurally valid quote is not proof of entailment.

Verification: all 1,106 tests pass, Ruff and strict mypy (45 source files) pass.
Five new invented regressions cover source ordering/packing and rejection of
related-only continuity/items; summary related-only rejection was already covered.
Claude reviewed only generic generation code and tests and found no confirmed
defects. It noted increased prompt size; existing capacity gates remain intact.
Three actual installed-model SHARED/PUBLIC invented-data cases passed structural
validation: project brief, reversed source order and packed 248+11 catalog.
These required one call each, with no retries or private inputs. Observed latencies
were approximately 11.7, 11.8 and 22.6 seconds. These passes do not establish
private-case success or final semantic/style quality; invented previews still
contain some repeated summary/item phrasing.

The new excluded proposal is prepared against the latest protected 21-Source
checkpoint and clarified instruction. Same selected meeting/project brief and
pinned local model; no earlier meetings or additional sources. It now measures
25,480 serialized characters and 5,956 exact input tokens, with 13 quote spans,
1,600 output-token cap and unchanged 32,000-character route / runtime capacity
caps. New proposal, authority, claim, draft and receipt paths preserve both prior
attempts. Existing pinned recovery receipts, clean pushed code revision and
launcher hash must match. One corrected private attempt including canonical
audit/state protection requires a fresh specific human decision before execution.
After a valid local draft, obtain Zac's accuracy/context/style feedback before
wider history work. Canonical Zac State, Events, gateway and roadmap order remain.

Approval/source: Zac's You’re approved for one diagnostic attempt; standing
engineering authority for clarified instructions, invented tests and PUBLIC
benchmarks. No third private generation has been authorized or executed.

## D034U - Citation Checks Passed; Display Budget Rejection Protected

Date: 2026-10-04
Status: Approved attempt completed without a draft; revised-budget private attempt pending.

Zac approved one corrected citation attempt at pushed checkpoint 66ae923. It
made one private local call and failed closed after 46.87 seconds with the safe
code DISPLAY_TOO_MANY_WORDS. Validation reached the overall display-word check:
quote identity, meeting/related roles, individual claim and summary/continuity
checks had passed. The displayed result exceeded the existing 180-word cap; the
later character-cap check was not reached. Passing citations does not prove
semantic accuracy. No raw failed response was retained or draft released, and
no extra private call was made under that consumed authority.

The approved protection remainder succeeded for all 26 Source artifacts and
fresh encrypted BRAINSTORM state/journal through separate-client readback,
decryption, full disposable restoration and current-state comparison. Independent
metadata checks confirm schema 0005, five SUCCEEDED backup runs and zero
remaining disposable databases. No new business evidence was ingested.

Generation instructions now aim for 100 words of claim prose, leaving room for
labels, owner/date annotations and uncertainty notices inside the unchanged
180-word/1400-character display caps. This is guidance, not a new validator or
a guarantee of completeness. Preserve material decisions, commitments, risks,
unresolved issues and uncertainty. Faithful facts take priority over prompt
length targets; oversize remains a host rejection. Combining items requires the
same kind, owner, due date and inferred status plus room for all supporting
citations. No truncation, citation insertion, cap relaxation, automatic revision
call, new runtime or gateway/Event/State change is introduced.

Claude's generic-code review identified combination and wording ambiguities,
which were corrected. Invented model testing additionally exposed an unsupported
release condition and a no-owner inference from no promise; explicit guidance
now forbids both. Further Claude review highlighted that fixed schema caps and
quote validation do not prove semantic completeness. Those caps remain unchanged;
semantic/style evaluation and Zac's feedback are still required. This work does
not claim that prompts can guarantee absence of omissions or distortions.

Verification: Ruff, strict mypy (45 source files), 85 affected validation tests
and the full 1,106-test suite pass. Final actual PUBLIC benchmarks both passed
structural validation at 96 displayed words / 684 characters, with approximately
15.5 and 30.1 seconds latency; each fixture made one call without retry.
Manual review of their invented text preserved distinct owners/dates and original
release conditions, but is not a general semantic-quality guarantee.
Dense PUBLIC invented-model fixtures include three distinct
agreements, two commitments with separate owners/dates, duplicate exports and
blocked permissions. Benchmark observations and superseded wording are preserved
in the local work directory. No private text was supplied to the cloud assistant
or independent reviewer. PRIVATE-case success remains untested after this change.

A fresh excluded proposal binds the same two prose sources, selected installed
local model, clarified prompt, latest protected 26-Source checkpoint and pinned
recovery receipts. It measures 26,354 serialized characters, 6,121 exact input
tokens and 13 quote spans; output cap remains 1,600 and request freshness 120
seconds. New proposal/authority/claim/draft/receipt paths preserve prior attempts.
The prepared one-attempt launcher includes canonical audits and encrypted
protection. Fresh specific approval is required for this additional private run.
A valid draft's accuracy, context and concise wording must be assessed before
wider history imports. Existing roadmap order and case-specific SOW reasoning
remain intact.

Approval/source: Zac's Yes approved for the corrected citation attempt; standing
engineering authority for wording fixes and invented-data tests. No fourth
private call is authorized or performed.

## D034V - First Validated Private Local Shadow Draft Returned

Date: 2026-10-04
Status: Real bounded draft returned and protected; human semantic/style assessment pending.

Zac's explicit Yes approved authorized the prepared word-budget attempt at clean
pushed checkpoint 2d6f23c. The exact proposal, launcher hash and code revision
were bound to fresh owner-only expiring authority, then consumed once. The
trusted concrete operator made exactly one real private local generation call,
with no fallback or automatic retry. It returned a draft after 62.76 seconds
total operator time. The rendered review is 128 words and 866 characters, within
unchanged 180-word/1400-character limits. Quote/role, per-claim, summary/continuity,
runtime pin/token/completion, freshness and canonical authorization checks passed.

REQUEST_PREPARED, DISPATCH_STARTED and DRAFT_VALIDATED audits were committed.
Concrete post-run protection passed and all seven actual full-restore checks
completed. Independent metadata checks confirm 31 Sources, six SUCCEEDED
artifact backup runs, unchanged schema 0005 and zero disposable databases.
This covers canonical audit/state and source artifacts with approved encrypted
recovery, not promotion of generated prose into canonical knowledge.

The generated review is an owner-only Git-excluded local Markdown draft. Its
hash matches the private receipt, its display count is independently verified,
and it remains PENDING_HUMAN_REVIEW. The local file was queued for the native
Codex editor; its prose was neither printed into cloud tool results nor supplied
to the independent Claude engineering reviewer. The local draft/receipt remain
outside Git and are not claimed to be part of canonical artifact backup coverage.
No external AI, publishing, new sources or broader source/model authority were
used. The successful attempt's authority is consumed as well.

This is the first structurally validated real draft, not semantic/style acceptance
or completion of production intelligence. A quote's existence does not prove
entailment, completeness, ownership or correct contextual interpretation. Zac
must assess what is factually wrong/missing and what does not sound like him.
Only then record exact-draft evaluation and decide the next bounded refinement.
Do not fabricate feedback, auto-promote prose or widen history/source access.
The confirmed continuing engagement remains a case-specific exception. State,
Events, gateway, provider neutrality and later roadmap phases remain unchanged.

Verification: actual one-shot operator plus independent metadata/hash/permission/
word-count checks. No implementation changed in this completion checkpoint;
D034U's 1,106-test/lint/strict-typing checks remain the code baseline.

Approval/source: Zac's latest explicit Yes approved for the revised-budget local
attempt, including approved canonical audit/state recovery protection.

## D034W - Human Feedback Requires Context and Usefulness Revision

Date: 2026-10-04
Status: Feedback preserved; quality/context design under independent review; private scope decisions pending.

Zac identified an entity shorthand error, insufficient detail and a lack of
project context in the first structurally validated draft. He wants relevant
research, a targeted question when missing context affects usefulness, and a
high-capability model to assess the presentation and produce a better draft.
The draft is not accepted as useful or semantically correct. Structural success
in D034V remains an execution/validation result, not delivery acceptance.

Exact correction and feedback are saved in an owner-only excluded note bound to
the original local file hash. A separate local acronym-corrected preview preserves
the original and remains NEEDS_REVISION. No immutable transcript or existing
canonical row was edited. The note is not a ReviewEvaluation: full task/context/
review bindings and independent reviewer identity have not been reconstructed.
Do not record invented criterion grades or an EVALUATION_RECORDED audit.

Inspection found that the real operator retained rendered prose and closed audit
digests but not the complete structured review/context packet. Hashes cannot
recover omitted fields. Before the next evaluable live draft, preserve its exact
validated structured packet under the approved boundary and retention controls,
so future evaluation can bind to the actual reviewed result. Do not retrospectively
rebuild missing task/event identities or claim a canonical evaluation from text.

Required delivery behavior, from Zac's feedback: establish project purpose,
relevant prior status and what changed before drafting. Confirm source-to-project
relevance; one account may have multiple projects and SOW continuity is case-
specific. Distinguish observed history, current meeting changes, human corrections,
and unresolved links. If an unknown project relationship, term or earlier decision
could change the review, ask one concrete discriminating question first. More
sources alone do not establish completeness, and inferred associations remain
candidates until reviewed. Do not substitute an irrelevant short draft for missing
context. Preserve source facts and corrections separately with provenance.

The existing concise contextual summary, decisions/commitments, risks/follow-ups
structure remains. Brevity is a presentation objective, not a universal word
count that establishes usefulness. Current runtime caps remain unchanged pending
an exact revised scope/design; no silent parameter increase, new cloud adapter,
bulk history ingestion or competing roadmap is introduced. Acceptance must cover
project understanding, material coverage, factual/temporal support, genuine
agreements/promises, accurate terms, unresolved questions and actual usefulness
for Zac, in addition to quote/length checks. Independently assessed semantics and
Zac's feedback remain necessary; model judgments do not grant authority.

Public research: Anthropic's Contextual Retrieval article explains why isolated
passages lose entity/time/background meaning and recommends evaluating contextual
retrieval choices (https://www.anthropic.com/engineering/contextual-retrieval).
QAFactEval studies question-answering-based factual-consistency assessment
(https://aclanthology.org/2022.naacl-main.187/). These support investigating relevant
context and meaning checks; neither establishes correctness for this private case
or requires immediate embedding/vector-database adoption.

Claude Opus completed the generic code/design review successfully; CLI metadata
reports claude-opus-5-5. It read only the three authorized generic intelligence
modules, with no private meeting, draft, project material or repository docs.
It recommended explicit host-owned source roles and relevance/history labels, a
pre-draft context decision, clearer decision/commitment labels, relief from a
universal display word budget, and versioned exact review/evaluation packets.
Its proposal is review input, not an adopted architecture change. In particular,
its no-related-sources/no-question recommendation conflicts with Zac's instruction
when missing context affects usefulness, and will not be adopted. A confirmed
link also does not settle all competing workstream questions. Existing canonical
project assemblers already enforce reviewed association evidence; the narrow
three-file review did not inspect those and must not imply they are absent.
Current caps/contracts/digests remain unchanged until a scoped reviewed revision;
no blanket source relabelling, digest-v2 migration or link inference is adopted.
Separate questions ask
whether selected confidential materials may be reviewed by a top cloud model,
and whether relevant prior Fireflies/ClickUp engagement sources may be inspected.
Both responses remain pending; elapsed time is not approval. The prior local-only
private authority is consumed and does not authorize another generation or source
expansion. Standalone design review cannot be represented as private redrafting.

Approval/source: Zac's actual correction, delivery requirements and request for
high-capability design/redrafting. Generic research/design work is authorized;
the specific confidential cloud/source expansion questions remain open.

## Open Decisions
These choices have not yet been made:
- Search/retrieval technologies (PostgreSQL canonical storage chosen in D026)
- Production model/runtime adapters and routing (D019 benchmarks remain provisional)
- Cloud models and account configuration
- Fireflies broader live-connection scope, recurring access and source ACLs
  (one selected-meeting trial separately approved and verified under D033C)
- Event transport and workflow execution mechanism
- Lane B PERSONAL/SHARED state off-device destinations (BRAINSTORM selected in D033C)
- Text interface implementation
- Voice provider and API
- Whether to adopt OpenClaw/OCE after the D035 evidence-based evaluation
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
D034D now integrates explicitly selected reviewed project evidence into the
canonical meeting/draft context, verified with synthetic data. D034E adds the
read-only canonical refresh foundation. D034F adds exact-draft evaluation and
canonical audit primitives. D034G now verifies the fresh-snapshot operator host with audit-before-dispatch.
D034H adds the shared local runtime adapter with mandatory exact token-count
binding; D034J adds canonical one-shot authorization with mandatory recovery
verification. D034K now verifies the narrow installed-model tokenizer with PUBLIC synthetic
conformance. D034L adds the concrete protection adapter and verifies a full restore of the
existing real off-device snapshot with a key recovered from 1Password. D034M verifies
the current-state populated-copy upgrade and rollback rehearsal and records the
protected rollout preparation. D034N implements/tests pre-context recovery and
durable denials. D034O now provides the reviewed exact operator procedure and
operational-journal recovery. Its explicitly approved real operation completed
on 2026-10-04: fresh verified B2 recovery and live schema 0005 with old state
preserved. Next prepare exact reviewed project evidence and the separate concrete
one-shot private-trial proposal. Protect any new business evidence before
inference. Keep genuinely distinct projects separate. D034B's 27B synthetic result is a
candidate for future bounded local shadow review, with refresh/audit/evaluation
controls required before private inference. Preserve unresolved
source ACL, recurring-access and production-routing gates; recovery evidence
remains specific to the verified BRAINSTORM snapshot.

## D034X — bounded context research and manual Opus prototype

Date: 2026-10-04
Status: Research completed; draft review and additional editorial scope pending

Zac approved relevant read-only engagement research and one confidential cloud
review of the selected material. Four meeting transcripts and eight scoped task
records were prepared as an owner-only private research packet, excluding media
URLs and unnecessary identifiers. A confirmed project brief copy was hash-checked.
One actual Claude Opus response is preserved with private input authority and
research receipt. The prototype has not passed human usefulness review; source
identifier formatting and presentation length require refinement. Historical
task status is not evidence of current acceptance, and expectations must not be
reported as formal decisions. Keep research-source links provisional.

Automatic approval review rejected a second transmission containing the generated
assessment and confidential result printing. A precise scope question is pending;
no second cloud request occurred. The first draft is saved locally and clearly
marked as an unaccepted research prototype. No canonical source, schema, production
routing, runtime validator, publishing or broader history-import change occurred.
The private research files are not claimed to be covered by the existing canonical
encrypted-backup checkpoint. This checkpoint documents research, not semantic
acceptance, a canonical evaluation, or an architectural implementation.

## D034Y — confirmed contextual delivery and exact evaluation packet codec

Date: 2026-10-04
Status: Offline foundation implemented; protected storage not wired

Zac confirmed the researched prototype as much better and explicitly requested
Opus consultation on structures going forward. Exact feedback is preserved
privately against the draft hash. This confirms delivery direction, not each
canonical criterion or a further confidential transmission. The earlier local
compact draft remains rejected.

A real engineering-only Claude Opus consultation recommends richer evidence
roles, provisional continuity, conflict/clarification handling and parallel
contracts that preserve the existing operator. Primary judgment keeps the user
presentation to three sections and avoids duplicating the existing canonical
project/account model with unverified model-owned identities. The first narrow
implementation is a pure versioned codec retaining the full validated review
and context for exact later evaluation. This is deliberately smaller than
Opus's combined v2 proposal; richer output and protected persistence are separate
reviewed steps, preserving the roadmap and current runtime limits.

Independent Opus code review found missing nested-version acceptance, noncanonical
JSON acceptance and private exception retention. These were addressed through
canonical re-encoding checks, safe exceptions raised outside handlers, hidden
model error inputs and regression tests. Hosts must still disable traceback-local
capture and protect these full-evidence packets as private data. Digests prove
consistency, not authentication, freshness, approval or factual entailment. An
independently retained evaluation must reject edited/rehashed context.

No database/schema, source access, runtime, production route, validator limits
or canonical evaluation changed. The codec performs no storage or inference;
protected packet capture/restore and richer synthetic contracts remain next.
The automatic reviewer rejected replacement of the roadmap tail as potentially
destructive; an additive update preserved all existing sections instead.

Verification: 1,128 tests pass with two existing dependency warnings; Ruff and
strict mypy (46 source files) pass. Synthetic packet tests cover exact reload,
changed instructions/digests, omitted nested versions, duplicate JSON keys,
noncanonical encoding and edits with recomputed digests. No live model/data
operation was used by these tests.

## D034Z — offline contextual review structure

Date: 2026-10-04
Status: Implemented offline; generation/evaluation/storage wiring pending

A standalone initial-version contextual format follows Zac's confirmed research
draft direction and the real Opus engineering consultation. It does not replace
MeetingReview or modify any compact/live validator. Current overview and items
require meeting-only evidence; background uses related records labelled as
candidates; continuity stays provisional and cites both roles. Role-less sources
are rejected. Exact quotes cannot establish semantic truth or project identity.

Material conflicts/questions hold the full draft. The first targeted question
includes its context and reason; remaining questions stay in the structured
proposal with an explicit queue count. An empty overview is allowed only while
material clarification is required, avoiding forced speculative summaries.
Visible normal output uses three sections and labels item kinds, proposed owners
and dates. Its defensive 650-word/6000-character ceiling is not a length target
or a change to current model/runtime limits.

Independent Opus review found display-control injection, ambiguous candidate
background, unassigned evidence acceptance and insufficient conflict-question
context. These are fixed with display control rejection, explicit candidate
labels, stricter role checks and context-bearing questions. Minimum substantive
quotes and word-boundary checks reject tiny/mid-word citation tricks, but still
do not establish entailment. Regression tests cover injection, evidence roles,
conflict passages, held drafts, queue preservation and both display ceilings.

Remaining gates: exact contextual evaluation/packet support, protected capture/
restore, host-selected generation scope and semantic/human review. No source
retrieval, private model trial, database/schema mutation or production routing
was performed. Hosts must escape display content and disable exception-local
capture; the offline wrapper exposes only fixed errors. The existing roadmap
and later history/control-plane phases remain authoritative.

Verification: 1,176 tests pass (48 contextual structure tests), with two existing
dependency warnings. Ruff and strict mypy on 47 source files pass. The existing
compact review, generation, evaluation and operator files are unchanged.

## D034AA — exact contextual packets and independent evaluation bindings

Date: 2026-10-04
Status: Offline implemented; protected persistence remains next

The contextual format now has a canonical full-evidence packet with separate
format/version, host-declared builder/capture time, renderer version, exact
preview and review/context digests. Immutable bounded bytes and canonical
re-encoding reject defaulting/coercion or altered stored inputs. Capture cannot
precede observation; evaluation cannot precede capture or name a different
builder/task. The host must authenticate both builder and reviewer identities
and validate its clock separately; these records are not signed identities.

The parallel ten-criterion inventory retains the existing eight criteria plus
scope/continuity and conflicts/clarifications. Trusted independent reviewers
supply judgments. FAIL precedes other outcomes; unresolved material questions
produce NEEDS_CLARIFICATION, distinct from unreviewed criteria's NEEDS_REVIEW.
Neither PASS nor any packet permits an action or promotes a fact. The exact
packet digest prevents an edited/rehashed draft reusing earlier evaluation.

Actual independent Opus review found unbound builder identity, ambiguous held
outcomes and mutable input acceptance. These were fixed. Frozen synthetic
packet/preview tests require explicit version review on format drift, and
subprocess tests confirm deterministic reload across hash seeds. Missing nested
versions, renderer changes and altered previews/context are rejected.

No historical evaluation was reconstructed and no compact/live generation or
operator was changed. Full packet bytes remain private; disable traceback-local
capture. Protected canonical persistence must register exact artifacts within
the original boundary/classification and verify committed encrypted recovery
before release. This module does not provide durable capture, a storage backend,
backup proof, source freshness or identity authentication. Future persisted
evaluations need an exact codec too; packet capture time is host-declared.

Verification: 1,200 tests pass, including 24 contextual packet/evaluation tests;
Ruff and strict mypy (48 source files) pass. Two existing dependency warnings
remain. Frozen synthetic packet hash and exact preview plus two subprocess hash
seeds protect deterministic output. The new module performs no persistence.

## D034AB — canonical contextual capture and explicit recovery wiring

Date: 2026-10-04
Status: Synthetic implementation verified; no live operation enabled

Packets are registered as immutable MANUAL Sources in the existing boundary-
partitioned artifact inventory. Capture verifies canonical reference hashes,
current effective labels, caller boundaries and allowed classifications before
writing. It uses a savepoint so failed registration cannot leave a canonical row
that a caller accidentally commits. Artifact orphans remain possible on rollback
under the existing policy and are never automatically removed. Exact retries
reuse the Source; elevated packet/evidence labels reject stale packet reuse.

Load checks canonical permissions, independently retained digest and effective
label before packet I/O, then verifies bytes and all copied reference metadata.
This does not establish correct relationship selection, current source revisions
or semantic truth: the future trusted generation host still owns refresh and
truthful builder/runtime provenance. Helpers do not issue approval or commit.
Hosts must use a clean isolated transaction; earlier flushed unrelated writes
are not detectable solely from the ORM pending-object inventory.

The separate explicit BRAINSTORM recovery adapter checks controlled configuration
and live database/schema, rejecting redirected Session bindings. It verifies
recipient/identity readiness, encrypted packet/evidence reads, every artifact
referenced by the consistent state snapshot, encrypted state/journal recovery
and full disposable-state comparison. The operational journal and state export
share one read-only snapshot. Current labels are checked again after recovery.
No draft is returned by the adapter; future release must be gated by successful
protection and durable trusted audit. Real use still needs concrete host approval.

Independent Opus review found rollback, routed-session and snapshot coverage
issues; these were addressed. Its journal/target findings referred to the earlier
code and were already fixed during review. Conditional classification checks are
now also explicit. Inspection confirmed the existing backup/upgrade helpers
already guard restore URL and actual database before writes; no shared restore
code change was needed. A direct selector test confirms MANUAL packets enter
backup inventory. Production inventory has no synthetic baseline filters.

Tests use guarded zacai_test, invented sources, owner-only temporary artifacts,
throwaway age identities and local object clients. Existing synthetic fixtures
with unrelated artifact roots are excluded only by test monkeypatches; these
tests prove adapter mechanics, not real off-device B2 coverage. Failures cover
corrupt artifact/state/journal, wrong identity, restore failure and a Source
committed between artifact backup and snapshot. No real data/model call/upload
or production operator change occurred.

Next integrate exact contextual generation/evaluation/capture through trusted
authorization, current canonical relationship checks, durable audit and release
ordering before proposing a real richer trial. Persist recovery object metadata
and exact evaluation codecs in that host path; adapter success is not a durable
consent token or reusable backup checkpoint. Preserve the roadmap's later phases.

Verification: 1,215 tests pass, including 15 synthetic contextual storage/
recovery tests; Ruff and strict mypy (50 source files) pass. Two existing
dependency warnings remain. Existing compact operator and shared restore
components are unchanged; only the new explicit adapters are wired in tests.

## D034AC — confirmed usable v1 target and contextual generation linkage

Date: 2026-10-04
Status: Offline delivery-path integration implemented; runtime host pending

Zac explicitly confirmed source-backed contextual meeting reviews, concise
daily briefing with decisions/commitments/open loops/questions and private
text/mobile access as the first usable version. This is a release target within
the existing Phase 4/5 workflow/interface scope, not a competing architecture.
Broad history and specialist agents remain desired after existing gates.
ROADMAP Current Position is reconciled against actual completed checkpoints;
stale summaries are retained and explicitly labelled historical. Full phase
checkboxes do not imply every future capability precedes the bounded v1 release.

The next integration slice prepares a provider-neutral contextual request using
existing exact passage packing, a bound output schema and request-specific
evidence IDs. It resolves model draft text into host identities/classification
and exact quotes, then the invented-data integration test registers/reloads the
exact packet through canonical storage. It never dispatches or grants approval.
Distinct contextual capability is required; compact/contextual mixed declarations
are rejected here without changing the existing compact runtime or its consent.

Independent Opus review found evidence-ID reuse could attach one meeting's draft
to another request. IDs are now namespaced by the full context digest (128-bit
prefix), including task identity. Catalog/schema/instructions are rebuilt and
compared; mismatches reject. Fixed error categories distinguish host REQUEST
failures, DRAFT_SCHEMA, CITATION and VALIDATION without private diagnostics; no
automatic model retry is enabled. Bounded immutable provider JSON parsing rejects
duplicate keys and extra authority fields. Role instructions now include material
questions/conflicts and explicitly ground owners in supporting passages.

Opus also identified renderer-structure spoofing despite single-line controls.
The contextual validator now rejects model-written renderer labels and leading
list/heading markers. Normal rendering and existing frozen synthetic preview/
packet hashes are unchanged. Conflicts need current meeting/distinct passage
support; inferred FOLLOW_UP remains strict rather than silently rewritten.

Next compose the authorized runtime, current relationship/source refresh, exact
request/audit binding, canonical capture, durable recovery metadata and fail-
closed release into a demonstrable selected-meeting workflow. Prepare a concrete
new private-trial scope only after reviewed integration. Then implement briefing
and private interface delivery inside the existing roadmap, measuring usefulness
and coverage gaps. No live source/model access, new cloud transmission of client
data, production route, scheduler or private mobile service was enabled here.

Verification: 1,243 tests pass, including 28 contextual generation/linkage tests;
Ruff and strict mypy on 51 source files pass, with two existing dependency
warnings. Frozen contextual packet/preview tests remain unchanged and pass.

### D034AC scope clarification — contextual execution remains the full goal

On 2026-10-04 Zac clarified that the desired full product should understand how
he wants requested work completed from accumulated context and then plan, build
and delegate to suitable models/agents efficiently across accuracy, speed and
cost. The previously confirmed meeting review/daily briefing/private interface
release remains the first useful slice of that larger architecture.

Use the existing roadmap rather than creating another plan. Delivery acceptance
for later execution/artifact phases must test contextual fit, useful completed
work, appropriate routing and independent verification, not only valid schemas
or summaries. Reuse relevant examples and confirmed preferences; ask a short
question when missing context would materially change the result. Feedback can
revise retained standards with provenance and case-specific scope rather than
turning every prior example into a universal rule. This clarification grants no
new source access, client-data model transmission or external action authority.

## D034AD — contextual host composition under explicit adapters
Date: 2026-10-04
Status: Implemented and verified with invented data; live operator pending

Keep the contextual path distinct from the compact operator and its authority.
Use existing canonical assemblers/Event contracts and gateway/route eligibility,
then replace only the task's compact capability/instruction with the contextual
workflow. Selection/relevance stays a trusted host choice, not model inference.
The host accepts no permissive authorization/protection defaults, discovers no
sources and enables only declared local routes in this library slice.

Canonical closed audit metadata binds run/task/builder, complete request digest,
context digest, route/pin and captured packet Source/hash. One immutable run scope
includes selection, boundaries/classifications, builder and route/pin; the same
scope/digest enters preflight, claim and rechecks. Runtime preflight receives
evidence only after claim. A concrete backend must authenticate this scope and
durably enforce expiry, revocation and replay; the protocol is not authority.

The host commits dispatch-prepared metadata before one bounded generation,
refreshes evidence/associations, commits packet plus capture audit atomically,
verifies protection, reloads the exact canonical packet and rechecks after that
read. No draft or material question returns if any gate fails. Persisted output
is still a proposal needing independent factual/usefulness evaluation. A saved
packet/audit or absence of failure never proves the user actually received it.

Opus reviewed seven engineering files only (actual model claude-opus-5-5). Its
concrete findings led to complete scope/digest binding, separate dispatch-age
and monotonic release budgets, audited sanitized cancellation, atomic capture
and truthful DISPATCH_PREPARED naming. The 120-second dispatch-age rule remains;
recovery may take longer within an explicit release budget, and authority expiry
still rejects. Final-load revocation and project-link withdrawal are tested.

Review disposition: user delivery confirmation belongs to the future interface,
with PACKET_CAPTURED explicitly documented as possibly returned. The actual
protector recovers all snapshot Source hashes, including audits, and the host
integration additionally decrypts/checks each audit in tests. The shared legacy
compact audit/freshness exception internals were not broadly rewritten here;
new host failures/cancellations retain no diagnostic exception chains. Contract
revalidation is already configured in the base Contract; a concrete runtime must
use the bounded duplicate-key raw-output parser before returning a draft. Shared
pre-context audit format remains accurate minimal metadata, not a success claim.

Required operator work: concrete contextual one-shot authority and runtime,
durable recovery receipt/object keys bound to run/packet, and failed-attempt
protection/reconciliation. These remain gates before a scoped private trial;
no real client-data call, source import, B2 upload or production activation took
place. Synthetic crypto/restore uses throwaway keys and independent local object
readers in guarded zacai_test; unrelated prior test inventory is filtered only
in test fixtures. This is not new live off-device backup evidence.

Verification: 1,274 tests pass, including 31 contextual-host tests; Ruff and
strict mypy on 52 source files pass. Two existing dependency warnings remain.
No manual push is needed.

## D034AE — contextual authority ledger and durable recovery lookup
Date: 2026-10-04
Status: Implemented and synthetic integration verified; live operator pending

Reuse existing canonical Source ledger helpers and advisory locking. Contextual
consent/revocation/claim have distinct closed formats and external-ref prefixes;
compact approval cannot authorize a contextual run. A consent binds builder,
selection, exact allowed boundary/classification sets, local route/pin and
prepared-content digest. TTL is at most 15 minutes and recording requires an
active decision now, with actual record time retained. Serializations are bounded
to the existing 32 KB authority envelope. Host adapters remain outside agents.

The prepared digest normalizes only host evidence-ID namespaces and fresh task/
event identities; passage text, roles, instructions, schema, source metadata and
budgets remain bound. Actual claims bind actual run/builder/scope/request/context
and canonical consent digests. Scope mismatch, expiry, replay, wrong requests,
revocation or lost recovery reject. Recovery work occurs before taking the claim
lock; locked re-read checks current authority and consumption before commit.
Rechecks repeat activity checks after recovery. Repeated revocation confirms the
existing denial, including after expiry.

Independent Opus review highlighted snapshot-isolation races in the shared lock
helper. Authority reads/mutations now require READ COMMITTED, with tests that
reject REPEATABLE READ ledger sessions; evidence snapshot transactions remain
unchanged. PostgreSQL documents that repeated-read snapshots can predate a
waiting lock, while READ COMMITTED commands receive fresh snapshots:
https://www.postgresql.org/docs/16/transaction-iso.html
This is a library guard, not a database configuration or schema rollout. No
unique-ref schema migration or protection against arbitrary admin writes is
claimed; trusted ledger mutations use the serialized helper.

The existing Brainstorm read-only recovery verifier receives a recovery-only
legacy-shaped view. This view is never persisted as a compact consent or used
for approval/dispatch. It preserves actual checkpoint/key evidence checks and
canonical selected-source/relationship verification without duplicating logic.

Recovery avoids self-referential hashes: commit a canonical MANUAL locator
Source before artifact backup/state snapshot. Its ref indexes packet plus nonce:
contextual-recovery-locator/{packet_source_id}/{locator_id}. The locator is a
planned pointer, never a success assertion. After independent artifact reads and
full disposable state/journal restore, write/read/decrypt an encrypted immutable
receipt binding locator/source/hash, task/builder/packet, exact audit IDs, backup
run and state/journal object/hash pairs. The snapshot includes the locator Source
so receipt discovery survives restore. Fresh lookup uses that verified canonical
index; its digest is consistency evidence, not an independent authentication
anchor. Full restored-state trust must still come from independently verified
checkpoint/key evidence. Lookup skips only missing receipt objects, rejects
corruption and requires exactly one completed candidate.

All protection reads are bounded and verify returned size; state/journal cipher
hashes are rechecked during receipt loading. Host audits must bind the same
context/request/route/pin and complete stages. The default host requires a
durable receipt bound to its actual packet/task/builder/audits. Only explicit
invented fixtures may allow missing receipts. Current labels on returned audit/
locator metadata are checked before release. A slow authority recheck is followed
by fresh evidence/route checks immediately before dispatch. Receipt records
recovery, never human delivery or semantic correctness.

Opus reviewed engineering code only (actual model claude-opus-5-5). Findings on
isolation, age at dispatch, packet-indexed receipt discovery, current consent
time, lock duration, repeated revocation and bounded reads were addressed.
Standalone packet protection may omit host audits; a real host always supplies
and verifies its full audit set. Future operator construction must use actual
recovery/protection adapters and forbid synthetic bypasses. Single-writer UUID
receipt objects are checked for pre-existence; object-store conditional writes,
retention/manifest concurrency, failed-attempt recovery and interface delivery
receipts remain explicit operator/hardening work. No mutable success flag is
substituted for independent recovery.

Verification: 1,325 tests pass; Ruff and strict mypy on 54 source files pass.
Tests include real canonical concurrent claims/revocation, expiry during
recovery, isolation rejection, exact prepared/actual digest binding, default
receipt enforcement, damaged/mismatched receipts, packet lookup/orphan/ambiguity
and combined canonical authorization + actual read-only recovery verifier +
protector. Provider output and escrow/topology attestations are invented;
crypto/independent local reads/disposable restores are real. Existing dependency
warnings remain. No actual approval, model call, B2 upload or production service
was enabled. The existing roadmap order and first usable release target remain.


## D034AF — explicit contextual loopback runtime, no enabled live trial

Use a separate contextual runtime adapter while retaining the existing compact
adapter and compact authority boundaries. Share only fixed loopback transport,
model metadata verification and verified offline tokenizer/template mechanics.
The tokenizer exposes separate exact schema entrypoints; accepting a contextual
schema never broadens compact counting. Trusted host owns construction and
approval. Output remains a draft until host quote/role/context validation,
canonical capture and independently verified protection succeed.

No budget change or evidence clipping is an implementation shortcut. Exact
payload/token counts bind preflight; the runtime verifies reported input usage,
complete stopping, output budget and model pin on both sides of one call. The
attempt remains consumed after failures/interruptions and diagnostics discard
backend text/chains. This is a synchronous trusted single-owner adapter; no
concurrent service or runtime scheduler is introduced. Loopback metadata is not
an attestation against a compromised host, and late rejection is not a process
kill deadline. Semantic accuracy and usefulness require separate evaluation.

The full canonical authority/recovery/protection integration test uses this
concrete adapter with mocked provider output. Offline installed-tokenizer
measurement of invented evidence is 1,552 input + 1,600 reserved output tokens;
it does not justify changing real trial budgets or assert real data will fit.
1,370 tests, Ruff and strict mypy on 55 source files pass. One-shot construction,
failed-attempt recovery/reconciliation, exact real scope and usefulness review
remain next under the existing roadmap. No live workflow was enabled.


D034AF independent Opus engineering review (actual claude-opus-5-5) found raw
chat-template control strings in evidence could affect role boundaries. Both
local serializers now escape `<` in the JSON evidence string without changing
canonical transcripts, source hashes or parsed passage text. The pinned offline
counter additionally rejects registered special-token strings in message
contents. Regression tests cover the boundary injection, exact capacity edge,
wrong compact tokenizer pairing and preserved parsed evidence. Counter errors
now discard private exception chains; contextual draft parsing rejects non-finite
JSON constants explicitly. Contextual capability checks were added during
independent implementation review before Opus returned the same finding.

Runtime instances remain synchronous and single-owner; concurrent scheduling
requires separately governed construction/locking. Error reporters must not
capture traceback locals. Exact prompt-usage mismatch fails closed and may
consume an attempt even if runtime reuse/cache behavior caused it; no relaxed
usage check is added without verifying runtime semantics. These are limitations,
not evidence of a successful real trial. One-shot operator and failed-attempt
reconciliation remain the next delivery step.


## D034AG — one-shot operator, failed-attempt recovery and read-only preparation

Use concrete contextual authority/runtime/recovery/protection wiring with no
synthetic bypass in the operator. Serialize this operator's attempts and shared
manifest work using an existing-database transaction advisory lease, disable
applicable idle/transaction timeout for that lease, check it before critical
writes and release, and withhold output on uncertainty. Preserve verified receipt
metadata when lease cleanup fails. This is not remote-object fencing or a lock
shared by unrelated operators/databases; exclusive recovery windows remain.

Share existing bounded encrypted snapshot/journal/full restore mechanics for
successful packets and failed-attempt evidence. Success explicitly binds the
approval and consumed claim. A failure locator is a planned canonical Source
written before its snapshot; its independently encrypted receipt is written
only after real restore. Check canonical audit sequence/route/request/task,
exact claim serialization and any captured-but-withheld packet hash. No failure
receipt grants dispatch, retry or delivery. Preserve cancellation during cleanup;
sanitize exception chains and nonzero integer exit status. Error reporting must
omit traceback locals.

Preparation verifies actual recovery and exact source evidence before metadata
preflight; its internal consent-shaped recovery view is never an authority
record. Proposal source/route/digests/capacity remain private metadata. Later
operator use requires independently authenticated human consent and all fresh
canonical checks. Reconciliation is read-only, independently checks required
approval/claim/packet receipt inventory and explicitly treats captured packets
as needing review, never delivered. A claimed incomplete run requires operator
review/new approval; it is never retried automatically. Its 2,000-row audit bound
is conservative and must be replaced with indexed metadata before larger scale.

Actual Opus code-only reviews found and informed fixes for lease cleanup/loss,
interruption handling, withheld packet protection and receipt coverage. Shared
_bytes already checks effective CONFIDENTIAL classification before content reads;
explicit base-label checks and regression guards clarify that invariant.
1,394 tests pass; Ruff and strict mypy on 59 source files pass. Invented provider/
escrow/topology fixtures do not establish real off-device coverage.

A separate authorized real read-only B2 recovery/local-tokenizer measurement
found the previously approved meeting + project brief requires 6,890 input plus
1,600 output reservation, beyond 8,192. No generation/upload/import or cap change
occurred. The three earlier meeting and eight ClickUp research exhibits that
supported the preferred researched draft are not canonical Source context yet.
Prepare a hash-bound bounded import proposal, retaining them as candidate
research exhibits with original provider IDs and separate unconfirmed
interpretations. Do not imply a native provider capture or promote project links.
Human intake/backup scope, protected recovery and exact faithful model/budget
trial follow in that order under the existing roadmap.


## D034AH — approved candidate research evidence and honest partial recovery

Existing research snapshots may enter canonical Source provenance under an exact
human-approved hash-bound scope without becoming native provider captures,
current facts or confirmed project connections. Store them as MANUAL candidate
evidence with provider/original ID, proposal/packet/record hashes, explicit
unconfirmed relationships and separately marked research interpretation. Keep
the approved canonical record encoding for integrity; it is not the original
input packet's formatting. Future retrieval must decode these roles explicitly.

Predictable reference conflicts must reject before artifact writes. Later
separately approved packet snapshots may preserve the same record under their
own approval namespace. Caller owns authenticated consent, live target/lease,
commit and real recovery. This helper grants no permission, executes no model,
changes no business entity and enables no ingestion service.

Real intake committed eleven exhibits and approval/locator metadata. Actual B2
artifact recovery of all thirteen new Sources is verified; a local diagnostic
full current-state/journal restore passes. Final remote checkpoint binding and
receipt are still unverified because missing-object existence checks and scoped
listing return access denied. Neither a successful journal row nor a local
restore alone establishes that final remote checkpoint. Preserve partial state;
no automatic re-import/retry or denial-as-absence behavior.

Native capability inspection confirms the old bucket-specific backup key has
readFiles/writeFiles only. Human explicitly approved replacement restricted to
zac-ai-brainstorm-backup, BRAINSTORM/, readFiles/writeFiles/listFiles, no deletes.
Replacement creation/installation still needs account access. Do not use a broad
console Read and Write preset if it adds delete capability; validate exact
capabilities before installing. Do not rotate the master key or revoke the old
key as an inferred side effect. Finish missing checkpoint recovery before the
new contextual trial. Engineering passes 1,409 tests, Ruff and strict mypy; Opus
reviews were code/invented tests only, without client-source egress.


## D034AI — split uploader and read-only recovery verifier

Retain the existing read/write uploader and use the separately user-created,
1Password-recovered verifier restricted to the existing Brainstorm bucket and
BRAINSTORM/ prefix. This supersedes the pending replacement-key implementation
in D034AH; no master-key rotation or old-key revocation occurred. Backblaze's
Read Only preset includes readFiles/listFiles plus bucket metadata reads and
shareFiles download-authorization capability. Fresh authorization checks the
actual credential against the exact accepted allowlist and checks that its ID
differs from the uploader. Runtime verification uses read/list operations only.

Receipt absence checks belong to the verification client, preserving writer
scope. Never turn a 403 into absence. The deliberate one-time intake repair used
the original encrypted state/journal, original journal-to-live backup-run binding,
all thirteen intake artifacts and full disposable restore/current-state checks.
Confirm cleanup before a receipt claims it, then upload/read back only the missing
encrypted receipt. Private approval, attempt/completion records and hashes are
owner-only ignored files. No repeated intake, snapshot, inference or entity writes.
A restored checkpoint is not new device-loss credential escrow evidence.

Use native Keychain reads with a private local stdin pipe where the CLI's access
control blocks newly installed entries. Credentials never enter argv, plaintext
files, logs or model input. Do not force-kill a restore child at a short parent
timeout: its cleanup must run. This bridge is an operator helper, not a new
agent credential gateway or enabled service.

D034AI validation: 1,411 tests pass (two existing dependency warnings); Ruff
and strict mypy on 60 source files pass.


## D034AJ — explicit research excerpts; consent-bound larger local profile

Keep native meeting selection and reviewed project evidence distinct from MANUAL
candidate research. Add a strict contextual research selection format; reject
unknown fields rather than silently drop history into the legacy selection.
Consent binds source/record/field hashes, exact Unicode-code-point spans and host
relevance rationale. Rationale is not model evidence. Do not normalize or shift
ranges after source changes. Unsupported/oversized spans reject before consent;
final serializer/token limits still apply. Candidate roles never assert prior
native meeting chronology or promote project/SOW identities.

Preserve original Event provenance, including non-context dependency Sources,
then append research references. Original import records remain unchanged;
projection excludes derived interpretations, status/parent/list metadata and
marks names/timestamps as captured/unverified. Re-recorded wrappers for the same
original provider record are duplicate-denied within this bounded slice. Future
history comparison of multiple versions needs a deliberate separate structure.
JSON strings escape line-separator controls and retain exact original ranges.

Extend read-only recovery with additional pinned MANUAL Sources and require them
in both encrypted artifact storage and the restored state. A contextual recovery
view is never a compact consent or dispatch grant. Accept the hash-bound existing
contextual-research checkpoint namespace as reusable same-boundary recovery
material; this does not grant authority or excuse freshness checks.

The fixed named local profile mac-loopback-contextual-16k maps to 16,384 only for
the pinned qwen3.8:27b-mlx model. The default stays 8,192 and compact schema/counting
cannot use the larger profile. Treat profile identity as part of the exact human
route approval; changing its semantics requires a new identity, not altering the
meaning of outstanding consent. No automatic context expansion, trimming or cloud
fallback. The profile is implemented/validated for an exact proposed one-shot
trial, not registered as an unattended service.

Actual PUBLIC conformance and real read-only B2 recovery passed. Lexical excerpt
selection is a proposed source scope, not evidence of topical sufficiency. If the
first draft needs context, return a targeted material question under Zac's
preference rather than invent history or produce an irrelevant summary. Private
trial approval and later human semantic/usefulness feedback remain separate.


## D034AK — retain private-safe failure operation, preserve historical audit bytes

A real approved candidate-history review failed after DISPATCH_PREPARED. Existing
sanitization retained failure recovery but discarded the operation that failed.
Do not reconstruct or guess its cause. Future contextual RUN_FAILED audits may
carry a closed host-owned failure_step enum. It labels the active operation, not
a verified root cause, and never grants processing authority or retries.

Keep legacy audit serialization byte-exact by omitting the new field when absent.
Reject free text and labels on nonfailed stages. The canonical Zac Event contract,
old encrypted receipts, immutable Source records and processing scope remain
unchanged. Protect failed attempts even when no useful draft is available. New
private processing still requires a fresh exact human decision; successful backup
recovery is not successful product delivery.


Diagnostic labels apply only after a contextual request exists. Freshness age,
request integrity, evidence refresh, route, approval recheck, generation and
latency checks each set their own constant immediately before the operation.
Pre-context records are unchanged and remain unlabeled. Labeled audit artifacts
require D034AK-compatible readers; older builds reject the additive field. Do
not roll recovery readers back below that floor after the first labeled write.


Pair a failure operation with a strict dispatch_attempted flag: it records whether
the host attempted runtime.generate(), not proof of successful transport. Enforce
pre/post dispatch and packet binding consistency. Cache validated original audit
bindings before assigning the live request; a changed request must not destroy its
own failure audit. Preserve committed packet/audit IDs before session exit so a
close failure cannot hide durable records. Observer failure has its own fixed
message rather than falsely claiming the durable audit is unavailable.


## D034AL — explicit output reservation; closed private-safe runtime reasons

Preserve consumed approvals and protected failed-attempt receipts. The diagnostic
attempt's known operation is GENERATION; its inner reason is unavailable. PUBLIC
output exhaustion is a reproduction, not a retrospective private diagnosis.

A task explicitly reserves 1,600 or 3,200 tokens. Default stays 1,600 independently
of route ceiling. Operators reject over-ceiling reservations; preparation rejects
before artifact/metadata I/O. Consent binds full ModelRoute and prepared task limits;
both-direction ceiling-only and reservation-only changes reject before generation.
Window, pinned model, 64,000-byte maximum and 120-second generation budget remain.

Runtime errors expose only typed RuntimeFailureCode values. Inner hints are accepted
only at token count (pin/count/capacity) and dispatch (transport/response/output);
version/pin/post-dispatch stages keep their host-assigned reason. Length replies
must pass authority and usage checks before OUTPUT_LIMIT can be assigned, and
OUTPUT_LIMIT requires reported output at cap with total usage below context cap.
UNSPECIFIED is omitted and rejected as an explicit audit value. Optional fields
omit absent values and preserve historical audit bytes. New coded audits require
D034AL-compatible recovery readers; older readers reject unknown fields.

Opus recommended compact, material-item-preserving instructions and a measured
larger reservation. Never parse/repair partial JSON or omit facts to force a fit.
No related evidence means empty background/continuity. All runtime trials in this
engineering change use invented PUBLIC evidence. Controlled 16-item structural
success does not validate semantic entailment or private delivery quality. Track
schema capacity above 16 material items before widening v1 use. No canonical Zac
Event change, provider egress, recurring intake or automatic retry is introduced.

Validation: all 1,541 tests pass; Ruff and strict mypy (62 source files) pass.
Fresh read-only same-scope preparation measures 9,268 input + 3,200 output tokens
within 16,384; encrypted selected artifacts/full disposable restore verify and
clean up, with canonical state unchanged and no private generation.


### D034AL approved trial outcome — do not infer the missing inner reason

The approved sealed manifest hash was
7ce143698ed97a1528033cc52eeb9fd5e371d6a5d15fcc58d8a8cc33326b0dee.
Its one-shot attempt failed at DRAFT_VALIDATION after generation returned and the
host latency check passed. No raw invalid model content was captured/logged.
The private failed-attempt sidecar is PROTECTED_FAILURE_NO_RETRY; SHA-256
839b6e612b852f329bb2b122d0ccea91d14c7925832f9e09667ee9fa908173d3.
It retains the actual verified encrypted artifact/state/journal recovery receipt.
Canonical audit fields are source-hash checked; Source inventory 62 and disposable
restore database count zero. Draft and result files are absent. This establishes
validation rejection, not its missing inner cause or semantic quality. Preserve
the consumed approval, exact sealed launcher and failure receipt. No retry grant.

Before proposing another private call, consult Opus on code-only delivery/validator
alignment and add fixed diagnostic categories using invented data. Do not weaken
roles/citations, repair unsupported claims or treat a PUBLIC pass as proof of
private usefulness. No manual push or credential action is required from Zac.


### Code-only Opus delivery review after the protected rejection

Opus reviewed contextual_generation.py, contextual_review.py and the shared
review_generation.py without tools/private evidence. It found independently
verifiable schema/instruction mismatches: continuity accepts/defaults inferred
false while ProvisionalConnection requires true; conflicts permit one citation
while validation requires two distinct supporting passages; FOLLOW_UP instruction
says proposed while validation requires every follow-up provisional; overview
wording invites prior context while citations must remain meeting-only. These are
code findings, not a diagnosis of the consumed private attempt. Other proposed
quote-catalog/display-budget refinements require separate design/testing; do not
apply every suggestion or weaken protections automatically.

Next bounded engineering checkpoint: preserve closed, content-free resolution/
validation reason codes in failed audits; align contextual draft schema and plain
instructions to the existing continuity/conflict/inference/role rules; verify
invented mixed-role fixtures and malformed-output denials. Consult Opus on changes.
Only then measure/seal another exact private proposal. No automatic mutation of
unsupported claims, partial JSON repair, retry, fact promotion or new source scope.
The code-only review is retained in the existing local work directory; no private
source or generated prose was supplied to Opus.


## D034AM — schema-visible inference, closed rejection reasons, stable packet bytes

Fix the observed schema/instruction mismatches before another private attempt.
Continuity requires explicit strict true; conflicts require min2 supporting IDs;
items use discriminated DECISION/COMMITMENT/FOLLOW_UP/RISK shapes with required
provisional true for follow-ups and false for agreements. Do not coerce/rewrite
unsupported output. Missing overview still reaches final OVERVIEW_MISSING, keeping
semantic rejection observable. Request/shape/citation/validation categories are
closed enums; specific rule reasons attach only to VALIDATION. Lookup of malformed
secondary diagnostic objects cannot suppress the original failure/audit.

New optional draft_failure_code/draft_rejection audit fields belong only to failed
DRAFT_VALIDATION before capture; runtime and draft fields cannot coexist. Null,
free-text and impossible combinations reject; omitted historical fields preserve
canonical bytes. A typed rejection requires D034AM-compatible recovery readers.
No private coded record was generated by this engineering checkpoint.

Use the existing minimum quote predicate during catalog preparation as well as
final validation. Retain short source passages with citable=false, but never offer
those IDs for citation or remove original evidence. Unknown/duplicate/non-citable
IDs reject with CITATION. Static schema does not prove IDs, role support, entailment
or completeness; host checks and actual human usefulness evaluation remain needed.

Independent Opus code review found no important defects in the final delta. Earlier
findings about early overview rejection, ambiguous short-passage co-citation wording
and inference instruction clarity were corrected. PUBLIC model probing exposed a
semantic suggestion defect after a structurally valid output; this was treated as
a delivery failure rather than hidden by passing tests. Final measured PUBLIC
case retains the two exact promises, hold/risk and unowned provisional suggestion,
with accurate current/prior status. Independent Opus assessment of source texts,
draft and rendered preview: PASS with nonblocking labeling/concision refinements;
no defect blocks one bounded HUMAN usefulness trial. Not a general semantic grade
or private-content verdict. All intermediate fixed-metadata probes are retained.

Preserve v1 packet golden SHA-256 ec0ec819dafbf8f41c99a8d0aae700501fc56df77e138d85f82f4463cefdb59e.
The attempted draft-heading change failed that compatibility test and was reverted.
Add the fixed draft label and clearer owner/date/suggestion labels only through
render_contextual_delivery_preview, outside canonical saved preview bytes. The
same material-question hold remains. Current private launcher uses this display
layer only after protected packet release; no raw invalid drafts are exposed.

Validation: 1,571 tests pass; Ruff and strict mypy (63 files) pass. Read-only exact
same-source preparation: 10,568 input + 3,200 reserved output, 16,384 window,
42,403 bytes. Actual selected encrypted evidence and full original-checkpoint
restore pass/clean up, no new Source/business writes, private generation or upload.
The prior three one-shot approvals remain consumed. The new aligned scope requires
fresh approval, not a replay. Model/profile/privacy/latency limits remain unchanged.

Briefing/private-interface requirements are prepared in the existing roadmap:
verified packet/state inputs with visible coverage and provisional open loops,
then authenticated private views/approval flows on the Mac host. No new competing
plan, source integration, remote deployment or persistent-agent control plane.


## D034AN — role requirements belong in the provider draft contract

D034AM's one approved attempt failed closed on CONTINUITY_RELATED after dispatch,
with verified failure recovery and no released draft. It revealed that instructing
the model to cite both roles was insufficient: the generic evidence array allowed
meeting-only continuity. Do not weaken the validator or append citations after
model output. The consumed approval cannot be replayed.

Use provider draft format zac-contextual-draft-v2. Host-qualified evidence IDs
include meeting or related role; continuity requires meeting_evidence_ids and
related_evidence_ids, each nonempty and at most two, at most four combined. Static role patterns
expose this distinction to providers without embedding volatile request IDs into
the schema. Host-owned catalog lookup and final role checks remain authoritative;
a matching pattern is not provenance, permission, entailment or usefulness proof.
Schema/roles remain bound by prepared consent across fresh task identities.

The v2 format is ephemeral proposed model output only. Canonical Review/Packet/
Zac Event contracts remain v1; saved prior packet bytes retain their existing
reader and digest behavior. Old provider draft shape rejects explicitly. No silent
migration, automatic repair, universal project mapping or expanded permissions.


D034AN validation and delivery evidence: every provider review section is required
explicitly, with empty arrays where justified. This prevents silent structural
omission; it does not prove factual completeness. A revised PUBLIC output passed
structure but omitted every material item, and Opus graded NEEDS_REVISION. That
failed rehearsal remains recorded. The required-section correction then returned
all five material items (hold, two promises, risk, unowned suggestion), both exact
owners/dates, dated background and source-supported continuity. Independent Opus
quality review: PASS, with minor repetition/date-anchor refinements retained for
human evaluation. No private prose was submitted to Opus.

Opus code review identified and resolved mismatched citation bounds, absent-history
schema/payload divergence and typed schema equality. Each continuity role has
1–2 IDs; no citable prior context constrains background/continuity to zero entries.
The runtime dispatches the exact consent-bound schema. Offline counting permits
only those two fixed shapes, rejecting bool/int substitutions and arbitrary schema
changes. A PUBLIC no-related rehearsal also preserves every material item while
returning background/continuity empty. Measured input matches reported input in
both PUBLIC cases: mixed 3,573 / output 1,216 / about 32 seconds; no-related 3,356 /
output 944 / about 27 seconds. These are bounded observed conformance, not proof
of impossible runtime violations or general usefulness. Host validation remains
mandatory even when grammar is ignored; forged IDs and wrong roles still reject.

Full suite: 1,595 passed. Final typed-gate refinements: 199 focused tests passed;
Ruff and strict mypy (63 source files) pass. Canonical packet golden bytes remain
unchanged. An earlier full run had one failure from simultaneous disposable-restore
checks; the isolated case and serial full rerun passed. Keep recovery verification
and restore-dependent test suites serial. No rule was weakened to pass a test.

Final read-only same-source preparation: 10,235 input + 3,200 reserved output =
13,435 <= 16,384; 43,349 bytes <= 64,000. Same six Source hashes, pinned local model,
120-second generation budget and BRAINSTORM/CONFIDENTIAL boundary; no private
model call, source-system read/write, consent, upload or fact promotion in preparation.
A fresh sealed one-shot decision remains required because the prior approved
attempt was consumed and the provider contract/instructions changed.

Final selected encrypted evidence/full original-checkpoint restore verified and
cleaned after test completion. Canonical state remains unchanged at 68 Sources.


### D034AN — approved real trial succeeded; usefulness review pending

Zac directly approved the exact sealed same-source one-shot on 2026-10-05.
Manifest SHA-256 6e6705a338fa265e0ee5101dce2879dc38740f8b085bd65119d27b1b6f9bfa98;
engineering code commit 06ee6e0d6bdc43ccc1298558bf0feeb5901c5657.
The consumed attempt began at 2026-10-05T12:19:25.029816Z. It completed with
PROTECTED_PRIVATE_DRAFT_NEEDS_HUMAN_REVIEW, verified encrypted recovery and
unchanged business state. Exact packet reloaded through canonical source ACLs;
re-rendered private display matches saved bytes. Structure: 4 overview, 2 background,
2 continuity and 12 items, no conflicts/clarifications. Counts are not recall,
entailment or usefulness proof. Canonical Source inventory is 75; no disposable
restore target remains. No automatic retry, source-system write, fact promotion,
external AI processing or wider intake. The previous failed attempts remain retained.

Packet SHA-256 2dab88966c0dfb44279237bebe7bd6dc60825cc0b0af621f8abed7b28e1e87cd.
Result sidecar SHA-256 87050568330b31c07fdc9c1504a880125438c29d6f4e12e7210054bf024aaf7a.
Private display SHA-256 0c603af0feb55bae257328ee0299b6ac1e5f3d3cd5ca9ce5ebe4bff93403eba8.
The private file is private-data/candidate-contextual-trial-draft-role-complete-2026-10-05.md,
excluded from Git. Opening in Codex was queued for this chat's Mac panel; this
is not proof of delivery/read/acceptance. Saved result retains delivery_recorded=false
and semantic_usefulness_verified=false. No private prose was sent to Opus/cloud.

Next input: Zac reviews actual project context, useful detail and voice. Do not
mark useful-v1 gate complete without that feedback. If changes are needed, use
targeted clarification and existing evidence; do not invent project/SOW standards.
After useful-review confirmation, proceed to bounded source-backed briefing/open
loops and then private text/mobile access in the established release order.


## D034AO — accepted useful review and first selected briefing view

Zac directly confirmed the protected D034AN result as a good starting point on
2026-10-05, requested nicely formatted/easy-to-understand delivery, and authorized
continuing. Record this as actual usefulness feedback, not ten independent rubric
PASS judgments or approval to promote every candidate fact. Preserve the accepted
original packet/result/display bytes. Formatting is a presentation concern, not a
new canonical memory or provider dependency. A later preference refinement does
not invalidate provenance or imply a universal project/SOW standard.

Implement render_selected_briefing as one pure offline HTML projection of an
already protected, source-ACL-checked contextual packet. Clear headings, mobile
viewport/wrapping, owner/date fields, candidate earlier context, provisional
connections and expandable numbered exact evidence. Retain every material item;
no automatic semantic deduplication, ranking, shortening or new model invocation.
Explicit coverage is one selected review plus its selected earlier context, with
other meetings/mail/calendar unchecked. Preparation/display time is not meeting
time. Dates from reviewed proposals never imply current completion or overdue
status. Suggested owners/dates stay suggestions; inferred content remains marked.
A material question/conflict holds all other claims and their evidence, labels
conflict vs missing context, and shows why the answer matters.

This is not an authenticated endpoint, publication authority, recovery gate,
daily-coverage assertion or complete briefing/open-loop engine. The trusted host
still checks retained protected receipts and canonical source ACLs before release.
Canonical Review/Packet/Zac Event v1 and saved preview bytes remain unchanged.
No new table, source intake, agent permissions, remote deployment or provider path.

Independent Opus review found three concrete presentation defects in the first
version (lost inference markers, ambiguous holds/conflict labels, overassertive
owner/date provenance). These were corrected and covered with regression tests.
Follow-up found no display-semantic blockers; vacuous assertions were corrected
and nested quote tamper tested. Final validation: 1,611 tests, Ruff and strict mypy
(64 source files) pass. Model-controlled markup is escaped; fixed CSS/CSP uses no
external assets/scripts. Code tests do not prove physical layout or Safari anchor
behavior. Browser policy blocked local-file visual preview; no workaround was
attempted. Visual mobile/print verification remains a release check, not a pass.

A read-only local projection of the accepted actual packet was saved privately
as private-data/selected-meeting-briefing-D034AO-2026-10-05.html, without exposing
private prose to cloud/Opus. The retained result hash and recovery receipt packet
binding were checked; canonical source ACLs refreshed. No new models, consent,
source/business writes or external delivery; Source inventory remains 75. Human
feedback and formatting preference are also retained in a private local sidecar.
These derived files can be regenerated from the protected packet and versioned
code; no separate new off-device protection claim is made for them.

Continue the existing release path: bounded current source coverage and reliable
commitment/open-loop status for the first daily briefing, then authenticated
private text/mobile views and approval flows. Existing Fireflies transport remains
selected-transcript-only; any listing/new capture capability must be concrete,
reviewed and approved before live use. Broader history, personal boundaries and
specialists remain staged. No automatic daily schedule is enabled.


## D034AP — ownership-oriented work briefing prototype

Zac clarified that a briefing should propose how Zac AI will get work done, not
just assign him a to-do list. Each proposal needs an outcome, concrete approach,
proposed method/action/destination and completion check, with four choices:
approve as proposed, approve with changes, review before shipping, or handle it
himself. Morning and evening serve distinct purposes and should be concise;
supporting detail stays expandable. This is a format/workflow requirement, not
a new daily schedule or blanket execution/source permission.

Add an offline work view to the existing selected-review renderer. WorkProposal
links an actionable commitment/follow-up by index to the exact canonical packet
digest; WorkPreference links to the entire exact proposal digest. They are
ephemeral presentation inputs, not new canonical tasks, approvals or execution
status rows. Changing outcome/steps/method/destination/check invalidates the old
preference. Changes require a revised plan/fresh preference; review-first does
not authorize shipping; self-handling does not prove completion. Missing plans
are explicitly unprepared and get no approval choices. Material context gaps
hold the work view and its prose. Quotes support the original item, not the
proposed approach. Existing owners are not reassigned to Zac.

Lead with outcome/first step and retain every step/method/destination/completion
check underneath expandable detail. Original review/context/evidence stays
available below; no business items are silently omitted. Completion is always
unverified in this prototype: no execution, completion observations, receipts
or durable lifecycle are synthesized. Fixed diagnostic text, HTML escaping and
exact packet revalidation remain in place. No controls are connected to dispatch.

The existing policy/gateway remain authoritative. Future execution must resolve
actual identities/destinations/routes, verify current ACLs and recovery, bind a
real authenticated approval to concrete actions, prevent replay/duplicates and
retain verified outcomes before reporting done. This presentation work fits
Phases 4/5 and previews the Phase 6 interface without enabling Phase 6 writes.
Canonical Event/Review/Packet v1 and original stored bytes stay unchanged; app
remains health-only. No source reads, private generation, credential access,
external delivery, persistent agent infrastructure or recurring automation.

Independent Opus bounded audit found a concrete blocker: planned inferred items
showed their inference label only in collapsed original-item details. Headline
now always retains the inference marker, with regression cases both with and
without a plan. Existing owner-from-review/suggested-owner/unconfirmed wording
is also visible on planned cards; self-handling never transfers ownership.
Opus follow-up reports no remaining blockers. Its conditional checks are
resolved: Contract is frozen and always revalidates, ContextualReview caps
items at 16 (matching proposal indices 0–15), and the integrated material-question
test holds the work cards. Whole-view rejection on stale preferences is intended,
not an implicit carry-over or silent drop. Approve wording matches Zac's explicit
requested choices, with preference-only/no-execution semantics for this prototype.

Two broader Opus CLI requests were stopped after prolonged no-output runs; they
are not counted as passed reviews. A minimal Opus availability check succeeded;
the subsequent bounded code audit and fix review returned actual findings. Only
code and invented fixtures were supplied, no confidential source/draft prose.
Mobile/print visual verification remains pending; generated invented HTML is an
offline prototype only, not proof of layout or authenticated delivery.

Final D034AP validation: 1,630 tests pass, Ruff passes and strict mypy passes
for 65 source files. Independent Opus blocker fixed and follow-up reports no
remaining blockers. No actual private work plan or new source/model run was
produced; this checkpoint is the offline proposed-work interface foundation.


## D034AQ — parallel foundation integration: work history, release and intake

Zac explicitly authorized coordinated parallel engineering while discussing
context homework. Three bounded tracks implement work observations, protected
briefing release composition and history-import preparation. They use the same
canonical state/provenance and existing roadmap; no persistent business-agent
workforce or competing memory/control plane is created. Root owns integration,
full serial tests, docs and Git; Claude Opus remains independent reviewer.

WorkJournal binds an exact WorkProposal and packet. Immutable ordered observations
retain reasons, source references, times, identifiers and a digest chain; reported
completion requires explicit reopening before later reports. Status is reported,
never VERIFIED_COMPLETE. WorkPreference is not authenticated approval. Append-only
snapshots reuse existing MANUAL Source/artifact storage with current ACL/hash/
classification checks. Prior snapshots remain available after reopening. Host
serialization and retained exact digests are required; there is no global latest
pointer, multi-writer reconciliation or trusted business-outcome verifier. Capture
does not commit, run recovery, issue execution authority or release private data.

Capture takes an aware trusted host clock, rejects future creation/report times
and evidence captured after its owning observation (or packet after journal
creation), and records actual host capture time separately from reported times.
Load rejects reports later than canonical capture. Digest/sequence/tip mismatches,
wrong boundaries, stale classification and material packet questions fail closed.
Exact-source provenance establishes observation lineage, not truth of its reason.
Observed time describes the host observation; original event time remains in
source context and is not inferred from journal capture time.

render_retained_briefing composes the existing ACL-refreshed exact packet loader
and renderer from an independently retained verified recovery receipt/digest.
Only BRAINSTORM/CONFIDENTIAL packets fit this existing receipt family. Packet
creation <= locator creation <= verification is intentional: the existing
protector mints the locator after packet capture/commit. Equality would reject
valid receipts. Exact packet bytes and renderer-owned work-plan/preference binding
remain enforced. Receipt shape/hash prove consistency only; authenticated identity,
current scope and independently established receipt origin are outer-host duties.
This is not an HTTP endpoint, session provider or enabled phone access. Existing
D025 loopback/Tailscale direction is retained; serving/session/privacy/log-rotation/
mobile visual release checks remain pending. No Serve/Funnel configuration changed.

History inspection validates a bounded trusted-host selection against original
opaque export bytes, exact hashes and nonoverlapping record spans. Original role/
time/order and account/provider IDs stay host declarations; previous matching
byte versions and changed IDs have separate candidate dispositions. No latest
version/complete-export claim, vendor parsing or source prose is returned. Required
boundary and classification scope plus LOCAL policy gate metadata release. Strict
UTF-8 manifests, unambiguous JSON, hash shapes and known chronology are checked.
Ownership/visibility/completeness/capture/recovery/fact-promotion properties are
fixed false. Whole-export mixed boundaries require a separately reviewed partition/
retention design; no silent split or attachment-path traversal. Imported historical
assistant suggestions/preferences remain candidates, not current user instructions.

Initial Opus audit found actual classification, mutable-readiness and time-control
gaps. Agent fixes cover those with invented regression cases. Its conditional
proposal-binding concern is already enforced by the existing renderer and tested
at release; its packet/locator timestamp equality suggestion conflicts with the
existing protection contract and is deliberately not adopted. Final review follows
with actual code and existing timestamp construction supplied. No private prose
was sent to cloud/Opus; agents accessed code and invented fixtures only.

Voice homework is retained in QUESTIONS.md: content options/backlog adapted to X
and LinkedIn, complementary company meeting lenses, proposal reuse with feedback,
premium design/motion reference GoCDG, optional tool-neutral 3D capability and a
future Brainstorm chief solution architect. These are project notes, not a claim
that all historical context is already imported into canonical Zac State. No live
company-wide Fireflies/X/Grok access, publishing, tool installation or agent
permission expansion is inferred from those desired workflows.

Final independent Opus follow-up found no concrete blockers. Nonblocking
limitations remain explicit: observation reasons/reporter identity require
trusted-host provenance and later outcome checking; hash-matched sources do not
prove semantic relevance. Reports currently persist/replay but are not yet wired
to the briefing status display. Source captured_at is the first host capture on
idempotent repeats. Failed canonical registration can leave an unreferenced
content-addressed artifact, governed by existing retention/recovery cleanup; a
savepoint does not roll back the artifact store. Source/classification revisions
need deliberate re-snapshot; branches need host reconciliation. As-of is a trusted
host display clock, not a client/model value. Receipt verifies historical recovery,
not today's completion or independently current remote object availability.

The existing receipt validator enforces locator.created_at <= verified_at; the
release seam additionally checks packet creation and host display ordering. The
renderer independently binds plan/preference digests before display. Canonical
roundtrip and retained earlier snapshots are tested. No auxiliary preference is
substituted for journal status. Explicit numeric-time hardening for the history
manifest is the final focused refinement before release.

Final D034AQ validation: 1,727 tests pass; Ruff and strict mypy (69 source
files) pass. Independent Opus follow-up reports no concrete blockers; final
explicit history datetime hardening and host/provenance wording were checked
with focused regressions and the serial full suite. No production data, live
source/model run, session, migration or deployment was performed.


## D034AR — protected cards and private-interface foundation

User-facing name is Caz AI; technical repository/package/Zac State/Event and
credential/storage identifiers remain unchanged. The user activated a continued
Goal toward the reviewed text-first iPhone trial with context gathering, dates,
coverage, provenance and one-at-a-time confirmation of material current facts.
This preserves Phases 4/5 and the existing wider roadmap; it does not declare v1
usable or complete. Voice remains the fast follow.

Reported-work journals now render with exact packet/plan binding, trusted host
as-of time and classification checks. Reports are not verified completion.
One-card rendering retains all original source items, labels proposed outcomes
separately, keeps material context questions as holds, and provides expandable
evidence. Work controls remain disabled presentation; no approval/execution
endpoint was created. Protected card release uses the independently retained
receipt/hash and fresh canonical ACLs, taking classifications only from the
BRAINSTORM scope. PERSONAL permissions cannot rescue a business denial.

Unmounted Google OIDC, persistent encrypted sessions and host enrollment are
implemented. Signed identity requires signature/audience/nonce/state/expiry;
both documented Google issuer forms normalize only after validation. Email or
Workspace administration grants no owner scope. Enrollment requires a short-lived
browser/Mac pairing code and exact host confirmation before producing a grant.
Separate bounded pending-login/user pools preserve authenticated capacity under
login floods; corrupt encrypted rows fail closed during identity revocation.
Exact Origin and session-CSRF protect logout; sign-in pages alone permit fixed
Google form navigation. Main runtime remains health-only/loopback; raw access
logging is disabled in its launcher without service restart.

Opus implemented reusable premium inline CSS and fixed Caz sign-in markup from
a bounded design brief; a separate invocation and helper independently reviewed
it. No scripts, remote fonts/assets, trackers or fabricated conversations. Native
radio/details behavior and print/contrast/motion fallbacks remain subject to
actual browser/iPhone/keyboard/print verification. Protected rendering permits
same-origin host logout without weakening default offline form denial.

PERSONAL drill code uses invented fixtures/throwaway keys and never reports real
intake readiness. A local full SQL rehearsal was independently checked and its
disposable target cleaned up. Shared nonblocking restore-target leases now cover
cooperating fixed-name helpers, schema/restore and the entire CLI drill composite;
nested operations reuse the validated owner connection. OID checks remain.
Noncooperating administrator SQL still requires an exclusive host window; this
is not hostile-DBA protection. The framing regression now tests parsing separately
and proves the public restore path refuses zacai_test before connection I/O.

Gmail original-byte/account/boundary inspection and fixed read-only Slack transport
and wire validation are offline preparation. No mailbox/Slack connection, OAuth
grant, source capture or historical-completeness claim occurred. Slack's low-level
seams still require the mandatory host boundary/classification/account gate before
live intake; Slack Connect and restricted channels cannot inherit a business
classification by assumption. Original private bytes are hidden from object repr.

The host startup seam selects only two proposed fixed SHARED Keychain entries,
uses no environment fallback, hides credentials from repr and sanitizes failures.
No actual credential was read or installed. Escrow/readback, native ACLs, exact
client/origin, stable owner enrollment and host/agent runtime separation remain
release gates. Separate PERSONAL uploader/encryption recovery/real off-device SQL
receipt are required before financial records; business consent/gates cannot be
relabeled PERSONAL.

Read-only setup verified the existing Mac Tailscale installation/self hostname;
Serve is unconfigured and Funnel is off. Google project/internal branding exists
and user MFA is enabled; web-client creation is awaiting specific approval. No
new client, public serving, network exposure, private model run or deployment.
Context inventories outside Git distinguish direct user decisions from stale
assistant checkpoints/example opinions, and locate seven checksum-matched Claude
proposal assets. These are not full exports or current-truth/canonical imports.
Provider readiness inventory records candidates and access/data-term differences
without changing model pins or creating accounts.

Independent Opus found substantive Origin/CSP, pairing, revocation, capacity,
source-vs-proposal presentation and restore-concurrency issues; corrections are
covered by focused regressions and actual-library mocked OIDC exchanges. Final
validation is recorded below after the serial suite completes.

Next: approved Google client/credential escrow, reviewed stable host enrollment
and private-only serving, real iPhone validation, gateway-backed conversation and
plan choices, bounded source/context intake and trustworthy completion checks.
Keep context/source gaps explicit; no numerical full-history coverage is claimed.

Final D034AR validation: 2,068 tests pass; Ruff and strict mypy (84 source
files) pass. Exact staged secret scan found no leaks. Independent Opus final
sign-in/startup follow-up reports no remaining concrete blocker in the shown
code. This is an engineering foundation verdict, not live authentication, full
context ingestion, usable mobile release or completion of the active Goal.
Library deprecation warnings remain documented upgrade work; no dependency
migration beyond the reviewed Authlib pin was attempted.


## D034AS — canonical draft choices and trusted private host composition

This checkpoint advances the existing Phase 4/5 private text delivery path;
Zac State remains canonical memory and provenance. Owner enrollment and browser
sessions are operational authentication state, not a second context store.
No new schema, Event contract, provider/model pin or roadmap phase is introduced.

Owner enrollment is now durably authenticated and bound to the exact Google
client and private origin. Missing, corrupt, wrong-key, revoked or old unbound
records fail closed; email/domain/admin status does not create scope. Explicit
local setup invalidates prior browser/OIDC sessions, including same-owner
re-enrollment. Composed owner revocation attempts session invalidation even when
owner persistence fails; partial failure requires stopping serving and trusted
local reconciliation. A failed durable write can leave a valid new record visible
without a successful acknowledgement. Neither rollback nor absence is promised.
HMAC/encryption cannot stop same-UID hostile code from replaying older files or
using host keys. Trusted launcher/runtime separation, safe filesystem ancestry
and stopping setup before owner serving remain operational release requirements;
these factories do not enforce a cross-process serving-mode lease or deploy TLS.

The new canonical choice path captures an exact authenticated host identity,
packet/recovery receipt, proposal fingerprint, request identity and preferred
approach. The four existing work choices remain draft preferences: as proposed,
with changes, review first and self-handle. They do not create executable approval,
agent permission, dispatch, publication or verified completion. Material questions
hold capture. BRAINSTORM/CONFIDENTIAL is the only initial protected choice family;
PERSONAL permissions cannot authorize or relabel business content. Request replay
is serialized; identical requests finish the same canonical append-only Source,
and conflicting replay cannot overwrite it. The host controller binds request
identity to owner/canonical packet/proposal across renewed forms, retains bounded
handles for reviewed retry and normalizes changes without introducing a new memory
store. A rotated receipt does not create a second conflicting choice; original
receipt provenance remains immutable and rotation requires explicit reconciliation.

A saved acknowledgement requires protection of the new committed choice, not
reuse of the old packet receipt. The concrete adapter reuses existing encrypted
artifacts, state snapshots, operational journal and disposable full restore.
Deterministic encrypted receipts are independently read back and never overwritten
when corrupt or mismatched. Shared reentrant maintenance-database/restore-target
leases and the existing operator lease remain intact. Choice loading releases its
initial SQL transaction before cold recovery, then uses a fresh READ COMMITTED
session for final owner, packet, Source, byte and ACL checks. Verification time
records completion; rollback checks and the successful journal run's aware
choice/start/finish/verification ordering remain enforced. Host capture/verification
and the controlled local PostgreSQL lifecycle timestamps share the same Mac clock:
no cross-host skew tolerance is granted. Clock rollback or inconsistent ordering
holds release. Python >=3.12 and actual PostgreSQL CSV timezone forms are exercised.

Historical recovery compares every restored frame/journal row and field, plus
all selected current Source columns and hashes, using an explicit complete
canonical column order independent of physical ALTER TABLE order. Both owned
read-only comparison transactions check actual public Source columns against
that complete list; ORM SQL names are checked too. Unknown/omitted fields hold
release. Selected-row COPY uses local UTC/ISO settings on both connections,
without changing historical snapshot framing/export. Unrelated new business records
do not invalidate historical recovery if those selected Sources are unchanged.
This optional verifier mode leaves existing full-current-business comparison
unchanged. Historical recoverability does not establish current context, work
readiness or completion; fresh selected ACL/packet gates still apply. Artifact
backup may repair/re-encrypt its stable plaintext-hash key. The immutable receipt
retains the initially observed artifact ciphertext checksum; current artifact
identity requires successful decryption and the exact canonical plaintext hash.
State/journal ciphertext-addressed pins remain exact. Full cold restores remain
repeated and serialized; no cached proof or performance readiness is claimed.
A failure after checkpoint upload can leave receipt-less state/journal objects;
failed Source registration can leave an unreferenced content-addressed artifact.
Trusted operator reconciliation and future reviewed garbage collection remain
necessary; this adapter does not auto-delete or broaden storage permissions.

Optional private owner host routes compose the retained plan controller with
current authenticated session, exact Host/Origin, CSRF, bounded unambiguous form
parsing and post-operation session/owner refresh. They remain explicitly injected
and unmounted in the default health-only app. Controller success means protected
draft preference saved, not work executed. A real text conversation, gateway
actions and mobile delivery are still pending. Optional routes have isolated
authenticated rehearsal coverage; final checkpoint validation remains pending.

Gmail transport now allows only fixed read-only profile/list/raw-message/history
HTTPS calls, with explicit host scope, account inspection, bounded responses and
closed errors. No proxy inheritance, redirects, arbitrary URL, automatic retry or
expired-history rescan authorization. The transport and Slack preparation were
exercised with invented replies only. Separately authorized bounded connected
Gmail/Slack research occurred and its coverage stays outside Git; it is not full
history ingestion or a Caz runtime connection. No runtime Gmail/Slack intake,
new source OAuth grants,
provider account creation, credential installation, private-source model disclosure, deployment
or iPhone validation occurred. PERSONAL intake remains closed pending its separate
uploader, recovered encryption identity and actual off-device state recovery.

Zac requested a progress bar. Delivery progress must reflect verified, agreed
v1 acceptance gates with visible evidence and pending holds, separately from the
larger architecture roadmap and engineering test/checkpoint counts. Do not invent
a percentage from files, elapsed effort or all roadmap checkboxes. Until the v1
gate denominator and measured acceptance are fixed, show named gate status and
unknown coverage honestly. Context gathering remains dated/source-backed and
one material question at a time; no full-history coverage claim is made.

A pure packet-follow-up contract is prepared for the next text-conversation
integration. It keeps existing Event/evidence/task envelopes and introduces a
distinct packet_followup capability, with concise cited answers, one targeted
clarification or an explicit unsupported outcome. Original evidence must
support business claims; user/parent/generated text is not interchangeable
evidence. Release requires a trusted host recheck of actual canonical Source
kinds, recovery, ACLs, relevance, freshness and semantic support. Declared
references and invented contract tests do not prove text capture or grant
processing consent. No runtime, concrete release gate or conversation route is
mounted.

Final D034AS validation: 2,428 tests pass in 98.46 seconds; Ruff and strict
mypy (91 source files) pass. Exact staged Gitleaks scan found no leaks.
Independent Opus and helper reviews identified and checked the corrections,
including slow capture acknowledgement, stable plan identity, actual Source
schema, evidence presentation and restored selected provenance. Actual guarded
SQL/age recovery used invented fixtures and local object clients; its narrowed
synthetic artifact inventory is not proof of production/B2 coverage. Three
existing dependency deprecation warnings remain.
This engineering checkpoint is not live authentication, usable conversation,
mobile acceptance or completion of the active Goal.

## D034AT — bounded conversation capture and host lifecycle

Continue the existing delivery sequence with canonical bounded packet questions,
not a separate chat memory or generic action agent. Preserve original text in a
USER_INSTRUCTION envelope; use the unchanged intelligence contract's explicitly
trimmed projection for inference and map citation offsets to the original.
Parent text is limited to selected direct turns for the same owner, conversation,
packet revision and receipt. It is historical context, not business evidence or
permission to replay ancestors. Recover pending parent bytes in the child's exact
dependency inventory; do not invent a parent recovery receipt.

Captured/protected questions and prepared requests grant neither model processing
nor execution. One-shot processing consent, actual local runtime dispatch, final
canonical/current-context and semantic release checks, and authenticated chat
routes remain separate integration gates. Do not repurpose a meeting-review
consent to authorize packet_followup. No external provider/private-source model
call is authorized by these code contracts.

Foreground enrollment and serving share one retained private lease file. On
shutdown, outstanding synchronous workers must finish before logging suppression
or the lease is released; unjoinable foreign threads remain a hold. Dedicated
foreground execution excludes pre-existing background threads. No timeout can
turn an incomplete recovery into a safe acknowledgement. Startup interruption
must cancel prepared enrollment and close the acquired lease. Forced process
termination is outside that lifecycle guarantee and requires reconciliation.

Each capture/protection adapter checks every observed clock against its local
watermark, and assembly uses the capture clock guard. Actual production composition
must share one trusted checked host-clock callable across components, rather than
wire one component's lock-owning method into another and risk lock inversion.
Component tests alone do not prove that future cross-component composition.
Final D034AT engineering checks passed; no live setup or iPhone acceptance
is asserted here.

Final D034AT engineering validation: 2,611 serial tests passed in 105.44 seconds,
with the same three dependency deprecation warnings. Final Ruff and strict mypy
(97 source files) passed; the annotation/offset-documentation precision changes
also passed all 14 assembly tests. Independent helper and Opus findings were
reconciled against real canonical contracts: duplicate Source context/provenance
remains invalid rather than silently deduplicated. Exact staged Gitleaks scanning
found no leaks; commit/push status is tracked against actual Git state. No live source/model call,
production migration, credential read, serving or iPhone acceptance occurred.


## D034AU — exact follow-up claims, retained generated replies and progress

Status: reviewed engineering checkpoint; no live owner/mobile acceptance.

Keep packet_followup distinct from contextual_meeting_review, including consent
Sources, exact local route capability, one consumed claim and original request
digest. The same observed host clock must be injected into the composed new
components. Reject future observation timestamps before committing authority.
Duplicate consent recording uses the existing immutable _write and returns the
same Source; it does not create another attempt or extend expiry.

A generated result remains a MANUAL Source, not USER_INSTRUCTION. Bind its exact
original claim, receipt references, user/packet/parents, source text, usage, draft
and display to an immutable attempt identity. Recover artifact plus canonical
state/journal before acknowledgement, then recheck current authority, owner,
access and independently recomputed release. Historical recovery is distinct
from a new inference or permission to display old outputs.

Opus review identified a real future-observation claim gap and pending recovery
after expiry. Correct them without extending processing authority. Conditional
duplicate-record replay concerns were checked against immutable _write and real
SQL idempotence/one-shot tests. Capability serialization is deliberately singleton;
no additional capability is silently introduced. Foreground Ctrl-C behavior must
be assessed against the actual private operator/Uvicorn path, not a raw injected
KeyboardInterrupt.

Owner requested a progress bar. Use the existing four acceptance gates, explicit
reviewed evidence/status/as-of and expandable next steps. The one accepted scoped
review is not complete daily coverage, deployed mobile access, a ten-case quality
rubric, or completion of the larger product vision. No invented effort estimate.

Real guarded SQL/age/local-client tests exercise original packet/user/claim/reply
records, full selected-row/state/journal recovery, leases and immutable retry.
Their authority recovery preflight and semantic usefulness remain explicit
invented fixtures; they are not production/B2/model readiness evidence.


Final D034AU engineering validation: 2,870 serial tests passed in 138.64
seconds, with the same three dependency deprecation warnings. Final Ruff and
strict mypy (105 source files) passed. Independent Opus/helper review corrections
include future-observation rejection, receipt-only pending recovery, original
record-before-expiry provenance and shared owner/view clock composition. The
actual SQL/local-age pending test recovers a timely committed reply after expiry
and canonical revocation, while active capture/load remain held. Authority
recovery preflight and semantic usefulness in that fixture are explicitly
invented; no production/B2/model/credential/listener/iPhone readiness is claimed.
Exact staged secret checks pass; commit/push are verified against actual Git.


## D034AV — authority durability is not processing permission

Canonical follow-up recording and claim acknowledgement require post-commit
recovery plus fresh active-authority checks. Failed committed attempts remain
consumed; historical repair yields only a recovery receipt. Share one exact
HostObservedClock between ledger and recovery, and check time after final owner
and cleanup callbacks. Owner/context callbacks must run outside recovery SQL and
restore leases. Initial recording lock is envelope-bound; subsequent active
acknowledgement shares the canonical Source lock used for cancellation.

The named Ask Caz action will require explicit protected canonical human-decision
provenance and a closed v2 consent reference, preserving original v1 history.
The current pure declarations cannot act as an issuer or replace actual session,
nonce, Source-kind/ACL/recovery/runtime checks. Generated replies remain generated
Sources, never relabelled human parent instructions or established business facts.

Use verified acceptance gates for the progress bar. It is protected presentation,
not canonical product state or permission, and does not estimate overall effort.

Final D034AV validation: 3,076 serial tests pass in184.03seconds; Ruff and strict
mypy (108 source files) pass. Named decisions retain original_observed_at so
cold restart need not infer a new request timestamp from a digest. Independent
code-only Opus review and helper reproductions guide the corrected clock/owner/
chronology checks. Actual local SQL/cold-restore drills remain explicitly bounded
fixture evidence; live off-device credentials/model/mobile acceptance is separate.

## D034AW — a retained named decision precedes the explicit v2 path
Status: Accepted implementation direction; production owner trial remains incomplete.

Retain the named processing choice as its own protected canonical USER_INSTRUCTION
Source, separate from the original question and generated reply. Bind the original
admission, actual protected question, published manifest, exact prepared request,
original observation and fixed expiry. The trusted authenticated controller owns
admission/nonce/session checks; a constructor or digest is never authentication.

Exact retries preserve the committed decision and its original time window. A failed
checkpoint withholds saved acknowledgement. Expired historical repair returns only
recovery evidence and does not grant active consent. V1 compatibility stays exact;
the distinct required v2 linkage has no permissive downgrade or automatic migration.
Actual v2 ledger/controller wiring remains a subsequent integration step.

The existing encrypted backup/restore engine owns decision recovery. The dedicated
receipt binds actual Source/inventory and independently pinned recovered-key evidence.
Fresh callbacks run outside SQL/restore leases and final canonical rows/time are
checked again before acknowledgment. The existing local follow-up transport now
bounds version/model/chat probes using one operation deadline; no legacy unbounded
version fallback is used in this path. No new cloud connection or agent privilege
is introduced by these engineering changes.

D034AW final validation: 3,295 serial tests pass in 230.24 seconds; Ruff and
strict mypy (112 source files) pass. Independent review findings have concrete
provenance/ACL/transaction/nested-DML corrections and regression evidence.
Trusted row adapters are not a general SQL-effects or hostile-host sandbox.
The exact named owner POST, v2 issuance and mobile acceptance remain subsequent
composition gates; test fixtures do not establish production authentication.


## D034AX — original authenticated action and explicit named-only recording
Status: Accepted implementation direction; engineering validation complete, owner trial pending.

Operational encrypted admission metadata supports restart and browser reuse,
but grants no permission by itself. The original authenticated owner session,
canonical protected question and separately retained named human decision must
match the published scope, immutable observation and fixed processing window.
GET reuse cannot dispatch or renew work. A valid original same-session pointer
may repopulate read-only cache after restart. Missing both pointer and cache may
lead to a fresh unconsumed action; it cannot retry an old consumed action.
Authenticated POST must separately match the exact published card, so another
tab changing a shared cookie cannot substitute a different displayed scope.

Named host composition explicitly enables named-only recording: reject new v1
consents and active v1 claim/recheck/reply consumption; preserve exact old v1
receipt bytes and historical ledger load/revocation/receipt-only repair.
V2 authority and reply protection require identical host clock and named binding
objects. Recovery callbacks run outside canonical SQL and restoration leases;
canonical rows/bytes/ACLs are reread after the last external callback.

New reply persistence is serialized against consent cancellation and checks
expiry/revocation again immediately before commit. Original replay timestamps
remain immutable. Receipt-only repair proves committed history and does not
renew inference or authorize external actions.

Terminal admission cleanup requires the actual host worker-drain guarantee.
No GET mutex, boolean constructor flag or shaped receipt proves that guarantee.
The installed persistence and closed v2 consumers do not yet mount submission,
model generation, Google owner sign-in, a network listener or phone acceptance.


D034AX final validation: 3,476 serial tests pass in 391.44 seconds, including
actual SQL/local-age v2 consent, one-shot claim, reply/reload and expired
receipt-only recovery under named-only mode. Ruff and strict mypy (115 source
files) pass. Independent Opus findings are reconciled with reproduced
legacy-consumption/cache regressions and explicit read-only restart semantics.
The exact staged scan passes without secrets; commit/push are verified separately.
Workspace-staged native submission, concrete bindings and worker lifecycle are
not installed by this checkpoint and remain required for an actual owner trial.


## D034AY — original scope, concrete proof lookup and actual host lifetime
Status: Implementation direction retained; release validation in progress.

Use exact independently retained packet/question/decision proof references and
actual canonical rows, not callback return shapes, as evidence. Runtime pins
cover the concrete reviewed local profile and serializer/tokenizer inventory.
Question-free display must use metadata-only profile verification, never an
invented FollowupRequest. Historical integrity permits receipt preservation
only; active original-session admission must be checked around long processing.

A native owner POST includes the exact displayed manifest digest. A shared
cookie changed by another tab cannot silently change the scope being approved.
New question admission is one-shot; an exception or reload does not redispatch.

Foreground owner-mode composition owns concrete sessions, grant, key and shared
clock. Worker lifetime drains before the existing retained mode lease is
released; an in-memory registration or shaped drain record grants no processing
permission. Enrollment stays isolated and cannot mount the question route.

Dated first-release acceptance remains distinct from current source access and
recovery proof. The progress bar counts accepted gates, never token effort or
completion of the broader vision. Physical iPhone acceptance remains required.


D034AY review reconciliation in progress: receipt-only history uses the concrete
canonical adapter's recorded pins, retained proofs and final canonical ACLs,
without probing today's runtime. Active processing still uses current runtime
verification and original admission; it cannot consume historical checks as
permission. Original question observation and processing deadline stay fixed.
Internal session proof checks use read-only authenticated observations rather
than refreshing idle activity; normal browser requests remain activity.

The process-wide submit lock covers only publication and atomic admission, not
long processing. Thread shutdown remains fail closed: no abandoned Python
worker or timeout releases the foreground lease early. Capacity/start failures
remain consumed held attempts requiring status review, not automatic retry.
A missing, malformed or expired POST pointer cannot issue a replacement action.
Historical read-only reply delivery, concrete production semantic validation,
actual processing deadlines and physical phone behavior remain subsequent
composition/acceptance gates.


D034AY corrected integration evidence: actual enrolled-owner store and native
HTTP GET composition pass together with disposable PostgreSQL/local-age full
State/journal restoration in 177.42 seconds. Invented Google identity and
runtime metadata remain explicit; no live identity, generation, cloud recovery
or phone usability claim follows from this fixture. Whole-tree Ruff, strict
mypy (124 source files) and diff checks pass; final serial suite and narrow
independent review remain running.

Display observations are bounded per-record digests and expiry only; decoded
parent text is fingerprinted transiently, never retained in that cache. Every
fresh display check performs actual recovery/runtime/session validation and
final canonical rows; a cache hit is not permission. The host requires the
concrete display gate and exact shared stores/clock. Expensive display checks
occur outside the short admission lock; the lock still rechecks original
pointer, actual ISSUED record, final rows and atomically consumes admission.
Completed worker retirement requires actual physical thread termination and
original expiry plus the authenticated operational-store cleanup acknowledgement.

Historical receipt integrity still depends on supported current serializers,
contracts and owner grants. Changes to those require explicit migration or a
hold, not silent compatibility assumptions. Before initial decision commit,
trusted construction supplies the original prepared request observation;
post-commit reconstruction preserves the stored observation. Pre-commit crash
reconciliation never authorizes automatic inference retry. Independent pipeline
capacity reservation, saved historical reply delivery, production semantic
release validation, representative latency and physical iPhone acceptance
remain subsequent gates in the existing roadmap.


D034AY further review findings reproduced before correction: ten regressions
failed for capacity consumption, cache-lock latency, foreign host bindings and
shutdown ordering; two existing host context faults already denied. Corrected
installed focused tests pass 112 cases in 5.15 seconds. The previous unchanged
serial baseline passed 3,671 tests in 616.54 seconds; corrected full-suite and
independent Opus review remain running, so this is not yet release evidence.

Native concrete worker composition now reserves bounded capacity before actual
SQLite admission. The reservation is transient correlation, never authority;
actual admitted scope/window transfers once. Failed admission releases capacity
only after an authenticated unchanged ISSUED read. Committed or unknown outcomes
remain held, never refunded/retried. Shutdown joins all physically started
threads before reporting any unstarted or reserved ambiguity. Display cache
locks cover bounded digest/expiry correlation only; recovery uses its separate
lease and final actual canonical bytes/ACL checks remain mandatory. Exact host
store/pointer key, context, clock and storage location are checked without
exposing secrets or initializing a comparison database.


D034AY lifecycle availability reconciliation: five additional regressions
reproduced known-unused expiry, admission-expiry reservation leakage, unrelated
cleanup denial, dispatch interruption and foreign-wrapper reservation transfer.
Two startup regressions reproduced lost-handle capacity and release of the
operator lock before a factory-created native worker terminated. Corrected
merged worker/store/host/operator focused tests pass 191 cases in 3.81 seconds;
installed display/helper concurrency tests pass 28 cases in 3.31 seconds. Ruff,
strict mypy (124 source files) and diff checks pass. Final serial regression and
independent lifecycle review remain running; this is not final release evidence.

The authenticated status API exposes original sealed operational metadata after
expiry solely for outcome reconciliation. It does not relax active get/admit or
return source text. An expired known reserved placeholder with no job can be
retired under the registry lock; uncertain Thread.start outcomes remain held.
Failed cleanup retains its exact slot rather than denying other free capacity.
Successful reservation dispatch does not perform unrelated retirement, and a
foreign wrapper cannot reconstruct missing original retained binding.

Graceful cleanup follows actual physical drain. Restart cleanup is private to
the actual owner-mode foreground operator after acquiring its retained flock,
validating current owner/key/context and requiring an empty open worker registry,
before exposing the app. Bounded authenticated expired rows matching the exact
current owner grant may be reclaimed by persisted digest. Active/unknown-scope
records remain, while corruption or oversized input aborts cleanup. Canonical
Sources, decisions, consumed claims and recovery proofs remain untouched. Deleted
expired operational metadata cannot dispatch, renew permission or replay work.
Failed startup joins newly created physical threads with logging/signals held
before releasing the actual lock; unrelated pre-existing threads are preserved.
This is controlled-process operational availability, not a same-user attacker
security boundary or a proof that production phone access is ready.

D034AY final lifecycle corrections: independent review exposed registration/
retirement clock ordering, generic calls consuming reserved placeholders, and
foreign-wrapper retention after denied dispatch. Original expiry is checked
under the registry guard; reserved-only transfer cannot allocate a missing job;
legacy wrapper retention and placeholder insertion are atomic. Generic direct
run/shielded-run cannot take a reserved placeholder. Read continuation accepts
authenticated question/decision attachments only when every original immutable
scope field and exact retained wrapper binding still matches.

Expired unchanged ISSUED outcomes are authenticated atomically inside admission
without a write. Missing, corrupt, consumed or uncertain outcomes never refund
capacity based on absence. Operator shutdown repeats the actual paired lifecycle
gate after physical thread drain so swallowed server-lifespan failure cannot
become success. Failure to install signal suppression cannot skip physical
drain; startup preserves unknown handlers and restores known ones separately.

The previous integrated serial baseline passed 3,733 tests in 615.67 seconds.
After the final reproduced lifecycle corrections, 261 focused integration tests
pass in 8.95 seconds; Ruff, strict mypy (124 sources) and diff checks pass.
A separate actual native-join interruption check passes against the existing
interrupt-safe drain helper. Final frozen-tree serial validation is still
running; independent conditional drain review is being reconciled against its
actual helper implementation. These are interim checks, not a release receipt
or evidence of live answers, source connections, Google credentials or iPhone
acceptance. D034AX remains the last committed validated release.

Final D034AY independent evidence reconciliation: Opus reviewed the actual
interrupt-safe physical drain helper and withdrew the conditional residual
shutdown finding (20.84 seconds, code review with tools disabled). A hypothetical
replacement helper that raises cannot reproduce the installed helper, which
re-enumerates actual native threads and catches interrupted joins/inventory.
The actual native-join interruption test passes. Independent lifecycle findings
are reconciled; frozen-tree serial validation and final secret scanning/commit
evidence still remain before release. No processing permission is granted by
this engineering review.

D034AY final release validation complete: the frozen integrated source passes
3,739 serial tests in 612.09 seconds (three existing dependency deprecations),
Ruff and strict mypy for 124 sources, plus diff checks. Independent Opus reviews
reconciled reproduced dispatch reservation, retention, expiry and shutdown
findings; the last conditional drain finding was withdrawn after inspection of
the actual helper and a passing native-join interruption check. Exact staged
secret scanning and the mandatory commit hook precede the authorized commit;
Git verifies commit/push separately. Earlier in-progress evidence above is
historical and is superseded by this validation result.

This engineering release supplies concrete host/runtime/source/recovery adapters,
optional native original-input question controls, the dated acceptance-gate bar
and actual bounded worker lifetime. Production question/semantic composition is
not mounted, Google client credential approval/setup and private serving remain
pending, and no physical iPhone trial has passed. No new live generation, broader
source import, personal financial intake, outbound message or credential was
enabled by this checkpoint. The existing first-usable gates and full roadmap
remain authoritative.


D034AZ interim integration — not a release receipt
The unmounted named question composition now binds the actual fixed local
profile/counter and performs its final combined canonical permission snapshot
after runtime/session/recovery callbacks. The final original session idle deadline
is carried through callback-free dispatch and result checks; no new expiry or
attempt is issued. Retained historical answers use current authenticated owner,
ACLs and original encrypted proof without new processing permission.

Integrated focused checks pass (176 dispatch/authorization, 148 history/session),
Ruff and strict mypy for 125 sources. Staged actual PostgreSQL concurrent elevation
and cancellation checks pass; the attempted deletion is correctly prohibited by
canonical Source append-only enforcement, and its corrected invariant test passes.
Combined final reply SQL checks pass (four actual concurrent elevation/revocation
cases plus the full encrypted graph); canonical pipeline reconciliation also
passes its actual current-session encrypted graph after original permission
expiry. Final Opus reconciliation review identified a pre-decode question
reference check and negative-test instrumentation gap; corrections precede
frozen full-suite validation.
D034AY remains the committed validated checkpoint. The separate reviewer-purpose
prototype is not mounted or authorized; independent findings about concrete proof
and single-dispatch ownership remain under correction. No live answers, new source
access, personal finance ingestion or phone acceptance is established here.


D034AZ reviewer recovery and historical-read review evidence (interim)
The dormant separate reviewer authority passes both actual local SQL/cold-encrypted
recovery cases, including protection failure followed by original-claim receipt
repair (2 tests, 90.65 seconds). The initial copied validation tree omitted the
unchanged canonical Alembic files; including those exact files corrected the
fixture rather than weakening restoration. This is disposable local recovery,
not live model invocation, owner review-purpose approval or off-device acceptance.

Historical reads retain the existing distinction between processing cancellation
and current owner data access: a retained, verified reply can carry an explicit
original-permission-revoked label only under the freshly authenticated original
owner grant, current canonical ACLs and exact protected provenance. Missing reply
proof returns text-free status, corrupt proof holds, and neither grants processing.
Named-only mode continues to reject new/active V1 processing while preserving the
previously recorded V1 history contract; canonical named reconciliation itself
requires exact V2 consent. Independent conditional V1-history concerns therefore
do not justify silently changing the existing historical ledger policy.


D034AZ final installed engineering validation
The frozen source passes 3,870 serial tests in 902.05 seconds, including actual
concurrent canonical ACL/cancellation checks and encrypted current-session
history/reconciliation. Three existing dependency deprecations remain. Ruff,
strict mypy for 126 sources and diff checks pass. Opus's reproduced pre-decode
question reference/ACL issue is corrected through the canonical turn reader;
negative retry tests explicitly record forbidden callback calls rather than let
caught AssertionError conceal them. Actual reconciliation asserts unchanged
Source count and backup-object hashes and denies a revoked replacement session.

This supersedes earlier interim validation status, not the remaining live release
gates. The production semantic pipeline remains unmounted; separate full-parent,
reviewer-child and genuine invocation capability work is staged and still requires
integration, independent review and actual acceptance. Google credential approval,
private serving, live useful results and physical phone trial remain unverified.
Exact staged secret scan and mandatory commit hook precede the authorized commit;
Git records commit/push separately. No broader source access, financial ingestion,
live generation or outreach is enabled by this release.


Active Goal delivery/context clarification — 2026-10-05
Zac requested that the v1 Goal include what is needed to finish and an explicit
memory/context plan. The existing Goal already includes those categories; the
ROADMAP Active Goal execution criteria section now makes their acceptance
concrete inside the existing four D034AC gates. Native Goal editing is not exposed
by the current agent status-only update tool, so this execution detail is retained
in the authoritative roadmap already referenced by the active Goal. No new Goal,
phase, source authority or completion percentage is created.

Usable release evidence must include actual private phone use, useful source-backed
text/review/briefing, protected retained results and a concise owner context review.
Source inventory, original evidence, confirmed-versus-provisional facts, time and
ACL-aware relevant retrieval, corrections and scoped feedback are required minimum
memory behavior. Full-history preparation continues alongside delivery and imports
follow existing gates; complete archives and specialist agents do not delay a
bounded v1 or become silently completed. Sensitive inventories and personal finance
remain outside engineering Git and in their separately protected boundaries.


Context-first delivery priority and writing direction (2026-10-06)
Zac explicitly prioritizes a verified context baseline and intelligent task
completion with minimal direction ahead of further prototype/interface work.
Continue the existing roadmap, preserving canonical Zac State/Zac Events,
provider neutrality, the external approval/credential gateway and separate
PERSONAL/BRAINSTORM recovery and permissions. Do not replace them with provider
memories or a competing context store. Native Goal objective editing is not
exposed by the available status-only tool; this current owner direction governs
execution and is retained in ROADMAP's priority clarification.

Current writing instruction: concise prose in Zac's voice, with no em dashes.
Sent-email examples and direct corrections guide generated delivery. Raw source
evidence stays intact; historical assistant drafts are not confirmed preferences.
Claude export intake and other source preparation do not authorize external
private-model processing, broad imports, outreach or financial actions.


Offline context preparation checkpoint (2026-10-06)
Add bounded ZIP metadata inspection and native Gmail/Slack artifact preparation
using existing history, policy, wire, SourceSystem and exact-byte hash contracts.
No new memory store, approval framework, provider grant, parser schema, runtime
mount or private inference is introduced. Preparation reports fixed-false capture,
recovery and completeness status. Raw provider evidence is distinguished from
decoded/canonical representations, and derivations pin exact originating wire
identities/hashes. Mailbox and Slack observation namespaces avoid false revisions.

Opus's concrete parser-allocation/ZIP64 differential and observation-provenance
findings were reproduced on predecessors and corrected before integration. Tests
assert forbidden constructor calls outside swallowed private-safe errors. Package
import adaptation preserves test function/class ASTs. Root validation:321 selected
tests, whole src/tests Ruff and strict mypy128 pass. This offline checkpoint does
not establish actual account authorization, canonical intake, full historical
coverage, current facts, useful task delivery or production/mobile readiness.


Local artifact isolation correction (2026-10-06)
Preserve the existing opaque ArtifactStore protocol and Source location contract.
Enforce canonical boundary-relative hash locations and descriptor-relative
no-follow operations, verify exact stored bytes and deny nonregular or multiply
linked files. Resolve the trusted configured root once for macOS alias support;
open directories before creating only missing ones. No schema, provider grant,
backup receipt, repair policy or orchestration framework changes. Existing
artifacts are not rewritten on an identical retry. Root installed validation:146 selected filesystem/context-preparation checks
and46 local encrypted backup/ingestion PostgreSQL regressions pass. Whole
src/tests Ruff, strict mypy128 and production-source secret scan pass. This is
local integrity and compatibility evidence, not new live off-device recovery.


Selected native evidence and retained proposal candidate (2026-10-06)
Reuse ArtifactStore, record_source, existing Source revisions and public native
wire/preparation codecs. Add no schema, memory store, provider grant or approval
framework. Writer results acknowledge successful nested savepoint exit only;
they remain uncommitted evidence references. Identical historical replay keeps
original dates and does not replace the current provider tip. A 32KB retained
proposal has its own MANUAL namespace and supports restart without original
caller input tuples. The subsequent inventory loader reconstructs provider
inputs from exact retained artifacts against the host-supplied approved bytes.

Public inventory recheck binds the hash-pinned batch envelope's control roles,
family identities, dates, ordered groups and false status flags, followed by
fresh complete Source/ACL scalar observations. It does not reparse provider
bodies or reread the approval body; complete original reconstruction belongs to
the loader. Matching hashes or caller-forged fingerprints cannot establish
authentication, processing permission, protected storage or current truth.

Retain existing bounds and canonical classification policy. A 256000-byte batch
envelope pre-put invariant is defense in depth; actual installed Gmail IDs are
bounded to 200 ASCII characters, so the previously proposed 3000-character-label
reachability example is invalid. No input widening or truncation is accepted.

Release evidence comprises 195 selected pure checks and 39 actual guarded
PostgreSQL cases, including four deliberately guarded administrative corruption
controls. The separate full encrypted reviewer trial failed before evaluation
retention after 952.59 seconds; one synthetic reviewer call succeeded, but final
retention/recovery acknowledgement remains unverified. No private source was imported and no live grant or route was enabled.


Complete native recovery selection (2026-10-06)
Add prepare_native_batch_recovery_selection to the existing native inventory
module; preserve every original module function and class AST and existing public
loader/verifier signatures. No schema, backup engine, native protection receipt,
permission framework or Source promotion is introduced. A recovery-labelled
selection must require the separately retained proposal Source; it cannot
silently use the earlier proposal-omitting native inventory alone. The proposal
may be retained later without restamping historical provider evidence.

Early closed tuple, UUID and bounded digest checks precede dictionary
materialization or private proposal reads. The proposal first binds supplied
batch/digest claims; the retained envelope subsequently verifies their actual
relationship. Complete final scalar observations include proposal and batch
namespace ambiguity, exact selected hashes, all Source columns and effective
ACLs. Same-system historical provider revisions remain legitimate. Fingerprints
compare current rows with the supplied loader snapshot; they are not unforgeable
original-load provenance or human authority.

Reuse the existing Source-driven artifact backup and State/journal restore
engines. Committed proposal Sources are already selected by boundary backup.
The complete selection specifies required exact UUID/hash/column coverage,
while byte presence and cryptographic restoration remain engine checks. The
metadata type retains false permission/recovery/fact/completeness flags even
when a synthetic recovery trial succeeds. No ambient registry or passing
protection callback is added.

Validation:76 pure controls and seven actual guarded PostgreSQL cases pass; the
latter include genuine local age-encrypted artifact/State/journal restore of
nine selected Sources. This is local synthetic acceptance, not off-device
durability, real recovered-key escrow, account authorization, private ingestion
or useful-output quality. The fresh-process whole-boundary SQL fixture remains
in engineering workspace staging rather than the ordinary full suite, where
other committed synthetic Sources can refer to unrelated ephemeral stores.


### Native projection preserves original evidence and creates a new task (2026-10-06)

Add one offline native_evidence_context module. Reuse retained native batch
loading, public provider parsers and the existing contextual serializer; introduce
no Source schema, memory store, provider route, model call or approval framework.
Selected context contains only exact provider spans. Host selection/relevance
and provenance dates belong to a noncitable metadata tuple, never synthetic
provider headers or omission bridges. Gmail support is exact UTF-8 RFC822, not
MIME body extraction or authored/sent-mail attestation.

Retain original_task and original_event without rewriting their canonical
identity. Generate distinct deterministic task/event UUIDs for the derived
context, binding the original task snapshot, selected text, ordered provenance
and metadata. Sort capability arrays and normalize all four metadata date fields
to UTC so equivalent instants and database connection timezones cannot change
those IDs. Source bytes/timestamps remain unchanged. Derived processing status
is NEW; original instructions/capabilities/budgets/correlation remain fixed.
Changing the original task snapshot, including its status, can change the
derivation identity. No old result or processing approval is adopted for it.

Validate real public inventory and every supplied-scope dependency before its
artifact read; preserve final callback-free Source/effective-ACL observations.
Actual serializer packing and quotation limits run before acknowledgement, with
no substitute parser or truncation. Pure cap negatives are not claimed to
discriminate every local check from independent serializer checks. The exact250
catalog positive/251 negative is a standalone serializer test, not a claim that
native output's64KB capacity can attain that overflow.

Local synthetic acceptance comprises49 new/129 combined pure checks and six
root-run cases (five actual PostgreSQL plus one smoke) in1.36 seconds. It proves
projection/inventory/identity checks under those fixtures, not human/account
authorization, off-device durability, real recovered keys, private import or
model-output quality. Keep the dedicated copied-tree SQL fixture in engineering
staging; install its five pure test modules without duplicating conftest or
standalone committed-store setup into the ordinary suite.


## D034BC - Native context V2 and bounded Claude metadata inspection

2026-10-06. Retain original Task JSON and exact ordered dependency roles in the
native request/packet derivation. Reconstruct the full identity-preserving
Source union, reject role/hash conflicts, mirror producer classification and
UTF-8 capacity bounds, and retain untrusted metadata separately from quotes.
None-proposal projection remains a structural preparation API; V2 admission
requires a retained proposal. A Source or supplied original Task does not
authenticate a human instruction or grant model processing. Genuine V1 bytes
and one-attempt admission remain separate.

Native assembly rechecks current canonical Source fingerprints, effective ACLs
and base/project relationships after reads. Concurrent retraction/association
withdrawal or ProjectHead version change holds. Root416 pure and10 real
PostgreSQL checks passed; Opus source-only review separately accepted the final
semantic correction. These checks do not prove useful private output or live
model readiness.

The Claude indexer is metadata/span inspection only. Preserve exact original
bytes and whole-file integrity hash; no record hashes as unnecessary guessing
oracles. Missing nonzero parent IDs remain explicit unresolved gaps. Present
invalid parent relationships hold. Conversation/message cross-kind collision
rejection is a conservative closed compatibility rule, not a vendor-wide UUID
namespace claim. Dates and assistant statements remain historical evidence.
Byte/lineage gate flags never imply existing selection or account completeness.
70 invented controls passed; final executable AST equals the independently
reviewed64-case predecessor. No actual archive application or new processing
permission occurs in this release.

Large-original custody/selection and native retained binding, consent, runtime
and protection are still required joins. Do not disguise chunks as complete
exports, misuse supersedes_source_id for derivation, weaken legacy caps or
assume a saved reader credential establishes PERSONAL recovery.


### Bounded local artifact reads for historical intake, October 6

The concrete local filesystem store exposes an optional exact bounded read.
It validates caller bounds, confined location, regular file, single link and
observed size before reading at most observed size plus one byte. Complete
length, post-read metadata and content hash must match. Growth, truncation,
links and cancellation never fall back to the existing unbounded read.
Existing store methods and protocol retain their executable behavior.

The separate100MB ceiling does not raise history selection or encrypted
recovery limits. This method proves point-in-time byte integrity only, not
Source rights, custody, account ownership, recovery or processing approval.
Independent Opus review requested size-based allocation; four invented
predecessor controls failed and the corrected89-case filesystem suite passed.
No actual archive is imported or read by this change.


### Claude whole-original selection metadata, October 6

A closed source-specific companion validates exact whole-original hash and
length, selected original IDs, roles, dates and UTF-8 byte spans. It does not
reserialize or truncate the export. Scope is one reviewed private boundary;
SHARED is refused. Known selected creation/update dates cannot follow the
declared export date. Account/reference/export dates remain host declarations,
not verified acquisition or ownership. Incomplete lineage and existing V1
selection limits stay unchanged. The separate100MB preparation bound does
not authorize large records or raise existing capture/recovery limits.

All nine inspection permission/proof flags are fixed False under ordinary
construction/replacement. The object remains forgeable trusted-code metadata,
not a security capability. No existing processing gate accepts it as approval.
Opus accepted the narrow corrections; root verified256 combined structural
and filesystem controls, including47 unchanged V1 history controls. Actual
whole-original custody, Source enrollment, current ACLs, encryption recovery
and fact promotion are separate unmet gates. No private export is read here.


### Retained native preparation and complete recovery inventory, October 6

Retain the exact preparation body and a separate closed dependency header,
using canonical Sources and existing artifacts. Header selectors contain no
question, instruction or relevance prose. Recheck current dependency rights
before body reads, and bind full canonical rows, original task/observation,
both own records and base/project relationships. A missing or changed pair
holds without repair or reminting. Caller owns the outer transaction and rolls
back after HOLD. READ COMMITTED checks are observation windows, not a claim
that concurrent administrative changes are impossible.

Genuine meeting/project selections contain 14/15 Sources: existing 12/13 plus
the preparation body and dependency header. Neither own record is processing
consent. Inventory flags remain false and no existing host treats it as an
approval or cold-recovery receipt. Current Claude indexer/companion and bounded
artifact reader are preserved; no schema, legacy limit or active route changes.
Independent Opus accepted the exact delta. Root current 139-source acceptance
passed 476 native/legacy pure, 153 installed compatibility pure and 12 actual
PostgreSQL cases. Full encrypted artifact/State/journal/key recovery and native
consent, canonical claim and useful-answer acceptance remain separate work.

Installed validation additionally passed 120 pure/database checks, with
configured mypy139 and Ruff clean. No private source was used.


### Large-original age resource control and child ownership (2026-10-06)

Keep the original age APIs and production limits unchanged; expose additive bounded helpers only. Own a fresh child session and retain its unreaped PID until the final group signal. On Darwin use kqueue exit observation; accept zombie-only EPERM only with an exact fixed-size libproc inventory proving the unreaped leader is the sole group member. Unknown host inventory, permission errors, output overflow or deadline failure hold. Hosts must exclude arbitrary-child reapers, private traceback-local capture and untrusted plugins that escape groups, change credentials or leave background descendants. Cleanup is not containment. Return fixed public errors while preserving caller exception-context limitations. Whole-original sizes, canonical custody, independent encryption escrow and actual remote artifact/State/journal recovery require separate accepted scopes; this library grants none.
