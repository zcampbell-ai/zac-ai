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
