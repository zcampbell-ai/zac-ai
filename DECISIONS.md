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

## Open Decisions
These choices have not yet been made:
- Application language and framework
- Database and search/retrieval technologies
- Local model runtime and specific models
- Cloud models and account configuration
- First read-only integration and its authorization method
- Event transport and workflow execution mechanism
- Secrets storage implementation
- Backup destination, schedule, retention, and recovery targets
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
