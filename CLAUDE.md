# Zac AI - Claude Code Instructions

## Mission
Build Zac AI as a vendor-neutral personal and business AI operating system for Zac Campbell.

Zac AI must own the durable state, memory, workflows, permissions, and history. No single model, interface, or orchestration framework should become a permanent dependency.

## Core architecture principles
- Zac AI is the system of record for AI state and orchestration.
- ChatGPT, Claude, local models, and future models are interchangeable intelligence providers.
- OpenClaw may be used as an orchestration component, but Zac AI must not depend on OpenClaw-specific storage or logic.
- Mac Studio is the initial always-on private compute node.
- Personal and Brainstorm data must have separate trust boundaries and permissions.
- Important facts and conclusions must retain source provenance.
- Preserve temporal history. Do not overwrite important historical states without versioning.
- People, companies, projects, opportunities, commitments, and decisions are first-class entities.
- New integrations should begin read-only unless explicitly approved otherwise.
- External or destructive actions require approval unless explicitly whitelisted.
- Secrets must never be committed to Git.
- No credentials, tokens, passwords, private keys, or production secrets in source files.
- Use environment variables or a proper secrets mechanism.
- All important actions must be logged.
- All new functionality must have tests where practical.
- Significant changes must be validated in development/staging or shadow mode before production use.
- Do not silently change architecture decisions.
- Document meaningful architectural decisions in DECISIONS.md.
- Prefer simple, modular, replaceable components.
- Optimize for reliability, security, observability, and maintainability before autonomy.

## Interfaces
Zac AI must support:
- Manual text chat
- High-quality natural voice conversation
- Approval/action views
- Mobile and desktop access

Voice must be a replaceable provider layer. GPT-Live-1 may be the initial provider if it provides the best conversational quality and value, but the system must allow Gemini Live, ElevenLabs, or future providers to replace it.

Voice does not own canonical memory.

## Model routing
The model router should eventually support:
- Fast local model for filtering, classification, extraction, and routine processing
- Stronger local model for private/general reasoning
- OpenAI models for high-value general reasoning when appropriate
- Anthropic models and Claude Code for technical and coding work
- Future models without architecture changes

Track model quality, latency, and cost by workflow.

## Core systems planned
- Zac State
- Brainstorm State
- Source-backed knowledge layer
- Event-driven ingestion
- Identity resolution
- Temporal/versioned memory
- Commitment engine
- Notification prioritization
- Approval/action gateway
- Evaluator/checker layer
- Outcome feedback loops
- ROI and performance scorecards
- Disaster recovery
- Staging and shadow mode
- Data classification and policy enforcement
- Specialist agent workforce
- Brainstorm knowledge and standards library
- Proposal/SOW/sales-material generation

## Planned integrations
Initial:
- Gmail
- Google Calendar
- Google Drive
- Slack
- Fireflies
- ClickUp
- Salesforce

Future:
- iMessage/SMS with explicit sensitive-data controls
- X/Twitter and other social intelligence sources
- Optional Muse integration
- LinkedIn publishing
- HeyGen avatar/video output
- Additional systems as needed

## Autonomy policy
Progress gradually:
1. Observe
2. Analyze
3. Recommend
4. Draft
5. Act with approval
6. Selective autonomous execution only after demonstrated reliability

Never expand permissions automatically.

## Self-improvement
Zac AI may eventually propose improvements to its prompts, workflows, agents, and routing.

Changes should follow:
Builder -> Tests -> Evaluator -> Staging/Shadow -> Human approval -> Production

Do not allow uncontrolled self-modification of security boundaries, permissions, or production infrastructure.

## Development behavior
Before making significant changes:
1. Read ARCHITECTURE.md
2. Read SECURITY.md
3. Read ROADMAP.md
4. Read DECISIONS.md
5. Confirm the requested task fits the current architecture

Keep changes focused and reversible.
