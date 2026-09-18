# Zac AI Architecture

## 1. Purpose

Zac AI is a personal and business AI operating system for Zac Campbell.

Its job is to:
- maintain durable personal and Brainstorm context
- understand current state across connected systems
- process events continuously
- identify what matters
- track commitments and open loops
- prepare and execute work safely
- route tasks to the best available model or tool
- minimize the amount of information Zac must manually review
- preserve evidence, history, and decision context
- support both manual text chat and high-quality voice interaction

Zac AI must remain independent of any single AI model, interface, or orchestration framework.

---

## 2. High-Level Architecture

User Interfaces
- Zac AI text chat
- Zac AI voice
- approval/action interface
- mobile interface
- desktop/web interface
- optional ChatGPT interface
- optional Slack or other quick-command surfaces

        |
        v

Zac AI Core
- Chief of Staff control plane
- task and workflow orchestration
- permission enforcement
- notification prioritization
- context assembly

        |
        +--------------------+
        |                    |
        v                    v

State and Memory        Agent Workforce
- Zac State             - Chief of Staff
- Brainstorm State      - Communications
- Knowledge layer       - Meeting
- Temporal history      - Sales / CRM
- Entity graph          - Project / Delivery
- Commitments           - Research / Strategy
- Decisions             - Artifact / Proposal
- Relationships         - Personal Admin
- Procedures            - Technical / Builder

        |
        v

Model Router
- fast local model
- strong local model
- OpenAI models
- Anthropic models
- Claude Code
- future models

        |
        v

Tools and Data Sources
- Gmail
- Google Calendar
- Google Drive
- Slack
- Fireflies
- ClickUp
- Salesforce
- browser
- local files
- future iMessage / SMS
- future X / social feeds
- future Muse
- future LinkedIn
- future HeyGen

---

## 3. Canonical State

Zac AI owns the canonical AI state.

ChatGPT, Claude, OpenClaw, and local models do not own the master memory.

### Zac State
May include:
- preferences
- goals
- relationships
- personal logistics
- communication style
- recurring routines
- decisions
- commitments
- open loops
- operating preferences

### Brainstorm State
May include:
- people and roles
- clients
- prospects
- partners
- services
- pricing
- projects
- opportunities
- proposals
- delivery status
- sales status
- company decisions
- operating procedures
- strategic initiatives
- AI systems
- technical standards

State must be source-backed where practical.

---

## 4. Entity Model

The following should become first-class entities:

- Person
- Company
- Client
- Prospect
- Partner
- Project
- Opportunity
- Meeting
- Message
- Document
- Task
- Commitment
- Decision
- Event
- Proposal
- Relationship
- Agent Action

Identity resolution should connect references across systems.

Example:
Josh McCoy in email, Salesforce, Fireflies, and documents should resolve to one person entity when confidently matched.

---

## 5. Event Layer

Zac AI should become event-driven.

Examples:
- new email
- Slack message
- Salesforce opportunity change
- ClickUp task change
- meeting completed
- document created or modified
- proposal sent
- client response
- calendar event changed
- agent action completed

Every event should ideally include:
- source
- timestamp
- related entities
- event type
- importance
- confidence
- provenance
- processing status

The event layer should allow Zac AI to react without waiting for Zac to ask.

---

## 6. Memory Architecture

Use multiple memory types.

### Working Memory
Current conversation, task, documents, and active context.

### State Memory
What is currently believed to be true.

### Historical Memory
What happened previously and how state changed over time.

### Procedural Memory
How Zac and Brainstorm do things:
- communication style
- proposal standards
- approval rules
- escalation patterns
- sales processes
- operating procedures

Important historical state should be versioned rather than overwritten.

---

## 7. Knowledge and Evidence Layer

Important claims should retain provenance.

Examples:
- source email
- Slack message
- Fireflies meeting
- Salesforce record
- ClickUp task
- Drive document
- user instruction

Zac AI should prefer evidence-backed conclusions.

For important judgments, store:
- conclusion
- confidence
- supporting sources
- contradictory evidence if relevant
- timestamp

---

## 8. Commitment Engine

Track commitments across systems.

A commitment should include:
- who committed
- what was promised
- to whom
- due date if known
- related entity
- source
- status
- confidence

Examples:
- Zac promised a client a follow-up
- Eric promised pricing
- client owes approval
- employee agreed to investigate something

The system should proactively surface at-risk or overdue commitments.

---

## 9. Notification Prioritization

The system should minimize interruptions.

Priority classes:
- Urgent: interrupt Zac
- Important: include in next briefing
- FYI: summarize later
- Noise: process and retain without surfacing

The notification model should improve based on Zac's behavior and feedback.

---

## 10. Approval and Action Gateway

All external actions should pass through a central approval system.

Action risk levels:

Low risk
- may eventually execute automatically

Medium risk
- normally requires approval

High risk
- always requires explicit approval

Examples of sensitive actions:
- sending external email
- deleting data
- modifying contracts
- changing financial records
- spending money
- modifying credentials
- publishing externally

Every executed action should be logged and verified.

---

## 11. Agent Architecture

The Chief of Staff is the primary control plane, not merely another specialist agent.

Initial specialist agents may include:

### Chief of Staff
- priorities
- daily state
- open loops
- decisions
- delegation
- approvals
- coordination

### Communications Agent
- email and Slack analysis
- drafts
- follow-ups
- response tracking

### Meeting Agent
- transcript processing
- decisions
- action items
- commitments
- CRM/task updates

### Sales / CRM Agent
- opportunities
- stale deals
- follow-ups
- proposal status
- CRM hygiene
- pipeline intelligence

### Project / Delivery Agent
- blockers
- delivery risk
- deadlines
- scope
- client sentiment
- project health

### Artifact Agent
- proposals
- SOWs
- sales decks
- case studies
- one-pagers
- reports

### Research / Strategy Agent
- market research
- competitive intelligence
- industry signals
- strategic analysis

### Personal Admin Agent
- personal calendar
- travel
- reminders
- personal logistics

### Technical / Builder Agent
- implementation
- coding
- Claude Code orchestration
- testing
- integration development

Agents should be invisible to Zac whenever possible. Zac interacts with outcomes, not agent mechanics.

---

## 12. Brainstorm Knowledge and Standards Layer

Maintain separate categories:

### Facts
- services
- capabilities
- team
- pricing
- case studies
- partnerships
- project history

### Standards
- brand
- tone
- proposal structure
- SOW structure
- pricing presentation
- approved language
- legal boilerplate
- claims policy

### Exemplars
- best proposals
- best decks
- best SOWs
- best emails
- best discovery documents
- best case studies

Artifacts should use relevant facts, standards, and exemplars before generation.

Outputs should be evaluated for:
- accuracy
- unsupported claims
- pricing consistency
- brand consistency
- scope consistency
- legal/commercial language
- source support

---

## 13. Model Routing

Zac should not have to choose models manually.

The router should select based on:
- task type
- quality requirement
- latency
- privacy
- cost
- tool capability
- current availability

Intended pattern:

Fast local model
- classification
- extraction
- routing
- filtering
- routine processing

Strong local model
- private analysis
- summaries
- normal reasoning
- large-volume background work

OpenAI
- difficult general reasoning
- research
- high-value synthesis
- voice where appropriate

Anthropic / Claude
- coding
- technical analysis
- implementation
- architecture work

Model performance should be measured against real Zac AI workflows.

---

## 14. Voice and Text Interfaces

Voice and text are equal first-class interfaces.

### Voice
Initial preference:
- GPT-Live-1 if it provides the best conversational experience and acceptable cost

Voice provider must be replaceable.

Potential alternatives:
- Gemini Live
- ElevenLabs
- future providers

Voice does not own canonical memory.

### Text
Zac AI must support manual text chat from:
- laptop
- phone
- browser
- future native app

Voice and text must share:
- history
- state
- permissions
- tools
- agents
- model routing

---

## 15. OpenClaw

OpenClaw may be used as an orchestration component.

Do not:
- store canonical identity only inside OpenClaw
- store irreplaceable business logic only inside OpenClaw
- make Zac AI dependent on OpenClaw-specific storage formats

OpenClaw should be replaceable.

---

## 16. Security and Trust Boundaries

Personal and Brainstorm data should be logically separated.

Data classes should include:
- Public
- Internal
- Confidential
- Highly Restricted

Data classification should influence:
- model routing
- storage
- retention
- agent access
- external API access
- logging
- approvals

Highly sensitive information should not automatically be sent to external models.

---

## 17. Staging and Shadow Mode

New workflows should follow:

Development
-> Test
-> Shadow Mode
-> Approval Mode
-> Production
-> Selective Autonomy

Shadow mode means the AI observes and predicts what it would do without actually taking the action.

Compare:
AI recommendation vs actual Zac decision.

Use results to determine reliability before expanding autonomy.

---

## 18. Evaluator Layer

Important outputs should be independently checked.

Evaluator responsibilities may include:
- factual consistency
- source support
- permissions
- security
- completeness
- policy compliance
- artifact quality
- action safety

Builder and evaluator should be separate roles where practical.

---

## 19. Self-Improvement

Zac AI may detect weak performance and propose improvements.

Example:
- Meeting Agent misses commitments
- Builder proposes change
- tests against historical meetings
- evaluator scores performance
- change enters staging
- Zac approves deployment

Never allow unrestricted self-modification of:
- security boundaries
- production permissions
- credentials
- approval rules
- critical infrastructure

---

## 20. Feedback and Outcomes

Track:
- Zac approvals
- Zac rejections
- edits
- ignored recommendations
- completed actions
- downstream outcomes

Use this to improve:
- prioritization
- routing
- communication
- recommendations
- automation confidence

---

## 21. Scorecards

Measure:
- hours saved
- commitments caught
- follow-ups generated
- important messages surfaced
- CRM updates completed
- meetings processed
- proposals generated
- risks identified
- actions approved
- actions rejected
- false positives
- agent failures
- local inference volume
- cloud API cost
- revenue influenced where measurable

---

## 22. Disaster Recovery

The system must be recoverable if:
- Mac Studio fails
- database corrupts
- model provider disappears
- OpenClaw is replaced
- credentials rotate
- local model changes

Requirements:
- version-controlled code
- backed-up databases
- reproducible infrastructure
- documented configuration
- restorable knowledge
- secrets stored separately
- no critical state existing only in one vendor

---

## 23. Future Communication Sources

### iMessage / SMS
Planned future source.

Requirements:
- explicit sensitive-data controls
- source provenance
- identity resolution
- temporal history
- permission restrictions

Do not prioritize initial implementation.

---

## 24. Social Intelligence

Future sources may include:
- X / Twitter
- social feeds
- industry signals
- optional Muse
- future social intelligence providers

Social data should inform:
- research
- trend detection
- relationship intelligence
- content ideation
- Brainstorm strategy

Social providers should not become canonical memory.

---

## 25. LinkedIn Publishing

Future LinkedIn Content Agent should use:
- Zac voice
- Brainstorm strategy
- social intelligence
- X/Twitter signals
- industry developments
- historical posts
- content performance

Initial workflow:
Research
-> Draft
-> Evaluator
-> Zac approval
-> Publish

Autonomous publishing only if explicitly authorized later.

---

## 26. HeyGen / Avatar Video

HeyGen is a future optional output provider.

Potential workflow:
Social intelligence
-> Content idea
-> Script
-> Zac approval
-> HeyGen avatar video
-> Final review
-> Publish

HeyGen must remain replaceable.

---

## 27. Brainstorm AI Operating System

Zac AI may eventually become the prototype for a broader Brainstorm AI operating system.

Potential role-based intelligence:
- Sales Intelligence
- Delivery Intelligence
- Engineering Knowledge
- Leadership Intelligence

Access must be role-based.

Zac's personal data must not automatically become company-wide knowledge.

---

## 28. Cost Philosophy

Optimize total value, not minimum API spend.

Preferred pattern:
- process high-volume routine work locally
- retrieve only relevant context
- cache stable results
- avoid reprocessing unchanged data
- use expensive frontier models selectively
- track cost by workflow and agent
- set budget alerts and limits

---

## 29. Build Philosophy

Build incrementally.

Each phase should create useful value.

Avoid large rewrites and unnecessary complexity.

Prefer:
- modular components
- clear interfaces
- testability
- observability
- security
- reversibility
- vendor independence

The goal is not to create many agents.

The goal is to create a reliable AI operating system that understands what is happening, knows what matters to Zac, prepares work, routes tasks intelligently, asks for as few decisions as practical, executes permitted actions safely, and verifies outcomes.
