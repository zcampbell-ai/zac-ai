# Zac AI

Zac AI is a personal and business AI operating system for Zac Campbell.

It is designed to maintain durable personal and Brainstorm context,
understand activity across connected systems, track commitments,
prepare useful work, and execute authorized actions safely.

## Current Status
Phase 0: Project Foundation.

The private GitHub repository has been cloned to ~/zac-ai on the
Mac Studio. The architecture, security policy, roadmap, and initial
decision log have been populated.

Application implementation and runtime operation are not yet verified.
This repository currently documents the intended system; it does not
yet establish that the planned capabilities are working.

Use ROADMAP.md for detailed progress and verified completion.

## Start Here
- CLAUDE.md: standing instructions for Claude Code.
- ARCHITECTURE.md: the full system blueprint and long-term scope.
- SECURITY.md: data handling, trust boundaries, and action permissions.
- ROADMAP.md: phased implementation and completion tracking.
- DECISIONS.md: accepted architectural choices and open decisions.

Before making significant changes, read all five documents.

## Core Principles
- Zac AI owns its canonical AI state, memory, and history.
- Models, interfaces, and orchestration providers remain replaceable.
- Personal and Brainstorm data have separate trust boundaries.
- Important facts and conclusions retain source evidence.
- Important historical state is preserved rather than silently overwritten.
- Integrations begin read-only unless explicitly authorized otherwise.
- External actions pass through a central permission and approval gateway.
- Secrets never belong in source code, Git, or logs.
- Reliability, security, and recoverability come before expanded autonomy.
- Build one useful, verified capability at a time.

## Intended System
The Chief of Staff control plane coordinates:
- Zac State and Brainstorm State
- Working, state, historical, and procedural memory
- Source-backed knowledge and identity resolution
- Event ingestion and cross-system context
- Commitments, decisions, open loops, and notification priorities
- Specialist workflows and artifact generation
- Model routing and cost tracking
- Approvals, action execution, and outcome verification
- Evaluation, feedback, scorecards, and controlled improvement

Text and voice are equal first-class interfaces. They share state,
history, tools, permissions, and routing.

See ARCHITECTURE.md for the complete design.

## Planned Integrations
Initial sources:
- Gmail
- Google Calendar
- Google Drive
- Slack
- Fireflies
- ClickUp
- Salesforce

Future scope:
- iMessage/SMS with explicit sensitive-data controls
- X/Twitter and other social intelligence
- Optional Muse
- LinkedIn publishing
- Optional HeyGen avatar/video output
- Broader Brainstorm intelligence with role-based access

Being listed here does not mean an integration is connected or authorized.

## Compute and Providers
The Mac Studio is the initial always-on private compute node.

The planned model router supports fast local models, stronger local
models, approved OpenAI and Anthropic models, and future providers.

Specific models, APIs, and infrastructure choices require verification
before adoption. OpenClaw is an optional orchestration candidate.

No provider or interface should be the only place canonical memory,
permissions, business rules, or historical state exist.

## Development Workflow
1. Read the project instructions and current roadmap.
2. Select one bounded task in the active phase.
3. Inspect the existing implementation before changing it.
4. Record meaningful architectural choices in DECISIONS.md.
5. Make focused changes.
6. Run relevant tests and verify the intended behavior.
7. Document limitations, configuration, and recovery steps.
8. Update ROADMAP.md only for work that has been verified.
9. Review changes for secrets and private data before committing.

Significant production changes follow the review, testing, staging,
and approval requirements in SECURITY.md.

## Local Repository
On the Mac Studio, enter the project folder with:

    cd ~/zac-ai

Inspect pending changes with:

    git status

### One-time setup: local secret-scanning safeguard (D022)

Before making any commit, install Gitleaks and point Git at this repo's
versioned hook directory (both are local, one-time steps every clone needs -
see RECOVERY.md):

    brew install gitleaks
    git config core.hooksPath .githooks

This makes every `git commit` run `gitleaks git --staged` against the staged
diff first and blocks the commit if a likely secret is found. See
`.gitleaks.toml` and DECISIONS.md D022 for how allowlisting a known false
positive works.

### Application (Phase 1 minimal health-check app)

Dependencies are managed with `uv` (see DECISIONS.md D020). Install them with:

    uv sync

Run the app (binds to `127.0.0.1` by default; see `src/zacai/config.py` for
Tier-0 settings):

    uv run zacai

Runtime mode is explicit and defaults to `development` (see DECISIONS.md
D021). Set `ZACAI_ENVIRONMENT=production` to run in production mode; only
`development` and `production` are accepted, and any other value fails
startup rather than being silently accepted. Only `development` mode ever
reads a local `.env.development` file:

    ZACAI_ENVIRONMENT=production uv run zacai

Verify it is running:

    curl http://127.0.0.1:8000/health

Stop it with `Ctrl+C` in the terminal running it, or:

    lsof -tiTCP:8000 -sTCP:LISTEN | xargs kill

Run tests, lint, and type checks:

    uv run pytest
    uv run ruff check .
    uv run mypy src

Logs are written as structured, redacted JSON to stdout (see
`src/zacai/logging_config.py` and SECURITY.md/DECISIONS.md D017).

## Secrets and Private Data
Keep credentials and private operational data out of this repository.

A private GitHub repository is not a secrets store.

Configure Git exclusions before staging files. Review staged changes
before every commit. Do not commit local backups, databases, private
exports, logs, or files containing credentials.

See SECURITY.md for the complete policy.

## Backups and Recovery
Git version control protects committed project files.

Operational databases, private state, configuration, and secrets need
appropriate separate backup and recovery procedures.

Document these procedures and test restoration as the runtime is built.

## Immediate Next Steps
- Verify this README.
- Update the roadmap to reflect verified foundation documents.
- Inspect repository status and configure Git exclusions.
- Review, commit, and back up the foundation documents.
- Install and configure Claude Code.
- Begin one bounded implementation task from the roadmap.
