# Bounded review host

D034G implements `execute_review_shadow` as a one-attempt operator library.
It is not an enabled service or CLI. D034H adds an explicit local runtime adapter; actual
recovery and protection backends remain to be verified before a private trial.
D034J supplies the canonical authorization ledger described below.

## Operator inputs

Use a fresh PostgreSQL engine-bound session factory, the existing ArtifactStore,
exact canonical Meeting/Source selections, optional explicit reviewed project
associations, current boundary/classification permissions and an approved route
registry. Selection remains a trusted operator responsibility; project identity
alone does not prove contextual relevance. Agents and source text cannot supply
permissions, adapters or approval records.

The three mandatory adapters have no permissive defaults:

- Authorization: verify operator scope and recovery before artifacts are read;
  durably consume one-shot human authority bound to selected evidence, effective
  labels, route, exact model digest and expiry; reject replay and recheck
  revocation. Its backend must audit pre-context denials because no truthful
  canonical review task exists yet at that point.
- Runtime: verify actual locality and exact model digest, enforce full serialized
  input/output capacity and transport deadline, make one call, return the existing
  ReviewDraft contract. No tools, external fallback, retries or implicit clipping.
- Protection: verify recovery coverage for committed audit Sources and their
  canonical state/artifacts, or fail. Fake test adapters prove orchestration,
  not real authorization, model locality or backup recovery.

## Sequence and output

Fresh read-only REPEATABLE READ snapshots assemble and refresh evidence. Audit
Sources are committed in separate transactions before generation. The host checks
route registration/eligibility and the existing gateway, claims authority, checks
freshness and revocation, generates once, resolves quotes, then checks freshness
and authority again. It commits draft-validation metadata and verifies protection,
then checks freshness/authority once more before returning an unevaluated draft.

One transcript may contain at most 18,000 characters; combined meeting context
remains capped at 24,000. Project/quote limits are unchanged. The runtime must also
check serialized prompt capacity. Oversized inputs reject rather than truncate.

ShadowReviewResult includes the draft, exact context and committed audit Source
IDs. It is not semantic PASS or fact/action approval. Use REVIEW_EVALUATION.md and
the existing evaluator for independent exact-draft judgments, then ask Zac for
feedback on delivery. Source-supported quotes alone do not establish good
interpretation, context, completeness or usefulness.

## Failure and operating limits

Invalid quote references, changed/retracted evidence, revoked/expired authority,
late output, audit commit failure or failed protection releases no successful
draft. Failures after authority claim consume that attempt. There is no retry or
model fallback. Exceptions expose fixed diagnostics, not private/backend text.
Failure audits are attempted; inability to commit one is a terminal failure.
Durable audits and orphan artifacts can remain under the existing D030 rules.
No deletion or approval renewal occurs automatically.

Read snapshots close before model/protection work. Checks at boundaries do not
create a global lock against concurrent changes after a read. Trusted runtime
and route declarations are not proof against hostile Python adapters or
infrastructure. The 120-second request lifetime is rechecked throughout; a slow
protection step can cause an otherwise valid draft to expire.

## Verification and next slice

967 guarded synthetic tests pass, including real PostgreSQL isolation and
separate committed audit visibility, generation/protection-time label changes
and revocation, terminal failures and exact input-size boundaries. D034H adds mocked runtime pin/binding/token
capacity/usage checks and a runtime-through-host audit integration, and scope denials that stop runtime
metadata calls before authorization claim. Ruff and
strict mypy pass. No actual private inference or production migration was run.

The shared local runtime adapter requires an exact local prompt token counter
bound to its model digest. It checks complete serialized capacity before metadata,
reserves output within 8,192 tokens, and rejects runtime input usage disagreement.
D034K supplies the narrow installed-model counter described below; ordinary
unit-test counters remain invented.
Calling the adapter directly grants no permission. It is not an enabled service.

Next implement and verify the recovery/protection
adapters using the existing gateway and backup/recovery mechanisms. Verify them synthetically,
prepare actual state restore evidence and protected migration procedure, then
present the exact private trial scope for approval. Do not substitute mock
recovery/authorization or treat general filesystem access as processing approval.

## Canonical authorization ledger (D034J)

`CanonicalReviewAuthorization` implements the authorization seam with canonical
Source artifacts. A trusted operator records actual human consent through
`record_review_consent`; the library cannot authenticate a chat approval and
ships no issuer endpoint. Consent binds exact evidence and generation request,
selection metadata, local route/model pin and an expiry of at most 15 minutes.
The host commits one durable claim before dispatch. Concurrent claims serialize;
revocations share that lock and remain append-only. Rechecks bind the same run
and reject current revocation, expiry, corrupt artifacts or recovery loss.

Consent/revocation Sources are USER_INSTRUCTION; consumption is MANUAL. Their
artifacts are included in the existing BRAINSTORM backup inventory and canonical
state snapshots. Inventory coverage is not proof of an actual encrypted restore.
The mandatory recovery adapter must verify current state, artifact and credential
recovery evidence and audit pre-context denials. No actual backend is included.
Historical imports and agents must never write these reserved review authority
namespaces or translate old conversational approvals into current permission.

Fifteen guarded synthetic authorization tests verify the ledger and host seam,
including actual concurrent database claims and backup boundary coverage. Claude
review found no blockers. No live approval or private inference has occurred.

## Verified tokenizer backend (D034K)

`OllamaQwenReviewTokenCounter` loads the hash-verified tokenizer/config blobs from
an explicitly pinned installed qwen3.8:27b-mlx manifest. Counting stays offline;
it includes the exact schema-bearing messages and the supported built-in
no-thinking renderer's markers/prefix. It supports only two text turns, no tools,
images or alternate modes. Padding/truncation are disabled. Original files are
reverified on each count; changed files fail closed.

The mandatory `LocalPromptTokenCounter.verify_runtime` compatibility method uses
metadata only. This backend accepts only the source-verified Ollama 0.35.1 version;
the runtime invokes it before and after generation. Runtime upgrades require
conformance re-verification. Requests explicitly set truncate=false and shift=false.
Per-attempt reported input usage must still equal the offline count exactly.

Install the optional backend with `uv sync --extra local-review`. Reproduce the
PUBLIC invented conformance check with:

```sh
.venv/bin/python benchmarks/tokenizer_conformance.py --models-root /Users/brainstormzac/.ollama/models
```

All three cases passed with exact counts (1,211 / 1,076 / 2,706 tokens). This is
observed compatibility for the tested cases, not proof of semantic quality or
permission for private inference. No enabled service or model download is added.
1,027 synthetic tests, Ruff and strict mypy pass with the local-review extra.
Real recovery/protection verification and concrete private scope approval remain.
