# Bounded review host

D034G implements `execute_review_shadow` as a one-attempt operator library.
It is not an enabled service or CLI. D034H adds an explicit local runtime adapter; actual
pre-context recovery wiring was then still pending. D034N implements and tests
the read-only recovery gate and host-owned pre-context denial record below;
approved real-store wiring and fresh protected rollout remain pending.
D034L supplies the concrete protection adapter described below.
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
  revocation. The host separately records pre-context denials because no truthful
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

Those pre-context mechanics are now implemented and verified synthetically in
D034N. Next finish the exact live operator procedure, including excluded
operational-journal recovery, and present the fresh protected schema rollout
decision. The exact private trial scope follows separately. Do not substitute mock
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
recovery evidence. D034N supplies the explicit recovery adapter and the host-owned
pre-context denial journal; no service or live scope is enabled.
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

## Full recovery protection (D034L)

BrainstormReviewProtector checks the three committed audit stages in host order,
canonical consent/claim bindings and current Source hashes/labels. It backs up
artifacts with the existing mechanism, independently retrieves/decrypts required
records, encrypts one consistent boundary state export under the existing state
prefix and verifies its remote ciphertext/plaintext hashes. Full disposable DB
restoration and every-field comparison must also succeed before draft release.
The host still refreshes source permissions/freshness and authority afterward.

The actual DisposableStateRestoreVerifier is mandatory. It refuses a connected
disposable target, leases its own calls and cleans up before success. Operate in
an exclusive recovery window relative to old drill tools. No plaintext export
file is written; the temporary PostgreSQL database does contain recovered state
until cleanup. Real stores/keys require approved host wiring and trial scope.

1,035 guarded synthetic tests pass with the local-review extra. Claude found no
blockers. Separately, the prior real D033C B2 snapshot passed full restoration and
was removed without canonical writes, uploads or model calls. This proves that
specific snapshot, not current-state protection or whole-machine recovery.
A freshly recovered 1Password copy also passed decryption and full restore; its
temporary file was removed and clipboard cleared without displaying secrets.
At D034L, pre-context recovery/denial audit, fresh protected schema rollout and
exact private trial/context consent remained; D034N completes the first mechanics.

## Pre-context recovery and denial records (D034N)

BrainstormReviewRecoveryGate requires an operator-pinned current encrypted
checkpoint, an independent verification client, a functional local backup
identity, the hash-pinned private receipt of its prior independent recovery and
the actual disposable restore verifier. It supplies no credential loader, upload,
issuer or permissive default. Receipt/reference matching alone cannot pass:
every call retrieves/decrypts the earlier escrow-verification object and the
separate current checkpoint, verifies the public recipient, independently
retrieves required selected/dependency artifacts and performs full restoration.
The shared normalized-envelope decoder identifies raw/account dependencies;
canonical metadata identifies reviewed project confirmations/supporting Sources.
It constructs no task/context packet and reads no local selected artifacts.
Decrypted backup bytes are used locally for recovery only, never sent to a model.

The recovered-key receipt is trusted operator evidence of the prior password-
manager exercise. Fresh cryptographic checks bind the currently usable local key
to that object. This verifies backup identity escrow/readiness, not all application
credentials, B2 key escrow or automated access to 1Password. Real off-device
durability still requires explicitly configured approved independent remote
clients; local test objects prove mechanics only.

The current business tables and every original checkpoint Source field must
match in fresh read-only snapshots. Additional Sources alone are allowed to avoid
the consent/claim/audit cycle; every required Source must exist in the recovered
checkpoint. New/changed business rows, labels, retractions or project versions
require a new checkpoint, even if the change is unrelated to this selection.
A schema downgrade cannot silently omit recovered association evidence. No
authority/audit prefix is used to ignore arbitrary business rows. Post-run
protection captures the review's new consent/claim/audit Sources separately.

This conservative one-attempt implementation fully restores on all five recovery
checks; remote/admin work can be slow and the existing 120-second request lifetime
still applies. No caching, retry, renewal or weaker fallback is introduced.
Snapshots close before restoration. These checks reduce races, not globally lock
canonical state against concurrent writers or hostile administrators.

Before a context packet exists, the host records ReviewPreContextAudit with its
real attempt/run UUID, timestamp and fixed rejection stage. It creates no task,
context digest, selected Source IDs, error text or permission grant. Owned
BRAINSTORM/CONFIDENTIAL metadata commits in a separate transaction and joins
existing artifact/state backup inventory. A missing journal permission or failed
write/commit is terminal audit-unavailable, never a fabricated durable record.

Twenty new guarded tests cover the gate and denial journal. No actual private
gate invocation, new B2 upload, live migration or model processing occurred in
D034N. The full regression and independent review results are in DECISIONS.md.


## D034AJ candidate context and explicit larger local profile

The contextual host accepts an exact ResearchReviewSelection in addition to the
legacy ReviewSelection. Candidate Sources use pinned envelope/record/field hashes
and explicit Unicode-code-point ranges; unknown fields and altered scope reject.
The host preserves original Event dependencies and refreshes the same projection
before dispatch and release. Import permission alone does not approve processing.
Candidate identity and dated metadata remain unconfirmed; interpretation and
status/parent/list fields are absent from the projection.

The additional MANUAL artifact hashes must recover and exist in the restored
checkpoint before context reads. Successful and failed packet recovery keep this
same scope. The named mac-loopback-contextual-16k profile is bound by the consent
route and fixed to 16,384 for the pinned qwen3.8:27b-mlx. Default remains 8,192;
byte ceiling remains 64,000. The real PUBLIC probe with 1,600 output reservation
matched 11,773 input tokens and completed in about 60 seconds. It proves runtime
conformance only. Exact proposed private evidence/profile/route approval and
semantic evaluation are still required; no service is enabled.
