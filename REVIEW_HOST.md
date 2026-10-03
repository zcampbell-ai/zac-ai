# Bounded review host

D034G implements `execute_review_shadow` as a one-attempt operator library.
It is not an enabled service or CLI. Real authorization, runtime and protection
backends remain to be implemented and verified before a private trial.

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

935 guarded synthetic tests pass, including real PostgreSQL isolation and
separate committed audit visibility, generation/protection-time label changes
and revocation, terminal failures and exact input-size boundaries. Ruff and
strict mypy pass. No actual private inference or production migration was run.

Next implement the explicit trusted adapters using the existing gateway,
benchmark transport and backup/recovery mechanisms. Verify them synthetically,
prepare actual state restore evidence and protected migration procedure, then
present the exact private trial scope for approval. Do not substitute mock
recovery/authorization or treat general filesystem access as processing approval.
