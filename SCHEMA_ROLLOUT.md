# Protected schema 0005 rollout

Status: preparation only. No live schema migration, fresh B2 upload or private
model processing is authorized by this document. Continue the existing D034
roadmap; schema 0005 supplies reviewed meeting/project associations and their
retractions. It does not rewrite immutable Meeting.project_id values.

## Scope and rehearsal

The live Mac Studio database is `zacai_dev`, currently at 0004. A read-only
inventory check on 2026-10-03 found canonical state only in BRAINSTORM. Recheck
before rollout; a new PERSONAL/SHARED inventory requires its own recovery coverage.

`scripts/rehearse_schema_rollout.py` is an explicit operator rehearsal. It reads
one current BRAINSTORM snapshot into bounded memory, restores it into guarded
`zacai_restore_test` at 0004, upgrades that populated copy to exactly 0005 and
compares every original field. The two new association tables must be empty.
It then downgrades the disposable copy to 0004 and requires an identical export.
The disposable database is removed before success is recorded. Run only in an
exclusive recovery window relative to legacy restore tools.

The 2026-10-03 rehearsal passed all three comparisons using current real
BRAINSTORM state. The disposable target was removed and live state stayed at
0004. This proves the populated-copy transition and empty-table rollback;
it does not replace a fresh off-device backup before the live upgrade.

```sh
.venv/bin/python scripts/rehearse_schema_rollout.py
```

No private text or snapshot hash is printed. The private receipt is saved outside
Git with mode 0600. No plaintext export file, upload, inference or canonical write
occurs. PostgreSQL temporarily holds the recovered private state. Operational
artifact_backup_run history is outside the canonical boundary export inventory;
this rehearsal does not verify restoration of that journal or a whole database.

## Procedure to finish before requesting the live decision

1. D034N completes the pre-context recovery verifier and denial-audit wiring,
   verified with invented state: recovery/authority failures stop local selected-
   context reads and model dispatch and produce durable metadata-only denials.
   Keep its real-store wiring explicit and within the approved operator scope.
2. D034O completes the exact live operator procedure and independent Claude review.
   Pin the Git revision and migration 0005; do not use a moving `head`. State
   which database and tables change and which recovery evidence is required.
3. Present Zac one concrete scope: a fresh encrypted BRAINSTORM state backup in
   the existing B2 state prefix, independent retrieval/full disposable restoration,
   followed by the pinned schema upgrade and verification. Include local recovery
   coverage for the excluded operational journal (D034O now encrypts, uploads
   and independently restores it as a separate payload). Broader history ingestion and
   private model processing remain their own decisions.
4. After that approval, use an exclusive write window. Recheck schema/boundaries,
   protect the current state and verify recovery before modifying `zacai_dev`.
   Stop on changed scope, missing coverage or failed comparison; do not proceed
   using the older D033C snapshot as if it were a current backup.
5. Apply only migration 0005. Verify the exact new revision, both new tables,
   their boundary constraints/append-only triggers, empty initial inventories,
   preservation of existing canonical rows and operational journal, and existing
   local health checks. Do not create reviewed project associations in this step.

## Rollback boundary

The rehearsal covers rollback while both newly added tables are empty. Before
any live downgrade, explicitly verify that condition and that no other writes
occurred during the protected window. Downgrading after association/retraction
records exist would discard that evidence: stop and prepare separately reviewed
recovery instead. Production restoration is not provided by the disposable-only
restore tools, and must never be attempted by bypassing their target guards.

Any failure leaves the workflow paused for operator investigation. No automatic
retry, authority renewal, production restore or wider access follows from this
procedure. A successful rollout still does not approve a private meeting review.

## D034O concrete operator scope

Preparation only. `src/zacai/schema_rollout.py` and
`scripts/protected_schema_rollout.py` implement the proposed operation. The
command defaults to proposal output and does not load credentials or touch a
database. Its explicit execute mode requires a private human-approved JSON scope
supplied by the trusted operator; it does not issue approval itself. Approval
pins the clean Git commit, exact migration-file SHA-256, `zacai_dev`, human
reference and an active lifetime of at most 15 minutes. A digest of the stripped unique human approval reference is consumed before
credential loading. Re-encoding timestamps, whitespace or changing pins cannot
reuse that human consent. Every newly approved attempt requires its own reference.

1. Capture schema-0004 BRAINSTORM canonical state and the complete
   `artifact_backup_run` operational journal in one read-only repeatable-read
   snapshot. Deny any other boundary's state or journal rows. Bound state at
   64 MB and journal at 4 MB; keep plaintext in memory. Require explicit port
   5432 and recheck actual server address/port/database. Pin table resolution to
   public, then pg_catalog, with temporary schemas last. Deny unexpected public
   tables before protection and after the upgrade.
2. Using the existing BRAINSTORM age key and scoped Mac Keychain B2 credentials,
   encrypt both separately and upload exactly two new objects to
   `zac-ai-brainstorm-backup` under `BRAINSTORM/state/<run UUID>/`: the canonical
   ciphertext hash and `journal-<ciphertext hash>`, each with an `.age` suffix.
   No bucket changes, listing, deletion or artifact upload. The explicit host
   disables SDK request retries; the workflow never retries automatically.
3. A separate object client verifies sizes and ciphertext/plaintext hashes,
   then restores both recovered payloads into guarded `zacai_restore_test`,
   compares every original field, verifies required Source hashes and journal
   boundary, and removes the disposable database. This does not prove
   whole-machine, application-credential or other-boundary recovery.
4. Remote operations and disposable recovery hold **no live write locks**.
   Once verified, briefly lock all original canonical tables,
   `artifact_backup_run` and `alembic_version` in SHARE mode, using NOWAIT and
   a rollout advisory lease. This pause affects whole tables, including writers
   for other boundaries. Stop if another writer prevents the lock. Compare the
   current canonical state and journal against the exact protected snapshot;
   any intervening change cancels the upgrade rather than silently refreshing it.
5. Inside that same externally owned PostgreSQL transaction, run exactly 0005;
   require its two association/retraction tables to be empty and verify columns,
   keys, composite boundary foreign keys, label checks, append-only triggers,
   revision, every old canonical field, full journal and database responsiveness.
   Recheck approval and code before commit. PostgreSQL transactional DDL rolls
   back a failed validation before commit; no automatic downgrade is performed.
6. Record a private mode-0600 receipt under Git-excluded `private-data`.
   STARTED precedes remote work, PREPARED requires actual verified recovery,
   and APPLIED follows commit. Failure or ambiguous final commit/receipt is
   FAILED_OR_UNCONFIRMED: inspect both receipt and live schema before any newly
   approved attempt. Encrypted orphan objects may remain on failure.

The trusted operator selects an exclusive recovery window: no concurrent legacy
restore drills or application/schema administration. Receipt/approval parents
must be owner-controlled and mode 0700. Approval files are owner-only, bounded,
and read without following symlinks. Their contents are trusted operator records,
not requests accepted from agents or retrieved meeting text.

Proposal-only command, safe before approval:

```sh
.venv/bin/python scripts/protected_schema_rollout.py
```

Only after actual fresh human consent, the trusted operator writes a mode-0600
approval file in `private-data` with `target_database`, `code_revision`,
`migration_hash`, `human_reference`, `approved_at`, `expires_at` and invokes:

```sh
.venv/bin/python scripts/protected_schema_rollout.py --execute --approval /Users/brainstormzac/zac-ai/private-data/schema-rollout-approval.json
```

No approval file has been issued for this operation. Success adds two empty
tables; reviewed project evidence and the bounded private meeting trial remain
separate subsequent steps. The existing D034M rehearsal and recovered-key proof
remain useful evidence, but neither authorizes this fresh upload or migration.

D034O validation: 1,077 tests pass with two existing dependency deprecation
warnings. Ruff and strict mypy pass across 44 source files. Claude's independent
review found no blockers. The rehearsal/test evidence establishes the mechanism;
the proposed fresh real off-device backup and live upgrade remain unexecuted.

Fresh failure-focused Claude review additionally found three low-severity
hardening issues: re-encoded approval replay, incomplete initial receipt logging
and ambient default-port redirection. Each was corrected with regression tests.
Explicit schema resolution and public-table inventory checks also remove the
reviewer's two unverified assumptions. If storage persistently refuses writes,
a failure receipt cannot be guaranteed; the attempt remains terminal with no
remote work or migration after an initial receipt failure.

Claude rechecked the corrections with no blockers. Read-only metadata confirmed
no unexpected public CREATE grants in either local dev or test database. The
exclusive operator window assumes schema administration stays paused; the claim
ledger is local to this controlled Mac and human references are issued uniquely
by the trusted operator. It does not authenticate arbitrary agent-supplied text.
