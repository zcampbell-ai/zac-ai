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
2. Prepare the exact live operator procedure and independent Claude review.
   Pin the Git revision and migration 0005; do not use a moving `head`. State
   which database and tables change and which recovery evidence is required.
3. Present Zac one concrete scope: a fresh encrypted BRAINSTORM state backup in
   the existing B2 state prefix, independent retrieval/full disposable restoration,
   followed by the pinned schema upgrade and verification. Include local recovery
   coverage for the excluded operational journal. Broader history ingestion and
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
