# Zac AI Recovery Architecture

Status: BRAINSTORM raw artifact recovery is real-off-device verified (D031B).
The approved D033C encrypted state snapshot has now also been retrieved from B2,
fully restored into a disposable database, compared on every row/field and removed
(D034L). This is specific-snapshot recovery evidence, not a fresh-state backup,
whole-Mac rebuild, credential escrow completion or private processing approval.
PERSONAL/SHARED have not run equivalent real drills. The Fireflies credential has
its separate human escrow attestation. See the dated verification details below.

## The three lanes

Each lane is independently restorable. Recovering one lane never
depends on recovering another.

### Lane A - Code and documentation
- What: all versioned code, configuration, and documentation in this
  repository.
- Where: GitHub (private repository), continuously, via ordinary
  commits and pushes.
- Encryption: the repository is private and relies on GitHub's
  standard transport and storage protections. No additional
  client-side backup encryption is applied to Lane A. This is
  acceptable only because secrets and Highly Restricted data must
  never be committed to it (see SECRETS.md, `.gitignore`) - Lane A is
  not a store for sensitive data, and its contents must never be
  treated as safe for public exposure.
- Status: complete and already validated by normal use.

### Lane B - Zac State / database
- What: the canonical Zac State (Person, Commitment, Source, and their
  evidence/head tables - D026), exported one trust boundary at a time.
- How (D028): `zacai.backup.export_boundary` streams every row for one
  boundary, across all seven tables in a fixed FK-safe order, directly
  through `age` encryption into a single artifact - no plaintext export
  file is ever written to disk in the normal path (see DECISIONS.md
  D028). Restore reverses this exactly, into a disposable
  `zacai_restore_test` database created and dropped only through a
  fixed-constant, D027-style guarded path - never `zacai_dev` or
  `zacai_test`.
- Where: a local, unencrypted `pg_dump -Fc` of the whole `zacai_dev`
  database is a separate, local-only fast-recovery safety net (never
  leaves the Mac Studio, not itself Lane B/off-device compliant). The
  actual Lane B artifacts are the three per-boundary encrypted exports;
  BRAINSTORM off-device destination is now the existing Brainstorm B2 bucket
  (Zac's D033C choice), with separate BRAINSTORM/state run-addressed objects.
  PERSONAL/SHARED destinations remain deferred. This selects architecture;
  D033C's separately approved trial performed and verified one real encrypted
  BRAINSTORM state export/upload on 2026-10-02; no recurring backup is scheduled.
- Encryption: client-side, via `age`, before any copy would leave the
  Mac Studio. **Three** separate keys - Personal, Brainstorm, and
  Shared - never one key across boundaries (D018, extended by D028 to
  cover the SHARED boundary D018 predates). Key-file mode, not
  passphrase mode. Private identities are never committed, logged,
  embedded in a script, or passed as CLI key material directly.
- Key recovery vs. Lane C: the three private identities are recoverable
  from two independent copies - local (outside this repository) and the
  existing password manager. **Reusing the password manager as this
  escrow location does not mean Lane C is implemented or tested** -
  Lane C remains about real application credentials (see Lane C below).
  This is a location reuse only.
- Frequency/retention: intended as a daily dump with a small rolling
  window (for example, 7 daily plus 4 weekly) once this runs against
  real data; v1 is manual only, no scheduled job yet (D028).
- Status: mechanism built and drill-tested (export from synthetic data,
  encrypt, decrypt, restore into a disposable database, verify boundary
  purity and integrity - D028). Running it for real against `zacai_dev`
  was separately approved and exercised for D033C on 2026-10-02. That
  snapshot includes one real meeting and its evidence. Independent B2 retrieval,
  ciphertext hash, authenticated decryption and plaintext hash equality passed;
  D034L subsequently verified a full database restore of this exact prior snapshot.

#### Lane B extension: raw ingestion artifacts (D030) - REAL-INGESTION HARD GATE

D030 added Zac State's first read-only ingestion architecture
(Fireflies, synthetic v1). Its raw artifact content (e.g. a transcript's
full text) does **not** live in PostgreSQL - it lives behind a separate
`zacai.ingestion.artifact_store.ArtifactStore` abstraction, with
`LocalFilesystemArtifactStore` as the only v1 backend, addressed by a
SHA-256 `content_hash` recorded on the corresponding `Source` row. Lane
B's mechanism above backs up PostgreSQL rows only - it does **not**
cover this local artifact directory at all.

**This is a blocking prerequisite, not a recommendation: no real
Fireflies content (or any future connector's real content) may be
ingested until all of the following are true:**
- Raw artifact backup/recovery has been **designed**.
- It has been **implemented**.
- Artifacts are **encrypted before any off-device storage** - the same
  "encrypt client-side before anything leaves the Mac Studio" principle
  Lane B's database export already follows (D018).
- Backups are **separated by PERSONAL/BRAINSTORM/SHARED boundary
  protections**, consistent with D018/D028's three-separate-keys
  requirement - never one shared key or one shared artifact set across
  boundaries.
- A **real restore drill has succeeded** - a design document alone does
  not satisfy this gate.
- Every restored artifact passes:
  `sha256(restored_bytes) == Source.content_hash`.

Status: **implemented and real-off-device-drill-verified for BRAINSTORM
(D031A/D031B).** D031A (`src/zacai/backup_artifacts.py`) implements
`age`-encrypted, content-addressed, per-artifact backup objects and an
encrypted per-boundary manifest, a strengthened four-part "already
protected" verification with repair-on-failure, restore, and integrity
reconciliation against `Source` rows - reusing D028's exact three
per-boundary `age` identities unchanged, no new key system. D031B Phase
1 added `S3CompatibleBackupObjectStore`, a single `boto3`-based
implementation satisfying any S3-compatible provider (proven hermetically
via `moto`, zero changes needed to the backup/restore algorithms) and
hardened `restore_boundary_artifacts` to enforce its restore-target
safety check internally and unconditionally. D031B Phase 2 (2026-09-22)
then ran a **real drill against a real Backblaze B2 bucket**
(`zac-ai-brainstorm-backup`) for the BRAINSTORM boundary: representative
synthetic artifacts were encrypted and uploaded, independently verified
present and byte-correct off-device via a separately constructed client,
restored into a brand-new local root from B2 alone, hash-verified
against `Source.content_hash`, and reconciled against a D028-restored
`zacai_restore_test` database - `missing=0`, `unexpected=0`,
`successful=True`. Wrong-identity rejection was also proven against the
real B2 manifest. Full detail in DECISIONS.md D031B.

**The artifact-backup/recovery precondition of the real-ingestion hard
gate is now satisfied for BRAINSTORM.** This does **not** by itself
approve, connect, or authorize any live Fireflies (or other) connector.
D033C separately obtained approval and completed one selected-meeting capture
on 2026-10-02 (see the operator verification below). PERSONAL and SHARED
boundaries have not yet run
their own equivalent real off-device drill and remain gated until they
do. See DECISIONS.md D030/D031A/D031B for the full architecture this
extends.

### Lane C - Secrets escrow
- What: an off-device copy of whatever credentials exist in macOS
  Keychain, scoped to approved integrations.
- Where: the existing password manager. No separate encrypted
  secrets archive is built.
- macOS Keychain remains the v1 production/runtime secret store on
  the Mac Studio (see SECRETS.md, DECISIONS.md D017).
- No Keychain export/import automation exists yet.
- Status: the approved Fireflies API key is stored in the BRAINSTORM-scoped
  Mac Keychain item. On 2026-10-02 Zac confirmed that he saved and recovered
  it from a 1Password Secure Note. This is a human recovery attestation;
  agents did not read the password manager. Other credentials are not covered
  by this specific attestation.

### D033C operator verification — 2026-10-02
- First attempt: consumed approval, FAILED at credential access before any
  Fireflies request; its audit and approval Source remain preserved.
- After human Keychain authorization and fresh explicit retry approval,
  the selected-meeting trial SUCCEEDED. Five BRAINSTORM / CONFIDENTIAL
  Source artifacts (two approvals, account reply, original transcript and
  normalized envelope) passed local hash checks and artifact backup coverage;
  artifact backup audit: checked=5, backed_up=5, failed=0.
- A separately constructed B2 client retrieved, decrypted and hash-verified
  the successful trial's four evidence/approval artifacts and the encrypted
  state snapshot. This proves byte recovery; it does not establish a full
  real-snapshot database restore or whole-Mac rebuild.
- The prior D031B encrypted manifest was preserved under the BRAINSTORM
  manifest-history prefix and independently read back before the canonical
  manifest changed. No prior drill objects were deleted.
- Private run identifiers, object references and ciphertext hash are in the
  local ignored `var/artifacts/trial-receipts/` receipt. Meeting content,
  account/meeting identifiers and credentials are excluded from Git.
- No scheduled backup, retention/deletion policy, latest-state pointer,
  recurring ingestion or external AI processing was enabled.

## Rebuild procedure if the Mac Studio is lost, fails, or is replaced

1. Provision replacement hardware and install a clean macOS baseline
   (FileVault, Tailscale re-enrollment - standard OS-level steps, not
   covered by this document).
2. Clone the GitHub repository. This restores all code, docs, and
   non-secret configuration (Lane A).
3. Follow the tool sequence recorded in DECISIONS.md (for example
   D016) to reinstall the development stack in the same order it was
   originally installed. This includes the local secret-scanning
   safeguard (D022): `brew install gitleaks`, then
   `git config core.hooksPath .githooks` inside the cloned repository -
   both are local, one-time steps that do not survive the clone by
   themselves.
4. Recreate each needed Keychain entry from the password manager
   escrow (Lane C), using the naming convention in SECRETS.md:
   `zacai-<boundary>-<service>-<credential>`.
5. Once real Lane B backups exist: retrieve each boundary's latest
   encrypted artifact from its off-device destination, decrypt it with
   that boundary's separately-held `age` identity (recovered from the
   password manager escrow, per Lane B above), and restore it into a
   freshly installed database engine using the same FK-safe restore
   logic `zacai.backup` uses for drills (D028).
6. Run the project's health checks to confirm the service starts,
   reads secrets correctly, and reconnects to state.
7. Re-verify that access is Tailscale-only before treating the system
   as back in production.
8. Log the recovery event and record any gaps found, per SECURITY.md
   logging requirements.

## Restoration testing

- Lane A: tested now. Clone this repository into a fresh, empty
  location and confirm it matches `origin/main`. This validates Lane
  A only.
- Lane B: the mechanism itself is tested (D028) - export, encrypt,
  decrypt, and restore into the disposable `zacai_restore_test`
  database, verified against synthetic data. Testing it against real
  `zacai_dev` data, and choosing the off-device destination, remain
  separate, later steps once real data actually exists.
- Lane C: must be tested once the first real, approved credential
  exists in Keychain and the password manager escrow. Verify the
  credential can be recovered from the password manager and used to
  bring the service up.
- Do not create a credential solely to run a recovery test. Lane C
  testing waits for a credential that a specific approved integration
  actually requires.
- A Lane A restore succeeding does not mean the full backup/recovery
  requirement is complete. The requirement remains incomplete until
  Lane B and Lane C have each been tested under the conditions above.

## References

- SECURITY.md - core backup, recovery, and secrets rules
- SECRETS.md - secrets management rules and credential-adding
  procedure
- DECISIONS.md D014, D017, D018, D028, D030, D031A - recovery, secrets,
  backup, and ingestion-artifact backup architecture rationale
- ROADMAP.md Phase 1, Phase 3, and Phase 11 - backup/restore, ingestion,
  and recovery testing tasks

## State backup compatibility and remaining rollout gate

D034I adds versioned state streams and synthetic recovery coverage for schema
0005's meeting/project associations and retractions. Live schema remains 0004.
During D034I, no production migration, real state export/restore or off-device
upload occurred; the subsequent D034L real restore is recorded below.

New exports begin with `zacai-state-backup-v2`, exact Alembic revision and trust
boundary. One fresh PostgreSQL REPEATABLE READ, READ ONLY transaction supplies
both revision and every exported table. Fixed schema inventories select 7, 21,
28, 28 or 30 tables for revisions 0001 through 0005. A 0004 export never queries
0005-only tables; unknown revisions fail. `artifact_backup_run` is operational
history excluded as before; independent artifact manifests remain authoritative.
A schema/table-inventory regression test now guards business-state coverage.

Restore accepts new streams and complete historical D028/D029/D030 unversioned
7/21/28-table inventories. It uses validated CSV column names so older Source
and Commitment rows restore after nullable schema additions. Unversioned EOF
cannot itself distinguish a deliberately shortened stream ending at a valid
older inventory; encryption authentication and original backup identity matter.
New version headers fix that structural ambiguity. Missing/trailing/unknown
frames, invalid headers/lengths/columns and mixed or incorrectly declared trust
boundaries reject and roll back. The disposable restore target must hold only
one boundary; this is not a production merge/import API.

Header lines are bounded to 256 bytes and individual table frames to 256 MiB.
Oversized tables fail; no rows are truncated or omitted. Export retains one table
in memory at a time, as before. Encryption/decryption remains subprocess-based,
with no persistent plaintext export in the normal path. Tests use passthrough
commands and invented data, not proof of actual age key recovery or live storage.

All restored tables commit together only after stream EOF and successful decrypt
exit. A valid-looking stream followed by a decrypt failure still rolls back.
Interrupted/malformed restores leave no committed partial state. Destructive
operations remain hardcoded to zacai_restore_test with existing target guards.

D034L now supplies full restoration evidence for the specific existing D033C
snapshot. Fresh current-state protection and schema 0005 rollout retain their concrete
checks and approval; D034L subsequently verified the recovered Brainstorm key. Synthetic format and
isolation drills do not satisfy those live gates.

## D034L full state restore — 2026-10-03

The existing real BRAINSTORM snapshot was retrieved from B2 without any upload,
verified against its recorded ciphertext hash and decrypted with the existing
local identity. Full restoration into zacai_restore_test passed deterministic
row/field comparison for every exported table and four required canonical Source
hashes. The temporary database was dropped. No plaintext export file was written;
PostgreSQL temporarily held the recovered private state during the explicit drill.
No canonical state, live schema, connector or model processing changed.

The new trusted review protector similarly requires actual encrypted artifact
readback, state readback/decryption equality and full restore before releasing a
successful review. Its integration was exercised with invented state, throwaway
keys and local object clients only; no real review backup was uploaded. It does
not grant processing permission. Its recovery verifier requires an exclusive
operator window relative to legacy drill tools.

Zac subsequently copied the Brainstorm key from 1Password and authorized private
verification. That freshly recovered copy successfully decrypted the same B2
snapshot, which again passed full restore and required Source checks. The clipboard
was cleared and the temporary key removed; the original local identity was not
modified and no key material was displayed. Other application credentials and
boundaries are not covered by this specific key recovery.
Private object references, timestamps and digests are stored in the ignored
private-data recovery receipt, never in repository documentation.
