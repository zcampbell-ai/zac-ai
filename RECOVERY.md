# Zac AI Recovery Architecture

Status: Lane B's database mechanism is built and drill-tested against
synthetic data (D028), but not yet exercised against `zacai_dev` for
real - see Lane B below. Lane B's raw-artifact extension (D030) is a
**hard, unsatisfied gate**: it blocks any real ingestion connector until
designed, implemented, and drill-tested - see Lane B below. Lane C holds
no real Zac AI credential yet. See DECISIONS.md D018/D028/D030 for the
full architecture decisions and rationale.

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
  the off-device destination for them remains deferred (DECISIONS.md
  Open Decisions), unchanged by D028.
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
  Lane C remains entirely about real application credentials, which do
  not exist yet (see Lane C below). This is a location reuse only.
- Frequency/retention: intended as a daily dump with a small rolling
  window (for example, 7 daily plus 4 weekly) once this runs against
  real data; v1 is manual only, no scheduled job yet (D028).
- Status: mechanism built and drill-tested (export from synthetic data,
  encrypt, decrypt, restore into a disposable database, verify boundary
  purity and integrity - D028). Running it for real against `zacai_dev`
  is a separate, later, explicitly-approved step, since `zacai_dev`
  currently holds no real data to back up yet.

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

Status: **not designed, not implemented, not drilled.** D030's synthetic
implementation is exempt from this gate (it stores only synthetic
fixture bytes, never real content), but a future, separate, explicitly-
approved milestone connecting a real Fireflies (or any other) account
must not be approved until this gate is satisfied. See DECISIONS.md D030
for the full architecture this extends.

### Lane C - Secrets escrow
- What: an off-device copy of whatever credentials exist in macOS
  Keychain.
- Where: the existing password manager. No separate encrypted
  secrets archive is built.
- macOS Keychain remains the v1 production/runtime secret store on
  the Mac Studio (see SECRETS.md, DECISIONS.md D017).
- No Keychain export/import automation exists yet.
- Neither the password manager nor Keychain holds any real Zac AI
  credential until a specific approved integration requires it.
- Status: not populated. Nothing to escrow yet.

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
- DECISIONS.md D014, D017, D018, D028, D030 - recovery, secrets, backup,
  and ingestion-artifact architecture rationale
- ROADMAP.md Phase 1, Phase 3, and Phase 11 - backup/restore, ingestion,
  and recovery testing tasks
