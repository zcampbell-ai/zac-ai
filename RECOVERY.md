# Zac AI Recovery Architecture

Status: BRAINSTORM raw artifact recovery is real-off-device verified (D031B).
The approved D033C encrypted state snapshot has now also been retrieved from B2,
fully restored into a disposable database, compared on every row/field and removed
(D034L). This is specific-snapshot recovery evidence, not a fresh-state backup,
whole-Mac rebuild, credential escrow completion or private processing approval.
PERSONAL/SHARED have not run equivalent real drills. The Fireflies credential has
its separate human escrow attestation. See the dated verification details below.

D034M additionally rehearsed a populated-copy schema 0004 -> 0005 upgrade and
rollback to 0004 using current BRAINSTORM state, with full comparison and cleanup.
This was local-only; it does not supply a fresh off-device backup or authorize
the live rollout. See [SCHEMA_ROLLOUT.md](SCHEMA_ROLLOUT.md) for preparation and
the empty-new-table rollback boundary.

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


## D034AI original research-intake recovery — 2026-10-04

The original encrypted BRAINSTORM state/journal was independently retrieved from
B2, hash-verified, decrypted and fully restored into zacai_restore_test. Canonical
business-state equality and all thirteen intake Source hashes passed. Cleanup
was confirmed before the missing encrypted recovery receipt was written and
independently read back/decrypted. Live canonical state was unchanged; no new
import or backup snapshot was created. This verifies the original checkpoint,
not a fresh recovered-identity escrow drill. Private receipts remain ignored.

The dedicated verifier is saved in 1Password and Mac Keychain, account
brainstormzac, services zacai-brainstorm-b2-verifier-key-id and
zacai-brainstorm-b2-verifier-application-key. Boundary-prefixed interface names
are BRAINSTORM_B2_VERIFIER_KEY_ID and BRAINSTORM_B2_VERIFIER_APPLICATION_KEY.
Its actual user-created Read Only preset is scoped to the existing bucket and
BRAINSTORM/ prefix and includes read/list, metadata reads and shareFiles; no
write/delete/admin permission. Verification uses read/list only. The uploader
remains separate and unchanged. Neither key nor source prose belongs in Git.


## Recovery location map — updated 2026-10-05

This is a navigation guide, never a credential store. It records locations and
verification status only. Do not place passwords, API keys, private age identities,
financial account details or private source content in this document.

| What to recover | Where to look | Status / next check |
| --- | --- | --- |
| Code, roadmap and this guide | Private GitHub repository `zcampbell-ai/zac-ai`; local checkout `/Users/brainstormzac/zac-ai` | Git checkpoints provide code/documentation recovery; uncommitted work is not yet covered. |
| PERSONAL backup storage | Backblaze B2, bucket `zac-ai-personal-backup`, object prefix `PERSONAL/`, endpoint `s3.us-east-005.backblazeb2.com` | Visibly verified private, encrypted at rest, empty on 2026-10-05. This is not a completed client-side encryption/recovery drill. |
| PERSONAL recovery-reader credentials | 1Password item **Zac AI Personal Backup Reader**; contains Key ID and Application Key together | User confirmed saved on 2026-10-05. Vault name not yet recorded; search the exact item title. Independent retrieval and runtime Keychain installation remain unverified. |
| PERSONAL reader application-key settings | Backblaze > B2 Cloud Storage > Application Keys; key name `zac-ai-personal-recovery-reader` | Verified bucket/prefix limited, read/list, no write/delete. Creating credentials does not authorize personal-data ingestion. |
| PERSONAL backup uploader credentials | Not configured yet | Separate least-privilege credential remains required. Do not substitute the Brainstorm uploader or master key. |
| PERSONAL client-side backup encryption key | Existing PERSONAL key location must be checked and its exact 1Password item title recorded | Do not assume the documented local key or escrow is currently recoverable. Independent recovery and real off-device drill remain pending. |
| BRAINSTORM backup storage | Backblaze B2 bucket `zac-ai-brainstorm-backup`, prefix `BRAINSTORM/` | Existing verified snapshot/drill scope described above; separate from PERSONAL. |
| BRAINSTORM independent backup reader | 1Password plus Mac Keychain, account `brainstormzac`, services `zacai-brainstorm-b2-verifier-key-id` and `zacai-brainstorm-b2-verifier-application-key` | Existing D034AI documented locations; exact 1Password item title/vault still to inventory. |
| Fireflies API credential | 1Password Secure Note (exact title/vault still to inventory); Mac Keychain account `zcampbell@brainstormtech.io`, service `zacai-brainstorm-fireflies-api-key` | User previously confirmed saved and recovered. Do not ask for the key in chat. |

When Zac is asked where an item lives, return its name and location plus the last
verified status. Unknown titles/vaults stay explicitly unknown until confirmed.
A saved-item attestation is distinct from successful independent recovery.
This guide is project documentation; it has not itself been imported into Zac
State or proved available through the future private interface.


### Caz AI Google sign-in configuration — 2026-10-05

Google Cloud project: **Caz AI Sign-in**, project ID `caz-ai-sign-in`, in the
Brainstorm organization. User-facing brand is Caz AI; existing technical Zac
identifiers remain intact. Internal Google Auth configuration exists; owner
reported and UI confirmed 2-Step Verification is on. This is sign-in configuration,
not an inherited Gmail/Drive authorization or proof of current Caz owner enrollment.

The web-client creation form is prepared. **No OAuth client credentials have been
created, saved or installed yet.** A specific client/callback approval is pending.
The Mac's Tailscale installation and its own online private hostname were checked
read-only; this does not prove HTTPS serving or iPhone reachability. Record the
exact approved callback and 1Password item/Keychain locations after creation and
installation, without placing secrets or raw callback tokens in this file.


## D034AS draft-choice and owner-host recovery boundaries

Protected draft choices reuse the existing BRAINSTORM artifact destination,
uploader/verifier separation and encryption/recovery machinery documented above.
No new actual storage account, credential location or key escrow was created in
this checkpoint. BRAINSTORM/CONFIDENTIAL choice coverage does not authorize
PERSONAL intake; that separate recovery path remains pending.

A choice acknowledgement requires its own committed Source/artifact and final
state/journal checkpoint, an encrypted immutable receipt and independent readback
plus full disposable restore. Historical recovery verifies every snapshot/journal
row and field and all selected current Source columns/hashes in one explicit
canonical column order. Actual public Source schemas on both databases must
exactly match that list; selected-row COPY normalizes local UTC/ISO formatting
within its read-only transactions. Historical framing/export remains unchanged.
Unrelated later
business records do not erase historical recoverability; current ACL/context
checks still govern release. Old packet receipts cannot cover new choice bytes.

The receipt's artifact ciphertext checksum records the initially observed backup.
Routine artifact repair may legitimately replace age ciphertext at a stable
plaintext-hash key. Recheck requires decryption and the exact canonical plaintext
hash; it does not demand that randomized ciphertext remain unchanged forever.
State and journal remain ciphertext-addressed and exactly hash-pinned. Corrupt or
mismatched existing receipts are never overwritten; reconciliation is a trusted
operator task. Failed protection may leave receipt-less state/journal objects or
unreferenced artifact bytes; no automatic deletion occurs. Future garbage
collection requires reviewed retention/reconciliation, not permission expansion.
No new live choice receipt or off-device drill is claimed here.

Persisted owner enrollment and encrypted browser sessions are authentication
operational state, not canonical memory or execution approvals. The actual host
operational directory, credential escrow and installed Keychain entries remain
unverified; do not invent location-map entries. Existing Google client creation
and private serving gates above remain open. After authentication-key loss or
configuration change, use explicit local owner enrollment; do not restore an old
scope file as authority. Setup invalidates prior sessions, including same-owner
re-enrollment. Composed revocation attempts both owner and session invalidation;
partial failure requires stopping serving and local reconciliation.

Same-UID authenticated-file rollback is not defeated by HMAC/encryption. Trusted
launcher/runtime separation and exclusive setup/serving remain requirements.
Shared reentrant maintenance/restore-target leases serialize cooperating recovery
helpers; third-party administrator SQL still requires an exclusive window.
The controlled local PostgreSQL and host timestamp checks share the same Mac
clock, with no cross-host skew allowance. Rollback or inconsistent chronology
holds release. Python >=3.12 parses actual PostgreSQL CSV timezone offsets.
Repeated full restores are not a measured interactive mobile performance result.
D034AS engineering validation passed; no deployed interface, actual iPhone access, full history
import, Caz runtime Gmail/Slack connection or financial intake follows from this
checkpoint. Separate bounded connected research is not canonical runtime intake.

## D034AT text-turn recovery and foreground operation

Canonical question envelopes use the existing BRAINSTORM artifact backup path.
Their exact source digest identifies immutable stored JSON, including original
text and owner/conversation/packet lineage. A distinct encrypted turn receipt is
retained at `BRAINSTORM/state/text-turn-{SourceUUID}/receipt-{turnDigest}.age`.
Its state and journal objects remain ciphertext-addressed beneath the same turn
prefix. The existing scoped uploader/independent reader and Brainstorm encryption
identity are reused; no new credential or location was installed in this checkpoint.
These receipts do not cover PERSONAL data or authorize model processing.

Recover the child, selected direct parents, packet and original packet evidence
with the full state snapshot and journal. A failed checkpoint leaves the same
canonical turn pending; retry the exact request/text rather than create or
acknowledge a replacement. Corrupt retained receipts require local reconciliation,
never overwrite. Original artifact plaintext hash remains authoritative across
legitimate age re-encryption; state/journal ciphertext pins and receipt bytes stay
exact. Current owner/access and chronology are checked after recovery as well.

The foreground operator module prepares mutually exclusive enrollment/owner
windows; it has not been registered as a CLI or started against real credentials.
Its reviewed operational directory must be explicit and private; no installed
location is claimed here. Keep the retained `private-mode.lock` file in place.
Workers, including unjoinable native threads, must stop before the mode lease and
private-log suppression are released. A persistent worker holds shutdown; forced
process termination requires operator reconciliation before starting another mode.
Google client/escrow, real private serving and physical iPhone validation remain
open as documented above. D034AT engineering checks passed as below.

Final D034AT engineering validation: 2,611 serial tests passed in 105.44 seconds,
with the same three dependency deprecation warnings. Final Ruff and strict mypy
(97 source files) passed; the annotation/offset-documentation precision changes
also passed all 14 assembly tests. Independent helper and Opus findings were
reconciled against real canonical contracts: duplicate Source context/provenance
remains invalid rather than silently deduplicated. Exact staged Gitleaks scanning
found no leaks; commit/push status is tracked against actual Git state. No live source/model call,
production migration, credential read, serving or iPhone acceptance occurred.


## D034AU — generated replies and explicit private trial entry

Generated reply artifacts use the existing BRAINSTORM partition. Their dedicated
encrypted recovery receipt is
`BRAINSTORM/state/text-reply-{SourceUUID}/receipt-{replyDigest}.age`. Exact state
and operational-journal ciphertext objects remain beneath that same UUID prefix.
The reply envelope retains the original consumed canonical claim/consent and
selected user/packet/parent/evidence references. No new credential was installed.

Failed protection leaves the immutable reply pending; reconcile/protect that
same Source rather than infer again or overwrite a receipt. Recovery of committed
history after processing expiry must not renew consent or release an answer.
PERSONAL recovery and company-source permissions remain separate.

`python -m zacai.interfaces.private_trial` is now an explicit enrollment-only
entry. Its nonsecret client/origin/private-directory arguments do not install
credentials, configure TLS or start anything unless the trusted local operator
invokes it. The owner view requires separately reviewed factory/artifact and
genuinely retained protected receipt composition. No production installation,
credential escrow, enrollment or iPhone acceptance is claimed by these files.


Final D034AU engineering validation: 2,870 serial tests passed in 138.64
seconds, with the same three dependency deprecation warnings. Final Ruff and
strict mypy (105 source files) passed. Independent Opus/helper review corrections
include future-observation rejection, receipt-only pending recovery, original
record-before-expiry provenance and shared owner/view clock composition. The
actual SQL/local-age pending test recovers a timely committed reply after expiry
and canonical revocation, while active capture/load remain held. Authority
recovery preflight and semantic usefulness in that fixture are explicitly
invented; no production/B2/model/credential/listener/iPhone readiness is claimed.
Exact staged secret checks pass; commit/push are verified against actual Git.


## D034AV follow-up authority recovery preparation

The existing BRAINSTORM identity proof verifier is reusable in
src/zacai/brainstorm_identity_recovery.py; original proof location, pinned digest,
operator flags, namespace and limits remain unchanged. It does not look up or
create credentials. The trusted host must supply the actual existing proof/key
configuration. No new live personal/business credential or production recovery
receipt was created by this engineering checkpoint.

Prepared follow-up authority receipts use BRAINSTORM/state/followup-authority-
<canonical-subject-Source-UUID>/receipt-<Source-content-hash>.age, with immutable
state and operational-journal ciphertext objects under that same namespace.
Receipts bind exact consent or consumed-claim dependencies and the independent
key-proof digest. They prove historical durability only; expiry/cancellation
still holds processing. Failed committed attempts require receipt-only repair,
not redispatch. Every operation uses the existing exclusive recovery-window
mechanics and actual canonical row/hash/ACL comparisons.

The guarded SQL/local-age drills use throwaway keys and invented operator-proof
flags plus local clients; they are not off-device or password-manager evidence.
Production wiring and actual independently recovered credentials remain separate
owner setup and live verification steps. Progress is a dated reviewed snapshot,
not proof that those external gates have passed.

## D034AW named-decision checkpoint preparation

A named processing choice is distinct from a question, consent or generated answer.
Its USER_INSTRUCTION Source uses `packet-followup-named-decision/<host request UUID>`.
Its dedicated encrypted checkpoint/receipt namespace is
`BRAINSTORM/state/named-decision-<canonical Source UUID>/`.
The receipt binds Source bytes/admission time, selected dependency inventory, independent
recovered-key proof, artifact backup run, full State and operational journal pins.

`BrainstormNamedDecisionRecovery` verifies original decision/question/direct parents,
packet/original evidence with current ACLs; actual decrypted artifact identity, complete
snapshot/journal cold restoration and current selected rows are verified through existing
checkpoint machinery. Corrupt or conflicting receipts are never overwritten.
`CanonicalNamedDecisionCapture.protect_pending` repairs retained history after expiry
under current host/session checks and returns only a receipt. It never renews an
admission, issues v2 consent, invokes a model or releases an answer.

The disposable SQL/local-age drill uses actual encrypted objects and cold restoration,
with invented admission/session and key-escrow flags. Production credentials, independently
recovered identity and live off-device availability require their existing operator gates.
No secret or current personal financial record is stored in these engineering documents.
