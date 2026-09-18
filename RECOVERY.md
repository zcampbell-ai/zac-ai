# Zac AI Recovery Architecture

Status: security rails only. Lane B does not yet exist (no canonical
Zac State/database). Lane C holds no real Zac AI credential yet. See
DECISIONS.md D018 for the full architecture decision and rationale.

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
- What: the canonical Zac State and Brainstorm State database, once
  it exists (Phase 2+).
- Where: a local encrypted dump on the Mac Studio, plus a client-side
  encrypted copy at an off-device destination. The specific
  destination is deferred (DECISIONS.md Open Decisions) until closer
  to when canonical Zac State is created.
- Encryption: client-side, before any copy leaves the Mac Studio.
  Personal and Brainstorm state use separate encryption keys - never
  one shared key across both trust boundaries. The specific
  encryption tool is not yet chosen; `age` is the current preferred
  candidate, not yet adopted or installed.
- Frequency/retention: intended as a daily dump with a small rolling
  window (for example, 7 daily plus 4 weekly), once Lane B exists.
- Status: does not exist yet. Not implemented until Phase 2 creates
  real Zac State.

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
   originally installed.
4. Recreate each needed Keychain entry from the password manager
   escrow (Lane C), using the naming convention in SECRETS.md:
   `zacai-<boundary>-<service>-<credential>`.
5. Once Lane B exists: retrieve the latest encrypted database backup
   from its off-device destination, decrypt it with the
   separately-held key for the correct trust boundary, and restore it
   into a freshly installed database engine.
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
- Lane B: must be tested once canonical Zac State exists. Restore the
  latest encrypted database backup into a separate test instance and
  verify the data matches.
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
- DECISIONS.md D014, D017, D018 - recovery, secrets, and backup
  architecture rationale
- ROADMAP.md Phase 1 and Phase 11 - backup/restore and recovery
  testing tasks
