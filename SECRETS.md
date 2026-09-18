# Zac AI Secrets Management

Status: security rails only. No real credentials or Keychain entries exist
yet. See DECISIONS.md D017 for the full architecture decision and rationale.

## Rules

- Never commit a secret to Git, in any form, in any file.
- `.gitignore` blocks `.env`, `.env.*` (except `.env.example`), `secrets/`,
  `*.pem`, `*.key`, `*.p12`, and local backup/archive patterns.
- `.env.example` lists variable names only, with placeholder or no values.
  Never add a real value to it.
- Development/test secrets may use a gitignored `.env.development` file.
  Development credentials only - never a real production/runtime secret.
- Real production/runtime secrets are stored in macOS Keychain. No
  plaintext `.env.production` file is ever used for a real credential.
  Keychain is the v1 mechanism and may be replaced later by a dedicated
  secrets manager without changing application code, since the
  application only ever consumes environment variables.
- Every secret name carries a trust-boundary prefix: `PERSONAL_`,
  `BRAINSTORM_`, or `SHARED_`. Access must be enforced in code by that
  prefix, not by naming convention alone.
- Secrets are never printed to logs. Centralized log redaction strips
  secret-like key names and common token shapes before anything is
  written or surfaced to Zac.
- Secrets recovery is documented and tested separately from code and
  database backup/restore.

## Adding a future credential

1. Confirm the credential is required by a specific, already-approved
   integration or component. Do not add one speculatively.
2. Choose the correct trust-boundary prefix and a clear name, e.g.
   `BRAINSTORM_SALESFORCE_CLIENT_SECRET`.
3. Add the variable name only (no value) to `.env.example` under the
   matching section.
4. For local development: put the real value in your own local, gitignored
   `.env.development`. Never share or commit that file.
5. For production/runtime: store the real value in macOS Keychain under
   the naming convention `zacai-<boundary>-<service>-<credential>` (e.g.
   `zacai-brainstorm-salesforce-client-secret`), and load it into the
   process environment only at service startup.
6. Confirm the config loader's boundary check can resolve the new
   variable for only the intended trust boundary, and confirm centralized
   log redaction covers it.
7. Never paste a real value into chat, a commit, an issue, or any
   documentation file, including this one.

## References

- SECURITY.md - core secrets rules, data classification, backups
- DECISIONS.md D017 - full architecture rationale
- ROADMAP.md Phase 1 - secrets management and secret-scanning tasks
