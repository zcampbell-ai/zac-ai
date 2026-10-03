# Questions for Zac

Updated: 2026-10-03
Purpose: Keep nonblocking decisions here while engineering continues. This log
is not approval evidence. Work is paused at Zac's request after the D034F
checkpoint; further implementation waits for him to resume. No immediate
question needs an answer to save this checkpoint.

## Decisions needed before a live/private step

- **Private meeting-review trial:** when the concrete host and recovery checks are
  ready, approve or decline one explicitly selected meeting, exact local model
  digest, selected context and scope. Existing Fireflies capture approval does
  not approve model processing. No approval is requested until that proposal is
  concrete and reviewable.
- **Production schema 0005 rollout:** approve the protected rollout after the
  actual state backup/restore evidence and rollback procedure are ready. The
  migration remains tested only in zacai_test.

## Feedback needed once there is a draft to judge

- Does the compact review explain what changed in the continuing project?
- Which material decision, commitment, risk or follow-up is missing or wrong?
- Which phrasing would you shorten/change so it sounds like you?

These are future feedback prompts, not a request to build a background document.
Use the first bounded review to identify gaps; collect only the context needed.

## Settled direction — do not ask again

- Zac State and Zac Events remain canonical; approval/security/credentials stay
  outside agents; providers/runtimes remain replaceable.
- Use the existing roadmap. Evaluate OCE before custom production multi-agent
  infrastructure; do not adopt it or delay the current workflow.
- Preserve continuing project identity across successive contracts/SOWs.
- Keep summaries short and contextual, then decisions/commitments, then
  risks/follow-ups. Owner/date and proposal/agreement distinctions matter.
- Keep Claude as an independent engineering reviewer.
- Continue authorized engineering independently and log nonblocking questions.
