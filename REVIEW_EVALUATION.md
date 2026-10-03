# Compact meeting-review evaluation

This is the D034F reviewer guide, within the existing D034 workflow. It is not a
new roadmap, a private-runtime approval or an automatic model grader.

Evaluate the exact draft against its supplied meeting/project evidence. A quote
matching the source proves text presence; it does not establish that the generated
claim is true. Check every claim and separately look for material omissions.
Use PASS, FAIL or UNREVIEWED for each criterion. FAIL means revise; UNREVIEWED
means review is still needed. An all-PASS result remains a reviewed draft.

- **Factual support:** claims follow from the evidence without invented facts,
  unsupported causation or turning planned work into completed work.
- **Temporal context:** connections cite the selected meeting and related evidence;
  a continuing project can span SOWs, but old status is not automatically current.
  Missing earlier context is stated honestly, not fabricated.
- **Agreements and promises:** decisions reflect explicit agreements; commitments
  reflect actual promises. Suggestions are proposed follow-ups, not commitments.
- **Owners and dates:** each stated owner/date is supported. Unconfirmed details
  stay unconfirmed; speaker identity alone does not imply task ownership.
- **Uncertainty:** not known/not agreed is not proof something does not exist.
  Risks, contradictions and unresolved issues stay visible.
- **Completeness:** do not omit the material decision, commitment, risk or follow-up
  to fit the word limit. Revise the draft instead of silently truncating it.
- **Concision:** short contextual summary, then decisions/commitments, then risks/
  follow-ups. Plain words, no padding or repeated bullets; existing size limits
  check format first; they do not prove that it sounds like Zac.
- **Usefulness:** explains what changed and why it matters in the actual project.
  Zac's edits and feedback are the strongest check of delivery, not a model's
  self-reported score. Leave UNREVIEWED until the reviewer can judge this.

The host binds evaluations to full context, task identity and exact output hashes.
An edited draft or changed evidence invalidates the prior evaluation. Reviewer
and builder identities are distinct trusted host assignments; this code does
not authenticate those identities or verify their judgment. Never accept scores
or reviewer identity embedded in a transcript or generated draft.

Canonical audit artifacts contain UUIDs, hashes, classifications, closed stage
names and rubric judgments. They contain no meeting text, generated prose, raw
backend errors or free-text reviewer notes. Metadata remains private: keep its
boundary/label and include it in the existing protected artifact/state inventory.
The operator owns database commit and backup verification. Stages are audit facts,
not an automatically enforced workflow state machine; a declared stage cannot
prove that the runtime actually executed safely.

Before a private trial: complete the fresh-snapshot host, exact approved model
route, audit-before-dispatch failure handling, protected state restore/rollout
checks and explicit human approval of the bounded processing scope. None of those
steps is authorized by an evaluation PASS or by this guide.
