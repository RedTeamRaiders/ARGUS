---
owasp_id: A04:2021
vuln_class: insecure_design
test_mode: blackbox
requires: []
primitive: business_logic_bypass
evidence_schema:
  required_proof: [logic_bypass_request_pair, impact_demonstration]
  min_tool_confirmations: 2
  oob_required: false
---

# Skill: Insecure Design — Black Box

## 1. Recon — Attack Surface Mapping
- Multi-step workflows: checkout, password reset, onboarding, approval
  chains — anywhere "step N requires step N-1 to have happened."
- Anything involving quantities, prices, or balances that the client
  submits (even partially) rather than the server deriving entirely
  server-side.
- Rate-limited or one-time-use mechanisms (CAPTCHA, discount codes,
  password-reset links) — test whether "one-time" and "rate-limited" are
  actually enforced, not just intended.

## 2. Detection Methodology — Probe Sequence
1. **Workflow bypass**: attempt to call a later step's endpoint directly
   without completing earlier steps (e.g. hit the checkout-confirm endpoint
   without ever adding items, or the email-verified-only endpoint without
   verifying).
2. **Value manipulation**: submit negative quantities, zero/negative
   prices, or values far outside realistic bounds for any client-submitted
   numeric field in a transaction.
3. **Reuse testing**: submit the same one-time token/code/CAPTCHA answer
   twice — does the second attempt still succeed?
4. **Race conditions**: fire the same state-changing request N times
   concurrently (discount redemption, balance deduction, like/vote
   counting) and check whether the server serialized them correctly.

## 3. Exploitation Path — Demonstrate Impact
- For workflow bypass: show the skipped step's intended effect (payment,
  verification) never happened, yet the end-state (order confirmed, account
  verified) was reached anyway.
- For value manipulation: show the financial/logical impact concretely —
  a negative quantity credited back to balance, not just "the request was
  accepted."
- For race conditions: script concurrent requests
  (`asyncio.gather`/`threading`) and show the final state is inconsistent
  with correct single-threaded serialization (e.g. a discount applied N
  times instead of once).

## 4. Evidence Capture
`evidence_schema` requires `logic_bypass_request_pair` (the sequence of
requests showing the step/validation was skipped) AND
`impact_demonstration` (the concrete resulting state — balance change,
unauthorized access granted, duplicate benefit obtained).

## 5. False-Positive Filtering
- A workflow step that's "skippable" but has no actual security
  consequence (a UI-only confirmation screen with no server-side gate
  intended) isn't a finding — confirm the skipped step was supposed to
  enforce something, not just guide UX.
- A race condition that exists but has negligible real-world impact (a
  view counter incrementing twice) doesn't warrant the same severity as one
  affecting money/access — scale the finding to actual impact, not
  theoretical non-atomicity alone.

## 6. CVSS Vector Construction
- Financial logic bypass (negative quantity, free checkout):
  `AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:N` (~7-8 High) — integrity of
  business state, not confidentiality, is what's broken.
- Workflow bypass reaching a privileged end-state (e.g. account verified
  without actually verifying): treat similarly to an auth/access-control
  finding — often High given direct identity/trust implications.
- Low-impact race conditions (counters, non-financial duplicate actions):
  Low/Medium — scale down from the "textbook" race-condition severity.

## 7. Remediation (by stack)
- Enforce state transitions server-side with an explicit state machine
  (order status enum with valid-transition checks), never infer "step 2
  happened" from the mere presence of a step-3 request.
- All quantity/price fields: validate server-side bounds (non-negative,
  realistic maximums) regardless of client-side validation; recompute
  price server-side from catalog data, never trust a client-submitted
  total.
- One-time tokens: invalidate atomically on first use (a DB transaction
  with a `used_at IS NULL` check-and-set, not a check followed by a
  separate update).
- Race conditions: wrap the read-modify-write in a DB transaction with
  appropriate row locking (`SELECT ... FOR UPDATE`) or an atomic increment
  operation instead of read-then-write application code.
