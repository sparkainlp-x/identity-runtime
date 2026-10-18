# Threat model

identity-runtime is a research prototype. It explores a runtime enforcement layer for identity, authorization, reversibility and audit evidence. It does not secure the model, sandbox the host, or replace identity and access management, and it has not been tested against real attackers. Architecture: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Measured behaviour: [benchmarks/results.md](benchmarks/results.md).

## Assets

- **The active personality version** and the record of who approved it.
- **The capability boundary**: which capabilities, contexts, budgets and expiries an avatar holds right now.
- **Human decisions**: module approvals, leases, held-action approvals, rollbacks and halt resets.
- **Action proofs** and the **ledger** that records them, as evidence of what was authorised, by whom and under which version.

## Trusted parties

| Party | Trusted for | Note |
|---|---|---|
| Operator | Everything | Runs the process and owns the state directory and the keyring. The runtime cannot protect anything from the operator. |
| Approvers | The decisions they make | Without a keyring an approver id is a plain string the caller asserts. With a keyring, approvals carry HMAC tokens, but the keyring is a shared secret: whoever holds it can approve as anyone in it. |
| Host application | Calling the runtime honestly and enforcing its answers | The runtime authorises and records; it executes nothing. |

The avatar, the model behind it and anyone who writes a manifest are **not** trusted.

## What the host application must enforce

1. Call `redeem_proof()` right before acting and act only if it returns `"redeemed"`, and only within that proof's capability, context and description. Redemption is single use (recorded in `state.json` and the ledger) and current-only: it is refused once the proof is redeemed, its lease is revoked or expired, its version is no longer active or the avatar is halted. `check_proof()`/`verify_proof()` are read-only previews; `proof_in_ledger()` is for audits only.
2. Do not act on a proof without redeeming it, and do not retry an action after a crash without deciding whether the earlier redemption already led to execution (the runtime cannot know).
3. With a keyring, generate a fresh nonce for every lease grant and rollback (`signing.new_nonce()`) and sign exactly the terms from `lease_terms()`.
4. Keep the avatar and its model away from the approval calls (`approve_module`, `grant_lease`, `approve_action`, `rollback`, `clear_halt`), the state directory and the keyring.
5. Sandbox the action itself, and run one runtime process per state directory.

## Adversaries considered

These are exercised by the tests and by [benchmarks/adversarial.py](benchmarks/adversarial.py):

- A **manifest author** who tries to enable a never-grantable or unknown capability, raise limits, drop mandatory human approval, or embed copy-pasted injection text (paraphrases get through).
- The **avatar** acting outside its lease, budget, context or policy, after expiry, revocation, a new commit, a rollback or a halt; declaring a low or malformed risk; or approving for itself, as another avatar, as its identity root or under a reserved id.
- Someone who can **edit `ledger.jsonl` or a version file but not `state.json`**: edited, deleted, reordered, truncated or dropped ledger lines are detected and the runtime turns read-only; a tampered version file fails its checksum when it is loaded.
- Someone **without the keyring** who forges an approval token or reuses one for a different action, module or capability.
- Someone who **captured a valid token or proof** and replays it: a proof redeemed twice or after its lease, version or halt state changed; a lease token replayed or reused with different terms; a rollback token replayed; a `clear_halt` token reused on a later halt; module tokens replayed on a re-upload of a superseded manifest.

## Out of scope

The operator; anyone who can write both `state.json` and `ledger.jsonl`; whoever holds the keyring; a compromised host or one that ignores proofs; attacks on the model itself (jailbreaks, paraphrased prompt injection, whether the model follows persona text); concurrent writers; network attackers (there is no network service); side channels.

## If the operator controls both the state file and the ledger

They can rewrite history. Dropping recent entries and moving the head in `state.json` back, or editing an entry and recomputing every later hash and the head, both verify as valid (0 of 40 detected in the committed benchmark run). The ledger is tamper-evident against partial edits, not tamper-proof. Two mitigations are open questions, not features:

- **External anchoring**: publish the ledger head to a store the operator cannot rewrite, so a rewritten chain no longer matches an earlier anchor.
- **Public-key approvals**: approvers sign with private keys the operator does not hold, so a rewritten history cannot contain approvals they never gave.

## Residual risks

- **Replay protection lives in `state.json`.** Redeemed proofs and used nonces are recorded there, so whoever can rewrite `state.json` can un-redeem a proof or reuse a nonce; the used-nonce list also grows without bound. Without a keyring nonces are optional.
- **A host that skips `redeem_proof()`** gets no single-use or freshness guarantee, and a crash between redeeming and acting leaves the outcome to the host.
- **Single-person steps.** Rollback and halt resets need one approver, even though tool and safety policy commits need two. Rollback can only restore a version that was committed before. `revoke_capability` needs no approver; that only removes authority, and the `by` field is whatever the caller says.
- **Self-asserted approver ids** when no keyring is configured.
- **Text screening and the shadow simulation** are string matching and fixed probes, not a model security evaluation.
- **OES-61440 is uncalibrated.** For example, a `send_email` lease of two or more units halts the avatar part-way through, even at declared risk 0 (left as is; listed under Open questions in the README). That fails safe, but it also means an avatar can halt itself through ordinary requests (a denial of service against itself).
- **Single process, local files**, no locking.
