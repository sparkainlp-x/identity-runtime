# Review of the first draft and what changed

The first draft (the "OES-61440 Autonomous Identity Runtime" script shared in conversation, October 2026) set out the right ideas: identity root, modular personality, capability leases, proof-carrying actions, a hash-chained ledger and a hierarchical tripwire. As written it could not complete its own demo. This repository is a rewrite; the draft itself is not included.

| # | Problem in the draft | Change here |
|---|---|---|
| 1 | The shadow-simulation stub returned forbidden markers for every adversarial prompt, so every personality was rejected and the demo then failed looking up a pending version that did not exist. | `simulation.py` runs deterministic checks: text screening of every key and value, a check for never-grantable capabilities, and fixed adversarial probes replayed against the compiled policy. A model hook is optional and off by default. |
| 2 | Quorum modules were approved by a single approver, so the version could never commit. | Tool and safety policy need two distinct approvers (case-insensitive). The avatar, other avatars, the identity root and reserved ids cannot approve. |
| 3 | Auto-approve modules (voice, appearance) were never marked approved, which also blocked the commit. | They are recorded as `runtime:auto` when the manifest passes and never block. |
| 4 | Rollback only wrote a log line. | Versions are stored by checksum; rollback restores the previous or a named committed version, re-checks its checksum, recompiles its policy, and revokes all leases and held actions. Commit does the same for the outgoing version. |
| 5 | The core needed numpy. | Standard library only; a test enforces it. The 1,920-membrane hierarchy is plain Python (about 0.02 s per decision). |
| 6 | Ledger events hash-chained mutable objects, did not record the identity root, and a corrupt last line was not handled. | Payloads are copied to plain JSON before hashing; every event carries `identity_root`; a torn or unparsable line, or a ledger shorter than the head saved in `state.json`, fails verification and makes the runtime read-only. |
| 7 | Lease ids could collide or be regenerated, leases were implicit, and there was no way to approve a held action. | Leases are created only by an explicit `grant_lease` from a person, with random ids, budgets and expiry, bound to the active version. `approve_action` consumes a held action's lease exactly once; held actions reserve a unit so the budget cannot be overspent. |
| 8 | The policy compiler accepted unknown capabilities and persona-supplied limits. | A runtime-side registry. Unknown or never-grantable capabilities are rejected; limits are clamped; mandatory human approval and mandatory forbidden actions cannot be removed. |
| 9 | Risk was whatever the caller said. | Effective risk is the larger of the declared risk and the capability's base risk; NaN or non-numeric risk counts as 1.0; anything at or above 0.5 is held regardless of the tripwire. |
| 10 | Code execution was an `exec()` placeholder. | Removed. `execute_code` is never grantable. The runtime authorises and records; it executes nothing. |
| 11 | Approvals were unsigned. | Optional HMAC-SHA256 approval tokens bound to avatar, manifest checksum or action id, module or capability, and approver. |

Wording was also changed: the draft's "revolutionary" framing and "what the demo proves" list are replaced by a plain description and a limitations section.
