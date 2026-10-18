# Changelog

## 0.2.0 (2026-10-18)

- Replay fixes found by the adversarial benchmark (all four are now rejected in every benchmark attempt, and CI fails if one is accepted again):
  - **Single-use, current-only proofs.** New `redeem_proof(proof, by="host")` consumes a proof once, right before the host acts. It refuses a proof that has been redeemed, whose lease is revoked or expired, whose version is no longer active, or whose avatar is halted. Redemptions are persisted (action status `redeemed` in `state.json`) and logged (`proof_redeemed`, `proof_redemption_refused`). There is a new read-only `check_proof()` (returns the reason) and `proof_in_ledger()` (a historical, audit-only lookup). The CLI adds `redeem` and `check-proof`.
  - **Lease tokens** bind a nonce and the full effective terms from the new read-only `lease_terms()`: avatar, version, policy hash, capability, contexts, human-review flag, `max_actions` and TTL. `grant_lease()` gains `nonce=`. Used nonces are recorded in `state.json`. A reused nonce or different terms are refused, and with a keyring a nonce is required.
  - **Rollback tokens** also bind a single-use nonce (`rollback(..., nonce=)`).
  - **Halt resets.** Each halt gets a `halt_id`, which is returned by `request_action`, shown by `current_identity()` and logged. `clear_halt` tokens bind it, so a token clears only that halt.
  - **Module approvals** bind the upload's `proposal_id`, which `receive_personality()` returns and `current_identity()["proposal_ids"]` lists. Re-uploading a superseded manifest creates a new proposal that needs fresh approvals.
  - **Ledger error message.** The read-only error after tampering now keeps the specific reason (for example "line 8 hash does not match its content") instead of a misleading "lines may have been removed".
  - **Helpers.** New `signing.module_detail`, `lease_detail`, `rollback_detail` and `new_nonce`.
- **Compatibility (breaking):**
  - `verify_proof()` is now current-only and read-only. It returns False once a proof is redeemed, its lease is revoked or expired, its version is replaced or the avatar is halted. Use `proof_in_ledger()` for the old "was it ever authorised" answer.
  - With a keyring, module, lease, rollback and clear_halt tokens made for 0.1.0 no longer verify. Sign the new detail strings instead; the CLI does this automatically.
  - State written by 0.1.0 still loads:
    - a version pending from before has proposal id `""`;
    - an avatar halted before has halt id `legacy-<identity_root>`;
    - `used_nonces` starts empty.
  - Calls without a keyring keep working unchanged, since `nonce` is optional there.
- Governance hardening (no version bump): THREAT-MODEL.md (assets, trusted parties, host obligations, adversaries, out of scope, operator-controlled state and ledger, residual risks) and docs/ARCHITECTURE.md with a mermaid boundary diagram, both linked from the README.
- `benchmarks/adversarial.py`: seeded, deterministic, standard-library adversarial benchmark over the public API (unapproved activation, expired leases, budget exhaustion, scope escalation, use after rollback or halt, ledger tampering, forged and replayed proofs and tokens) with committed `benchmarks/results.json` and `results.md`, tests, and a CI step that fails on any false approval. Committed run: 0 false approvals in 1,304 attacks; it also reports what gets through today (operator-level ledger rewrites, replay of proofs and of lease, clear_halt and module HMAC tokens) and that a send_email lease of two or more units halts the avatar part-way through.
- README leads with the research question and a five-minute quickstart verified from a clean checkout (validate, upload, approve, lease, authorise, held action, second version, rollback, verify), then architecture, threat model and benchmark; the Tesla pages are the secondary demo. New Open questions and Research collaboration sections; new limitations on replay.
- Precise wording: the talk page and demo page say the guide cannot generate an answer and selects from a finite set of scripted, sourced answers using browser-side matching; the README says what the runtime does not do (secure the model, sandbox the host, replace identity and access management); the demo page lists every caveat; risk handling is described exactly (`None`, NaN, infinite or non-numeric risk counts as 1.0).
- COMMERCIAL-LICENSE.md and README: commercial terms are not finalised; the author is open to discussing a separate licence for proprietary integration.

- Talk page (`talk.html`): scripted, sourced Q&A with the Tesla-inspired guide, browser speech synthesis and optional speech recognition, public-domain portrait credited in CREDITS.md.
- Talk page: original illustrated SVG character with viseme lip-sync from speech boundary events (timer fallback), blinking, eye tracking, a thinking state, typed captions and a coil backdrop; deeper default voice with saved settings; static and noscript text fallbacks.
- Talk page: male voice selection using known male and female voice names and Android voice ids, with a lowered-pitch fallback and a note when no male voice is installed, a Test voice button, and a saved female voice choice cleared on load. Still, labelled AI-generated portrait supplied by the author, never animated. Fair, solid skin colours so forced dark modes do not darken the illustration, and a closer stylised resemblance to Tesla.
- Talk page: broad sourced notes on electricity, current, magnetism, the power grid, lightning, energy and power, Tesla's inventions and his life, with single-word keywords. Questions that match weakly get the closest note with a lead-in, on-topic questions with no match get an overview, and only off-topic questions get the note that the guide covers Tesla and the history of electricity.
- Talk page: shorthand such as AC, DC, lab, bulb and Wardenclyffe is expanded in questions and keywords alike, and the question's words are highlighted in the answer bubble from escaped text; speech, lip sync and captions use the plain text.
- Talk page: keyword phrases also match when other words sit between their parts, so every listed question answers with its own note (tested, along with 45 everyday phrasings); a topic map of six groups; follow-up chips drawn from related notes, the same topic and the same group, never the note just given; spoken answers revealed word by word; idle breathing, glances, a listening head tilt and faint coil arcs for the illustrated guide, pausable and off with reduced motion.

## 0.1.0 (2026-10-18)

First public version: personality manifest validator, policy compiler with a runtime capability registry, deterministic shadow simulation, OES-61440 threshold-latch tripwire, capability leases, held and human-approved actions, quorum commits, rollback from a checksummed version store, fail-closed hash-chained ledger, optional HMAC approval tokens, CLI, Tesla-inspired and Sparky example personalities, a static demo page and an animated walkthrough built from recorded runtime output, 71 tests on Python 3.10-3.13.
