# identity-runtime

Governed, reversible avatar personalities with leased capabilities and a hash-chained audit ledger.

Research prototype from Spark AI NLP (Fredericton, New Brunswick, Canada). Classical, deterministic, standard-library-only Python 3.10+. It is not a product, it has not been tested against real attackers, and it does not make an AI model safe on its own.

- Live demo page: https://sparkainlp-x.github.io/identity-runtime/
- Animated walkthrough: https://sparkainlp-x.github.io/identity-runtime/animation.html (one recorded run of the Tesla-inspired example, step by step; keyboard controls, captions, respects reduced-motion settings)
- Talk with the Tesla guide: https://sparkainlp-x.github.io/identity-runtime/talk.html (type or speak a question; scripted, sourced answers read aloud by your browser's synthetic voice, with typed captions and an original illustrated character whose lips follow the words; male voices are chosen first where the browser has one, otherwise the pitch is lowered and the page says so; a still, labelled AI-generated portrait supplied by the author sits beside it; a fictional educational character, not Tesla himself, not an AI chatbot, not affiliated with or endorsed by Tesla, Inc.; portrait credit in [CREDITS.md](CREDITS.md))
- Author: Jean-François Brisson ([ORCID 0009-0000-9778-5374](https://orcid.org/0009-0000-9778-5374)), Spark AI NLP
- License: AGPL-3.0-only (commercial licensing: [COMMERCIAL-LICENSE.md](COMMERCIAL-LICENSE.md))
- DOI: [10.5281/zenodo.23448946](https://doi.org/10.5281/zenodo.23448946) (concept DOI, all versions); v0.1.0: [10.5281/zenodo.23448947](https://doi.org/10.5281/zenodo.23448947)

## The idea

A personality on its own is mostly harmless text. What makes an avatar risky is what it can do: send email, post, spend, change files, or change its own rules. So this runtime treats a personality as a versioned identity state that must be approved before it becomes active, and treats every capability as a short lease that a person grants, that runs out, and that can be revoked at any time.

- **Identity root.** Each avatar gets a fixed identity root the first time it is uploaded. New personality versions attach to that root; a manifest cannot change it.
- **Modular personality.** A manifest is split into modules (identity, reasoning, memory policy, tool policy, safety policy, interaction, voice, appearance). Each module has its own checksum.
- **Upload is not activation.** An uploaded manifest is checked against the schema, compiled into a runtime policy, and run through a deterministic shadow simulation. It then waits. Voice and appearance are approved automatically; identity, reasoning, memory policy and interaction need one human; tool policy and safety policy need two distinct humans. The version commits only when every module is approved. The avatar itself, any other avatar, and reserved ids (`runtime:`, `system`, `self`, ...) cannot approve.
- **The runtime owns the capability list.** A persona can only switch on capabilities in the runtime's registry, and can only make them stricter (fewer actions, shorter leases, narrower contexts, more human review). Unknown capabilities are rejected. Capabilities such as `modify_safety_policy`, `modify_own_personality`, `spend_money`, `delete_files` or `execute_code` can never be enabled; a manifest that tries is rejected.
- **Leases.** A person grants a lease for one capability with an action budget and an expiry, bound to the active personality version. Committing a new version, rolling back, or a halt revokes every lease.
- **Actions carry proof.** When the avatar asks to act, the runtime checks the lease, the context, the policy and the OES-61440 tripwire, then either denies, holds the action for a human, or authorises it. An authorised action gets a proof object (version checksum, policy hash, lease id, risk, tripwire counts) whose hash is written to the ledger. The runtime does not perform the action; the host application should act only on a proof it can find in the ledger.
- **Rollback.** Every committed version is kept in a version store keyed by its checksum. A person can restore the previous version, or any version this avatar committed before. Stored versions are re-checked against their checksum and their policy is recompiled, never trusted from disk.
- **Ledger.** Every step is appended to a hash-chained JSONL ledger. Editing, reordering or deleting lines breaks verification; a torn last line or a ledger shorter than the head recorded in the state file also fails. A broken ledger makes the runtime read-only.

## Upload a personality

```bash
git clone https://github.com/sparkainlp-x/identity-runtime
cd identity-runtime

python -m identity_runtime validate personalities/tesla.json     # dry run, no state
python -m identity_runtime upload personalities/tesla.json       # waits for approvals

python -m identity_runtime approve tesla-edu-guide all --as alice
python -m identity_runtime approve tesla-edu-guide tool_policy safety_policy --as bob   # second, distinct person

python -m identity_runtime grant tesla-edu-guide read_public_data --as alice --max-actions 10
python -m identity_runtime act tesla-edu-guide read_public_data --context research --risk 0.2   # authorised autonomously

python -m identity_runtime grant tesla-edu-guide send_email --as alice --max-actions 1
python -m identity_runtime act tesla-edu-guide send_email --context approved_outreach           # held for a human
python -m identity_runtime approve-action <action_id> --as bob                                 # consumes the lease once

python -m identity_runtime revoke tesla-edu-guide send_email --reason "done"
python -m identity_runtime rollback tesla-edu-guide --as carol      # after a second version was committed
python -m identity_runtime status tesla-edu-guide
python -m identity_runtime verify
python -m identity_runtime demo                                     # the whole lifecycle in a temp directory
```

State lives in `.identity-runtime/` (or `--state DIR`, or `$IDENTITY_RUNTIME_STATE`): `state.json`, `ledger.jsonl` and `versions/<checksum>.json`.

To require signed approvals, create a keyring and pass it to every command:

```bash
python -m identity_runtime keygen approvers.keyring.json alice bob carol
python -m identity_runtime --keyring approvers.keyring.json approve tesla-edu-guide all --as alice
```

Each approval then carries an HMAC-SHA256 token over exactly what is approved (avatar, manifest checksum or action id, module or capability, approver). These are shared-secret MACs, not public-key signatures: whoever holds the keyring can approve as anyone in it.

The same flow from Python:

```python
import json
from identity_runtime import IdentityRuntime

rt = IdentityRuntime(".identity-runtime")
up = rt.receive_personality(json.load(open("personalities/sparky.json")))
for module in up["awaiting"]:
    rt.approve_module("sparky-the-beaver", up["manifest_checksum"], module, "alice")
for module in ("tool_policy", "safety_policy"):
    rt.approve_module("sparky-the-beaver", up["manifest_checksum"], module, "bob")
rt.grant_lease("sparky-the-beaver", "read_public_data", "alice", max_actions=5)
print(rt.request_action("sparky-the-beaver", "read_public_data", "visitor_help", risk=0.1))
```

## Writing a personality

A manifest is a JSON file with `"schema": "identity-runtime/personality-v1"`, an `avatar_id` (lowercase letters, digits, hyphens), a `display_name` and `modules`. `identity`, `tool_policy`, `safety_policy` and `interaction` are required. See [personalities/tesla.json](personalities/tesla.json) and [personalities/sparky.json](personalities/sparky.json), and run `validate` to get every error in one pass.

A character based on a real historical person must use `"character_type": "inspired_by_historical_figure"`, name the person and lifespan in `inspired_by`, and carry a `disclaimer` that says what the character is not.

Capabilities the registry knows today: `respond_in_chat`, `read_public_data`, `summarize_document`, `draft_message`, `schedule_reminder`, and, always with human approval, `send_email`, `post_public`, `write_sandbox_file`. Limits are in [identity_runtime/policy.py](identity_runtime/policy.py).

### Example personalities

- **Inventor's Notebook guide** ([tesla.json](personalities/tesla.json)): a fictional educational character inspired by the historical inventor Nikola Tesla (1856-1943). It is not Nikola Tesla, does not speak for him or imitate his voice, and is not affiliated with or endorsed by Tesla, Inc. It teaches the history of alternating current and corrects popular myths: Wardenclyffe never delivered wireless power, and no "free energy" or "death ray" machine by Tesla has been documented. It makes no medical, free-energy or over-unity claims.
- **Sparky the Beaver** ([sparky.json](personalities/sparky.json)): the Fredericton Holograms mascot, a bilingual visitor guide that hands anything consequential to staff.
- [examples/malicious.json](examples/malicious.json) is a test fixture that must be rejected: it tries to enable `modify_safety_policy` and contains "ignore previous instructions".

## OES-61440, plainly

OES-61440 is the name of the tripwire's shape: 61,440 fixed threshold channels, grouped as 1,920 membranes of 32 channels, 480 supervisors of 4 membranes and 120 sectors of 4 supervisors. Each channel compares a fixed weighted sum of four signals (effective risk, the capability's base risk, context mismatch, lease use) with a fixed threshold; weights and thresholds come from SHA-256 of the channel index. A membrane trips on 17 of 32 channels, a supervisor on 3 of 4 membranes, a sector on 2 of 4 supervisors. One tripped sector holds the action for a human; when every sector and at least 95% of channels trip, the avatar is halted and all its leases are revoked until a person clears the halt.

It is deterministic and transparent, and nothing in it is learned. In effect it is a graded threshold on a weighted risk score. Its settings are illustrative choices, not calibrated against any incident data, and it is not a safety guarantee. It also sits next to a plain rule that does not depend on it: any action with effective risk of 0.5 or more is held for a human. The effective risk is the larger of the risk the caller declares and the capability's base risk, so an avatar cannot talk its way down by declaring zero risk; a missing or non-numeric risk counts as 1.0.

## Limitations

- **Text screening can be bypassed.** The injection and self-escalation patterns catch copy-pasted attacks and a few simple evasions (case, spacing, zero-width characters, full-width letters). Paraphrases will get through. The pattern list is in [identity_runtime/simulation.py](identity_runtime/simulation.py).
- **The shadow simulation does not run a model.** It replays fixed adversarial requests against the compiled policy. An optional `model_hook` can send probe prompts to a model you supply; none ships here, and screening its replies is again string matching.
- **No sandbox.** The runtime authorises and records; it executes nothing. Whatever performs the action must enforce the proof itself.
- **No public-key signatures.** Approvals are plain ids unless you configure the HMAC keyring, and the keyring is a shared secret. The ledger is tamper-evident, not tamper-proof: someone who can rewrite both the ledger and `state.json` can rebuild a consistent chain. Anchor the ledger head somewhere else if that matters.
- **Single process, local files.** No locking for concurrent writers and no network service.
- **Persona text is not enforced on a model.** Fields such as `myths_to_correct` describe intended behaviour. Whether a language model follows them depends on that model and how the host uses the manifest.

## Tests

```bash
python -m pip install pytest
python -m pytest -q
```

92 tests run in CI on Python 3.10-3.13 with warnings treated as errors. They cover the full Tesla lifecycle, quorum rules, self-approval refusal, lease budgets, expiry and clamping, held and approved actions, revocation, rollback (including across restarts and with a tampered version file), malicious and injected manifests, ledger tampering, truncation and tail deletion, signed approvals, the CLI, the static pages (including the animation's embedded data and the talk page's Q&A, sources, myth corrections, question matching, synonym expansion, escaped answer highlighting and self-containment) and the stdlib-only rule. [docs/REVIEW.md](docs/REVIEW.md) lists what was wrong with the first draft and how each item was handled.

## Citation

See [CITATION.cff](CITATION.cff). Cite the concept DOI [10.5281/zenodo.23448946](https://doi.org/10.5281/zenodo.23448946) for all versions, or the version DOI [10.5281/zenodo.23448947](https://doi.org/10.5281/zenodo.23448947) for v0.1.0.
