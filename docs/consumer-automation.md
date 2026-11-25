# Automatic isolated consumer signing and publication

This route automates cryptographic signing and publication **after independent
release approval and acceptance**. It never converts build success into device,
supplier or packet-path acceptance, manufactures PASS records, or changes the
existing eight qualification lanes or SDK publisher.

## Three independent roles

1. At the exact `consumer-automation-<SHA>` ref, builder authenticates the
   original signed encrypted request, complete first-attempt qualification and
   exact direct publisher artifact. No local/native rebuild occurs.
2. The completed `prepare-signing` job emits only `input.enc`: a new envelope
   encrypted directly to a dedicated signer public recipient. No delegated
   file key, capability or master-log private key is used.
3. Builder dispatches the consumer repository's exact `consumer-signer-<SHA>`
   workflow. It checks out only the reviewed builder implementation, never
   consumer source/scripts/executables. It authenticates producer/job/attempt,
   operator signature, original qualification/artifact, protected policy,
   receipt digests and archive bytes before reading private signing authority.
4. The signer returns an encrypted bundle and signed run-binding certificate
   to the existing builder input public recipient. Builder checks the signer
   run, ciphertext, certificate, original qualification and all signatures.
5. Only final publication receives existing `BIN_PUBLISH_TOKEN`. Signing,
   decryption and dispatch credentials are absent from this step. Existing
   reviewer gates remain deliberate: automated signing does not bypass approval.

Repository ID, actor, workflow/ref/SHA, first attempt and opt-in are checked in
workflow and runtime. Checkout credentials are not persisted. GnuPG imports one
approved key into an owner-only temporary home; no ambient keyring, credential
environment, passphrase argv or tool output is forwarded. Agent/key cleanup is
mandatory. Cleanup failure cannot grant PASS or hide an earlier assertion.
Builder checks out its immutable `github.sha`, not a mutable checkout variable.
The consumer workflow checks the cross-repository checkout against protected
policy with isolated standard Python **before executing any checked-out code**.
A mutable repository variable alone cannot select code that later gets secrets.

## Independent policy and protected environments

The protected release policy additionally requires `automation`:

- `builder_sha`, `signer_sha`: exact reviewed implementation/workflow commits.
- `signer_recipient`: independent dedicated HPKE public-recipient fingerprint.
- `operator_verify_sha256`: hash of canonical existing operator public-key JSON.
- `receipt_sha256`: exact approved canonical `dataplane`, `client` and `supplier`
  receipt hashes, not merely check names or self-reported PASS labels.

Both repositories independently provision the same release/qualification policy.
Changing even an all-PASS receipt fails before signing. Only eligible product or
verified synthetic acceptance belongs here; never encode anonymized real-host
operational evidence as a receipt.

| Environment | Repository | Allowed authority |
| --- | --- | --- |
| `consumer-release-preparation` | builder | Input/direct-artifact decryption and public signer recipient, no signing/publication key |
| `consumer-release-signing` | consumer | Dedicated input decryption and approved signer/passphrase, no destination publication token |
| `consumer-publication` | builder | Existing reviewer gate; separate dispatch, verification and publication steps |

Each environment permits only its exact immutable tag. The consumer's private
secrets are `CONSUMER_SIGNER_INPUT_PRIVATE_KEY_B64`,
`CONSUMER_RELEASE_SIGNING_PRIVATE_KEY_B64` (passphrase-protected armored OpenPGP,
base64 encoded), and separate `CONSUMER_RELEASE_SIGNING_PASSPHRASE`. Public/policy
secret names are explicit in the signer workflow. Do not copy signing authority
to builder/native jobs. Possession of a local key is not provisioning authority.

Builder receives only `CONSUMER_SIGNER_INPUT_PUBLIC_KEY_B64`, matching policy.
Existing `BIN_DISPATCH_TOKEN` is confined to orchestration and needs scoped
consumer workflow dispatch/result-read access. There is no credential fallback.

Builder opt-in variables: `CONSUMER_AUTOMATION_ENABLED=true` and
`CONSUMER_AUTOMATION_BUILDER_SHA`. Consumer variables:
`CONSUMER_SIGNER_ENABLED=true`, `CONSUMER_SIGNER_WORKFLOW_SHA` and
`CONSUMER_SIGNER_BUILDER_SHA`. Keep disabled until review, synthetic CI and exact
tag/environment policies are verified. Unsupported private environments or
missing permissions are blockers, not permission to downgrade key isolation.

## Changelog, latest and immutable assets

Optional `presentation` policy contains exactly `notes_sha256` and boolean
`make_latest`. Extract one bounded version section from `CHANGELOG.md` with
`consumer_presentation.extract_changelog()`, review against the released source,
and independently pin its UTF-8 hash. Use immutable links rather than relative
release-page URLs.

An OpenPGP presentation signature binds notes/latest to destination, source,
tag object, archive, approval and all eight asset hashes. Readable notes precede
a collapsible integrity section. Explicit latest selection is checked against
the actual latest endpoint.

New releases receive automatically signed UTC tag, archive, approval,
provenance and checksums. For an existing release provide its verified
`approval`, `approval_signature`, `tag` and `signatures` as `existing`: all remain
byte-identical. Only new presentation and the transport certificate are signed.
Metadata correction accepts only the exact original integrity marker or approved
final body. Foreign descriptions, moved tags and conflicting assets fail rather
than overwrite. Identical continuation is a no-op.

## One encrypted request

The private JSON payload has exactly `qualification_request`,
`qualification_request_id`, base64 canonical `receipts`, exact `notes` (or null),
and `existing` (null for a new release; the four fields above otherwise).

```sh
python -m secure_release.consumer_automation package \
  --bundle /private/automatic-release-request.json \
  --input-public /private/builder-input-public.json \
  --builder-sha FULL_REVIEWED_BUILDER_SHA \
  --output /private/new-automatic-dispatch.json
```

Submit that exact reviewed encrypted payload to the builder workflow. No local
OpenPGP signing command or qualification/device-acceptance rerun is needed.
Dispatch expires after six hours; signer handoff after thirty minutes; bounded
orchestration waits twenty minutes. Retry with a fresh encrypted request, never
an Actions rerun or changed released assets.
If a new release was interrupted after signing, reuse the authenticated prior
signer bundle as `existing` in the fresh request. Do not regenerate tag or asset
signature bytes for an already created tag/draft. Conflicting new bytes fail
closed; automatic continuation is not permission to overwrite a partial release.

Short-lived storage URLs travel only inside signer-recipient ciphertext.
Producer artifact ID/digest/size are independently checked before download.
Authorization never follows storage redirects. Artifacts/diagnostics contain
only ciphertext; raw URLs, tool output, keys, archives and plaintext plans are
never diagnostic uploads.

Synthetic tests use freshly generated Tink/OpenPGP keys and in-memory remote
APIs. They cover admission, exact archives, receipt pins, signatures, metadata
correction, original-signature preservation and run-bound encrypted exchange;
they do not prove actual hosted provisioning or authorize a real release.
