# precog-verifier

The reference verifier for the Psi Census study (https://psicensus.com). It checks the study's published
data, or one player's receipt, using only the public format in [`SPEC.md`](SPEC.md) (specification version 1, the version the study names at registration; later changes are published as dated amendments). It has no
runtime dependencies (Python standard library only) and needs no access to the operator's systems.
The code is short on purpose, so that you can read all of it.

This README is written for a reader who assumes the operator might cheat. It says what the verifier
proves, what it does not, and what you still have to check yourself.

## 1. What is claimed, and what the verifier proves

**The study.** People guess one of 5 symbols, 25 times per batch. After the batch is locked, a target
for each guess is derived from public randomness (the drand quicknet beacon) that did not exist when the
batch was locked. The question is whether the pooled hit rate differs from 20%. The analysis was
pre-registered; see section 5.

**What a clean run proves.** If `verify-release` prints `result OK` for a release, then, assuming the
two timestamp authorities and the drand network are honest and independent (below):

| Claim | Check that enforces it (error code) |
|---|---|
| Every published batch row hashes to its published leaf, so guesses and `sealed_at_ms` in the row are the ones that were committed | `leaf.mismatch` |
| The rows of each anchor reproduce its Merkle root and leaf count; no row was added, removed or edited after the root was fixed | `merkle.root_mismatch`, `merkle.count_mismatch`, `batch.leaf_index_gap` |
| The anchors form one unbroken hash chain from sequence 1; none was removed, re-ordered or replaced in the middle | `anchor.hash_mismatch`, `anchor.chain_broken`, `anchor.seq_gap` |
| Each anchor hash was signed by at least two different timestamp authorities, with tokens that verify against pinned certificates, valid at the token's own time | `tsa.invalid`, `tsa.wrong_imprint`, `tsa.too_few` |
| Every batch was sealed no later than the earliest timestamp of its anchor | `leaf.sealed_after_anchor` |
| The target round of every batch is the one implied by the authorities' timestamps, not one the operator chose | `target.round_wrong` |
| Every target round is a real drand round: its BLS signature verifies against the quicknet public key | `round.unavailable` (and the warnings `round.cache_missing`, `round.cache_bad` when the cached copy was replaced by a fetched one) |
| Every published hit count is the one recomputed from the guesses and the beacon output | `score.mismatch` |
| A daily head that is published names an anchor that exists in the release, with the same hash | `head.mismatch` |
| Every complete UTC day from the first anchor's day up to the time you judge the release at (`--as-of`, one hour of grace) has a head, so deleting the newest anchors together with their heads is noticed | `head.missing` |
| The reported `S` and `z` are computed only from a release with zero errors, and no batch is dropped because of an error | `analysis.withheld` |

Put together: a batch that was altered, inserted, or backdated after its target was known, or an anchor
that was removed from the middle of the chain, breaks one of the checks above. A release with any
error is invalid and the verifier prints no `S` or `z`. It never "excludes the bad rows and carries
on", because that would let someone drop unwelcome batches by corrupting them.

**Exclusions.** Exactly four, all fixed before a batch's target exists: batches with `source = canary`
(analysed separately), batches sealed before `registration_ms` in the manifest, repeated copies of a
batch ID (the first-committed copy counts; later copies do not; copies in the same earliest anchor are all
dropped), and, from `registration_ms` on, a first copy whose `test_id` is not `card5` (SPEC 9.2; it
is counted in `excluded_other_test` and gives the warning `batch.other_test_id`, never an error). Duplicates are
printed as the warning `batch.duplicate_id`. The counts of all exclusions are printed.

### What the verifier does not prove

Be sceptical about these. Each one is a place where trust in the operator, or your own checking, is still needed.

1. **It does not prove the release is complete or current.** The verifier checks a release against
   itself. A deleted anchor in the middle is detected. A deleted tail is detected up to the release cut,
   which is the `--as-of` time (default: your clock when you run it): every complete UTC day up to it needs a
   daily head, and a head that names a deleted anchor is `head.mismatch`, so removing the newest anchors needs
   removing every head back to the cut (`head.missing`). What is not detected is a tail newer than the last
   head, up to a day and an hour of anchors, and a deleted tail whose heads the operator also rewrote consistently
   (the Bitcoin proofs of the heads, section 3.7, would show that only for the heads whose proof is already confirmed). Judge an archived
   release later with `--as-of <the time you downloaded it>`, or it fails for the days since. To close the rest: download the export repeatedly, keep
   your copies, and compare the anchor hashes in them. An anchor hash that changes later, or disappears,
   is proof of rewriting. The operator's own nightly job does this (`tools/nightly_verify.py`, alerts
   `nightly.history_changed`, `nightly.stalled`, `nightly.latest_regressed`), but it is run by the
   operator, so run your own.
2. **It does not see batches that were never sealed.** The operator can reject, or never record, a
   batch before it is sealed. Before sealing no target exists, so this cannot depend on the outcome
   and does not bias the test. It does mean the study counts only what was sealed: rejections (rate limits, failed anchors) are
   logged by the operator but are not verifiable by you.
3. **It does not prove who played, or that a human made the guesses.** The operator could run fake
   players. They cannot see targets (those do not exist yet), so they add chance data and dilute any real effect.
   They cannot create an effect. The verifier has no check for this and does not claim one.
4. **Selective deployment and release timing are outside the verifier.** The operator decides when to
   publish a release and which release to call "the" release. The protocol fixes the analysis in
   advance so that a late choice of release does not change the pre-registered numbers, but only if you
   compare releases (item 1).
5. **The trust in the timestamp authorities and the beacon is real.** The target round cannot be
   known at sealing unless the drand network (threshold-signed by many independent operators) is
   compromised, or both timestamp authorities backdate a token at the operator's request. The
   verifier cannot detect that. It does check that the two authorities named in each anchor are two
   different `id`s in the manifest; it does not check that they are different companies. It warns
   (`tsa.same_root`, SPEC 11.2) when an anchor's tokens all chain to one `root_sha256`,
   but different roots do not prove different operators either, so read the manifest.
6. **The manifest and the unhashed row fields are taken from the operator.** `registration_ms`, the
   `source` field (`player` or `canary`), and the authority list are not covered by any hash or
   timestamp. Compare `registration_ms` with the registered date (or pass the published value with `--registration-ms`, which fails with `manifest.registration_mismatch` when the manifest differs: SPEC 11.3), and compare the canary count with the
   expected cadence (one canary batch every 4 hours). Canary rows are also checked: their guesses must
   be the ones derived from a cron slot just before `sealed_at_ms` (SPEC 9.7; section 3.8), so a
   relabelled player batch is an error. See section 6, "Known gaps", which also lists the checks that are not yet in the code.
7. **Mock authorities and the mock beacon verify too.** The verifier supports test-only authorities
   (`kind: mock-hmac`) and a test beacon (`network: mock-beacon`), whose keys and outputs are public.
   A release that uses them proves nothing. The verifier prints the warnings `manifest.mock_authority` and
   `manifest.mock_beacon` (SPEC 11.2), and with `--require-production` they are errors
   (exit status 1). Before you trust any `result OK`, run with `--require-production` and compare
   `manifest.json` with the values in "Expected production manifest" below. The bundled sample releases
   under `tests/data/` use mocks on purpose.
8. **Bitcoin anchoring of the daily heads is checked only as far as section 3.7 says.** A confirmed proof shows that a head existed by a time; a pending or unchecked one shows nothing yet.

### Expected production manifest

These are the values in the live manifest, `https://psicensus.com/export/manifest.json`, **as of 2026-10-19**.
Compare them with the `manifest.json` of any release you verify; they are a snapshot, not a promise, and a later
release may add an issuing CA to a list (the lists are append-only) or an authority. The tool does not compare
them for you.

| Field | Value |
|---|---|
| `beacon.network` | `drand-quicknet` |
| `beacon.chain_hash` | `52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971` |
| `beacon.genesis`, `period`, `margin_rounds` | `1692803367`, `3`, `2` |
| authority `digicert` | `kind: rfc3161`; `root_sha256` `552f7bdcf1a7af9e6ce672017f4f12abf77240c78e761ac203d1d9d20ac89988`; `issuing_ca_sha256` `ca0b1554ecd901ea19dcad8749e9f2648c8d6dfcea1add9d2c2109415bb82ccd` |
| authority `globalsign` | `kind: rfc3161`; `root_sha256` `2bcbbfd66282c680491c8cd7735fdbbab7a8079b127bec60c535976834399af7`; `issuing_ca_sha256` `52373a21b95b5e6de12a2bcf0ffb7d6a633b4caad725f64f6236fbe989dbc29e` |
| authority `certum` | `kind: rfc3161`; `root_sha256` `b676f2eddae8775cd36cb0f63cd1d4603961f49e6265ba013a2f0307b6d0b804`; `issuing_ca_sha256` `f882effc16de28d508c092e35825b00242cf963071c279ef09310d9d95784b35` |
| `with_participants` | `false` |

The three roots are different, so a production release raises no `tsa.same_root` warning. The
manifest's `release_id` is `live` and `registration_ms` is `1792972800000` (2026-10-26T00:00:00Z), the value in the
registered study. The study was registered on OSF on 25 October 2026: registration
https://osf.io/fqrsu/ (from the OSF project https://osf.io/sqc5n/). The registered file is
`docs/study-precognition.md`; its SHA-256 is
`a68cab9bf4aea361f716b64bfdde34abd0c1fa61f668cc1daed3b46af2cf755d` (12,702 bytes). To check the copy in this
repository against OSF, compare that value with `sha256sum docs/study-precognition.md` (PowerShell:
`Get-FileHash docs/study-precognition.md -Algorithm SHA256`).

## 2. Quick start

Requirements: Python 3.14 or newer (see `pyproject.toml`). No packages are needed to run it.
`pytest` is needed only to run the tests.

```
git clone https://github.com/kd7uiy/psicensus-verifier
cd psicensus-verifier
python -m venv .venv
.venv/bin/python -m pip install -e .          # Linux and macOS
.venv\Scripts\python -m pip install -e .      # Windows (cmd or PowerShell)
```

On Windows, clone with `git clone -c core.longpaths=true https://github.com/kd7uiy/psicensus-verifier`: some
file names under `src/precog_verifier/trust/` and `tests/data/` are long (a SHA-256 in hex), and without long-path
support the checkout is incomplete. The three pinned root certificates (`.der` files) in `src/precog_verifier/trust/`
must be present; if one is missing, the verifier reports `trust_root: no trusted root`, and the release looks invalid
when it is the checkout that is broken.

Use the virtual environment's Python for every command below: activate it, or call `.venv/bin/python` (Linux and macOS)
or `.venv\Scripts\python` (Windows) in place of `python`. Every command in this README is run from the repository root.

Without installing, `PYTHONPATH=src python -m precog_verifier ...` (Linux/macOS) or
`$env:PYTHONPATH="src"; python -m precog_verifier ...` (PowerShell) also works from the repository root.

### Verify a bundled test release (no network)

The `tests/data/` directory holds fixtures. `sample_release_real` carries real RFC 3161 tokens from the
three pinned authorities and real drand rounds, so it needs no network. `--as-of` pins the judging time (these fixtures are old, and the real one has no heads):

```
python -m precog_verifier verify-release tests/data/sample_release_real --offline --as-of 2026-10-06T00:30:00Z
```

Its output, in full:

```
result OK
as_of_ms 1791246600000
registration_ms 0 source=manifest
release_id test-real-fixtures-2026-10-05
analysis n_batches=7 N_trials=175 hits=32 rate=0.182857 S=-3 z=-0.566947
excluded pre_registration=0 duplicate_later=0 duplicate_same_anchor=0 other_test=0
interval pp_low=-7.640769 pp_high=4.212197
canary seen=0 n_batches=0 N_trials=0 hits=0 rate=n/a S=0 z=n/a
secondary unavailable code=secondary.no_participants
permutation unavailable code=permutation.pending round=32827710
ots confirmed=0 pending=0 unchecked=0 late=0 missing=0
errors 0 warnings 0
```

The other two fixtures use mock authorities (`sample_release`) and a synthetic test PKI
(`sample_release_rfc3161`); both need the extra trust directory:

```
python -m precog_verifier verify-release tests/data/sample_release_rfc3161 --offline --as-of 2023-11-17T00:00:00Z --trust-dir tests/data/rfc3161/synth/trust
```

This one prints `result OK` and one warning, `manifest.mock_beacon` (the fixture uses the test beacon), and exits 0.

### Download the real release and verify it

The public site serves the export at `https://psicensus.com/export/*`
(`manifest.json`, `page`, `chain`, `heads`, `ots`). The downloader is part of the package (standard library only):

```
python -m precog_verifier fetch https://psicensus.com ./release
python -m precog_verifier verify-release ./release --require-production --registration-ms 1792972800000
```

`--registration-ms <ms>` is optional: it fails the run with `manifest.registration_mismatch` when the manifest's
`registration_ms` differs from the value you pass (SPEC 11.3). The registered value is `1792972800000`.

What to expect today: batches sealed before the registration time are excluded; the analysis line shows
`n_batches=0` until a player batch is sealed after it, and the
warnings `canary.unverified count=4` and `ots.late count=1` and the line `permutation unavailable code=permutation.too_few`
are expected in today's record.

`fetch` needs `https` (plain `http` is accepted only for `localhost`, `127.0.0.1` and `::1`), and the directory must be empty or
missing. It prints `fetch OK ...` and exits 0, or prints `error <code>` and exits 1 (the export could not be downloaded;
nothing is left that looks like a release) or 2 (bad URL, or a directory that is not empty). It keeps no state and
writes no report; `verify-release` then repeats the whole verification yourself and refuses mock authorities and the mock
beacon. The operator's own nightly job uses the same downloader and adds state and alerts:

```
python tools/nightly_verify.py --base-url https://psicensus.com --work-dir ./release --report ./report.json
```

(`--work-dir` must be empty or absent; the downloaded release stays there.) The downloader never
drops, repairs or reorders anything, and it caps the size and the number of pages. Without `--offline`,
the verifier fetches any missing drand round from `api.drand.sh`, then `drand.cloudflare.com`, and checks
its BLS signature before using it. With `--offline` it uses only `rounds.jsonl` (and, for the Bitcoin proofs of the heads, `btc_headers.jsonl`), and a missing round is
`round.unavailable`. A full verification of a large release takes minutes of CPU: roughly 7 ms per round
in a batch and 145 ms for a single signature (`tools/bench_bls.py`).

### Check your own receipt

A receipt is the JSON file a player keeps for one batch (SPEC 10.2).

```
python -m precog_verifier verify-receipt receipt.json
python -m precog_verifier verify-receipt receipt.json --release ./release
```

Alone, it checks the leaf, the Merkle inclusion proof, the anchor hash, the timestamp tokens and the
target round. With `--release` it also confirms that the same anchor and the same batch row appear in the
published release unchanged: `receipt.not_in_release`, `receipt.row_changed`, `receipt.authority_mismatch`,
and `receipt.not_counted` (the receipt is for a duplicated batch ID and this copy is not the counted one).
This is the check that catches an operator who deleted or edited your batch: you hold the evidence.

### Reading the output

Exit status: 0 means no errors, 1 means at least one error, 2 means a usage problem (such as a missing directory).

```
result OK|FAIL
release_id <id>
analysis n_batches=… N_trials=… hits=… rate=… S=… z=…      (or: analysis withheld n_batches=… N_trials=…)
look j=… cut_ms=…                                              (only when the release_id is YYYY-Qn, SPEC 9.12)
excluded pre_registration=… duplicate_later=… duplicate_same_anchor=… other_test=…
interval pp_low=… pp_high=…                                    (95% interval for the hit rate minus 20%, in percentage points;
                                                               `interval withheld` when the analysis is, `n/a` values with no trials)
canary seen=… n_batches=… N_trials=… hits=… rate=… S=… z=…  (the same formula, the canary set only: section 3.8)
secondary stouffer_first k=… Z=…                               (after `secondary stouffer`; first batch of each participant, SPEC 9.10)
ots confirmed=… pending=… unchecked=… late=… missing=…          (the proofs of the daily heads, section 3.7)
warning <code> [anchor_seq=…] [batch_id=…] [detail=…]
error <code> [anchor_seq=…] [batch_id=…] [detail=…]
as_of_ms <ms>                                                  (the time the release was judged at, `--as-of` or your clock)
errors <n> warnings <m>
```

- `n_batches` is the number of counted batches; `N_trials` is 25 times that; `S` and `z` are defined in section 5.
- `analysis withheld` appears whenever there is any error. `S` and `z` are then not printed (`analysis.withheld` is
  added to the errors). No batch is excluded to make the numbers appear.
- `warning` lines never fail a run: `batch.duplicate_id` (every copy is listed), `round.cache_missing` or
  `round.cache_bad` (the cached round was missing or wrong and a verified one was fetched), and
  `anchor.time_regressed` (an anchor's token time is earlier than the previous anchor's),
  `manifest.mock_authority` and `manifest.mock_beacon` (the manifest names mock authorities or the mock beacon),
  and `tsa.same_root` (with `count=N`: N anchors whose tokens chain to a single `root_sha256`), and the four notices
  `ots.pending`, `ots.unchecked`, `ots.late` and `ots.missing` about the Bitcoin proofs of the heads (each once, with
  `count=N` and the first 20 dates; section 3.7; `--require-production` does not make them errors).
  With `--require-production` the two `manifest.mock_*` notices are errors instead.
- `warning batch.other_test_id` (SPEC 9.2; `count=N` in the detail): N first-copy player rows from
  `registration_ms` on carry a `test_id` other than `card5`. They are not counted and are shown as `other_test=N`.
- `error look.after_cut` (SPEC 9.12; one per anchor, only when `release_id` is `YYYY-Qn`): the anchor's
  time is after the end of that quarter. The line `look j=<n> cut_ms=<ms>` gives the look number `n` (the number of
  quarter starts after `registration_ms`, up to and including the cut) and the cut. The tool prints `n` and does not
  judge it; the range of looks is the study's.
- `error manifest.registration_mismatch` (only with `--registration-ms N`, SPEC 11.3): the manifest's
  `registration_ms` is not `N`. The output always has a line `registration_ms <value> source=manifest` (or
  `source=option` when you passed the value and it matched); `source=manifest` means the value that decides which
  batches count was taken from the operator's manifest only. `N` is Unix milliseconds, digits only.
- An example of failure, from a copy of `sample_release` in which one guess in an old row was edited
  (the tool prints every failing check, never only the first):

```
result FAIL
analysis withheld n_batches=12 N_trials=300
warning manifest.mock_authority detail=mock authorities prove nothing: tsa-a, tsa-b
warning manifest.mock_beacon detail=network=mock-beacon; a mock beacon proves nothing
error leaf.mismatch anchor_seq=3 batch_id=4c089c33… detail=published leaf differs from rebuilt leaf
error merkle.root_mismatch anchor_seq=3 detail=rebuilt root differs from the anchor
error analysis.withheld detail=the release has errors; S and z are not reported
errors 3 warnings 2
```

Error codes are stable identifiers; the full list and their order are in SPEC section 11.

## 3. How each step works

Each step is a short module in `src/precog_verifier/`. The specification is [`SPEC.md`](SPEC.md); you can
write your own verifier from it. The frozen test vectors in `vectors/*.json` are byte-exact cases any
implementation should reproduce. The domain tags are `precog/leaf/v1`, `precog/anchor/v1`, `precog/target/v1`,
`precog/canary/v1` and `precog/permutation/v1` (SPEC 1); they are historic and fixed.

### 3.1 Leaf (SPEC 3)
`leaf = sha256("precog/leaf/v1" || batch_id || str8(test_id) || guesses(25 bytes) || u64(sealed_at_ms))`.
No player identifier is part of it. `source`, `hits` and `target_round` are not part of it; `hits` and `target_round`
are recomputed (3.5, 3.6); `source` is a gap (section 6).

### 3.2 Merkle tree (SPEC 4)
RFC 9162 section 2.1: `0x00` for leaves, `0x01` for inner nodes, an odd leaf is not duplicated. The verifier
rebuilds each anchor's root from its rows in `leaf_index` order, requires the indexes to be exactly
`0..leaf_count-1`, and requires the row count to equal `leaf_count`. A receipt is checked by an inclusion
proof against the same root.

### 3.3 Anchor chain (SPEC 5)
`anchor_hash = sha256("precog/anchor/v1" || u64(anchor_seq) || prev_anchor_hash || merkle_root || u64(leaf_count))`.
Anchor 1 has an all-zero predecessor; each later anchor commits to the previous one. Because `leaf_count` is in the
hash, dropping a leaf changes the anchor even if someone recomputes the tree.

### 3.4 Timestamp tokens (SPEC 6)
Each anchor carries RFC 3161 tokens from at least two authorities listed in the manifest, whose message
imprint is `anchor_hash` itself. The `rfc3161` plugin is written with the standard library only (a bounded
DER reader, an X.509 subset, CMS SignedData, RSA PKCS#1 v1.5 with SHA-256/384/512). It accepts a token only if

- the imprint is the anchor hash, the signed attributes and the signature verify,
- the signer chains to a certificate whose SHA-256 is in the manifest's `issuing_ca_sha256` list, and then to the
  manifest's `root_sha256`, and
- every certificate in that chain (the root included) was valid at the token's own `genTime`, not today.

Roots are looked up only by their pinned hash. The shipped ones are in `src/precog_verifier/trust/`
(DigiCert Trusted Root G4, GlobalSign Timestamping Root R45, Certum Trusted Network CA 2); the folder's
README says where each came from. Certificates embedded in a token never extend trust. `--trust-dir DIR`
adds more directories of `<sha256>.der` files. Anything the plugin does not implement (RSA-PSS, ECDSA, SHA-1,
unknown critical extensions) fails closed with `tsa.invalid`; the reason is the first word of `detail`.
Revocation cannot be checked years afterwards and is not attempted: the archived tokens are the evidence.

Which tokens count is the manifest's decision, so read the manifest (section 1, item 7). The issuing-CA list is
append-only; a quietly added CA shows in the manifest's history in the public repository.

### 3.5 Target round (SPEC 7)
The drand quicknet chain has a fixed genesis, a 3-second period, and a public key (SPEC 7 lists them; the
verifier compares the manifest with these constants). The target round for an anchor is

```
t_anchor     = ceil(max(gen_time_ms over the anchor's tokens) / 1000)
target_round = the first round whose publication time is >= t_anchor + 2 * 3 s
```

**Why the target cannot be known at sealing.** The target depends on the timestamps the authorities place on
the anchor, and the anchor contains the batch. The round is at least 6 seconds after the later timestamp,
and drand's output for a round does not exist until that round is published. The operator cannot choose
the round, only receive it: any other round in a row is `target.round_wrong`. The later of the two token times is used, so
neither authority alone can move the round earlier. If both authorities backdated their clocks together,
the verifier could not tell (section 1, item 5).

### 3.6 Scoring (SPEC 8)
For guess `i`: `h = sha256("precog/target/v1" || randomness || str8(test_id) || batch_id || u32(i))`,
`target[i] = u64(h[0:8]) mod 5`, where `randomness = sha256(signature)` of the round and the signature is
verified against the quicknet public key. `hits` is the count of matches. The verifier recomputes every
batch's hits; a published `hits` that differs is `score.mismatch`. The BLS12-381 arithmetic, hash-to-curve
(RFC 9380) and pairing are in `src/precog_verifier/bls/`, standard library only, and are tested against
vectors in `tests/data/bls/` generated with a separate implementation (`tools/bls_oracle.mjs`).

`rounds.jsonl` is only a cache. A missing or invalid cached round is fetched and verified, or the check is
incomplete (`round.unavailable`, an error).

### 3.7 Daily heads, NIST pulses and OpenTimestamps (SPEC 10.1)
Once a day the operator publishes a head: the latest anchor hash, the number of anchors that day, and a NIST
beacon pulse (or `null`). Heads are `heads/YYYY-MM-DD.json` in the release. What the verifier checks about a head
is the `head.mismatch` rule above: it must name an anchor that exists, with the same hash. A head with
sequence 0 in a release that holds an anchor is also `head.mismatch`.

The point of heads is external anchoring: the head's `anchor_hash` is submitted to OpenTimestamps calendars, which
commit it into a Bitcoin block. Once the calendars have done so, `heads/<date>.ots` is published next to the head
(the export serves it at `/export/ots`). SPEC 11.4 says what the verifier does with these files; it
needs no Bitcoin node and trusts neither the operator, the calendars nor a block explorer.

**What is checked.** Each `heads/<date>.ots` must parse strictly (SPEC 11.4): the OpenTimestamps magic, version 1,
file hash sha256, the digest equal to the head's `anchor_hash`, a tree of sha256, append and prepend steps only
(arguments of at most 4096 bytes, at most 256 steps deep), attestations of the kinds pending, bitcoin or unknown, and
no byte after the tree; otherwise `ots.invalid` (an error). For each Bitcoin attestation the verifier computes the 32
bytes `m` at the end of its path and needs the 80-byte Bitcoin block header of the attested height. A header is
*acceptable* when its double SHA-256 hash, as a little-endian number, is at most the target in its own `bits` field,
and that target is not easier than the pinned work floor `OTS_MAX_TARGET` (compact `0x17087bc0`, about a quarter of
the difficulty of the blocks in the test vectors). If an acceptable header's merkle root (bytes 36 to 67) equals `m`,
the proof is **confirmed** and the header's `time` is the Bitcoin time. So the check rests on proof of work, not on
where the 80 bytes came from. Headers come from, in order:

1. `btc_headers.jsonl` in the release (lines `{"height": h, "header": "<160 hex>"}`; the downloader writes it; an
   entry that is not acceptable is ignored), then, unless `--offline`,
2. `https://blockstream.info/api` (`block-height/<h>`, then `block/<id>/header`), and, if its header is not acceptable or
   does not match,
3. `https://mempool.space/api` (the same two paths).

Both sources are asked before a proof is called contradicted, so a matching header from either one confirms it. The
reference verifier sends at most 5 requests a second to the explorers (counting each of the two HTTP requests of a
lookup), stops asking a source for the rest of the run after 3 failed lookups in a row (an unknown block, answered
404, is not a failure), and stops asking altogether after 600 seconds of explorer time. A height it could not reach
leaves its proof `ots.unchecked`; the verifier never turns an unreachable source into `ots.invalid`.

Results (one `ots confirmed=<n> pending=<n> unchecked=<n> late=<n> missing=<n>` line; `late` heads are also counted
as confirmed):

| Code | Kind | Meaning |
|---|---|---|
| `ots.invalid` | error | the file does not parse as above, or an acceptable header contradicts the proof (a different merkle root) from both sources (the release cache never counts against a proof) |
| `ots.unchecked` | warning | no acceptable header could be compared (offline, sources down, or one source only disagreed) |
| `ots.pending` | warning | only pending or unknown attestations: the calendars have not got the head into a block yet (hours; never an error) |
| `ots.late` | warning | confirmed, but the block's time is later than 00:00 UTC of the day after the head's date plus 48 hours |
| `ots.missing` | warning | a head whose date plus 4 days has passed at `--as-of` and that has no `.ots` file |

A warning is one entry per release, with `count=N` and the first 20 dates. `--require-production` does not turn any of
them into an error. Tests inject the header sources, so the suite never uses the network.

**What is not claimed.** The height named in an attestation is not checked against the chain, and a header is accepted
for its own work, not for its place in the chain; forging an acceptable header costs at least about a quarter of the
work of a block at today's difficulty, for a proof whose hash was fixed beforehand. A confirmed proof shows that the
head's hash existed by the header's time. It does not show that the head is complete or honest (that is section 1,
item 1, and the checks above). A pending or unchecked proof shows nothing yet. The NIST pulse of a head is
checked only when the verifier is online and only as a cross-check (SPEC 11.5): the
verifier fetches the pulse from the `uri` if it is on beacon.nist.gov and warns (`nist.mismatch`,
`nist.out_of_window`, `nist.foreign_uri`, `nist.unchecked`) when the value or the time does not fit. It is never an
error, because the pulse is not part of any hashed input. With `--offline` nothing about pulses is checked. To
check a proof by hand with the official client (a separate program that needs a Bitcoin node or an explorer):

```
pip install opentimestamps-client
ots verify -d <anchor_hash from the head file> heads/<date>.ots
```

The proof's digest is the head's `anchor_hash` (the 32 bytes themselves), which is why `-d` is used.

### 3.8 Canary batches
The operator runs a bot that plays through the whole pipeline (`source = canary`), about
one batch every 4 hours. The verifier analyses canary batches separately with the same formula and
prints them on the `canary` line. `seen` counts every canary row; the other figures use the canary set of SPEC
9.9: `card5` rows sealed at or after `registration_ms`, first copy only, so the beta's canary rows
from before registration are in `seen` only. They are never part of the study result. The canary exists to detect bugs:
an apparent effect in canary data means a fault in the pipeline, and the study's own pre-registration says
the main result is then void until it is found. Because `source` is not hashed (section 6), the canary's
guesses are not random: they are derived from the cron slot as `guess[i] = u64(sha256("precog/canary/v1" ||
u64(slot_ms) || u32(i))[0:8]) mod 5` (SPEC 9.7), and the verifier rejects a `canary` row whose
guesses (and `test_id` `card5`) do not match a whole-minute slot in the 10 minutes before `sealed_at_ms`:
`canary.guesses_mismatch`, an error from `registration_ms` on, and the warning `canary.unverified` (with a count) for
earlier rows from the beta, which used random guesses.
The other direction is checked too (SPEC 9.8). A `player` row whose guesses are the canary
guesses of a slot in that same window is a canary batch published as a player batch: `canary.relabelled`, an error from
`registration_ms` on (one per row, the detail names the slot), and a warning with a count for earlier rows.

## 4. Reproducing every number

All of the numbers come from one release directory and this code; there is no hidden input.

1. Download the export (section 2) and keep the files. `manifest.json`, `batches.jsonl`, `anchors.jsonl`,
   `rounds.jsonl`, `heads/`, and (optionally) `heads/*.ots` and `btc_headers.jsonl`.
2. `python -m precog_verifier verify-release ./release`. `n_batches`, `N_trials`, `hits`, `rate`, `S` and `z`
   are printed on the `analysis` line.
3. By hand, the counted batches are the rows with `source == "player"`, `sealed_at_ms >= registration_ms`
   (from the manifest) and `test_id == "card5"` that are the first-committed copy of their `batch_id`. Then
   `N_trials = 25 * n_batches`, `S = sum(hits) - 5 * n_batches`, `z = S / sqrt(N_trials * 0.16)`.
   The null interval is `d = (hits / N_trials - 0.2) * 100` plus or minus `1.96 * sqrt(0.16 / N_trials) * 100`, in
   percentage points. The code is `src/precog_verifier/analysis.py` (about 200 lines).
4. To reproduce `hits` for one batch from scratch, take its guesses and `target_round`, get that round from
   drand (`https://api.drand.sh/52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971/public/<round>`),
   and follow section 3.6. The verifier does the same and verifies the BLS signature first.
5. The tests regenerate the frozen vectors and compare them byte for byte, and include statistical checks of
   target uniformity and null calibration, and attack tests: `python -m pip install -e ".[dev]"` then
   `python -m pytest`. Each attack test tampers with a valid synthetic release (backdating, deletion,
   insertion, round substitution, forged or missing timestamps, and so on) and asserts the specific error code.

## 5. The pre-registered analysis

The full text is in this repository as `docs/study-precognition.md`, and is
published unchanged on OSF at the same time. The verifier implements the primary analysis:

- Unit: one sealed batch of 25 guesses. H0: the pooled hit rate is 20%; H1 (two-sided): it differs from 20%.
- `S = sum over counted batches of (hits - 0.2 * 25)`; `z = S / sqrt(N_trials * 0.2 * 0.8)`. This is valid
  however many batches people choose to play.
- Counted: every sealed and anchored player batch of the test `card5` from the registration date on, except exact
  repeats of a batch ID (section 1). No exclusion for player behaviour, speed, device or result. No exclusion for a
  verification failure either: the whole release is withdrawn, the fault explained, and a corrected release
  issued.
- Looks: quarterly data releases, up to 20 looks over 5 years. The threshold per look is
  `|z| >= 5.55` (two-sided p < 5.7e-7 / 20, Bonferroni across looks on a 5-sigma overall threshold).
  The verifier prints `z`; it does not apply this threshold or decide anything.

Secondary analyses are reported next to the primary result and are never the headline. Per-participant capping
and a Stouffer combination across participants are specified in SPEC section 9 and printed as `secondary`
lines (SPEC 9.10 also defines a second Stouffer statistic over each participant's first counted batch,
`secondary stouffer_first`, and SPEC 9.6 the null interval on the `interval` line); they need participant numbers, so the release format has no such column until the participant data is
released (`with_participants` in the manifest), and the output says `secondary.no_participants` until then.

The **permutation control** is SPEC section 9.11 (the
`precog/permutation/v1` tag is frozen). It takes the same counted batches as the primary result, orders
them by anchor number and batch ID, and shuffles them with one published random shuffle in which no batch keeps
its own place. The shuffle is seeded by the drand round that comes at least 24 hours after the latest anchor
time of the release, so nobody can pick a favourable pairing, and anyone can re-derive it. Each batch's guesses are
then scored against the targets of the batch it is paired with, with the same `z` formula; under chance that `z`
is standard normal, and a real effect must vanish. It prints a `permutation` line. Until that round exists the
line says `permutation.pending`; when the round cannot be obtained it says `permutation.round_unavailable`
(for example with `--offline` and no cached copy of the round). These are notices only: they never make a
release invalid. The control is withheld whenever the primary result is, and it is not run for the canary set.

## 6. Known gaps

These are limits of the current code, found while writing this document. They are tracked and will be
closed or documented in the specification. Do not assume a check exists for them.

- Heads are required only up to `--as-of` (SPEC 10.1). The newest head is not required to name the last anchor, and
  the Bitcoin proofs of the heads are judged by SPEC 11.4 (section 3.7).
- `source` (`player` or `canary`) and `hits` are not in the leaf. `hits` is recomputed. `source` is checked only
  for canary rows, whose guesses must be derived from a cron slot (SPEC 9.7), so relabelling a
  player batch as canary is an error after registration. The beta canary rows sealed before registration used random
  guesses and appear as the warning `canary.unverified`. A receipt check does not compare `source`.
  Player rows are also checked (SPEC 9.8), and one that carries canary guesses is
  `canary.relabelled` (section 3.8).
- `registration_ms` comes from the manifest, which the operator writes. The verifier prints
  `excluded pre_registration` so you can see the number, but it cannot tell whether the date is the registered one unless you pass `--registration-ms 1792972800000`.
- Mock authorities and the mock beacon are accepted, with a warning (an error with `--require-production`); the
  tool does not compare the manifest with the expected production values (section 1, item 7).
- Two authorities with different `id`s but the same operator count as two. The same `root_sha256` gives the warning
  `tsa.same_root`, but different roots do not prove different operators.
- The Bitcoin proofs of the heads are checked as section 3.7 says (and a pending proof proves nothing yet); NIST pulses are cross-checked only online and only as warnings (SPEC 11.5); offline they are recorded, not checked.

## Reporting a problem

If you find a release that verifies but should not, a check that does not do what this document says, a
mismatch between this README and the code, or a way to bias the result without tripping a listed check,
please report it. Give the release you used (`release_id` and the SHA-256 of `manifest.json`), the command,
and the output.

To report a suspected vulnerability privately, use the repository's **Security** tab (GitHub's private vulnerability reporting; see [`SECURITY.md`](SECURITY.md)). For anything else, such as a mismatch between this document and the code, open an issue at https://github.com/kd7uiy/psicensus-verifier/issues.

## Layout

- `SPEC.md`: the public specification (version 1). `vectors/`: frozen test vectors, generated by `tools/gen_vectors.py`.
- `src/precog_verifier/`: the verifier. `testing.py` builds synthetic releases for tests.
- `src/precog_verifier/trust/`: the pinned root certificates. `tests/`: the test suite; `tests/data/`: fixtures.
- `tools/`: `nightly_verify.py` (download and verify), `bench_bls.py`. The downloader it uses is the package module `precog_verifier/fetch_export.py` (with `tokenjoin.py`); `tools/fetch_export.py` and `tools/tokenjoin.py` only keep the old import names working.
- Export transport: the HTTP endpoints the downloader reads are described in the module docstring of `src/precog_verifier/fetch_export.py`.

## Continuous checks

Two GitHub Actions workflows run in this repository. `ci.yml` runs on every push and pull request: it installs the package, runs the test suite and verifies the bundled sample release. `nightly.yml` runs once a day (and on request): it runs `tools/nightly_verify.py`, which downloads the live export from https://psicensus.com with this repository's downloader (the code behind `python -m precog_verifier fetch`), verifies it with `verify-release --require-production --registration-ms 1792972800000` judged at the time the download started, and writes a report that is kept as a run artifact. The Bitcoin block headers and the OpenTimestamps proofs already downloaded are kept between runs in the Actions cache; this only saves requests to the public explorers and the site, and the verifier checks every header and proof itself. A red nightly run means the download or the verification failed; the report says which, and the run opens (or comments on) one issue titled "Nightly verification failed".
