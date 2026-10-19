# precog verifier specification

Version: **v1** (approved by Ben 2026-10-03; amendments 1–4 the same day; 4 replaces 1 and 3, before vectors were frozen; amendment 5, 2026-10-03, defines `cert_sha256`; amendment 6, 2026-10-04, replaces it with `issuing_ca_sha256` and `root_sha256`; amendment 7, 2026-10-05, text only: sub-millisecond `genTime` truncation in §6 and a head with no NIST pulse in §10.1, both already the behaviour of the reference verifier; amendment 8, 2026-10-10, text only: no head before the first anchor in §10.1, already the behaviour of the reference verifier and the Worker). Amendment 10, 2026-10-10, approved by Ben the same day: daily heads are required up to `as_of` (§10.1, §11), a verifier input and not a release field. Amendment 11, 2026-10-10, approved by Ben the same day: the type of `participant` in §10.1 (validation only, no byte encoding changes). No byte encoding or test vector changes in amendments 5, 6, 7 or 8: the CA fields are manifest and receipt metadata only and are not part of any hashed input. Amendment 9 (2026-10-10, approved by Ben the same day): verifiable canary guesses, one new tag `precog/canary/v1` and codes `canary.guesses_mismatch` / `canary.unverified`; no existing encoding or vector changes. Amendment 12 (2026-10-11, approved by Ben the same day): the permutation control, one new tag `precog/permutation/v1` and three notice codes; no existing encoding or vector changes. Amendment 13 (2026-10-11, approved by Ben the same day): warnings for mock authorities, the mock beacon and anchors whose tokens share one root, and `--require-production`; no new tag, no existing encoding or vector changes. Amendment 14 (2026-10-11, approved by Ben the same day): the verifier option `--registration-ms` and the error `manifest.registration_mismatch`, a way for a reader to pin the registration time to the value published with the pre-registration; no new tag, no existing encoding or vector changes. Editorial edit, 2026-10-11, no amendment number: references to the maintainers' internal planning notes and documents were removed or replaced by neutral wording in §9, §10.1 and §13; no change to any byte encoding, tag, vector, rule, code or behaviour. Amendment 15 (2026-10-12, approved by Ben the same day): the OpenTimestamps proofs of the daily heads are checked against Bitcoin block headers, one optional release file `btc_headers.jsonl` and five codes (`ots.invalid`, `ots.pending`, `ots.unchecked`, `ots.late`, `ots.missing`); no new tag, no existing encoding, vector or code changes. Amendment 16 (2026-10-13, approved by Ben the same day): the NIST pulse recorded in a daily head is fetched and compared when the verifier is online, four warning codes (`nist.mismatch`, `nist.out_of_window`, `nist.foreign_uri`, `nist.unchecked`); no new tag, no byte encoding, vector or existing code changes, and offline verification is unchanged. amendment 17 (2026-10-16, approved by Ben 2026-10-16): a `player` row carrying the canary guesses of a candidate slot of its window is the code `canary.relabelled` (an error from `registration_ms` on, a warning before), with new vectors in a new file; no new tag, no byte encoding, existing vector or existing code changes.
Once approved, the test vectors in `vectors/` are frozen. After that, any change to a byte encoding needs a new version tag (`.../v2`).

This document is public. It describes the published data and the algorithms that anyone can use to check them. It assumes no access to the operator's systems.

## 1. Notation

| Notation | Meaning |
|---|---|
| `\|\|` | Byte concatenation |
| `u8(x)`, `u32(x)`, `u64(x)` | Unsigned integer, fixed width, **big-endian** |
| `str8(s)` | `u8(len(s)) \|\| ascii(s)`; `s` matches `^[a-z0-9_-]{1,32}$` |
| `sha256(...)` | SHA-256, 32-byte output |
| `TAG(name)` | The ASCII bytes of a fixed domain tag, with no length prefix (the tags are fixed literals and always come first) |
| hex | Lowercase hexadecimal, no `0x` prefix |

Domain tags: `precog/leaf/v1`, `precog/anchor/v1`, `precog/target/v1`, (amendment 9, §9) `precog/canary/v1`, and (amendment 12, approved by Ben 2026-10-11, §9) `precog/permutation/v1`.

## 2. Fields

| Field | Type | Notes |
|---|---|---|
| `batch_id` | 16 bytes | Random. Published as 32 hex characters. (Non-normative: the operator's server draws 128 random bits at seal time; players cannot choose it. The verifier cannot check who chose an id and does not need to.) |
| `test_id` | slug | `card5` for the 5-symbol card test |
| `guesses` | 25 bytes | Each value 0–4. Published as a 25-character digit string, e.g. `"0314200413..."`. Any other value is invalid |
| `sealed_at_ms` | u64 | Server time when the batch was sealed, in Unix milliseconds |
| `anchor_seq` | u64 | Starts at 1 and goes up by 1 per anchor |
| `leaf_index` | u64 | The batch's position in its anchor's tree: 0..leaf_count-1, in seal order |
| `target_round` | u64 | drand quicknet round number |

## 3. Leaf
```
leaf = sha256( TAG("precog/leaf/v1") || batch_id || str8(test_id) || guesses || u64(sealed_at_ms) )
```
No participant identifier is included.

## 4. Merkle tree (RFC 9162 §2.1, formerly RFC 6962)
The input is the ordered list `D = [leaf_0, …, leaf_{n-1}]` with `n ≥ 1`. An empty tree is never anchored.
```
MTH([d])  = sha256( 0x00 || d )
MTH(D[n]) = sha256( 0x01 || MTH(D[0:k]) || MTH(D[k:n]) )   where k = largest power of two < n
```
The `0x00` and `0x01` prefixes mean a leaf can never be mistaken for an inner node. When the number of leaves is odd, the tree is split as above; the last leaf is **not** duplicated. This rules out the duplicate-leaf ambiguity found in some Merkle designs.

**Inclusion proof** (audit path): the list of sibling hashes from the leaf up to the root, each 32 bytes, published as hex. It is checked with the RFC 9162 §2.1.3.2 algorithm, using `leaf_index`, `leaf_count`, `sha256(0x00 || leaf)` and the path.

## 5. Anchor and the anchor chain
```
anchor_hash = sha256( TAG("precog/anchor/v1") || u64(anchor_seq) || prev_anchor_hash || merkle_root || u64(leaf_count) )
```
- For `anchor_seq = 1`, `prev_anchor_hash` is 32 zero bytes. For every later anchor it is the previous anchor's `anchor_hash`.
- `leaf_count` is committed separately, so dropping leaves always changes the hash.

## 6. Timestamp tokens
Each anchor carries tokens from **at least two different** authorities named in the release manifest.
- An RFC 3161 token's `messageImprint` is `{ hashAlgorithm: sha256, hashedMessage: anchor_hash }`. In other words, `anchor_hash` itself is the imprint and is not hashed again.
- `gen_time_ms` is the token's `genTime` in Unix milliseconds. If the token has no fractional seconds, the fraction is 0. If it has more than three fraction digits, the extra digits are dropped (truncated toward zero, never rounded): `.1239` gives 123 ms. Every later use of the token time (the published `gen_time_ms`, §7 and §11 check 4) uses this truncated value. (Amendment 7, text only.) Truncation can make `t_anchor` in §7 up to 1 ms earlier than the exact `genTime` rounded up; the target round then still follows the token time by the margin minus less than 1 ms, which is accepted.
- In v1 the verifier treats token checking as a plugin chosen by the authority's `kind` in the manifest:
  - `rfc3161`: real tokens, checked by the standard-library plugin `precog_verifier.rfc3161`.
  - `mock-hmac`: testing only (§12).

## 7. Target round (drand quicknet)
Constants. Confirmed against the live network on 2026-10-03 (chain hash, genesis, period and public key; no differences).

| Constant | Value |
|---|---|
| `chain_hash` | `52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971` |
| `genesis` | `1692803367` (Unix seconds) |
| `period` | `3` seconds |
| `margin_rounds` | `2` |
| `public_key` (G2, hex) | `83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a` |
| scheme | `bls-unchained-g1-rfc9380`; signed message = `sha256(u64(round))` |

```
round_time(r)  = genesis + (r - 1) * period                           for r ≥ 1
t_anchor       = ceil( max(gen_time_ms over all tokens on the anchor) / 1000 )   (seconds; every token must be valid)
threshold      = t_anchor + margin_rounds * period
target_round   = smallest r ≥ 1 with round_time(r) ≥ threshold
               = ceil( (threshold - genesis) / period ) + 1
```
`t_anchor` uses the **later** of the two token times, so neither authority alone can move the round earlier. The release supplies the round's `signature`. Its randomness is `sha256(signature)`. A full verifier also checks the BLS signature against the chain's public key (the standard-library `drand-quicknet` beacon plugin, `precog_verifier.bls`).

## 8. Targets and scoring
```
for i in 0..24:
    h         = sha256( TAG("precog/target/v1") || randomness || str8(test_id) || batch_id || u32(i) )
    target[i] = u64(h[0:8]) mod 5
hits = count of i where guesses[i] == target[i]
```
The modulo bias of a 64-bit value reduced mod 5 is about 2⁻⁶², which is negligible.

## 9. Analysis (matches `study-precognition.md` §5)
**Principle** (amendment 4, 2026-10-03, which replaces amendments 1 and 3): an exclusion is allowed only if it is fixed **before the batch's target exists**. Any rule that can still be triggered after targets are known, by changing, dropping or adding published data, is a channel for selection bias, and the spec has none.

**Counted batches** are rows where all of the following hold:
- `source == "player"`
- `sealed_at_ms ≥ registration_ms` (taken from the manifest)
- the row is the **first copy** of its `batch_id` (see below)

**A release with any error is invalid.** Errors include every code in §11 except warnings. The verifier reports all the error codes, prints the counts, and **withholds `S` and `z`** (`analysis.withheld`). Batches are never excluded because of a verification failure. A failure means the published data does not match its own commitments or the public beacon. The fix is to withdraw the release, explain the fault publicly, and reissue it from the raw data.

**Beacon rounds.** `rounds.jsonl` is a cache and is never authoritative. If a cached round is missing or fails its signature check, the verifier fetches the round from the beacon network through the beacon plugin. If it still cannot get a valid round, verification is **incomplete** (`round.unavailable`), which is an error: the analysis is withheld, and no batch is excluded.

**Duplicate IDs.** The copy in the earliest anchor (lowest `anchor_seq`) is the batch.
- Copies in later anchors were committed after it, so they are never counted.
- If two or more copies share the earliest anchor, they were all committed before that anchor's target existed. Dropping all of them is blind to the outcome, so **all** of them are excluded.
- Duplicates are already fixed in timestamped anchors, so a reissued release could not remove them. They are therefore reported as a prominent **warning** (`batch.duplicate_id`, listing every copy), not as an error, and the release stays valid.
- They are counted separately: `duplicate_later` (later copies not counted) and `duplicate_same_anchor` (blind exclusions).

```
N_trials = 25 * (number of counted batches)
S        = Σ (hits - 0.2 * 25)
z        = S / sqrt(N_trials * 0.2 * 0.8)
```
The output contains `n_batches`, `N_trials`, total hits, the hit rate, `S` and `z` (or `analysis.withheld`), the duplicate counts, the pre-registration count and the canary count. Canary batches are analyzed separately with the same formula. The permutation control (`study-precognition.md` §7 item 3) is specified in amendment 12 below (approved by Ben 2026-10-11).

> **Approved by Ben 2026-10-10 (secondary analyses; the permutation control is amendment 12 below, approved 2026-10-11).** Secondary analyses: per-participant capping and per-participant Stouffer (`study-precognition.md` §7 items 1 and 2; decided 2026-10-10). Text only: no byte encoding, tag, error code or vector changes, and the primary analysis above is unchanged.
>
> **Status.** Both are secondary: they are reported, never the headline, and have no threshold. They are computed from the counted batches above and from nothing else, so every exclusion rule above applies first (canary, before `registration_ms`, and non-first copies of a `batch_id` never take part and never use up a cap slot).
>
> **Participant numbers.** `participant` is published only when the manifest has `with_participants: true` (§10.1). The secondary analyses are **not available** when `with_participants` is `false`, or when any counted row has a `null` `participant`. Then no secondary figure is computed, and the output carries the code `secondary.no_participants` instead. This is a notice in the analysis output, not an entry in the error or warning lists: it never makes a release invalid, never changes `ok`, and verification is unchanged. Two `participant` values are the same participant exactly when their JSON values are equal.
>
> **Quarter.** The UTC calendar quarter of `sealed_at_ms`: the Gregorian date of the instant `sealed_at_ms` milliseconds after 1970-01-01T00:00:00Z, in UTC, with Jan-Mar, Apr-Jun, Jul-Sep and Oct-Dec as quarters 1 to 4. A quarter is identified by (year, quarter number): Q1 2027 and Q1 2028 are different quarters. The last millisecond of a quarter (for example 2027-03-31T23:59:59.999Z) belongs to it, and the next millisecond (2027-04-01T00:00:00.000Z) starts the next.
>
> **Per-participant cap.** From the counted batches, form one group per (participant, quarter). Order each group by the key `(sealed_at_ms, anchor_seq, batch_id)`, ascending, where `sealed_at_ms` and `anchor_seq` compare as integers and `batch_id` compares as its 16 raw bytes (the decoded form of the 32 hex characters), lexicographically, each byte as an unsigned value (equivalent to comparing the lowercase hex strings). Keep the first 20 batches of each group (at most 500 trials) and drop the rest. The key uses no result, so which batches are kept never depends on outcomes. Report for the kept set: `n_batches`, `N_trials = 25 * n_batches`, `hits`, the hit rate, `S` and `z` with the same formulas as above, and `removed` = counted batches minus kept batches.
>
> **Stouffer per-participant z, on the kept set.** For each participant `i` with `n_i >= 1` kept batches (in any quarter): `S_i = Σ (hits - 5)` over the participant's kept batches, and `z_i = S_i / sqrt(25 * n_i * 0.2 * 0.8)`. With `k` = the number of such participants, `Z = (Σ z_i) / sqrt(k)`, unweighted. Report `k` and `Z`. With `k = 0` there is no `Z`. (The reference verifier sums with `math.fsum`; any exact or correctly rounded summation agrees to within floating-point error.)
>
> **Withheld.** Whenever the primary analysis is withheld (any error in §11), the kept-set `hits`, rate, `S`, `z` and `Z` are not reported; the counts (`n_batches`, `N_trials`, `removed`, `k`) are. If both apply, "not available" takes precedence.
>
> **Output (reference verifier).** After the `canary` line: `secondary capped n_batches=… N_trials=… removed=… hits=… rate=… S=… z=…` and `secondary stouffer k=… Z=…`; or `secondary withheld capped_n_batches=… capped_N_trials=… removed=… k=…`; or `secondary unavailable code=secondary.no_participants`. The analysis object carries the same values under `secondary`.

> **Amendment 9, approved by Ben 2026-10-10. Verifiable canary guesses (decided 2026-10-10).** Adds one domain tag, `precog/canary/v1`, one verification rule and two codes. No existing byte encoding, tag, leaf, vector or the primary analysis changes.
>
> **Why.** `source` is not in the leaf, so without this rule whoever writes the export could relabel a badly scoring player batch as `canary` and drop it from the study; every hash would still verify. The canary's guesses are therefore made checkable: they come from public data that is fixed before the batch's target exists, and a `canary` row whose guesses do not match is rejected.
>
> **Derivation.** A canary batch is created by a scheduled job at the job's scheduled time `slot_ms`, in Unix milliseconds, always a whole minute (`slot_ms mod 60000 == 0`). For `i = 0..24`:
> ```
> guess[i] = u64( sha256( TAG("precog/canary/v1") || u64(slot_ms) || u32(i) )[0:8] ) mod 5
> ```
> This is the construction of §8 with a different tag and input. The modulo bias is the same negligible ~2^-62. Vectors: `tests/data/canary_v1/guesses.json` (several slots, among them 0, a real 2026 slot and the largest whole minute below 2^64).
>
> **Rule.** For every row with `source == "canary"`: let `s = sealed_at_ms`. The row is **verified** if its `test_id` is `card5` and there is a whole minute `m` (`m mod 60000 == 0`, `m ≥ 0`) with `s - 600000 ≤ m ≤ s` such that `guesses == derive(m)` (the 25 digits above). That is at most 11 candidate slots (11 when `s` is itself a whole minute, otherwise 10; fewer near time zero). A row that is not verified gives:
> - `canary.guesses_mismatch`, an **error** (the release is invalid; S and z are withheld, §9), when `sealed_at_ms ≥ registration_ms`;
> - `canary.unverified`, a **warning**, when `sealed_at_ms < registration_ms` (the beta: such batches are never counted anyway). It is reported once per release, with the count of such rows in the detail (`count=N`).
>
> The rule reads only the published row and the manifest. Players' rows are not checked by it, and no row is excluded from or added to any count because of it (as everywhere in §9, a failure invalidates the release; it never changes which batches are counted).
>
> **Chance of passing by accident.** A relabelled player batch carries guesses the player chose, independently of the operator. Each of its at most 11 candidate strings is one of 5^25 ≈ 2.98 × 10^17, so a given batch passes with probability at most 11 / 5^25 ≈ 3.7 × 10^-17. Even if the operator could pick the one batch to relabel out of N player batches, the chance that any of them passes is at most N × 3.7 × 10^-17 (about 4 × 10^-11 for N = 10^6). The operator cannot move this: the guesses are inside the leaf, which is anchored and time-stamped, and the window is only ten minutes wide. The operator can still create extra canary batches at will; they are analysed separately and never counted in the study.
>
> **Blind to results.** `slot_ms` is the scheduled time of the job, fixed before the batch is sealed; the batch's target round is chosen afterwards, from the anchor's token time (§7), and the beacon output for it does not yet exist at sealing. So the canary guesses cannot depend on any target, and the rule cannot depend on any outcome.
>
> **Amendment 12, approved by Ben 2026-10-11. Permutation control (option A).** Adds one domain tag, `precog/permutation/v1`, and three notice codes. No existing byte encoding, tag, leaf, vector, error code or the primary analysis changes. Approved by Ben 2026-10-11 together with these defaults (no `--as-of` restriction on the set, precedence as built, the seed round R is always fetched and not added to `rounds.jsonl` by the builder); the tag is frozen.
>
> **Why.** The targets of a batch are fixed by the beacon and independent of every guess (§8), so scoring any guesses against any other batch's targets hits with probability exactly 0.2 per trial, whatever the guesser's habits. A real effect (guesses that predict their own batch's target) must vanish when the pairing is broken. What the control catches is a pipeline fault that makes the primary look good for a reason other than the pairing (a leaked target, a bad join, a mis-ordered row). It is one published number, `z`, expected to be unremarkable.
>
> **Set.** Exactly the counted batches of the primary analysis (§9: player, `sealed_at_ms ≥ registration_ms`, first copy, same-anchor duplicates excluded), after every exclusion rule above. The verifier applies no other restriction to the set (`--as-of` only judges the heads, §10.1). Order them by `(anchor_seq as an integer, batch_id as its 16 raw bytes compared as unsigned bytes, lexicographically)` and index them `0..n-1` in that order. No hit, time or participant takes part in the order.
>
> **Cut and seed round.** `t_cut` is the largest `t_anchor` (§7, in seconds) among the anchors of the release (every anchor with a valid token time). The seed round `R` is the first drand quicknet round whose time is at least `t_cut + 86400` seconds (24 hours), by the §7 formula:
> ```
> R = max(1, ceil( (t_cut + 86400 - genesis) / period ) + 1)
> ```
> `randomness(R)` is `sha256(signature)` of that round, obtained and checked like any other round (the cache `rounds.jsonl`, then the beacon plugin; the BLS signature is verified). The round is not part of the release's commitments: no row refers to it.
>
> **Seed and stream.**
> ```
> seed  = sha256( TAG("precog/permutation/v1") || randomness(R) || u64(n) )
> B_j   = sha256( seed || u64(j) )                          j = 0, 1, 2, ...
> words = for each j in order, the four big-endian u64 values of B_j[0:8], B_j[8:16], B_j[16:24], B_j[24:32]
> ```
> Words are consumed in that order and never reused.
>
> **Uniform integer in [0, m)**, `m ≥ 1`: `limit = 2^64 - (2^64 mod m)`; take the next word `w`; if `w < limit` the result is `w mod m`, otherwise take another word and repeat. (For `m = 1` one word is still consumed and the result is 0.)
>
> **Derangement (Sattolo).** Start with `a[k] = k` for `k = 0..n-1`. For `i = n-1` down to `1`: `j = uniform(i)` (in `[0, i)`); swap `a[i]` and `a[j]`. The result is a single `n`-cycle, so `a[k] != k` for every `k` when `n ≥ 2`, and every `n`-cycle is equally likely.
>
> **Scoring.** Batch `k` is scored against batch `a[k]`: `hits_k` is the number of positions `t` (0..24) where `guesses_k[t] == targets_{a[k]}[t]`, and `targets_b` are the §8 targets of batch `b` with **b's own** round, `test_id` and `batch_id` (recomputed from the beacon output; never taken from the published `hits`). Then the primary formulas: `N_trials = 25 n`, `hits = Σ hits_k`, the rate, `S = Σ (hits_k - 5)` and `z = S / sqrt(N_trials * 0.2 * 0.8)`.
>
> **Null distribution.** Each batch's targets are used exactly once and are independent uniform symbols, so each `hits_k` is Binomial(25, 0.2) whatever the guesses are, and `z` is N(0, 1) exactly. There is no threshold: "vanishes" means `z` is unremarkable next to the primary's own noise. It is one draw and has low power against a subtle fault.
>
> **Blind to results.** Neither the operator nor a player can steer the pairing: the release content is fixed (anchored and time-stamped) before round `R` exists, `R` is at least 24 hours after the latest anchor time, and the order and the seed use no result. Anyone re-derives `R`, the seed and the pairing from the release alone; no manifest field is needed.
>
> **Notices.** The control is secondary. When it cannot be computed, the analysis output carries a notice code, not an entry in the error or warning lists; a notice never makes a release invalid, never changes `ok`, and verification is unchanged (as with `secondary.no_participants`). Precedence, first that applies:
> 1. `permutation.too_few`: `n < 2` (a derangement needs two batches). No round is reported.
> 2. `permutation.pending`: round `R` is later than the analysis time (`round_time(R)` is after the `--as-of` time if given, else the verifier's clock). This is the normal state of a nightly run within a day of the newest anchor.
> 3. Withheld (next paragraph).
> 4. `permutation.round_unavailable`: round `R` should exist but no valid round can be obtained (not in the cache with a valid signature, and not fetched or not valid; always so offline when `R` is not cached). This does **not** invalidate the release: the control is secondary and `R` is not part of the release's commitments. If no anchor has a token time there is no `t_cut`, and the code is given without a round.
>
> **Withheld.** Whenever the primary analysis is withheld (any error in §11), only `n_batches`, `N_trials` and the seed round `R` are reported; `hits`, rate, `S` and `z` are not (the notices 1 and 2 above still take precedence). A withheld control does not fetch round `R`.
>
> **Canary.** No permutation control is run for the canary set.
>
> **Output (reference verifier).** After the `secondary` lines: `permutation round=R n_batches=… N_trials=… hits=… rate=… S=… z=…`; or `permutation withheld round=R n_batches=… N_trials=…`; or `permutation unavailable code=permutation.<x> round=R` (`round=` is omitted when no round was computed: `permutation.too_few`, or no anchor has a token time). The analysis object carries the same values under `permutation`.
>
> **Vectors.** `tests/data/permutation_v1/vectors.json`, generated by `tools/gen_permutation_vectors.py` (standard library only, independent of the verifier code): seeds and derangements from fixed randomness for `n = 2, 3, 5, 10, 1000` (for 1000, the first 10 entries and the SHA-256 of the permutation written as big-endian `u32` values), the first stream words, and a `uniform` draw that hits rejection.

> **Amendment 13, approved by Ben 2026-10-11. Trust notices: mock authorities, mock beacon, shared root.** Adds three codes (`manifest.mock_authority`, `manifest.mock_beacon`, `tsa.same_root`) and one verifier option (`--require-production`). No domain tag, byte encoding, leaf, vector, existing error code, hashed input or the primary analysis changes; no release field is added. Nothing here makes a release that was valid before invalid unless the reader asks for it with `--require-production`.
>
> **Why.** §12 lets a manifest name mock authorities (`kind: mock-hmac`) and the mock beacon (`network: mock-beacon`), whose keys and outputs are public, so anyone can build a release that passes every check in §11. §11 step 4 asks for two different authority `id`s, not two different operators. The verifier therefore says so in its output instead of leaving it to the reader's reading of `manifest.json`.
>
> **Rules.**
> - `manifest.mock_authority`: the manifest lists at least one authority with `kind == "mock-hmac"`. One notice per release; the detail lists the mock `id`s in sorted order.
> - `manifest.mock_beacon`: `beacon.network == "mock-beacon"`. One notice per release; the detail names the network.
> - Both are **warnings** by default. With `--require-production` they are **errors** (the release is invalid, S and z are withheld, §9, and the exit status is 1) under the same codes; every other check and number is unchanged. A verifier given no option behaves as before except for the added warnings.
> - `tsa.same_root`: for each anchor whose tokens are all valid (§11 step 4), take the set of `root_sha256` values of the authorities that issued those tokens (a manifest entry without `root_sha256`, such as a mock, adds none). If the set has exactly one member, the anchor counts. A **warning**, once per release, when at least one anchor counts, with `count=N` (the number of such anchors) in the detail. An anchor with no `root_sha256` at all (only mocks) is not counted: the mock notice already covers it. It is never an error, also with `--require-production`: two authorities may legitimately share a root, and the reader judges whether that matters.
>
> **What is not claimed.** None of this proves that a release is genuine. A manifest that names a real kind and real-looking pins is still the operator's statement (§10.1); the reader compares the manifest with the values the project publishes. A different `root_sha256` does not prove two different operators.

> **Amendment 14, approved by Ben 2026-10-11. `--registration-ms`: pin the registration time to the published value.** Adds one verifier option (`--registration-ms N`) and one error code (`manifest.registration_mismatch`). No domain tag, byte encoding, leaf, vector, hashed input, existing error code or the primary analysis changes; no release field is added or removed. A verifier given no option behaves as before.
>
> **Why.** `registration_ms` is read from `manifest.json`, which the operator writes, and it decides which batches count (§9: `sealed_at_ms ≥ registration_ms`). Nothing in the release ties it to the date the pre-registration was published, so a later value would silently move batches into the excluded group. The reader can now say which value they expect, taken from the pre-registration itself.
>
> **Rules.**
> - `--registration-ms N`: `N` is an integer, Unix milliseconds, written as 1 to 15 ASCII digits (no sign, fraction, exponent, space or other numeral system). Anything else is a usage error (exit status 2) before any release is read. A library caller passes an integer `0 ≤ N < 10^15`; any other value (a boolean, a string, a float) is refused.
> - When `N` is given and `manifest.registration_ms` is not equal to `N`, the verifier reports the **error** `manifest.registration_mismatch`, once per release, with the detail `manifest=<manifest value> expected=<N>`. The release is invalid, S and z are withheld (§9) and the exit status is 1. Every other check and count is unchanged (the manifest value is still the one used to count, so the printed counts show what the manifest claims).
> - `manifest.registration_ms` is a required field (§10.1), so a manifest that has none fails as `format.invalid` whether or not the option is given; the new code is never reported for it.
> - When `N` is given and equals the manifest value, nothing is added to `errors` or `warnings`.
> - When the option is absent, the result is exactly what it was before: no error and no warning is added. The reference command line instead prints one notice line after the `as_of_ms` line, `registration_ms <value> source=manifest` (or `source=option` when the option was given and matched), so a reader can see that the value that decides the pre-registration cut came from the operator's manifest only. This line is part of the command line output, not of the result's `errors` or `warnings`, and it does not change the exit status.
>
> **What is not claimed.** The option does not say where the reader should get the published value, or that the published value is itself the registered one: the reader compares it with the pre-registration itself. It does not cover any other manifest field.

> **Amendment 15, approved by Ben 2026-10-12. OpenTimestamps proofs of the daily heads.** Adds one optional release file (`btc_headers.jsonl`, a cache like `rounds.jsonl`), five codes (`ots.invalid` error; `ots.pending`, `ots.unchecked`, `ots.late`, `ots.missing` warnings) and one CLI line. No domain tag, byte encoding, leaf, vector, hashed input, existing error code or the primary analysis changes. A release without `.ots` files and older than the rules below is judged as before, except for the `ots.missing` warning.
>
> **Why.** A head (§10.1) is the operator's statement that an anchor existed by a date. Its `anchor_hash` is submitted to OpenTimestamps calendars, which commit it into a Bitcoin block. A Bitcoin block header carries its own proof of work, so a reader can check the commitment without trusting the operator, the calendars or a block explorer.
>
> **Rules.**
> - **File.** `heads/D.ots` is optional. When present it must parse strictly: the OpenTimestamps magic, version 1, file hash op sha256, digest equal to the 32 bytes of the head's `anchor_hash`, a tree of the operations sha256, append and prepend only (each append/prepend argument at most 4096 bytes, depth at most 256), attestations of the kinds pending, bitcoin or unknown, and no trailing bytes. Anything else is the **error** `ots.invalid` for date D.
> - **Bitcoin attestation.** For each bitcoin attestation (height `h`), let `m` be the 32 bytes the path from the digest computes. The verifier needs the 80-byte block header for `h`. A header is **acceptable** when (1) its double-sha256 hash, read as a little-endian integer, is at most the target its own `bits` field encodes, and (2) that target is at most the pinned constant `OTS_MAX_TARGET` = compact `0x17087bc0` (a minimum amount of work per header, see below). The header's merkle root (bytes 36-67) must equal `m`.
> - **Where headers come from.** First `btc_headers.jsonl` in the release (lines `{"height": h, "header": "<160 hex>"}`; written by the downloader; never authoritative: an entry that is not acceptable is ignored), then, unless `--offline`, a public source fetched by height (the reference verifier asks one fixed source and, if its header is not acceptable or does not match, a second one; both URLs are listed in the README). A source is only a way to get bytes; trust comes from rules (1) and (2).
> - **Outcome per proof.** At least one bitcoin attestation with an acceptable header whose merkle root equals `m`: **confirmed**; its Bitcoin time is the header's `time` field. An acceptable header whose merkle root differs from `m`, from BOTH sources: **error** `ots.invalid` (the proof contradicts Bitcoin). No acceptable header could be obtained (offline, sources down, or one source only disagreed): **warning** `ots.unchecked`. Only pending or unknown attestations: **warning** `ots.pending` (calendars need hours; never an error).
> - **Time.** A confirmed proof whose Bitcoin time is later than 00:00 UTC of D+1 plus 48 hours: **warning** `ots.late`. The head still stands; only the external upper bound is weaker. (A Bitcoin time can be up to about two hours off real time by Bitcoin's own rules; the 48 hours absorb this.)
> - **Missing.** A head D with `as_of_ms` (amendment 10) at least 00:00 UTC of D+4 and no `heads/D.ots`: **warning** `ots.missing`, once per release, listing the dates (first 20).
> - **Several attestations, contradiction, limits (ratified by Ben 2026-10-12).** A proof with several bitcoin attestations is **confirmed** when any one confirms; otherwise `ots.invalid` when any one is contradicted, otherwise `ots.unchecked`. Attestations are examined by ascending height, stopping at the first confirmation (its block time decides `ots.late`), and at most 16 distinct heights of one proof are examined. "Contradicted" means: no acceptable header with the merkle root `m` was found, and acceptable headers with another root came from both source 1 and source 2 (the release cache never counts against a proof); a matching acceptable header from the cache or either source confirms. A file larger than 128 KiB is `ots.invalid`. A `heads/D.ots` whose date has no valid head file is ignored.
> - Every warning is one entry per release with `count=N` and the first 20 dates in the detail (the reference verifier writes `count=N; <meaning>: date, date, ...`). `--require-production` (amendment 13) does not turn any of them into errors.
> - The reference command line prints one line `ots confirmed=<n> pending=<n> unchecked=<n> late=<n> missing=<n>`; a `late` proof is also counted in `confirmed`.
> - A writer of `.ots` files that the verifier will read must stay inside these rules (the operator's Worker refuses sha1, ripemd160 and keccak256 steps and more than 256 steps on a path, and checks its served files with the same shared test cases).
>
> **What is not claimed.** The height in an attestation is not checked against the chain; a header is accepted for its own work, not for its place in the chain. Rule (2) means forging an acceptable header costs at least the work of one real block at the pinned difficulty. A confirmed proof shows that the head's hash existed by the header's time; it does not show that the head is complete or honest (§11 does that). NIST pulses are not covered by this amendment (amendment 16 below adds a separate, online check of them).

> **Amendment 16, approved by Ben 2026-10-13. The NIST pulse of a daily head is checked when the verifier is online.** Adds four warning codes (`nist.mismatch`, `nist.out_of_window`, `nist.foreign_uri`, `nist.unchecked`) and one CLI line. No domain tag, byte encoding, leaf, vector, hashed input, existing code or the primary analysis changes; no error is added. Offline (`--offline`) the result and the output are exactly what they were before.
>
> **Why.** A head (§10.1) records `nist_pulse: {uri, output_value}`. A NIST beacon pulse cannot be known before its time, so a head that carries the true pulse of the day's boundary was written no earlier than that pulse; this is a lower bound on when the head was made, next to the upper bound that an `.ots` proof gives (amendment 15). Until now the verifier only recorded the pair.
>
> **Rules.**
> - **When.** Only if the verifier is not offline, and not for a release whose manifest names the mock beacon (§12). Nothing is fetched for a head whose `nist_pulse` is `{null, null}`; such a head is counted as `absent` and is not a warning (amendment 7).
> - **Allowlist.** The `uri` is fetched only if it matches `^https://beacon\.nist\.gov/beacon/2\.0/chain/[0-9]{1,9}/pulse/[0-9]{1,15}$`. Any other value (another host, scheme or path, or a `uri` that is not a string while `output_value` is set) is **warning** `nist.foreign_uri` and nothing is requested.
> - **Request.** One `GET` of the `uri` per head: no credentials, redirects not followed, at most 64 KiB of body, 10 seconds. The body must be JSON with an object `pulse` whose `uri` equals the requested one, whose `outputValue` is 128 hex digits and whose `timeStamp` is an ISO-8601 UTC time. Any failure (network, status other than 200, a body of the wrong shape) leaves the head **unchecked**.
> - **Compare.** `output_value` (a string) equals `outputValue` when compared as lowercase hex, otherwise (including an `output_value` that is not a string) **warning** `nist.mismatch`. Let `B` be 00:00:00.000 UTC of D+1 for the head of date D. The pulse `timeStamp` must lie in [`B` - 60 s, `B` + 5 minutes], the window in which the operator's Worker accepts a pulse for the head (the endpoint answers with the first pulse at or after the time asked for); otherwise **warning** `nist.out_of_window`. A head that is both is reported as `nist.mismatch` only. All good: **matched**.
> - **Limits.** At most 400 requests per run, newest heads first, at most 5 requests a second, 300 seconds of network time in all, and no further request after 3 failed requests in a row (a status 404 is an answer, not a failure). Heads not reached are **unchecked**. Nothing is kept between runs.
> - **Warnings.** `nist.unchecked` (the pulse could not be fetched or read, or the limits were reached): one entry per release with `count=N` and the first 20 dates in the detail, written `count=N; <meaning>: date, date, ...`, like amendment 15. The same for the other three codes. `--require-production` (amendment 13) does not turn any of them into an error.
> - The reference command line prints one line, after the `ots` line and only when the check ran: `nist matched=<n> absent=<n> unchecked=<n> mismatch=<n> out_of_window=<n> foreign_uri=<n>`; each head is counted once.
>
> **Why a warning and not an error.** The pulse is in no hashed input (the head's hash chain and the `.ots` proof cover `anchor_hash` only), so it cannot change what the verifier proves about the anchors, the targets or the score. NIST labels its beacon "Version 2.0 (Beta)" and gives no availability or retention promise, and a pulse can be unreachable for reasons the operator does not control; an error would let that fail every release and the nightly job. A mismatch is still loud: it is the only outcome where the operator's record and NIST disagree.
>
> **What is not claimed.** A matching pulse shows that the head was written no earlier than the pulse; it does not show when it was written at most (that is the `.ots` proof), and it does not show that the head is complete or honest. The host is trusted as NIST's published endpoint (TLS to that name); the verifier does not check NIST's signature on the pulse. An unreachable NIST proves nothing either way.

> **Amendment 17, approved by Ben 2026-10-16. A canary batch published as a player batch is an error.** Adds one verification rule and one code, `canary.relabelled` (an error, or a warning before `registration_ms`). No domain tag, byte encoding, leaf, vector, hashed input, existing code or the primary analysis changes; no release field is added. It reuses the derivation and the window of amendment 9 unchanged. Once approved, the sentence "Players' rows are not checked by it" in amendment 9 no longer holds: player rows are checked by this amendment.
>
> **Why.** `source` is not in the leaf (§3), and amendment 9 checks only rows labelled `canary`. So whoever writes the export can, after the targets exist, publish a canary batch that happened to score well as `source == "player"`: every hash still verifies and the batch is counted (§9). The canary runs several times a day and about 1 in 20 of its batches scores 9 or more, so the choice is real and grows with time. With this rule the label is checked in both directions: from `registration_ms` on, a `card5` row is `canary` exactly when its guesses are the canary guesses of a candidate slot (amendment 9 for `canary` rows, this rule for `player` rows), up to the chance below. The label is then fixed by hashed data that exists before the target.
>
> **Rule.** For every row with `source == "player"`, whatever its duplicate status: let `s = sealed_at_ms`. The row **matches** if its `test_id` is `card5` and there is a whole minute `m` (`m mod 60000 == 0`, `m ≥ 0`) with `s - 600000 ≤ m ≤ s` such that `guesses == derive(m)` (amendment 9's derivation). These are exactly amendment 9's candidate slots: at most 11 (11 when `s` is itself a whole minute, otherwise 10; fewer near time zero). A row whose `test_id` is not `card5` never matches. A matching row gives:
> - `canary.relabelled`, an **error**, one per row with its `anchor_seq` and `batch_id`, when `sealed_at_ms ≥ registration_ms`. The reference verifier writes the detail `slot_ms=<m>; …` with the lowest matching slot. The release is invalid: `S` and `z` are withheld (`analysis.withheld`, §9), and so are the secondary figures and the permutation control (their own withheld rules).
> - `canary.relabelled`, a **warning**, once per release with `count=N` (the number of such rows) in the detail, when `sealed_at_ms < registration_ms`. Such rows are never counted in the study (§9); the warning says that the beta's labels cannot be relied on for them.
>
> `--require-production` (amendment 13) does not change either. The rule reads only the published row and the manifest's `registration_ms`, offline or online alike. Rows labelled `canary` are not checked by it (amendment 9 checks them). As everywhere in §9, no row is excluded from or added to any count because of it: the printed counts still follow the published labels. The fix for an error is to withdraw the release and reissue it with the row labelled `canary`, which its guesses show it is.
>
> **Interaction with amendment 9.** The two rules look at disjoint rows (`canary` rows there, `player` rows here), so both codes can appear in one release. A swap of labels (a canary published as player and a player published as canary) gives `canary.relabelled` for the first and `canary.guesses_mismatch` (or `canary.unverified` before `registration_ms`) for the second. Before `registration_ms`, `canary.unverified` and the warning `canary.relabelled` are separate entries with separate counts.
>
> **Chance of a false positive per player row.** A player who does not compute the canary derivation chooses guesses independently of it, and `derive(m)` is one of 5^25 = 298,023,223,876,953,125 ≈ 2.98 × 10^17 strings. With at most 11 candidate slots, an honest row matches with probability at most 11 / 5^25 ≈ 3.7 × 10^-17; over N = 10^6 player rows, at most about 3.7 × 10^-11. This is the same bound as amendment 9's chance of passing by accident.
>
> **A player who copies the canary guesses on purpose.** The derivation is public, so a player can compute `derive(m)` for the current minute and submit it. Without a guard such a row would make every release from then on invalid, and reissuing would not help (the row really is a player's). **Operator precondition:** before `registration_ms`, the operator's server refuses to seal a `player` batch whose guesses match a candidate slot of the `sealed_at_ms` it would record, by this same rule. That refusal happens before the batch is sealed, so before its target exists, and is blind to the outcome (§9, amendment 4); like every refused seal it is never stored, anchored or scored. With the guard in place, a matching player row from `registration_ms` on can only come from a relabelling or a fault in the operator's server, and both are the operator's to answer for. The guard itself cannot be checked from the release; a missing or broken guard shows up as this error once a copied batch has been sealed.
>
> **Blind to results.** The rule reads `guesses`, `test_id` and `sealed_at_ms`, all in the leaf and fixed when the batch is sealed, before its target round exists (§7), and the manifest's `registration_ms`. No hit, target or round takes part, so whether a row matches never depends on an outcome. It never excludes a row, so it cannot be used to drop one.
>
> **Cost.** At most 11 candidate slots of at most 25 SHA-256 each, so at most 275 SHA-256 per player row (2.75 million at 10,000 rows). The reference verifier compares digit by digit and stops at the first difference, about 1.25 SHA-256 per slot and about 12.5 per row for a non-matching row: about 0.3 seconds for 10,000 rows on a laptop (the full derivation for every slot, the worst case, about 5 seconds).
>
> **Vectors.** `tests/data/canary_relabel_v1/vectors.json`, generated by `tools/gen_canary_relabel_vectors.py` (standard library only, independent of the verifier code): the row fields the rule reads and the lowest matching slot or `null`, among them both window edges (sealed on a whole minute, ten minutes back inside and eleven outside; one millisecond later, ten minutes back outside), a slot after `sealed_at_ms`, another `test_id`, a changed first, middle and last digit, and time zero. No existing vector changes.
>
> **What is not claimed.** The rule does not show that every canary batch the operator sealed is in the release, or that the canary ran at every scheduled slot (a dropped canary row is not caught here; compare the canary count with the cadence the README gives). It does not cover a `test_id` other than `card5`, for which there is no canary derivation. It does not show that the operator's seal guard exists. A receipt check does not compare `source` (§10.2).

## 10. Published formats

### 10.1 Release directory
```
manifest.json
batches.jsonl
anchors.jsonl
rounds.jsonl          # cache of drand rounds: {"round", "signature"}; never authoritative (§9)
heads/YYYY-MM-DD.json # daily chain heads
heads/YYYY-MM-DD.ots  # optional OpenTimestamps proof of the head's anchor_hash (amendment 15)
btc_headers.jsonl     # optional cache of Bitcoin block headers {"height", "header"}; never authoritative (amendment 15)
```

`manifest.json`:
```json
{ "format": "precog-release/v1", "release_id": "2027-Q1", "registration_ms": 0,
  "beacon": { "network": "drand-quicknet", "chain_hash": "…", "genesis": 1692803367, "period": 3, "margin_rounds": 2 },
  "authorities": [ { "id": "tsa-a", "kind": "rfc3161", "name": "…", "issuing_ca_sha256": ["hex64", "…"], "root_sha256": "hex64" },
                   { "id": "tsa-test", "kind": "mock-hmac", "name": "…" } ],
  "with_participants": false }
```

`batches.jsonl`, one JSON object per line:
```json
{ "batch_id": "hex32", "test_id": "card5", "guesses": "25 digits", "sealed_at_ms": 0,
  "source": "player", "anchor_seq": 1, "leaf_index": 0, "leaf": "hex64",
  "target_round": 0, "hits": 0, "participant": null }
```
`participant` is present only when `with_participants` is true. **Amendment 11 (2026-10-10, approved by Ben):** when `with_participants` is true, every row's `participant` is a JSON integer `p` with 0 <= p < 2^53, written without a fraction or exponent; floats (even `1.0`), booleans, strings, `null` and a missing key are `format.invalid`. When `with_participants` is false, `participant` is `null` or absent on every row; any other value is `format.invalid`. `leaf` and `hits` are published for convenience. The verifier recomputes both and fails if either differs.

`anchors.jsonl`:
```json
{ "anchor_seq": 1, "prev_anchor_hash": "hex64", "merkle_root": "hex64", "leaf_count": 1,
  "anchor_hash": "hex64", "tokens": [ { "tsa_id": "tsa-a", "gen_time_ms": 0, "token": "base64" } ] }
```

`heads/YYYY-MM-DD.json`:
```json
{ "date": "YYYY-MM-DD", "anchor_seq": 0, "anchor_hash": "hex64", "anchors_that_day": 0,
  "nist_pulse": { "uri": "…", "output_value": "hex" } }
```
If no NIST pulse could be recorded for a head, both `uri` and `output_value` are `null`; the object and its two keys are always present (amendment 7, text only). A missing pulse is not an error. **Amendment 16:** when the verifier is online, the pulse of a head is fetched from NIST and compared, with warnings only (see amendment 16 after amendment 15 and check 6d in §11). `nist_pulse` is not part of any hashed input and is not covered by a `.ots` proof.

The chain of daily heads starts on the UTC date of the first anchor: there is no head for any date before it, so every head has `anchor_seq` ≥ 1. A head with `anchor_seq` 0 in a release that holds any anchor is `head.mismatch` (amendment 8, text only).

**Heads are required (amendment 10, 2026-10-10, approved by Ben).** The release has no cut time of its own (the manifest holds none, and a time taken from the release would move back with a truncation). The verifier therefore judges the release **as of** a time that it is given: `as_of_ms`, Unix milliseconds, from the command line `--as-of` (Unix milliseconds, or ISO-8601 UTC `YYYY-MM-DDTHH:MM:SS[.fff]Z`); the default is the verifier's own clock when it is run. The `as_of` used is printed (`as_of_ms <n>`). Let `D0` be the UTC date of the first anchor (lowest `anchor_seq`; its time is the later token `gen_time_ms` rounded up to the second, as in the head rule). A UTC date `D` with `D0 <= D` is **due** when `as_of_ms >= 00:00:00.000 UTC of D+1 + 1 hour`. The hour is a grace period, because the head of `D` is written by the Worker's cron at about 00:05 UTC on `D+1` (with backfill of missed days). Every due date must have a head file `heads/D.json`; otherwise there is one error `head.missing` naming the dates (the first 20 are listed). A date is due whether or not any anchor was made that day. A release with no anchors has no due date. Consequences: a tail deleted together with its heads is noticed up to `as_of`; a release verified long after it was downloaded fails for the days since, so an archive is judged with `--as-of <the time it was downloaded>`; the downloader and the nightly job use the time their download started. Verifying a receipt does not use heads or `as_of`. A head file that is present but invalid is `format.invalid`, and the date also counts as missing. The `.ots` proofs of the heads are judged by amendment 15, not by this rule. No byte encoding or test vector changes.

### 10.2 Receipt (held by the player)
```json
{ "format": "precog-receipt/v1", "batch_id": "…", "test_id": "card5", "guesses": "…",
  "sealed_at_ms": 0, "leaf": "hex64", "leaf_index": 0, "proof": ["hex64", "…"],
  "anchor": { …same shape as one anchors.jsonl line… }, "target_round": 0,
  "authorities": [ { "id": "tsa-a", "kind": "rfc3161", "name": "…", "issuing_ca_sha256": "hex64", "root_sha256": "hex64" } ] }
```
**Certificate pinning fields** (amendment 6, 2026-10-04; replaces `cert_sha256` from amendment 5, which is no longer valid). All hashes are lowercase hex SHA-256 of the DER encoding of a certificate.
- `issuing_ca_sha256` (manifest): a **non-empty, append-only array** of distinct hashes of issuing CA certificates, that is, the CAs that sign the authority's signer certificates. A token verifies if its chain, built from the certificates embedded in the token, reaches **any** member. Entries are never removed, so old tokens keep verifying. There are no validity windows in the manifest: chain validation uses the certificates' own validity at the token's `genTime`, not at verification time. It is neither the signer certificate (signers rotate) nor the root.
- `issuing_ca_sha256` (receipt): a single **string**, the hash of the issuing CA that actually signed that token.
- `root_sha256` (manifest and receipt): a single string, the hash of the pinned root certificate that every listed issuing CA must chain to. Checking that chain is done by the `rfc3161` plugin; v1 only defines the fields and their shape.
- `rfc3161` entries must carry both fields. `mock-hmac` entries carry neither (a mock has no certificate); a mock entry with any of them, or any entry with the old `cert_sha256`, is `format.invalid`. Other kinds are not checked for these fields in v1.
- **Receipt against release:** the receipt's entry must equal the manifest entry in every field except `issuing_ca_sha256`, and the receipt's `issuing_ca_sha256` string must be a member of the manifest's array. Otherwise the check fails with `receipt.authority_mismatch`. A standalone receipt has no manifest, so the CA member check is made only against a release.
- Rotation: a new issuing CA is added to the manifest array and the old entries stay, so earlier tokens keep verifying.

`authorities` holds the manifest entry of each authority that issued a token on the anchor (amendment 2, 2026-10-03). A receipt checked on its own uses these entries to choose the token plugin and to bind each token to a certificate. It never guesses the kind from the token bytes. When a receipt is checked against a release, the entries must match the release manifest's entries (equality, with the issuing-CA membership rule above), or the check fails with `receipt.authority_mismatch`.

### 10.3 Test vectors
`vectors/<name>.json`: `{ "spec": "v1", "description": "…", "cases": [ { "name": "…", "input": {…}, "output": {…} } ] }`. Bytes are written as hex.

## 11. Verification procedure and error codes
A release is verified in this order. Each step stops at, or collects, errors with the codes shown. Codes are stable identifiers, not display text.

| # | Check | Error codes |
|---|---|---|
| 0 | Format and fields valid; `batch_id`s unique; `leaf_index` values per anchor are exactly 0..leaf_count-1 | `format.invalid`, `batch.duplicate_id`, `batch.leaf_index_gap` |
| 1 | Rebuild each leaf; it matches the published `leaf` | `leaf.mismatch` |
| 2 | Rebuild each Merkle root; it matches the anchor; the row count matches `leaf_count` | `merkle.root_mismatch`, `merkle.count_mismatch` |
| 3 | Recompute each `anchor_hash`; the chain links with no gaps from seq 1; every daily head matches the anchor at its seq | `anchor.hash_mismatch`, `anchor.chain_broken`, `anchor.seq_gap`, `head.mismatch`, `head.missing` (every due date has a head, given `as_of_ms`; amendment 10) |
| 4 | At least two valid tokens from different authorities, each covering `anchor_hash`; `sealed_at_ms` ≤ the earliest token time of the anchor | `tsa.invalid`, `tsa.wrong_imprint`, `tsa.too_few`, `leaf.sealed_after_anchor`; `tsa.same_root` (warning, amendment 13) |
| 4b | Trust notices (amendment 13, approved 2026-10-11): a mock authority or the mock beacon in the manifest; a warning, an error with `--require-production` | `manifest.mock_authority`, `manifest.mock_beacon` |
| 4c | Registration pin (amendment 14): with `--registration-ms N`, `manifest.registration_ms` must equal `N` | `manifest.registration_mismatch` |
| 5 | `target_round` equals the computed round (§7) | `target.round_wrong` |
| 6 | Round valid, taken from the cache or fetched from the beacon; recomputed hits equal the published `hits` | `round.unavailable`, `score.mismatch` (cache problems that a fetch fixes are warnings: `round.cache_missing`, `round.cache_bad`) |
| 6b | Canary rows (amendment 9): `source == "canary"` rows carry the guesses derived from a whole-minute slot in the 10 minutes before `sealed_at_ms`, and `test_id` `card5`. Failing: error from `registration_ms` on, warning before | `canary.guesses_mismatch`, `canary.unverified` (warning) |
| 6c | OpenTimestamps proofs of the heads (amendment 15): strict parse, Bitcoin headers by proof of work, merkle root, late and missing proofs. Only `ots.invalid` is an error | `ots.invalid`; `ots.pending`, `ots.unchecked`, `ots.late`, `ots.missing` (warnings) |
| 6d | Amendment 16: NIST pulses of the heads, online only: the pulse at the head's `uri` has the head's `output_value` and a time inside the head's window. Warnings only | `nist.mismatch`, `nist.out_of_window`, `nist.foreign_uri`, `nist.unchecked` (warnings) |
| 6e | Amendment 17, approved by Ben 2026-10-16: no `player` row carries the canary guesses of a whole-minute slot in the 10 minutes before its `sealed_at_ms` (amendment 9's window, `test_id` `card5`). Matching: error from `registration_ms` on, warning before | `canary.relabelled` (error; a warning before `registration_ms`) |
| 7 | Run the analysis (§9) and print it; if there were any errors, withhold `S` and `z` | `analysis.withheld` |

A **receipt** check runs steps 1, 2 (by proof), 3 (one anchor), 4 and 5 on the receipt alone. Against a release, it also confirms that the anchor line and the batch row appear in the release unchanged (`receipt.not_in_release`, `receipt.row_changed`, `receipt.authority_mismatch`).

## 12. Mock authorities (testing only)
- **MockTSA** (`kind: mock-hmac`). Its token is the base64 of the JSON `{"tsa_id", "anchor_hash", "gen_time_ms", "mac"}`, where `mac = HMAC-SHA256(key, tsa_id || anchor_hash || u64(gen_time_ms))`. The test keys are published in the vectors. A mock token proves nothing and exists only to exercise the verifier.
- **MockBeacon**: `signature(r) = sha256("precog/mock-beacon/v1" || u64(r))`, with the same `round_time` constants as quicknet.

## 13. Resolved review questions (2026-10-03)
1. **Target domain tag.** The original design had no tag on the target hash. This adds `precog/target/v1` and length-prefixes `test_id`. **Decided: adopt both** (§8).
2. **Publishing `sealed_at_ms`.** The leaf commits to it, so it must be published, and exact times can let someone who knows when a friend played find their row (a caveat from the handoff). The anchor's timestamp tokens already give similar precision. **Decided: keep it** and disclose it in the privacy text (phase 4).
3. **Rounding.** `t_anchor` rounds **up** to the whole second before the 2-round margin is added. **Approved.**
4. **Monotonic anchor times.** Token times across anchors should rise with `anchor_seq`. Clock skew between authorities makes a strict check fragile, so v1 reports it as a warning (`anchor.time_regressed`), not a failure. **Approved.**
