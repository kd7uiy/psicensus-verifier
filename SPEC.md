# precog verifier specification

Specification version 1. This is the version the study names at registration; later changes are published as dated amendments.

The test vectors in `vectors/` are frozen. Any change to a byte encoding needs a new version tag (`.../v2`).

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

Domain tags: `precog/leaf/v1` (§3), `precog/anchor/v1` (§5), `precog/target/v1` (§8), `precog/canary/v1` (§9.7) and `precog/permutation/v1` (§9.11). The mock beacon of §12 uses `precog/mock-beacon/v1`.

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

**Publishing `sealed_at_ms`.** The leaf commits to `sealed_at_ms`, so it must be published exactly. Exact times can let someone who knows when a friend played find their row. The anchor's timestamp tokens already give similar precision, and the privacy policy will disclose it.

## 3. Leaf
```
leaf = sha256( TAG("precog/leaf/v1") || batch_id || str8(test_id) || guesses || u64(sealed_at_ms) )
```
No participant identifier is included. `source`, `hits`, `target_round` and `participant` are not part of the leaf.

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
- `gen_time_ms` is the token's `genTime` in Unix milliseconds. If the token has no fractional seconds, the fraction is 0. If it has more than three fraction digits, the extra digits are dropped (truncated toward zero, never rounded): `.1239` gives 123 ms. Every later use of the token time (the published `gen_time_ms`, §7 and §11 check 4) uses this truncated value. Truncation can make `t_anchor` in §7 up to 1 ms earlier than the exact `genTime` rounded up; the target round then still follows the token time by the margin minus less than 1 ms, which is accepted.
- The verifier treats token checking as a plugin chosen by the authority's `kind` in the manifest:
  - `rfc3161`: real tokens, checked by the standard-library plugin `precog_verifier.rfc3161`.
  - `mock-hmac`: testing only (§12).
- The certificate pinning fields of an authority (`issuing_ca_sha256`, `root_sha256`) are defined in §10.2. They are manifest and receipt metadata only and are not part of any hashed input.
- **Monotonic anchor times.** Token times across anchors should rise with `anchor_seq`. Clock skew between authorities makes a strict check fragile, so the verifier reports it as a warning (`anchor.time_regressed`), not a failure.

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
`t_anchor` rounds **up** to the whole second before the 2-round margin is added. It uses the **later** of the two token times, so neither authority alone can move the round earlier. The release supplies the round's `signature`. Its randomness is `sha256(signature)`. A full verifier also checks the BLS signature against the chain's public key (the standard-library `drand-quicknet` beacon plugin, `precog_verifier.bls`).

## 8. Targets and scoring
```
for i in 0..24:
    h         = sha256( TAG("precog/target/v1") || randomness || str8(test_id) || batch_id || u32(i) )
    target[i] = u64(h[0:8]) mod 5
hits = count of i where guesses[i] == target[i]
```
The target hash has its own domain tag, `precog/target/v1`, and length-prefixes `test_id`. The modulo bias of a 64-bit value reduced mod 5 is about 2⁻⁶², which is negligible.

## 9. Analysis (matches `study-precognition.md` §5)

### 9.1 Principle
An exclusion is allowed only if it is fixed **before the batch's target exists**. Any rule that can still be triggered after targets are known, by changing, dropping or adding published data, is a channel for selection bias, and the spec has none.

### 9.2 Counted batches (R1)
**Counted batches** are rows where all of the following hold:
- `source == "player"`
- `sealed_at_ms ≥ registration_ms` (taken from the manifest)
- the row is the **first copy** of its `batch_id` (§9.5)
- `test_id == "card5"`

**One test.** A `player` row sealed at or after `registration_ms` that is the first copy of its `batch_id` and has another `test_id` is **excluded**, not an error:
- it is counted in the count `excluded_other_test`;
- the release gets the **warning** `batch.other_test_id`, once per release, with `count=N` in the detail (`count=N; player rows of another test, not counted`). `--require-production` (§11.2) does not change it.

Every other check (leaf, Merkle, tokens, round, score, and the canary rules of §9.7 and §9.8) applies to such a row unchanged.

**Exclusion counts.** The exclusion counts are disjoint, each row in the first that applies: `excluded_pre_registration`, `duplicate_later`, `duplicate_same_anchor`, `excluded_other_test`. The permutation control (§9.11) and the secondary analyses (§9.10) use the counted batches, so they follow every rule of this section. Since a row of another test is never counted, the canary rules not covering a `test_id` other than `card5` (§9.8, "What is not claimed") cannot move a counted number.

**Operator precondition.** Before `registration_ms`, the operator's server refuses to seal any batch whose `test_id` is not `card5`, until a later amendment admits another test. Like every refused seal, such a batch is never stored, anchored or scored. The guard cannot be checked from the release; a row of another test that appears anyway is excluded by the rule above and shown by its count and warning. It is not an error because an anchored row can never be removed by a reissue: one such row, from a fault or from anyone who reached the seal route, would make every later release invalid with no possible fix.

**Blind to results.** `test_id` is in the leaf (§3), fixed when the batch is sealed, before its target round exists (§7). The operator cannot change it afterwards without `leaf.mismatch`, so the exclusion cannot be used to drop a batch after its result is known.

### 9.3 A release with any error is invalid
Errors are the codes of the §11.1 table that are not warnings (§11.1 says which) and, for a receipt check, the codes of §11.6. Notices (§11.1) and builder refusals (§9.14) are not errors. The verifier reports all the error codes, prints the counts, and **withholds `S` and `z`** (`analysis.withheld`). Batches are never excluded because of a verification failure. A failure means the published data does not match its own commitments or the public beacon. The fix is to withdraw the release, explain the fault publicly, and reissue it from the raw data.

### 9.4 Beacon rounds
`rounds.jsonl` is a cache and is never authoritative. If a cached round is missing or fails its signature check, the verifier fetches the round from the beacon network through the beacon plugin. If it still cannot get a valid round, verification is **incomplete** (`round.unavailable`), which is an error: the analysis is withheld, and no batch is excluded.

### 9.5 Duplicate IDs
The copy in the earliest anchor (lowest `anchor_seq`) is the batch.
- Copies in later anchors were committed after it, so they are never counted.
- If two or more copies share the earliest anchor, they were all committed before that anchor's target existed. Dropping all of them is blind to the outcome, so **all** of them are excluded.
- Duplicates are already fixed in timestamped anchors, so a reissued release could not remove them. They are therefore reported as a prominent **warning** (`batch.duplicate_id`, listing every copy), not as an error, and the release stays valid.
- They are counted separately: `duplicate_later` (later copies not counted) and `duplicate_same_anchor` (blind exclusions).

### 9.6 Primary analysis and the null interval (R4)
```
N_trials = 25 * (number of counted batches)
S        = Σ (hits - 0.2 * 25)
z        = S / sqrt(N_trials * 0.2 * 0.8)
```
The output contains `n_batches`, `N_trials`, total hits, the hit rate, `S` and `z` (or `analysis.withheld`), the duplicate counts, the pre-registration count, `excluded_other_test` and the canary count. Canary batches are analyzed separately with the same formula, over the canary set of §9.9. The permutation control (`study-precognition.md` §7 item 3) is specified in §9.11.

**The null interval.** Whenever `z` is reported (not withheld, `N_trials > 0`), the verifier also reports the two-sided 95% interval for the pooled hit rate minus 0.2, in percentage points, not adjusted for looks: `d = (hits / N_trials - 0.2) * 100`, `half = 1.96 * sqrt(0.16 / N_trials) * 100`, `interval_pp = [d - half, d + half]`. The constant is exactly 1.96. The interval is `null` when `z` is withheld or `N_trials = 0`; when both hold, the output line is `interval withheld`. It is computed from the counted batches only (not the canary set, not the capped set). It is a function of the counted batches, so it is as blind to results as they are.

**Output (reference verifier).** The `excluded` line ends with ` other_test=N`. The line `interval pp_low=… pp_high=…` follows the `excluded` line (`interval withheld` when withheld, `interval pp_low=n/a pp_high=n/a` when `N_trials = 0`). The analysis object carries `excluded_other_test` and `interval_pp` (`{"low", "high"}` or `null`).

### 9.7 Canary guesses
**Why.** `source` is not in the leaf, so without this rule whoever writes the export could relabel a badly scoring player batch as `canary` and drop it from the study; every hash would still verify. The canary's guesses are therefore made checkable: they come from public data that is fixed before the batch's target exists, and a `canary` row whose guesses do not match is rejected.

**Derivation.** A canary batch is created by a scheduled job at the job's scheduled time `slot_ms`, in Unix milliseconds, always a whole minute (`slot_ms mod 60000 == 0`). For `i = 0..24`:
```
guess[i] = u64( sha256( TAG("precog/canary/v1") || u64(slot_ms) || u32(i) )[0:8] ) mod 5
```
This is the construction of §8 with a different tag and input. The modulo bias is the same negligible ~2^-62. Vectors: `tests/data/canary_v1/guesses.json` (several slots, among them 0, a real 2026 slot and the largest whole minute below 2^64).

**Candidate slots.** For a row with `s = sealed_at_ms`, the candidate slots are the whole minutes `m` (`m mod 60000 == 0`, `m ≥ 0`) with `s - 600000 ≤ m ≤ s`. That is at most 11 candidate slots (11 when `s` is itself a whole minute, otherwise 10; fewer near time zero).

**Rule for canary rows.** For every row with `source == "canary"`: the row is **verified** if its `test_id` is `card5` and there is a candidate slot `m` such that `guesses == derive(m)` (the 25 digits above). A row that is not verified gives:
- `canary.guesses_mismatch`, an **error** (the release is invalid; S and z are withheld, §9.3), when `sealed_at_ms ≥ registration_ms`;
- `canary.unverified`, a **warning**, when `sealed_at_ms < registration_ms` (the beta: such batches are never counted anyway). It is reported once per release, with the count of such rows in the detail (`count=N`).

The rule reads only the published row and the manifest. It checks only rows labelled `canary`; `player` rows are checked by §9.8. No row is excluded from or added to any count because of it (as everywhere in §9, a failure invalidates the release; it never changes which batches are counted).

**Chance of passing by accident.** A relabelled player batch carries guesses the player chose, independently of the operator. Each of its at most 11 candidate strings is one of 5^25 ≈ 2.98 × 10^17, so a given batch passes with probability at most 11 / 5^25 ≈ 3.7 × 10^-17. Even if the operator could pick the one batch to relabel out of N player batches, the chance that any of them passes is at most N × 3.7 × 10^-17 (about 4 × 10^-11 for N = 10^6). The operator cannot move this: the guesses are inside the leaf, which is anchored and time-stamped, and the window is only ten minutes wide. The operator can still create extra canary batches at will; they are analysed separately and never counted in the study.

**Blind to results.** `slot_ms` is the scheduled time of the job, fixed before the batch is sealed; the batch's target round is chosen afterwards, from the anchor's token time (§7), and the beacon output for it does not yet exist at sealing. So the canary guesses cannot depend on any target, and the rule cannot depend on any outcome.

### 9.8 A canary batch published as a player batch
**Why.** `source` is not in the leaf (§3), and §9.7 checks only rows labelled `canary`. Without this rule, whoever writes the export could, after the targets exist, publish a canary batch that happened to score well as `source == "player"`: every hash would still verify and the batch would be counted (§9.2). The canary runs several times a day and about 1 in 20 of its batches scores 9 or more, so the choice is real and grows with time. With this rule the label is checked in both directions: from `registration_ms` on, a `card5` row is `canary` exactly when its guesses are the canary guesses of a candidate slot (§9.7 for `canary` rows, this rule for `player` rows), up to the chance below. The label is then fixed by hashed data that exists before the target.

**Rule.** For every row with `source == "player"`, whatever its duplicate status (`s = sealed_at_ms`): the row **matches** if its `test_id` is `card5` and there is a candidate slot `m` (§9.7: at most 11, 11 when `s` is itself a whole minute, otherwise 10; fewer near time zero) such that `guesses == derive(m)` (§9.7's derivation). A row whose `test_id` is not `card5` never matches. A matching row gives:
- `canary.relabelled`, an **error**, one per row with its `anchor_seq` and `batch_id`, when `sealed_at_ms ≥ registration_ms`. The reference verifier writes the detail `slot_ms=<m>; …` with the lowest matching slot. The release is invalid: `S` and `z` are withheld (`analysis.withheld`, §9.3), and so are the secondary figures and the permutation control (their own withheld rules).
- `canary.relabelled`, a **warning**, once per release with `count=N` (the number of such rows) in the detail, when `sealed_at_ms < registration_ms`. Such rows are never counted in the study (§9.2); the warning says that the beta's labels cannot be relied on for them.

`--require-production` (§11.2) does not change either. The rule reads only the published row and the manifest's `registration_ms`, offline or online alike. Rows labelled `canary` are not checked by it (§9.7 checks them). As everywhere in §9, no row is excluded from or added to any count because of it: the printed counts still follow the published labels. The fix for an error is to withdraw the release and reissue it with the row labelled `canary`, which its guesses show it is.

**Interaction with §9.7.** The two rules look at disjoint rows (`canary` rows there, `player` rows here), so both codes can appear in one release. A swap of labels (a canary published as player and a player published as canary) gives `canary.relabelled` for the first and `canary.guesses_mismatch` (or `canary.unverified` before `registration_ms`) for the second. Before `registration_ms`, `canary.unverified` and the warning `canary.relabelled` are separate entries with separate counts.

**Chance of a false positive per player row.** A player who does not compute the canary derivation chooses guesses independently of it, and `derive(m)` is one of 5^25 = 298,023,223,876,953,125 ≈ 2.98 × 10^17 strings. With at most 11 candidate slots, an honest row matches with probability at most 11 / 5^25 ≈ 3.7 × 10^-17; over N = 10^6 player rows, at most about 3.7 × 10^-11. This is the same bound as §9.7's chance of passing by accident.

**A player who copies the canary guesses on purpose.** The derivation is public, so a player can compute `derive(m)` for the current minute and submit it. Without a guard such a row would make every release from then on invalid, and reissuing would not help (the row really is a player's). **Operator precondition:** before `registration_ms`, the operator's server refuses to seal a `player` batch whose guesses match a candidate slot of the `sealed_at_ms` it would record, by this same rule. That refusal happens before the batch is sealed, so before its target exists, and is blind to the outcome (§9.1); like every refused seal it is never stored, anchored or scored. With the guard in place, a matching player row from `registration_ms` on can only come from a relabelling or a fault in the operator's server, and both are the operator's to answer for. The guard itself cannot be checked from the release; a missing or broken guard shows up as this error once a copied batch has been sealed.

**Blind to results.** The rule reads `guesses`, `test_id` and `sealed_at_ms`, all in the leaf and fixed when the batch is sealed, before its target round exists (§7), and the manifest's `registration_ms`. No hit, target or round takes part, so whether a row matches never depends on an outcome. It never excludes a row, so it cannot be used to drop one.

**Cost.** At most 11 candidate slots of at most 25 SHA-256 each, so at most 275 SHA-256 per player row (2.75 million at 10,000 rows). The reference verifier compares digit by digit and stops at the first difference, about 1.25 SHA-256 per slot and about 12.5 per row for a non-matching row: about 0.3 seconds for 10,000 rows on a laptop (the full derivation for every slot, the worst case, about 5 seconds).

**Vectors.** `tests/data/canary_relabel_v1/vectors.json`, generated by `tools/gen_canary_relabel_vectors.py` (standard library only, independent of the verifier code): the row fields the rule reads and the lowest matching slot or `null`, among them both window edges (sealed on a whole minute, ten minutes back inside and eleven outside; one millisecond later, ten minutes back outside), a slot after `sealed_at_ms`, another `test_id`, a changed first, middle and last digit, and time zero.

**What is not claimed.** The rule does not show that every canary batch the operator sealed is in the release, or that the canary ran at every scheduled slot (a dropped canary row is not caught here; compare the canary count with the cadence the README gives). It does not cover a `test_id` other than `card5`, for which there is no canary derivation. It does not show that the operator's seal guard exists. A receipt check does not compare `source` (§10.2).

### 9.9 The canary set (R2)
The canary statistics are computed over the rows with `source == "canary"`, `test_id == "card5"` and `sealed_at_ms >= registration_ms` that are the first copy of their `batch_id` (the duplicate rule of §9.5), with the primary formula. The count `n_canary` (printed as `seen`) is every row with `source == "canary"`, of any time and copy. Rows sealed before `registration_ms` are in `seen` only. A release has one canary set; across releases it is cumulative because releases are (§9.12). The canary line of the reference verifier keeps its format; its `n_batches`, `N_trials`, `hits`, `rate`, `S` and `z` are those of this set. No permutation control is run for the canary set (§9.11).

**Blind to results.** The `source` of a canary row is checked against public data fixed before its target (§9.7 and §9.8); `sealed_at_ms`, the copy rule and `registration_ms` are all fixed before any target of the set exists.

### 9.10 Secondary analyses (R3)
Secondary analyses: per-participant capping and per-participant Stouffer (`study-precognition.md` §7 items 1 and 2). The primary analysis above does not depend on them.

**Status.** They are secondary: they are reported, never the headline, and the verifier applies no threshold to them; the bars of the study are applied by the release builder to the values the verifier reports (§9.13). They are computed from the counted batches above and from nothing else, so every exclusion rule above applies first (canary, before `registration_ms`, another `test_id`, and non-first copies of a `batch_id` never take part and never use up a cap slot).

**Participant numbers.** `participant` is published only when the manifest has `with_participants: true` (§10.1). The secondary analyses are **not available** when `with_participants` is `false`, or when any counted row has a `null` `participant`. Then no secondary figure is computed, and the output carries the code `secondary.no_participants` instead. This is a notice in the analysis output, not an entry in the error or warning lists: it never makes a release invalid, never changes `ok`, and verification is unchanged. Two `participant` values are the same participant exactly when their JSON values are equal. A participant is one `participant` value of the release; `k` is the number of participants with at least one counted batch, the same `k` for both Stouffer variants below.

**Quarter.** The UTC calendar quarter of `sealed_at_ms`: the Gregorian date of the instant `sealed_at_ms` milliseconds after 1970-01-01T00:00:00Z, in UTC, with Jan-Mar, Apr-Jun, Jul-Sep and Oct-Dec as quarters 1 to 4. A quarter is identified by (year, quarter number): Q1 2027 and Q1 2028 are different quarters. The last millisecond of a quarter (for example 2027-03-31T23:59:59.999Z) belongs to it, and the next millisecond (2027-04-01T00:00:00.000Z) starts the next.

**Per-participant cap.** From the counted batches, form one group per (participant, quarter). Order each group by the key `(sealed_at_ms, anchor_seq, batch_id)`, ascending, where `sealed_at_ms` and `anchor_seq` compare as integers and `batch_id` compares as its 16 raw bytes (the decoded form of the 32 hex characters), lexicographically, each byte as an unsigned value (equivalent to comparing the lowercase hex strings). Keep the first 20 batches of each group (at most 500 trials) and drop the rest. The key uses no result, so which batches are kept never depends on outcomes. Report for the kept set: `n_batches`, `N_trials = 25 * n_batches`, `hits`, the hit rate, `S` and `z` with the same formulas as above, and `removed` = counted batches minus kept batches.

**Stouffer in two variants.** Both are computed only when the secondary analyses are available, and both are withheld exactly when the Stouffer `Z` of variant (b) is.
- **(b) Capped batches, per-participant z on the kept set.** For each participant `i` with `n_i >= 1` kept batches (in any quarter): `S_i = Σ (hits - 5)` over the participant's kept batches, and `z_i = S_i / sqrt(25 * n_i * 0.2 * 0.8)`. With `k` = the number of such participants, `Z = (Σ z_i) / sqrt(k)`, unweighted. Report `k` and `Z`. With `k = 0` there is no `Z`. (The reference verifier sums with `math.fsum`; any exact or correctly rounded summation agrees to within floating-point error.)
- **(a) First batch.** For each participant, the **first counted batch** is the counted batch with the smallest key `(sealed_at_ms, anchor_seq, batch_id)`, compared exactly as in the per-participant cap, over all of the participant's counted batches of every quarter. **Ties:** two counted batches never share a `batch_id` (only the first copy of an id is counted), so the key is a total order and there is no tie. Because the cap keeps the earliest batches of each quarter by the same key, the first counted batch is always a kept batch, so it does not matter whether it is taken before or after the cap. Then `S_first = Σ (hits_first,i - 5)` over the `k` participants (an exact integer) and `Z_first = S_first / sqrt(25 * k * 0.2 * 0.8) = S_first / (2 * sqrt(k))`: the primary formula applied to the set of first batches. With `k = 0` there is no `Z_first`.
- **The bar** (applied by the release builder, §9.13) is |Z| >= 4.22 for variant (a) at each look, compared with the unrounded value the verifier computes (in the reference verifier a double; the printed six decimals are for reading only). A `null` value never crosses. (b) is reported for description only and has no bar; a value of (b) beyond 4.22 is not a finding.

**Blind to results.** The key `(sealed_at_ms, anchor_seq, batch_id)` is fixed when the batch is sealed and anchored, before its target round is chosen from the anchor's tokens. A participant's first batch therefore does not depend on any result, so `hits_first,i - 5` has mean 0 under chance however the player continues afterwards. Variant (b) has no such protection, because its `n_i` can depend on earlier results (the expected value of its `Z` is not 0 under chance when players decide to continue after seeing results); this is why only (a) has a bar, and (b) is reported for description only.

**Withheld.** Whenever the primary analysis is withheld (any error in §11), the kept-set `hits`, rate, `S`, `z`, `Z` and the first-batch `S_first` and `Z_first` are not reported; the counts (`n_batches`, `N_trials`, `removed`, `k`) are. If both apply, "not available" takes precedence.

**Output (reference verifier).** After the `canary` line: `secondary capped n_batches=… N_trials=… removed=… hits=… rate=… S=… z=…`, `secondary stouffer k=… Z=…` and, right after it, `secondary stouffer_first k=… Z=…` (only in this state; `k` is shared); or `secondary withheld capped_n_batches=… capped_N_trials=… removed=… k=…`; or `secondary unavailable code=secondary.no_participants`. The analysis object carries the same values under `secondary`, with `secondary.stouffer_first` as `{"k", "Z", "S"}`: `Z` and `S` are `null` when withheld; the whole object is `null` when the secondary analyses are unavailable; with `k = 0`, `S = 0` and `Z` is `null`.

**What is not claimed.** A participant is whatever one `participant` value groups; the verifier cannot tell what it stands for (at registration, one device: the study, section 9). If participant numbers could ever merge (a future sign-in, which needs its own amendment), a merge would be a choice a player can make after seeing results: it would keep the earlier of two first batches, drop the other from variant (a) and lower `k`; this specification does not make (a) immune to that. A reset device (cleared data, an erase) starts a new participant at a time the player chooses; the new participant's first batch is still sealed before its target.

### 9.11 Permutation control
**Why.** The targets of a batch are fixed by the beacon and independent of every guess (§8), so scoring any guesses against any other batch's targets hits with probability exactly 0.2 per trial, whatever the guesser's habits. A real effect (guesses that predict their own batch's target) must vanish when the pairing is broken. What the control catches is a pipeline fault that makes the primary look good for a reason other than the pairing (a leaked target, a bad join, a mis-ordered row). It is one published number, `z`, expected to be unremarkable.

**Set.** Exactly the counted batches of the primary analysis (§9.2: player, `sealed_at_ms ≥ registration_ms`, first copy, same-anchor duplicates excluded, `test_id` `card5`), after every exclusion rule above. The verifier applies no other restriction to the set (`--as-of` only judges the heads, §10.1). Order them by `(anchor_seq as an integer, batch_id as its 16 raw bytes compared as unsigned bytes, lexicographically)` and index them `0..n-1` in that order. No hit, time or participant takes part in the order.

**Cut and seed round.** `t_cut` is the largest `t_anchor` (§7, in seconds) among the anchors of the release (every anchor with a valid token time). The seed round `R` is the first drand quicknet round whose time is at least `t_cut + 86400` seconds (24 hours), by the §7 formula:
```
R = max(1, ceil( (t_cut + 86400 - genesis) / period ) + 1)
```
`randomness(R)` is `sha256(signature)` of that round, obtained and checked like any other round (the cache `rounds.jsonl`, then the beacon plugin; the BLS signature is verified). The round is not part of the release's commitments: no row refers to it. The release builder does not add round `R` to `rounds.jsonl`.

**Seed and stream.**
```
seed  = sha256( TAG("precog/permutation/v1") || randomness(R) || u64(n) )
B_j   = sha256( seed || u64(j) )                          j = 0, 1, 2, ...
words = for each j in order, the four big-endian u64 values of B_j[0:8], B_j[8:16], B_j[16:24], B_j[24:32]
```
Words are consumed in that order and never reused.

**Uniform integer in [0, m)**, `m ≥ 1`: `limit = 2^64 - (2^64 mod m)`; take the next word `w`; if `w < limit` the result is `w mod m`, otherwise take another word and repeat. (For `m = 1` one word is still consumed and the result is 0.)

**Derangement (Sattolo).** Start with `a[k] = k` for `k = 0..n-1`. For `i = n-1` down to `1`: `j = uniform(i)` (in `[0, i)`); swap `a[i]` and `a[j]`. The result is a single `n`-cycle, so `a[k] != k` for every `k` when `n ≥ 2`, and every `n`-cycle is equally likely.

**Scoring.** Batch `k` is scored against batch `a[k]`: `hits_k` is the number of positions `t` (0..24) where `guesses_k[t] == targets_{a[k]}[t]`, and `targets_b` are the §8 targets of batch `b` with **b's own** round, `test_id` and `batch_id` (recomputed from the beacon output; never taken from the published `hits`). Then the primary formulas: `N_trials = 25 n`, `hits = Σ hits_k`, the rate, `S = Σ (hits_k - 5)` and `z = S / sqrt(N_trials * 0.2 * 0.8)`.

**Null distribution.** Each batch's targets are used exactly once and are independent uniform symbols, so each `hits_k` is Binomial(25, 0.2) whatever the guesses are, and `z` is N(0, 1) exactly. There is no threshold: "vanishes" means `z` is unremarkable next to the primary's own noise. It is one draw and has low power against a subtle fault.

**Blind to results.** Neither the operator nor a player can steer the pairing: the release content is fixed (anchored and time-stamped) before round `R` exists, `R` is at least 24 hours after the latest anchor time, and the order and the seed use no result. Anyone re-derives `R`, the seed and the pairing from the release alone; no manifest field is needed.

**Notices.** The control is secondary. When it cannot be computed, the analysis output carries a notice code, not an entry in the error or warning lists; a notice never makes a release invalid, never changes `ok`, and verification is unchanged (as with `secondary.no_participants`). Precedence, first that applies:
1. `permutation.too_few`: `n < 2` (a derangement needs two batches). No round is reported.
2. `permutation.pending`: round `R` is later than the analysis time (`round_time(R)` is after the `--as-of` time if given, else the verifier's clock). This is the normal state of a nightly run within a day of the newest anchor.
3. Withheld (next paragraph).
4. `permutation.round_unavailable`: round `R` should exist but no valid round can be obtained (not in the cache with a valid signature, and not fetched or not valid; always so offline when `R` is not cached). This does **not** invalidate the release: the control is secondary and `R` is not part of the release's commitments. If no anchor has a token time there is no `t_cut`, and the code is given without a round.

**Withheld.** Whenever the primary analysis is withheld (any error in §11), only `n_batches`, `N_trials` and the seed round `R` are reported; `hits`, rate, `S` and `z` are not (the notices 1 and 2 above still take precedence). A withheld control does not fetch round `R`.

**Canary.** No permutation control is run for the canary set.

**Output (reference verifier).** After the `secondary` lines: `permutation round=R n_batches=… N_trials=… hits=… rate=… S=… z=…`; or `permutation withheld round=R n_batches=… N_trials=…`; or `permutation unavailable code=permutation.<x> round=R` (`round=` is omitted when no round was computed: `permutation.too_few`, or no anchor has a token time). The analysis object carries the same values under `permutation`.

**Vectors.** `tests/data/permutation_v1/vectors.json`, generated by `tools/gen_permutation_vectors.py` (standard library only, independent of the verifier code): seeds and derangements from fixed randomness for `n = 2, 3, 5, 10, 1000` (for 1000, the first 10 entries and the SHA-256 of the permutation written as big-endian `u32` values), the first stream words, and a `uniform` draw that hits rejection.

### 9.12 The look (R5)
A *quarter boundary* is 00:00:00.000 UTC on 1 January, 1 April, 1 July or 1 October. Look `j` (`j = 1, 2, ...`) is the release whose cut `c_j` is the `j`-th quarter boundary strictly after `registration_ms` (a boundary equal to `registration_ms` is not a look). The look's release holds the longest prefix of the anchor chain whose `t_anchor` (the later token `gen_time_ms`, rounded up to the second, as in §7 and the head rule) is `<= c_j`, with its rows, rounds and the heads of the UTC days that ended at or before `c_j`, and it is judged with `as_of_ms = c_j`. Its `release_id` is `YYYY-Qn`, the quarter that ends at `c_j` (the instant `c_j - 1` lies in it); `cut(YYYY-Qn)` is the first instant of the next quarter. There are at most 20 looks; the final look is `j = 20`. A quarter with fewer than 200 counted batches has no release, and it is still look `j`.
- **Builder (§9.14).** It refuses a cut that is not `cut(release_id)`, and a look number outside 1 to 20.
- **Verifier (§11 step 3b).** When `release_id` matches `^[0-9]{4}-Q[1-4]$`, the verifier computes `c = cut(release_id)` and the look number `j` from the manifest's `registration_ms` (the number of quarter boundaries in `(registration_ms, c]`; it may be 0 or above 20, which is printed, not judged), prints `look j=<j> cut_ms=<c>`, and reports the **error** `look.after_cut`, once per anchor with its `anchor_seq`, for every anchor whose `t_anchor > c`. For any other `release_id` (the live export says `beta`) nothing is printed or checked. Here `t_anchor` is taken over the anchor's valid tokens; an anchor with no valid token time is not checked by this rule (§7; such an anchor already fails §11.1 step 4: `tsa.invalid` or `tsa.too_few`).

**Output (reference verifier).** The line `look j=… cut_ms=…` follows the `release_id` line, only for a `YYYY-Qn` release.

**Blind to results.** The cuts are calendar instants fixed by `registration_ms`, which is published before the first counted batch.

**What is not claimed.** The look check does not show that the release holds every anchor up to the cut; the daily heads (§10.1) do that up to `as_of`.

### 9.13 Bars, verdicts and display (R6, R7)
The rules of §9.13 and §9.14, and the builder bullet of §9.12, are rules of the maintainers' release builder and the results page, written here so that a reader can check a published result against them; the verifier itself applies no threshold. The verifier cannot show that a page applied them, only that the numbers it shows are right.

**Bars and verdicts (R6).** All are compared with the unrounded values:
- main: |z| >= 5.55 (the primary result of §9.6);
- Stouffer (a): |Z| >= 4.22; a crossing is a secondary finding, never the headline. Stouffer (b) has no bar and is reported for description only;
- canary: |z| >= 5.55 on the canary set of §9.9. If it is crossed, the look is **void**: the page shows no verdict at all (neither the main nor the Stouffer ones), shows the numbers and a void notice, and the look still counts as one of the 20. Every later look is void too, until a dated public amendment of the study names the fault and the time from which a new canary set starts. The release builder records the first void look and the amendment that ended the void as constants, and refuses to build a later look while an earlier void release is not recorded (`release.void_not_recorded`).

**How numbers are shown (R7, display only).** On the results page every z and Z is shown truncated toward zero at 2 decimals, computed from the decimal form of the value (in Python `Decimal(repr(z)).quantize(Decimal("0.01"), ROUND_DOWN)`; binary arithmetic such as `trunc(z * 100) / 100` is wrong, as it shows 0.29 as 0.28). A truncated value of zero is shown without a sign. Because every bar has 2 decimals, a shown value reaches a bar exactly when the unrounded one does. The null interval is shown rounded outward at 2 decimals (the low end down, the high end up), so the shown interval always contains the computed one. The verifier output, `result.json` and the released files keep the unrounded values; nothing reported is truncated.

### 9.14 The release builder's fixed checks (R8)
The builder always verifies with `--require-production` (§11.2) and `--registration-ms R`, where `R` is a constant in the builder equal to the integer published in section 4 of the registered study. It has no option, flag or parameter that turns either off. While `R` is not set (before registration) the builder refuses to build (`release.not_registered`). It also refuses a cut other than `cut(release_id)` (`release.cut_not_quarter`) and a look number outside 1 to 20 (`release.not_a_look`), each before anything is read or written. The verifier cannot show that the builder applied these; a reader runs the verifier with `--require-production --registration-ms R` themselves.

| Code | Kind | Where | Meaning |
|---|---|---|---|
| `release.not_registered` | builder refusal | builder | the registration constant is not set (§9.14) |
| `release.cut_not_quarter` | builder refusal | builder | the cut is not `cut(release_id)` (§9.12, §9.14) |
| `release.not_a_look` | builder refusal | builder | the look number is outside 1 to 20 (§9.12, §9.14) |
| `release.void_not_recorded` | builder refusal | builder | an earlier void release is not recorded (§9.13) |

### 9.15 Vectors of the study rules (R1 to R7)
`tests/data/study_rules_v1/vectors.json`, generated by `tools/gen_study_rules_vectors.py` (standard library only, independent of the verifier code). Cases: (R1, §9.2) a `card5` and a non-`card5` player row after registration, a non-`card5` row before registration (counted in `excluded_pre_registration` only) and a non-`card5` later copy (counted in `duplicate_later` only); (R2, §9.9) canary rows sealed at `registration_ms - 1` and at `registration_ms` exactly (in the set), a later copy and a same-anchor pair after registration; (R3, §9.10) participants with one batch, with two batches sharing `sealed_at_ms` (decided by `anchor_seq`), with two sharing `sealed_at_ms` and `anchor_seq` (decided by the `batch_id` bytes, including a pair whose order differs between byte order and a signed comparison), with batches in two quarters, and with more than 20 in a quarter (the first is kept either way), with `Z_first` and `Z` for each; (R4, §9.6) the interval at `N_trials` = 25, 5,000 and 250,000 (half-widths 15.68, 1.108743 and 0.1568 percentage points), with hits above, at and below 20%, and at `N_trials = 0` (`null`); (R5, §9.12) `registration_ms` 2027-02-01T00:00:00Z (1801440000000): look 1 is cut at 2027-04-01 (1806537600000, `2027-Q1`), look 20 at 2032-01-01 (1956528000000, `2031-Q4`), and 2032-04-01 is look 21; `registration_ms` 2027-04-01T00:00:00Z exactly (1806537600000): look 1 is 2027-07-01 (1814400000000) and look 20 is 2032-04-01 (1964390400000); an anchor with `t_anchor = c` (in) and `c + 1000` (out); (R7, §9.13) z shown: 5.55 as 5.55, 5.549999 as 5.54, -5.546 as -5.54, 0.29 as 0.29, 4.35 as 4.35, 4.2199 as 4.21, -0.004 as 0.00; interval shown outward: [-0.1234, 0.1901] as [-0.13, 0.20].

## 10. Published formats

### 10.1 Release directory
```
manifest.json
batches.jsonl
anchors.jsonl
rounds.jsonl          # cache of drand rounds: {"round", "signature"}; never authoritative (§9)
heads/YYYY-MM-DD.json # daily chain heads
heads/YYYY-MM-DD.ots  # optional OpenTimestamps proof of the head's anchor_hash (§11.4)
btc_headers.jsonl     # optional cache of Bitcoin block headers {"height", "header"}; never authoritative (§11.4)
```

`manifest.json`:
```json
{ "format": "precog-release/v1", "release_id": "2027-Q1", "registration_ms": 0,
  "beacon": { "network": "drand-quicknet", "chain_hash": "…", "genesis": 1692803367, "period": 3, "margin_rounds": 2 },
  "authorities": [ { "id": "tsa-a", "kind": "rfc3161", "name": "…", "issuing_ca_sha256": ["hex64", "…"], "root_sha256": "hex64" },
                   { "id": "tsa-test", "kind": "mock-hmac", "name": "…" } ],
  "with_participants": false }
```
`registration_ms` is a required field. The certificate pinning fields are defined in §10.2.

`batches.jsonl`, one JSON object per line:
```json
{ "batch_id": "hex32", "test_id": "card5", "guesses": "25 digits", "sealed_at_ms": 0,
  "source": "player", "anchor_seq": 1, "leaf_index": 0, "leaf": "hex64",
  "target_round": 0, "hits": 0, "participant": null }
```
`participant` is present only when `with_participants` is true. When `with_participants` is true, every row's `participant` is a JSON integer `p` with 0 <= p < 2^53, written without a fraction or exponent; floats (even `1.0`), booleans, strings, `null` and a missing key are `format.invalid`. When `with_participants` is false, `participant` is `null` or absent on every row; any other value is `format.invalid`. This is validation only; `participant` is in no hashed input. `leaf` and `hits` are published for convenience. The verifier recomputes both and fails if either differs.

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
If no NIST pulse could be recorded for a head, both `uri` and `output_value` are `null`; the object and its two keys are always present. A missing pulse is not an error. When the verifier is online, the pulse of a head is fetched from NIST and compared, with warnings only (§11.5, check 6d in §11.1). `nist_pulse` is not part of any hashed input and is not covered by a `.ots` proof.

The chain of daily heads starts on the UTC date of the first anchor: there is no head for any date before it, so every head has `anchor_seq` ≥ 1. A head with `anchor_seq` 0 in a release that holds any anchor is `head.mismatch`.

**Heads are required up to `as_of`.** The release has no cut time of its own (the manifest holds none, and a time taken from the release would move back with a truncation). The verifier therefore judges the release **as of** a time that it is given: `as_of_ms`, Unix milliseconds, from the command line `--as-of` (Unix milliseconds, or ISO-8601 UTC `YYYY-MM-DDTHH:MM:SS[.fff]Z`); the default is the verifier's own clock when it is run. `as_of_ms` is a verifier input, not a release field. The `as_of` used is printed (`as_of_ms <n>`). Let `D0` be the UTC date of the first anchor (lowest `anchor_seq`; its time is the later token `gen_time_ms` rounded up to the second, as in the head rule). A UTC date `D` with `D0 <= D` is **due** when `as_of_ms >= 00:00:00.000 UTC of D+1 + 1 hour`. The hour is a grace period, because the head of `D` is written by the Worker's cron at about 00:05 UTC on `D+1` (with backfill of missed days). Every due date must have a head file `heads/D.json`; otherwise there is one error `head.missing` naming the dates (the first 20 are listed). A date is due whether or not any anchor was made that day. A release with no anchors has no due date. Consequences: a tail deleted together with its heads is noticed up to `as_of`; a release verified long after it was downloaded fails for the days since, so an archive is judged with `--as-of <the time it was downloaded>`; the downloader and the nightly job use the time their download started. Verifying a receipt does not use heads or `as_of`. A head file that is present but invalid is `format.invalid`, and the date also counts as missing. The `.ots` proofs of the heads are judged by §11.4, not by this rule.

### 10.2 Receipt (held by the player)
```json
{ "format": "precog-receipt/v1", "batch_id": "…", "test_id": "card5", "guesses": "…",
  "sealed_at_ms": 0, "leaf": "hex64", "leaf_index": 0, "proof": ["hex64", "…"],
  "anchor": { …same shape as one anchors.jsonl line… }, "target_round": 0,
  "authorities": [ { "id": "tsa-a", "kind": "rfc3161", "name": "…", "issuing_ca_sha256": "hex64", "root_sha256": "hex64" } ] }
```
**Certificate pinning fields.** All hashes are lowercase hex SHA-256 of the DER encoding of a certificate. They are manifest and receipt metadata only and are not part of any hashed input.
- `issuing_ca_sha256` (manifest): a **non-empty, append-only array** of distinct hashes of issuing CA certificates, that is, the CAs that sign the authority's signer certificates. A token verifies if its chain, built from the certificates embedded in the token, reaches **any** member. Entries are never removed, so old tokens keep verifying. There are no validity windows in the manifest: chain validation uses the certificates' own validity at the token's `genTime`, not at verification time. It is neither the signer certificate (signers rotate) nor the root.
- `issuing_ca_sha256` (receipt): a single **string**, the hash of the issuing CA that actually signed that token.
- `root_sha256` (manifest and receipt): a single string, the hash of the pinned root certificate that every listed issuing CA must chain to. Checking that chain is done by the `rfc3161` plugin; this specification only defines the fields and their shape.
- `rfc3161` entries must carry both fields. `mock-hmac` entries carry neither (a mock has no certificate); a mock entry with any of them, or any entry with the field `cert_sha256` (not a valid field), is `format.invalid`. Other kinds are not checked for these fields.
- **Receipt against release:** the receipt's entry must equal the manifest entry in every field except `issuing_ca_sha256`, and the receipt's `issuing_ca_sha256` string must be a member of the manifest's array. Otherwise the check fails with `receipt.authority_mismatch`. A standalone receipt has no manifest, so the CA member check is made only against a release.
- Rotation: a new issuing CA is added to the manifest array and the old entries stay, so earlier tokens keep verifying.

`authorities` holds the manifest entry of each authority that issued a token on the anchor. A receipt checked on its own uses these entries to choose the token plugin and to bind each token to a certificate. It never guesses the kind from the token bytes. When a receipt is checked against a release, the entries must match the release manifest's entries (equality, with the issuing-CA membership rule above), or the check fails with `receipt.authority_mismatch`. A receipt check does not compare `source`.

### 10.3 Test vectors
`vectors/<name>.json`: `{ "spec": "v1", "description": "…", "cases": [ { "name": "…", "input": {…}, "output": {…} } ] }`. Bytes are written as hex. Further vectors are named in the sections they test (§9.7, §9.8, §9.11, §9.15). Some vector files carry a label (`spec`, `status`) from when they were written; it is not normative.

## 11. Verification procedure and codes

### 11.1 Steps and codes
A release is verified in this order. Each step stops at, or collects, errors with the codes shown. Codes are stable identifiers, not display text. A code marked (warning) never makes a release invalid; a code with a condition is as its row says; every other code in this table is an error (§9.3). All errors are collected; step numbers name checks, and the order of error lines is not specified.

| # | Check | Codes |
|---|---|---|
| 0 | Format and fields valid; `batch_id`s unique; `leaf_index` values per anchor are exactly 0..leaf_count-1 | `format.invalid`, `batch.duplicate_id` (warning, §9.5), `batch.leaf_index_gap` |
| 1 | Rebuild each leaf; it matches the published `leaf` | `leaf.mismatch` |
| 2 | Rebuild each Merkle root; it matches the anchor; the row count matches `leaf_count` | `merkle.root_mismatch`, `merkle.count_mismatch` |
| 3 | Recompute each `anchor_hash`; the chain links with no gaps from seq 1; every daily head matches the anchor at its seq; every due date has a head, given `as_of_ms` (§10.1) | `anchor.hash_mismatch`, `anchor.chain_broken`, `anchor.seq_gap`, `head.mismatch`, `head.missing` |
| 3b | The look (§9.12): for a release whose `release_id` is `YYYY-Qn`, no anchor's `t_anchor` is after the cut of that quarter (the first instant of the next quarter) | `look.after_cut` |
| 4 | At least two valid tokens from different authorities, each covering `anchor_hash`; `sealed_at_ms` ≤ the earliest token time of the anchor; anchors whose tokens share one root (§11.2); token times rise with `anchor_seq` (§6) | `tsa.invalid`, `tsa.wrong_imprint`, `tsa.too_few`, `leaf.sealed_after_anchor`; `tsa.same_root` (warning), `anchor.time_regressed` (warning) |
| 4b | Trust notices (§11.2): a mock authority or the mock beacon in the manifest; a warning, an error with `--require-production` | `manifest.mock_authority`, `manifest.mock_beacon` (warnings; errors with `--require-production`, §11.2) |
| 4c | Registration pin (§11.3): with `--registration-ms N`, `manifest.registration_ms` must equal `N` | `manifest.registration_mismatch` |
| 5 | `target_round` equals the computed round (§7) | `target.round_wrong` |
| 6 | Round valid, taken from the cache or fetched from the beacon (§9.4); recomputed hits equal the published `hits` | `round.unavailable`, `score.mismatch`; cache problems that a fetch fixes: `round.cache_missing` (warning), `round.cache_bad` (warning) |
| 6b | Canary rows (§9.7): `source == "canary"` rows carry the guesses derived from a whole-minute slot in the 10 minutes before `sealed_at_ms`, and `test_id` `card5`. Failing: error from `registration_ms` on, warning before | `canary.guesses_mismatch`, `canary.unverified` (warning) |
| 6c | OpenTimestamps proofs of the heads (§11.4): strict parse, Bitcoin headers by proof of work, merkle root, late and missing proofs. Only `ots.invalid` is an error | `ots.invalid`; `ots.pending`, `ots.unchecked`, `ots.late`, `ots.missing` (warnings) |
| 6d | NIST pulses of the heads (§11.5), online only: the pulse at the head's `uri` has the head's `output_value` and a time inside the head's window. Warnings only | `nist.mismatch`, `nist.out_of_window`, `nist.foreign_uri`, `nist.unchecked` (warnings) |
| 6e | Player rows (§9.8): no `player` row carries the canary guesses of a whole-minute slot in the 10 minutes before its `sealed_at_ms` (§9.7's window, `test_id` `card5`). Matching: error from `registration_ms` on, warning before | `canary.relabelled` (error; a warning before `registration_ms`) |
| 7 | Run the analysis (§9) and print it; if there were any errors, withhold `S` and `z` | `analysis.withheld`; `batch.other_test_id` (warning, §9.2) |

A **receipt** check runs steps 1, 2 (by proof), 3 (one anchor), 4 and 5 on the receipt alone; its own codes are in §11.6.

**Notices.** The analysis output may carry notice codes, which are not entries in the error or warning lists: `secondary.no_participants` (§9.10), `permutation.too_few`, `permutation.pending` and `permutation.round_unavailable` (§9.11). The release builder's refusals (`release.*`) are listed in §9.14.

### 11.2 Trust notices: mock authorities, mock beacon, shared root
**Why.** §12 lets a manifest name mock authorities (`kind: mock-hmac`) and the mock beacon (`network: mock-beacon`), whose keys and outputs are public, so anyone can build a release that passes every check in §11. §11.1 step 4 asks for two different authority `id`s, not two different operators. The verifier therefore says so in its output instead of leaving it to the reader's reading of `manifest.json`.

**Rules.**
- `manifest.mock_authority`: the manifest lists at least one authority with `kind == "mock-hmac"`. One notice per release; the detail lists the mock `id`s in sorted order.
- `manifest.mock_beacon`: `beacon.network == "mock-beacon"`. One notice per release; the detail names the network.
- Both are **warnings** by default. With the verifier option `--require-production` they are **errors** (the release is invalid, S and z are withheld, §9.3, and the exit status is 1) under the same codes; every other check and number is unchanged. Without the option they are warnings only.
- `tsa.same_root`: for each anchor whose tokens are all valid (§11.1 step 4), take the set of `root_sha256` values of the authorities that issued those tokens (a manifest entry without `root_sha256`, such as a mock, adds none). If the set has exactly one member, the anchor counts. A **warning**, once per release, when at least one anchor counts, with `count=N` (the number of such anchors) in the detail. An anchor with no `root_sha256` at all (only mocks) is not counted: the mock notice already covers it. It is never an error, also with `--require-production`: two authorities may legitimately share a root, and the reader judges whether that matters.

**What is not claimed.** None of this proves that a release is genuine. A manifest that names a real kind and real-looking pins is still the operator's statement (§10.1); the reader compares the manifest with the values the project publishes. A different `root_sha256` does not prove two different operators.

### 11.3 Registration pin: `--registration-ms`
**Why.** `registration_ms` is read from `manifest.json`, which the operator writes, and it decides which batches count (§9.2: `sealed_at_ms ≥ registration_ms`). Nothing in the release ties it to the date the pre-registration was published, so a later value would silently move batches into the excluded group. The reader can therefore say which value they expect, taken from the pre-registration itself.

**Rules.**
- `--registration-ms N`: `N` is an integer, Unix milliseconds, written as 1 to 15 ASCII digits (no sign, fraction, exponent, space or other numeral system). Anything else is a usage error (exit status 2) before any release is read. A library caller passes an integer `0 ≤ N < 10^15`; any other value (a boolean, a string, a float) is refused.
- When `N` is given and `manifest.registration_ms` is not equal to `N`, the verifier reports the **error** `manifest.registration_mismatch`, once per release, with the detail `manifest=<manifest value> expected=<N>`. The release is invalid, S and z are withheld (§9.3) and the exit status is 1. Every other check and count is unchanged (the manifest value is still the one used to count, so the printed counts show what the manifest claims).
- `manifest.registration_ms` is a required field (§10.1), so a manifest that has none fails as `format.invalid` whether or not the option is given; `manifest.registration_mismatch` is never reported for it.
- When `N` is given and equals the manifest value, nothing is added to `errors` or `warnings`.
- When the option is absent, no error and no warning is added for it. The reference command line prints one notice line after the `as_of_ms` line, `registration_ms <value> source=manifest` (or `source=option` when the option was given and matched), so a reader can see whether the value that decides the pre-registration cut came from the operator's manifest only. This line is part of the command line output, not of the result's `errors` or `warnings`, and it does not change the exit status.

**What is not claimed.** The option does not say where the reader should get the published value, or that the published value is itself the registered one: the reader compares it with the pre-registration itself. It does not cover any other manifest field.

### 11.4 OpenTimestamps proofs of the daily heads
**Why.** A head (§10.1) is the operator's statement that an anchor existed by a date. Its `anchor_hash` is submitted to OpenTimestamps calendars, which commit it into a Bitcoin block. A Bitcoin block header carries its own proof of work, so a reader can check the commitment without trusting the operator, the calendars or a block explorer.

**Rules.**
- **File.** `heads/D.ots` is optional. When present it must parse strictly: the OpenTimestamps magic, version 1, file hash op sha256, digest equal to the 32 bytes of the head's `anchor_hash`, a tree of the operations sha256, append and prepend only (each append/prepend argument at most 4096 bytes, depth at most 256), attestations of the kinds pending, bitcoin or unknown, and no trailing bytes. Anything else is the **error** `ots.invalid` for date D. A file larger than 128 KiB is `ots.invalid`. A `heads/D.ots` whose date has no valid head file is ignored.
- **Bitcoin attestation.** For each bitcoin attestation (height `h`), let `m` be the 32 bytes the path from the digest computes. The verifier needs the 80-byte block header for `h`. A header is **acceptable** when (1) its double-sha256 hash, read as a little-endian integer, is at most the target its own `bits` field encodes, and (2) that target is at most the pinned constant `OTS_MAX_TARGET` = compact `0x17087bc0` (a minimum amount of work per header, see below). The header's merkle root (bytes 36-67) must equal `m`.
- **Where headers come from.** First `btc_headers.jsonl` in the release (lines `{"height": h, "header": "<160 hex>"}`; written by the downloader; never authoritative: an entry that is not acceptable is ignored), then, unless `--offline`, a public source fetched by height (the reference verifier asks one fixed source and, if its header is not acceptable or does not match, a second one; both URLs are listed in the README). A source is only a way to get bytes; trust comes from rules (1) and (2).
- **Outcome per proof.** At least one bitcoin attestation with an acceptable header whose merkle root equals `m`: **confirmed**; its Bitcoin time is the header's `time` field. An acceptable header whose merkle root differs from `m`, from BOTH sources: **error** `ots.invalid` (the proof contradicts Bitcoin). No acceptable header could be obtained (offline, sources down, or one source only disagreed): **warning** `ots.unchecked`. Only pending or unknown attestations: **warning** `ots.pending` (calendars need hours; never an error).
- **Several attestations, contradiction, limits.** A proof with several bitcoin attestations is **confirmed** when any one confirms; otherwise `ots.invalid` when any one is contradicted, otherwise `ots.unchecked`. Attestations are examined by ascending height, stopping at the first confirmation (its block time decides `ots.late`), and at most 16 distinct heights of one proof are examined. "Contradicted" means: no acceptable header with the merkle root `m` was found, and acceptable headers with another root came from both source 1 and source 2 (the release cache never counts against a proof); a matching acceptable header from the cache or either source confirms.
- **Time.** A confirmed proof whose Bitcoin time is later than 00:00 UTC of D+1 plus 48 hours: **warning** `ots.late`. The head still stands; only the external upper bound is weaker. (A Bitcoin time can be up to about two hours off real time by Bitcoin's own rules; the 48 hours absorb this.)
- **Missing.** A head D with `as_of_ms` (§10.1) at least 00:00 UTC of D+4 and no `heads/D.ots`: **warning** `ots.missing`, once per release, listing the dates (first 20). A release without `.ots` files therefore gets no OpenTimestamps code other than `ots.missing`.
- Every warning is one entry per release with `count=N` and the first 20 dates in the detail (the reference verifier writes `count=N; <meaning>: date, date, ...`). `--require-production` (§11.2) does not turn any of them into errors.
- The reference command line prints one line `ots confirmed=<n> pending=<n> unchecked=<n> late=<n> missing=<n>`; a `late` proof is also counted in `confirmed`.
- A writer of `.ots` files that the verifier will read must stay inside these rules (the operator's Worker refuses sha1, ripemd160 and keccak256 steps and more than 256 steps on a path, and checks its served files with the same shared test cases).

**What is not claimed.** The height in an attestation is not checked against the chain; a header is accepted for its own work, not for its place in the chain. Rule (2) means forging an acceptable header costs at least the work of one real block at the pinned difficulty. A confirmed proof shows that the head's hash existed by the header's time; it does not show that the head is complete or honest (§11.1 does that). NIST pulses are not covered by this check (§11.5 is a separate, online check of them).

### 11.5 NIST pulses of the daily heads (online only)
**Why.** A head (§10.1) records `nist_pulse: {uri, output_value}`. A NIST beacon pulse cannot be known before its time, so a head that carries the true pulse of the day's boundary was written no earlier than that pulse; this is a lower bound on when the head was made, next to the upper bound that an `.ots` proof gives (§11.4).

**Rules.**
- **When.** Only if the verifier is not offline, and not for a release whose manifest names the mock beacon (§12). Offline (`--offline`) nothing is fetched, no `nist.*` code is reported and no `nist` line is printed. Nothing is fetched for a head whose `nist_pulse` is `{null, null}`; such a head is counted as `absent` and is not a warning (§10.1).
- **Allowlist.** The `uri` is fetched only if it matches `^https://beacon\.nist\.gov/beacon/2\.0/chain/[0-9]{1,9}/pulse/[0-9]{1,15}$`. Any other value (another host, scheme or path, or a `uri` that is not a string while `output_value` is set) is **warning** `nist.foreign_uri` and nothing is requested.
- **Request.** One `GET` of the `uri` per head: no credentials, redirects not followed, at most 64 KiB of body, 10 seconds. The body must be JSON with an object `pulse` whose `uri` equals the requested one, whose `outputValue` is 128 hex digits and whose `timeStamp` is an ISO-8601 UTC time. Any failure (network, status other than 200, a body of the wrong shape) leaves the head **unchecked**.
- **Compare.** `output_value` (a string) equals `outputValue` when compared as lowercase hex, otherwise (including an `output_value` that is not a string) **warning** `nist.mismatch`. Let `B` be 00:00:00.000 UTC of D+1 for the head of date D. The pulse `timeStamp` must lie in [`B` - 60 s, `B` + 5 minutes], the window in which the operator's Worker accepts a pulse for the head (the endpoint answers with the first pulse at or after the time asked for); otherwise **warning** `nist.out_of_window`. A head that is both is reported as `nist.mismatch` only. All good: **matched**.
- **Limits.** At most 400 requests per run, newest heads first, at most 5 requests a second, 300 seconds of network time in all, and no further request after 3 failed requests in a row (a status 404 is an answer, not a failure). Heads not reached are **unchecked**. Nothing is kept between runs.
- **Warnings.** `nist.unchecked` (the pulse could not be fetched or read, or the limits were reached): one entry per release with `count=N` and the first 20 dates in the detail, written `count=N; <meaning>: date, date, ...`, like §11.4. The same for the other three codes. `--require-production` (§11.2) does not turn any of them into an error. No error comes from this check.
- The reference command line prints one line, after the `ots` line and only when the check ran: `nist matched=<n> absent=<n> unchecked=<n> mismatch=<n> out_of_window=<n> foreign_uri=<n>`; each head is counted once.

**Why a warning and not an error.** The pulse is in no hashed input (the head's hash chain and the `.ots` proof cover `anchor_hash` only), so it cannot change what the verifier proves about the anchors, the targets or the score. NIST labels its beacon "Version 2.0 (Beta)" and gives no availability or retention promise, and a pulse can be unreachable for reasons the operator does not control; an error would let that fail every release and the nightly job. A mismatch is still loud: it is the only outcome where the operator's record and NIST disagree.

**What is not claimed.** A matching pulse shows that the head was written no earlier than the pulse; it does not show when it was written at most (that is the `.ots` proof), and it does not show that the head is complete or honest. The host is trusted as NIST's published endpoint (TLS to that name); the verifier does not check NIST's signature on the pulse. An unreachable NIST proves nothing either way.

### 11.6 Receipts
A receipt (§10.2) is checked by steps 1, 2 (by inclusion proof), 3 (one anchor), 4 and 5 of §11.1 on the receipt alone, using the receipt's `authorities` entries. Against a release, it also confirms that the anchor line and the batch row appear in the release unchanged (`receipt.not_in_release`, `receipt.row_changed`) and that the authority entries match the manifest (`receipt.authority_mismatch`, §10.2). Against a release, a receipt for a copy that is not the counted copy of a duplicated `batch_id` (§9.5) gives `receipt.not_counted`.

## 12. Mock authorities (testing only)
- **MockTSA** (`kind: mock-hmac`). Its token is the base64 of the JSON `{"tsa_id", "anchor_hash", "gen_time_ms", "mac"}`, where `mac = HMAC-SHA256(key, tsa_id || anchor_hash || u64(gen_time_ms))`. The test keys are published in the vectors. A mock token proves nothing and exists only to exercise the verifier.
- **MockBeacon**: `signature(r) = sha256("precog/mock-beacon/v1" || u64(r))`, with the same `round_time` constants as quicknet.

A manifest that names either gets the trust notices of §11.2.
