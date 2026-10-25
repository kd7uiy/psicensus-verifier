# Pre-Registration: Precognition Study (5-Symbol Card Test)

Status: **registered** on 25 October 2026 (OSF project: https://osf.io/sqc5n/). It may only be amended by a dated, public amendment that does not apply to data already collected.

## 1. Question
Can people predict a card that is chosen by public randomness *after* they guess, better than chance?

## 2. Hypotheses
- **H0:** the pooled hit rate equals 20% (5 symbols).
- **H1 (two-sided):** the pooled hit rate differs from 20%. Doing worse than chance would also be a finding.

## 3. Design
- **Unit:** one sealed batch of exactly 25 guesses. Targets come from the first drand round after the batch's independent timestamp (see the public verifier repository, https://github.com/kd7uiy/psicensus-verifier, and its `SPEC.md`).
- Players may play any number of batches, on any days. Practice mode is separate and never counted.
- Players see their result only after the whole batch is sealed.
- A batch's seal time is when the server received it, which may be later than when it was played (for example, if the player went offline and the batch was sent when they came back). The guesses are fixed on the device before they are sent, so the delay cannot depend on the targets.
- The page encourages focused guessing (a rotating prompt and a gentle slow-down nudge when guesses come very fast). Guess timing is neither recorded nor sent, and it never affects whether a batch counts.

## 4. What counts
- **Every** batch of this test that is sealed and anchored counts, from the registration time onward. "This test" means `test_id = card5` (25 guesses, 5 symbols).
- **Registration time.** `registration_ms = 1792972800000` (Unix milliseconds), which is `2026-10-26T00:00:00Z`: 00:00 UTC on the day after this document was uploaded to OSF. A batch counts if its `sealed_at_ms` is at or after this value. Every release states the same value, and anyone can check that it does with the verifier option `--registration-ms 1792972800000`.
- **Excluded by rule, and only these.** Each is fixed before the batch's targets exist, so none can depend on results:
  - canary-bot batches (`source = canary`), which are analyzed separately as a control (section 7 item 4). The canary set is the canary batches sealed at or after the registration time, first copy only, by the same duplicate rule as below. A canary batch is recognized by its guesses, which are computed from its scheduled time before its targets exist: a batch whose guesses are the canary's for its time is a canary batch whatever its label, and if one is published as a player batch the release fails verification.
  - batches sealed before the registration time (beta testing);
  - batches of another test (`test_id` other than `card5`). The site refuses to seal any other test, and a verifier spec amendment is required before it may; if one appears anyway, it is excluded and reported with its count;
  - repeated copies of a batch ID. The copy committed first is the batch, and later copies are never counted. If several copies were committed together, before their targets existed, all of them are excluded. Duplicates are reported with their count.
- **No exclusion for failed verification.** If any part of a data release fails verification, the whole release is invalid. No result is reported from it, the fault is explained publicly, and a corrected release is issued. Batches are never quietly dropped.
- **Beacon rounds come from the public drand network**, not from our copy of them. If a round cannot be obtained and verified, the check is incomplete and no result is reported until it can be.
- No exclusions based on player behavior, speed, device or results.

## 5. Primary analysis
- Statistic: `S = sum over batches of (hits - 0.2 * 25)`; `z = S / sqrt(N_trials * 0.2 * 0.8)`.
- This is valid however many batches people choose to play, including choices made after seeing earlier results (checked by simulation).

## 6. Looks and stopping
The data is released publicly, so anyone can compute the running z. Rather than pretend there is a single look, every look is planned and corrected for:
- **Looks:** a look is the data release cut at 00:00:00.000 UTC on the first day of a calendar quarter (1 January, 1 April, 1 July, 1 October). It holds every batch whose anchor time is at or before the cut (the anchor time is the later of the anchor's two independent timestamps, rounded up to the second), from the registration time on, so each look includes all earlier ones. Look 1 is the first quarter boundary after the registration time; there are at most **20 looks (5 years)**. A quarter with fewer than 200 counted batches has no release, and it still uses up one of the 20 looks. The release builder refuses any other cut.
- **Threshold per look:** two-sided p < 5.7e-7 / 20 = 2.9e-8, which is |z| ≥ **5.55** (Bonferroni across looks on a 5-sigma overall threshold).
- **Stop for evidence:** if any look crosses 5.55, the study reports a positive result, keeps collecting, and invites replication.
- **Final look:** the 20th quarter boundary after the registration time (5 years). There is no cap on the number of trials: the study runs the full 5 years however much data comes in.
- **Null result:** at every look we report the two-sided 95% interval for the pooled hit rate minus 20%, in percentage points: `(hits / N_trials - 0.2) * 100 ± 1.96 * sqrt(0.16 / N_trials) * 100`. It is not adjusted for the number of looks, and it is shown rounded outward to 2 decimals, so the shown interval always contains the computed one. The final look's interval is the headline null result: "if there is an effect, the hit rate differs from 20% by no more than X percentage points (95% confidence)", where X is the end of the interval farthest from 0. For example, at 10,000 counted batches (250,000 guesses) the interval reaches about 0.16 percentage points either side of the observed difference.
- **How z is shown:** z is shown cut to 2 decimals, toward zero (5.549 is shown as 5.54, and -5.549 as -5.54). Every bar is applied to the full, unrounded z. Because the bars have 2 decimals, a shown z reaches a bar exactly when the full z does, so the shown number and the verdict always agree. The released data files keep the full value.

## 7. Secondary analyses (reported, but not the headline)
1. **Per-participant capping:** each participant's contribution capped at **500 trials (20 batches) per quarter**, so a few heavy players cannot dominate. The batches kept are the participant's earliest-sealed in that quarter, so which batches count never depends on results. A participant is a device (section 9).
2. **Per-participant z, combined across participants (Stouffer),** to ask whether a typical player beats chance. A participant is a device (section 9). Two variants are reported:
   - **(a) First batch (confirmatory).** Each participant's first counted batch only: the earliest by seal time, then anchor number, then batch ID. `z_i = (hits - 5) / 2` and `Z_first = (sum of z_i) / sqrt(k)`, with `k` the number of participants. This is the main formula of section 5 applied to these batches. **Bar:** |Z_first| >= 4.22 at a look, applied to the unrounded value. Over all 20 looks this keeps the chance of any crossing by luck alone at about 0.0005 (two-sided p < 2.5e-5 per look). A crossing is reported as a secondary finding, never as the headline.
   - **(b) Capped batches (description only).** Each participant's batches kept after the cap in item 1 (at most 500 trials per participant per quarter): `z_i = S_i / sqrt(25 * n_i * 0.2 * 0.8)` over that participant's `n_i` kept batches, and `Z_capped = (sum of z_i) / sqrt(k)`, unweighted. It has no bar and is never reported as a finding.

   **In plain words:** (a) uses one batch per player, picked by time before any result is known, so it cannot be pushed by players who decide to keep going after a lucky or unlucky start; it uses less data. (b) uses more of each player's batches, but if players tend to keep playing after a good (or bad) result, it can drift away from 0 even when nothing but luck is at work, so it is shown only to describe the data.
3. **Permutation control**: guesses scored against mismatched targets. A real effect must vanish here. In plain words: take the same batches the main result counts, put them in a fixed order (anchor number, then batch ID), and shuffle them with one published random shuffle in which no batch stays in its own place. Each batch's guesses are then scored against the targets of the batch the shuffle assigns it (that batch's own beacon round and ID), and the same `z` formula is applied. The shuffle is seeded by the public randomness of the first drand round at least 24 hours after the latest anchor time in the release, so nobody, the operator included, can choose a favourable pairing; anyone can re-derive it. Exact rule: `seed = sha256("precog/permutation/v1" || randomness(R) || u64(n))`, `n` the number of counted batches, `R` that round; random integers come from `sha256(seed || u64(j))` blocks (four 64-bit words each) by rejection sampling; Sattolo's algorithm (`for i = n-1 down to 1: swap a[i] with a[uniform(i)]`) gives a single cycle `a`, and batch `k` is scored against batch `a[k]`. Under chance this `z` is standard normal. It is one number with no threshold, reported as a check: if it is far from 0 while the main result is not, the pipeline has a fault. It cannot be computed until that round exists (the report says "pending" until then) and is not run for the canary set.
4. **Canary data:** the canary set (section 4: canary batches sealed at or after the registration time, first copy only, all looks so far together) is scored with the formula of section 5. A fixed public rule cannot beat chance, so it must show no effect. **Bar:** |z| >= 5.55 at a look, applied to the unrounded z. If it is crossed, the pipeline has a fault: that look is void and shows no verdict (neither the main one nor the secondary ones). Its numbers are still published, the fault is looked for and explained publicly, and the void look still counts as one of the 20. Every later look is void too, until a dated public amendment of this document names the fault and the time from which a new canary set starts.

## 8. Exploratory analyses
Anything else (time of day, streak length, first batch of the day versus later ones, device type) is labeled exploratory, corrected for multiple comparisons, and never reported as a finding on its own.

## 9. Data and code
- Released quarterly once thresholds are met: rows without participant numbers at 200 batches; with participant numbers at 1,000 batches from 100 distinct participants.
- **A participant is a device.** There is no sign-in, so each device (one browser on one computer or phone) has its own random participant number, and one person on two devices, or after clearing the browser's data or using "Delete my data", counts as two participants. "Distinct participants" therefore overstates the number of people. Participant numbers are random labels; they are never derived from the device, and a device keeps its number in every release.
- If sign-in is ever added, that is a dated public amendment of this document made before it goes live. Under it, a device that signs in would take the account's participant number for its earlier batches too, so published participant numbers could only merge between releases, never split, and the per-participant analyses would use the latest release.
- **The analysis** is the verifier specification v1 (`SPEC.md` at the public verifier's tag `v1.0.0`, commit `af8def40d93e804fadca746862bdc144f52b8c44`), as carried out by the public reference verifier at that tag. Running it on a release reproduces every reported number. A later amendment of the verifier applies to this study only through a dated, public amendment of this document, and never to data already collected.
- **Every release is built and checked** with `--require-production` (no test timestamp authority or test beacon is accepted) and `--registration-ms 1792972800000`. The release builder has no way to turn either off. Anyone can run the same check: `python -m precog_verifier verify-release <release folder> --require-production --registration-ms 1792972800000 --as-of <cut in Unix ms>`.

## 10. Plain-language summary
> We decided how to judge this before anyone played. Every locked-in round counts, good or bad. We check four times a year, and because checking often makes lucky streaks look real, the bar is set very high: a result this strong would happen by chance about once in 35 million tries. If nothing shows up, we'll say how small any effect would have to be.
