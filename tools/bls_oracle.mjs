// DEV-TIME ONLY. Independent oracle for the BLS12-381 test vectors (never used at runtime, never by tests).
// Uses @noble/curves (the same library the browser app uses) plus a few lines of BigInt field math.
//
//   node verifier/tools/bls_oracle.mjs generate <keys-dir>   -> JSON {points, pairing, synth} on stdout
//   node verifier/tools/bls_oracle.mjs check-live            -> reads {public_key, rounds:[{round,signature}]} on stdin,
//                                                               prints {ok:[bool...]} using noble
//
// <keys-dir> must be OUTSIDE the repository: the throwaway secret keys live there (raw hex, never checked in);
// a rerun with the same keys-dir reproduces every output byte for byte (BLS signatures are deterministic).
import { bls12_381 as b } from "@noble/curves/bls12-381.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const G1 = b.G1.Point;
const G2 = b.G2.Point;
const { Fp, Fp2 } = b.fields;
const sigs = b.shortSignatures;
const P = Fp.ORDER;
const R = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n;
const DST = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
const OTHER_DST = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";
const QUICKNET_PK =
  "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a";

const hex = (u) => Buffer.from(u).toString("hex");
const unhex = (s) => new Uint8Array(Buffer.from(s, "hex"));
const be = (n, len) => unhex(n.toString(16).padStart(len * 2, "0"));
const u64 = (n) => be(BigInt(n), 8);
const u64le = (n) => u64(n).reverse();
const cat = (...a) => Uint8Array.from(a.flatMap((x) => [...x]));
const withFlags = (bytes, set, clear = 0) => {
  const o = Uint8Array.from(bytes);
  o[0] = (o[0] & ~clear & 0xff) | set;
  return o;
};
const flip = (bytes, byteIdx, mask) => {
  const o = Uint8Array.from(bytes);
  o[byteIdx] ^= mask;
  return o;
};

function keyFile(dir, name) {
  const f = path.join(dir, name);
  if (!fs.existsSync(f)) fs.writeFileSync(f, randomBytes(32).toString("hex") + "\n");
  return unhex(fs.readFileSync(f, "utf8").trim());
}

// ----------------------------------------------------------------- point helpers
const isQR = (a) => Fp.pow(a, (P - 1n) / 2n) === 1n;
const g1Rhs = (x) => Fp.add(Fp.mul(Fp.mul(x, x), x), 4n);
const g2Rhs = (x) => Fp2.add(Fp2.mul(Fp2.mul(x, x), x), { c0: 4n, c1: 4n });
const g1Bytes = (x, sortFlag) => {
  const o = be(x, 48);
  o[0] |= 0x80 | (sortFlag ? 0x20 : 0);
  return o;
};

function g1OnCurveNotInSubgroup(startX) {
  for (let x = BigInt(startX); ; x++) {
    const rhs = g1Rhs(x);
    if (!isQR(rhs)) continue;
    const y = Fp.sqrt(rhs);
    const pt = G1.fromAffine({ x, y });
    if (!pt.isTorsionFree()) return { x, y, pt };
  }
}
function g1NotOnCurve(startX) {
  for (let x = BigInt(startX); ; x++) if (!isQR(g1Rhs(x))) return x;
}
function g2OnCurveNotInSubgroup(startI) {
  for (let i = BigInt(startI); ; i++) {
    const x = { c0: i, c1: 1n };
    let y;
    try {
      y = Fp2.sqrt(g2Rhs(x));
    } catch {
      continue;
    }
    const t = Fp2.sub(Fp2.mul(y, y), g2Rhs(x));
    if (!Fp2.is0(t)) continue;
    const pt = G2.fromAffine({ x, y });
    if (!pt.isTorsionFree()) return { x, y, pt };
  }
}
function g2NotOnCurve(startI) {
  for (let i = BigInt(startI); ; i++) {
    const x = { c0: i, c1: 2n };
    let ok = true;
    try {
      const y = Fp2.sqrt(g2Rhs(x));
      ok = Fp2.is0(Fp2.sub(Fp2.mul(y, y), g2Rhs(x)));
    } catch {
      ok = false;
    }
    if (!ok) return x;
  }
}
const g2Bytes = (x, sortFlag) => {
  const o = cat(be(x.c1, 48), be(x.c0, 48));
  o[0] |= 0x80 | (sortFlag ? 0x20 : 0);
  return o;
};

const expectNobleRejectsG1 = (bytes) => {
  try {
    G1.fromBytes(bytes);
  } catch {
    return;
  }
  throw new Error("noble accepted a G1 encoding that must be invalid: " + hex(bytes));
};
const expectNobleRejectsG2 = (bytes) => {
  try {
    G2.fromBytes(bytes);
  } catch {
    return;
  }
  throw new Error("noble accepted a G2 encoding that must be invalid: " + hex(bytes));
};

function seedScalar(label) {
  let k = BigInt("0x" + hex(sha256(new TextEncoder().encode("psi-census/bls-vector/" + label)))) % (R - 1n);
  return k + 1n;
}

function buildPoints() {
  const g1 = G1.BASE;
  const g2 = G2.BASE;
  const gen1 = g1.toBytes();
  const gen2 = g2.toBytes();
  const inf1 = G1.ZERO.toBytes();
  const inf2 = G2.ZERO.toBytes();
  const v1 = (name, bytes) => ({ name, hex: hex(bytes) });
  const i1 = (name, bytes, reason) => ({ name, hex: hex(bytes), reason });

  const offG1 = g1OnCurveNotInSubgroup(1);
  const offG1Bytes = g1Bytes(offG1.x, offG1.y > (P - 1n) / 2n);
  const offG2 = g2OnCurveNotInSubgroup(1);
  const offG2Bytes = g2Bytes(offG2.x, offG2.y.c1 !== 0n ? offG2.y.c1 > (P - 1n) / 2n : offG2.y.c0 > (P - 1n) / 2n);
  const p1 = be(P, 48);
  const p2 = be(P, 48);

  const g1Valid = [
    v1("g1_generator", gen1),
    v1("g1_infinity", inf1),
    v1("g1_generator_neg", g1.negate().toBytes()),
    v1("g1_2g", g1.double().toBytes()),
    v1("g1_3g", g1.multiply(3n).toBytes()),
    v1("g1_r_minus_1_g", g1.multiply(R - 1n).toBytes()),
    v1("g1_derived_a", g1.multiply(seedScalar("g1/a")).toBytes()),
    v1("g1_derived_b", g1.multiply(seedScalar("g1/b")).toBytes()),
  ];
  const g1Invalid = [
    i1("g1_len_47", gen1.slice(0, 47), "length"),
    i1("g1_len_49", cat(gen1, [0]), "length"),
    i1("g1_len_0", new Uint8Array(0), "length"),
    i1("g1_not_compressed", withFlags(gen1, 0, 0x80), "flags"),
    i1("g1_x_equals_p", cat(withFlags(p1, 0x80)), "x_range"),
    i1("g1_x_above_p", withFlags(be(P + 1n, 48), 0x80), "x_range"),
    i1("g1_x_all_ones", withFlags(new Uint8Array(48).fill(0xff), 0x80, 0xe0), "x_range"),
    i1("g1_infinity_stray_bits", cat(inf1.slice(0, 47), [1]), "infinity_encoding"),
    i1("g1_infinity_sort_flag", withFlags(inf1, 0x20), "infinity_encoding"),
    i1("g1_infinity_wrong_length", inf1.slice(0, 47), "length"),
    i1("g1_infinity_not_compressed", withFlags(inf1, 0x40, 0x80), "flags"),
    i1("g1_not_on_curve", g1Bytes(g1NotOnCurve(1), false), "not_on_curve"),
    i1("g1_off_subgroup", offG1Bytes, "not_in_subgroup"),
    i1("g1_off_subgroup_sign_flipped", flip(offG1Bytes, 0, 0x20), "not_in_subgroup"),
  ];
  for (const c of g1Invalid) if (c.reason !== "flags") expectNobleRejectsG1(unhex(c.hex));

  const g2Valid = [
    v1("g2_generator", gen2),
    v1("g2_infinity", inf2),
    v1("g2_generator_neg", g2.negate().toBytes()),
    v1("g2_2g", g2.double().toBytes()),
    v1("g2_3g", g2.multiply(3n).toBytes()),
    v1("g2_r_minus_1_g", g2.multiply(R - 1n).toBytes()),
    v1("g2_derived_a", g2.multiply(seedScalar("g2/a")).toBytes()),
    v1("g2_derived_b", g2.multiply(seedScalar("g2/b")).toBytes()),
  ];
  const g2NotOn = g2NotOnCurve(1);
  const g2Invalid = [
    i1("g2_len_95", gen2.slice(0, 95), "length"),
    i1("g2_len_97", cat(gen2, [0]), "length"),
    i1("g2_len_0", new Uint8Array(0), "length"),
    i1("g2_not_compressed", withFlags(gen2, 0, 0x80), "flags"),
    i1("g2_x1_equals_p", withFlags(cat(p1, gen2.slice(48)), 0x80), "x_range"),
    i1("g2_x0_above_p", cat(withFlags(gen2.slice(0, 48), 0), be(P + 1n, 48)), "x_range"),
    i1("g2_infinity_stray_bits", cat(inf2.slice(0, 95), [1]), "infinity_encoding"),
    i1("g2_infinity_sort_flag", withFlags(inf2, 0x20), "infinity_encoding"),
    i1("g2_infinity_wrong_length", inf2.slice(0, 95), "length"),
    i1("g2_not_on_curve", g2Bytes(g2NotOn, false), "not_on_curve"),
    i1("g2_off_subgroup", offG2Bytes, "not_in_subgroup"),
    i1("g2_off_subgroup_sign_flipped", flip(offG2Bytes, 0, 0x20), "not_in_subgroup"),
  ];
  for (const c of g2Invalid) if (c.reason !== "flags") expectNobleRejectsG2(unhex(c.hex));
  void p2;

  const ks = [1n, 2n, 3n, 5n, 7n, 0x10001n, R - 2n, R - 1n, R, seedScalar("mul/a"), seedScalar("mul/b"), seedScalar("mul/c")];
  const mul = (Pt, k) => (k % R === 0n ? Pt.ZERO.toBytes() : Pt.BASE.multiply(k).toBytes());
  return {
    source: "generated by verifier/tools/gen_bls_vectors.py with @noble/curves as the oracle (every invalid encoding is also rejected by noble)",
    g1: { valid: g1Valid, invalid: g1Invalid },
    g2: { valid: g2Valid, invalid: g2Invalid },
    g1_mul: ks.map((k) => ({ k: k.toString(16), point: hex(mul(G1, k)) })),
    g2_mul: ks.map((k) => ({ k: k.toString(16), point: hex(mul(G2, k)) })),
    _offG1: offG1Bytes,
    _offG2: offG2Bytes,
  };
}

// ----------------------------------------------------------------- pairing
const fp12Flat = (f) => {
  const out = [];
  for (const h of [f.c0, f.c1]) for (const c of [h.c0, h.c1, h.c2]) out.push(c.c0, c.c1);
  return out.map((n) => n.toString(16).padStart(96, "0"));
};
function buildPairing() {
  const pairs = [
    [1n, 1n],
    [2n, 3n],
    [seedScalar("pair/a"), seedScalar("pair/b")],
    [R - 1n, 5n],
  ];
  const cases = pairs.map(([a, c]) => {
    const p1 = G1.BASE.multiply(a);
    const q2 = G2.BASE.multiply(c);
    return { g1: hex(p1.toBytes()), g2: hex(q2.toBytes()), gt: fp12Flat(b.pairing(p1, q2)) };
  });
  return {
    source:
      "gt = e(g1, g2) as computed by @noble/curves, which is the textbook pairing f^((p^12-1)/r) raised to the power 3 (its final exponentiation uses the Hayashida-Hayasaka-Teruya chain; gcd(3, r) = 1 so both are valid pairings), as [c0.c0.c0, c0.c0.c1, c0.c1.c0, c0.c1.c1, c0.c2.c0, c0.c2.c1, c1.c0.c0, ..., c1.c2.c1] with Fp2 = Fp[u]/(u^2+1), Fp6 = Fp2[v]/(v^3-(u+1)), Fp12 = Fp6[w]/(w^2-v); each coefficient is 96 hex digits. Oracle: @noble/curves pairing()",
    cases,
  };
}

// ----------------------------------------------------------------- signatures
const msgOf = (round) => sha256(u64(round));
function sign(sk, round, dst = DST, msg = msgOf(round)) {
  return sigs.sign(sigs.hash(msg, dst), sk).toBytes();
}
function nobleVerify(sigBytes, round, pkBytes) {
  try {
    return sigs.verify(sigBytes, sigs.hash(msgOf(round), DST), pkBytes) ? "noble-verify-true" : "noble-verify-false";
  } catch {
    return "noble-rejects-input";
  }
}

function buildSynth(dir, offG1, offG2) {
  const sk = keyFile(dir, "bls_dev_sk.hex");
  const sk2 = keyFile(dir, "bls_dev_sk2.hex");
  const pk = sigs.getPublicKey(sk).toBytes();
  const pk2 = sigs.getPublicKey(sk2).toBytes();
  if (hex(pk) === QUICKNET_PK) throw new Error("test key equals the quicknet key");
  const cases = [];
  const add = (name, round, sigBytes, why, pkBytes) => {
    const oracle = nobleVerify(sigBytes, round, pkBytes ?? pk);
    const c = { name, round, signature: hex(sigBytes), expect: oracle === "noble-verify-true", oracle };
    if (why) c.why = why;
    if (pkBytes) c.public_key = hex(pkBytes);
    cases.push(c);
    const expectOk = name.startsWith("ok_");
    if (c.expect !== expectOk) throw new Error(`oracle disagrees with the intended outcome of ${name}: ${oracle}`);
  };
  const good = (r) => sign(sk, r);
  add("ok_round_1", 1, good(1));
  add("ok_round_2", 2, good(2));
  add("ok_round_big", 32_000_000, good(32_000_000));
  add("ok_round_2_32", 2 ** 32, good(2 ** 32), "round needs more than 32 bits");
  add("ok_round_2_63", 2 ** 53, good(2 ** 53), "round above 2^53 is still an exact u64");
  const s100 = good(100);
  add("bad_sig_bit_first", 100, flip(s100, 0, 0x01), "bit 0 of the first byte");
  add("bad_sig_bit_last", 100, flip(s100, 47, 0x01), "bit 0 of the last byte");
  add("bad_sig_bit_middle", 100, flip(s100, 24, 0x10), "a bit in the middle");
  add("bad_pk_bit", 100, s100, "one bit of the public key flipped", flip(pk, 50, 0x04));
  add("bad_pk_infinity", 100, G1.ZERO.toBytes(), "infinity public key with infinity signature (trivially satisfies the pairing equation)", G2.ZERO.toBytes());
  add("bad_pk_off_subgroup", 100, s100, "public key on the curve but not in G2", offG2);
  add("bad_pk_other_key", 100, s100, "valid signature, different valid public key", pk2);
  add("bad_wrong_round", 9, good(7), "signature of round 7 presented for round 9");
  add("bad_round_plus_one", 101, s100, "signature of round 100 presented for round 101");
  add("bad_other_dst", 100, sign(sk, 100, OTHER_DST), "signed with the POP ciphersuite tag");
  add("bad_message_not_hashed", 100, sign(sk, 100, DST, u64(100)), "signed u64be(round) without the sha256");
  add("bad_round_le_encoding", 100, sign(sk, 100, DST, sha256(u64le(100))), "round encoded little-endian");
  add("bad_sig_off_subgroup", 100, offG1, "on the curve, not in G1");
  add("bad_sig_off_curve", 100, g1Bytes(g1NotOnCurve(5), false), "x has no y on the curve");
  add("bad_sig_infinity", 100, G1.ZERO.toBytes(), "point at infinity");
  add("bad_sig_x_ge_p", 100, withFlags(be(P + 7n, 48), 0x80), "x = p + 7");
  add("bad_sig_wrong_flags", 100, withFlags(s100, 0, 0x80), "compression flag cleared");
  add("bad_sig_len_47", 100, s100.slice(0, 47), "47 bytes");
  add("bad_sig_len_49", 100, cat(s100, [0]), "49 bytes");
  add("bad_sig_negated", 100, flip(s100, 0, 0x20), "sort flag flipped = -sig");
  add("bad_sig_is_g1_generator", 100, G1.BASE.toBytes(), "the generator in place of a signature");
  add("bad_sig_other_key", 100, sign(sk2, 100), "valid signature by a different key");

  const goodItems = [];
  for (let i = 0; i < 12; i++) {
    const r = 1000 + 37 * i;
    goodItems.push({ round: r, signature: hex(good(r)) });
  }
  const verifyItem = (it) => sigs.verify(unhex(it.signature), sigs.hash(msgOf(it.round), DST), pk);
  const badSets = [];
  const addBad = (name, items) => {
    const bad = [];
    items.forEach((it, i) => {
      let ok = false;
      try {
        ok = verifyItem(it);
      } catch {}
      if (!ok) bad.push(i);
    });
    if (bad.length === 0) throw new Error("batch case with no bad item: " + name);
    badSets.push({ name, items, bad_indexes: bad });
  };
  const clone = () => goodItems.map((x) => ({ ...x }));
  let it = clone();
  it[5].signature = hex(flip(unhex(it[5].signature), 20, 0x01));
  addBad("one_bad_sig", it);
  it = clone();
  [it[2].signature, it[3].signature] = [it[3].signature, it[2].signature];
  addBad("swapped_sigs", it);
  it = clone().map((x) => ({ ...x, signature: hex(flip(unhex(x.signature), 30, 0x02)) }));
  addBad("all_bad", it);
  it = clone();
  it[0].signature = hex(flip(unhex(it[0].signature), 10, 0x08));
  addBad("bad_first", it);
  it = clone();
  it[it.length - 1].round += 1;
  addBad("bad_last", it);
  it = clone();
  it[1].signature = hex(flip(unhex(it[1].signature), 5, 0x40));
  it[8].signature = hex(sign(sk2, it[8].round));
  addBad("two_bad", it);
  it = clone();
  it[4].signature = hex(offG1);
  addBad("one_off_subgroup", it);
  it = clone();
  it[6].signature = hex(G1.ZERO.toBytes());
  addBad("one_infinity", it);
  // a forged pair whose errors cancel in a plain (unrandomised) product: s_a + d and s_b - d
  const dd = G1.BASE.multiply(seedScalar("cancel"));
  const pa = G1.fromBytes(unhex(goodItems[0].signature)).add(dd).toBytes();
  const pb = G1.fromBytes(unhex(goodItems[1].signature)).subtract(dd).toBytes();
  it = clone();
  it[0].signature = hex(pa);
  it[1].signature = hex(pb);
  addBad("cancelling_pair", it);
  return {
    source: "generated by verifier/tools/gen_bls_vectors.py; signed with a throwaway key kept outside the repository (only the public key is checked in)",
    note: "public_key below is a throwaway key made for these tests; it is NOT the drand quicknet key",
    dst: DST,
    public_key: hex(pk),
    cases,
    batch: { good: goodItems, bad: badSets },
  };
}

// ----------------------------------------------------------------- main
const mode = process.argv[2];
if (mode === "generate") {
  const dir = process.argv[3];
  if (!dir) throw new Error("keys dir required");
  fs.mkdirSync(dir, { recursive: true });
  const pts = buildPoints();
  const offG1 = pts._offG1;
  const offG2 = pts._offG2;
  delete pts._offG1;
  delete pts._offG2;
  const out = { points: pts, pairing: buildPairing(), synth: buildSynth(dir, offG1, offG2) };
  process.stdout.write(JSON.stringify(out));
} else if (mode === "check-live") {
  const input = JSON.parse(fs.readFileSync(0, "utf8"));
  const ok = input.rounds.map((r) => nobleVerify(unhex(r.signature), r.round, unhex(input.public_key)) === "noble-verify-true");
  process.stdout.write(JSON.stringify({ ok }));
} else {
  throw new Error("usage: generate <keys-dir> | check-live");
}
