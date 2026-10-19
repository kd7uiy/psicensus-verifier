#!/usr/bin/env python3
"""DEV-TIME ONLY. Writes verifier/tests/data/rfc3161/structural.json: the shared structural vectors.

Both implementations of the RFC 3161 structural check read this one file:
  * the Python plugin (verifier/tests/test_rfc3161_structural.py, precog_verifier.rfc3161.token.check_structure)
  * the notary's check (the Worker's parity test)
Cases are built from the three real tokens (certificates stripped: the structural check never needs them);
signatures are NOT valid after editing, which is fine because neither structural check verifies them.
Deterministic: no keys, no randomness, no openssl.

Each case: {name, token (hex), digest (hex), nonce (hex, raw big-endian, only the notary uses it),
            python: {ok, gen_time_ms} | {ok:false, code, reason},
            worker: {ok, gen_time_ms} | {ok:false, code}}
The notary has no separate code for "wrong hash algorithm"; it reports tsa.imprint_mismatch, as does the plugin
(tsa.wrong_imprint). The nonce is checked by the notary only (the verifier never sees the request).
"""
import calendar
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import derkit as d  # noqa: E402

DATA = HERE.parent / "tests" / "data" / "rfc3161"
NONCES = {"digicert": "92030175ec8ce2fa", "globalsign": "d7d5c498774a5f3a", "certum": "3734d3b97a9b6ad6"}
OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_TSTINFO = "1.2.840.113549.1.9.16.1.4"
OID_DATA = "1.2.840.113549.1.7.1"
SHA256 = "2.16.840.1.101.3.4.2.1"


class Real:
    """A real TimeStampResp taken apart (certificates dropped)."""

    def __init__(self, name):
        t = (DATA / "real" / f"{name}.tsr").read_bytes()
        self.name = name
        resp = d.children(t, 0)
        ci = resp[1]
        ex = d.children(t, ci[1])[1]
        sd = d.children(t, ex[1])[0]
        kids = d.children(t, sd[1])
        self.sd_version, self.sd_algs, encap = (d.raw(t, k) for k in kids[:3])
        self.signer_infos = d.raw(t, kids[-1])
        octs = d.children(t, d.children(t, kids[2][1])[1][1])[0]
        self.fields = [d.raw(t, f) for f in d.children(t, d.children(t, octs[1])[0][1])]
        self.digest = bytes.fromhex((DATA / "real" / "digest.hex").read_text().strip())
        self.nonce = NONCES[name]


def build(real: Real, fields=None, *, status=0, econtent_oid=OID_TSTINFO, tst_tag=0x30, status_der=None, token=True,
          sd_version=None, octet_wrap=True, tst_raw=None) -> bytes:
    fields = real.fields if fields is None else fields
    tst = tst_raw if tst_raw is not None else d.tlv(tst_tag, b"".join(fields))
    econtent = d.octet(tst) if octet_wrap else tst
    encap = d.seq(d.oid(econtent_oid), d.ctx(0, econtent))
    sd = d.seq(sd_version or real.sd_version, real.sd_algs, encap, real.signer_infos)
    ci = d.seq(d.oid(OID_SIGNED_DATA), d.ctx(0, sd))
    st = status_der if status_der is not None else d.seq(d.integer(status))
    return d.seq(st, ci) if token else d.seq(st)


def ms_of(s: str) -> int:
    """Independent expectation: whole seconds via calendar.timegm, fraction truncated to ms."""
    base, frac = (s[:-1].split(".") + [""])[:2] if "." in s else (s[:-1], "")
    y, mo, dd, hh, mi, ss = (int(base[i : i + n]) for i, n in ((0, 4), (4, 2), (6, 2), (8, 2), (10, 2), (12, 2)))
    return calendar.timegm((y, mo, dd, hh, mi, ss)) * 1000 + int((frac + "000")[:3])


cases: list[dict] = []


def add(name, token, real, *, digest=None, py_ok=None, py_fail=None, worker_fail=None, worker_ok=None, note=None):
    """py_ok = gen_time_ms; py_fail = (code, reason). worker defaults are derived from the python expectation."""
    dg = digest if digest is not None else real.digest
    if py_ok is not None:
        py = {"ok": True, "gen_time_ms": py_ok}
        w = {"ok": True, "gen_time_ms": py_ok} if worker_ok is None else worker_ok
    else:
        code, reason = py_fail
        py = {"ok": False, "code": code, "reason": reason}
        derived = {"not_granted": "tsa.not_granted", "imprint": "tsa.imprint_mismatch"}.get(reason, "tsa.malformed")
        w = {"ok": False, "code": worker_fail or derived}
    c = {"name": name, "token": token.hex(), "digest": dg.hex(), "nonce": real.nonce, "python": py, "worker": w}
    if note:
        c["note"] = note
    cases.append(c)


INV = "tsa.invalid"
WI = "tsa.wrong_imprint"


def main() -> int:
    dc, gs, ce = Real("digicert"), Real("globalsign"), Real("certum")
    base_ms = ms_of("20261004135333Z")
    for r, s in ((dc, "20261004135333Z"), (gs, "20261004135334Z"), (ce, "20261004135335Z")):
        add(f"real_{r.name}", build(r), r, py_ok=ms_of(s))

    # -------------------------------------------------------------- status
    for st, reason in ((0, None), (1, None), (2, "not_granted"), (3, "not_granted"), (4, "not_granted"), (5, "not_granted")):
        add(f"status_{st}", build(dc, status=st), dc, **({"py_ok": base_ms} if reason is None else {"py_fail": (INV, reason)}))
    add("status_single_byte_ff", build(dc, status_der=d.seq(d.tlv(0x02, b"\xff"))), dc, py_fail=(INV, "not_granted"))
    add("status_two_byte_integer", build(dc, status_der=d.seq(d.tlv(0x02, b"\x00\x00"))), dc, py_fail=(INV, "malformed"))
    add("status_empty_sequence", build(dc, status_der=d.seq()), dc, py_fail=(INV, "malformed"))
    add("status_not_an_integer", build(dc, status_der=d.seq(d.null())), dc, py_fail=(INV, "malformed"))
    add("rejected_without_token", build(dc, status=2, token=False), dc, py_fail=(INV, "not_granted"))
    add("granted_without_token", build(dc, status=0, token=False), dc, py_fail=(INV, "malformed"))

    # -------------------------------------------------------------- framing
    ok = build(dc)
    add("empty", b"", dc, py_fail=(INV, "malformed"))
    add("one_byte", b"\x30", dc, py_fail=(INV, "malformed"))
    add("truncated_half", ok[: len(ok) // 2], dc, py_fail=(INV, "malformed"))
    add("truncated_by_one", ok[:-1], dc, py_fail=(INV, "malformed"))
    add("trailing_byte", ok + b"\x00", dc, py_fail=(INV, "malformed"))
    add("leading_byte", b"\x00" + ok, dc, py_fail=(INV, "malformed"))
    add("not_a_sequence", b"\x31" + ok[1:], dc, py_fail=(INV, "malformed"))
    add("length_exceeds_input", ok[:2] + bytes([ok[2] + 1]) + ok[3:] if ok[1] & 0x80 else ok, dc, py_fail=(INV, "malformed"))
    add("indefinite_length", b"\x30\x80" + ok[len(ok) - (len(ok) - (2 + (ok[1] & 0x7F))) :] + b"\x00\x00", dc, py_fail=(INV, "malformed"))
    # -------------------------------------------------------------- encapsulated content
    add("econtent_type_is_data", build(dc, econtent_oid=OID_DATA), dc, py_fail=(INV, "content_type"))
    add("tstinfo_four_fields", build(dc, dc.fields[:4]), dc, py_fail=(INV, "malformed"))
    add("tstinfo_thirteen_fields", build(dc, dc.fields + [d.integer(i) for i in range(1, 9)]), dc, py_fail=(INV, "malformed"))
    add("tstinfo_is_a_set", build(dc, tst_tag=0x31), dc, py_fail=(INV, "malformed"))
    add("tstinfo_empty_octet_string", build(dc, tst_raw=b""), dc, py_fail=(INV, "malformed"))

    # -------------------------------------------------------------- message imprint
    f = dc.fields
    imprint = lambda alg_der, hm_der: d.seq(alg_der, hm_der)  # noqa: E731
    sha256_null = d.alg(SHA256)
    sha256_absent = d.seq(d.oid(SHA256))
    good_digest = d.octet(dc.digest)

    def with_imprint(i):
        return build(dc, [f[0], f[1], i, f[3], f[4], f[5]])

    flipped = bytearray(dc.digest)
    flipped[-1] ^= 1
    add("imprint_last_byte_differs", with_imprint(imprint(sha256_null, d.octet(bytes(flipped)))), dc, py_fail=(WI, "imprint"))
    add("imprint_first_byte_differs", with_imprint(imprint(sha256_null, d.octet(bytes([dc.digest[0] ^ 1]) + dc.digest[1:]))), dc, py_fail=(WI, "imprint"))
    add("imprint_digest_expected_differs", build(dc), dc, digest=bytes(flipped), py_fail=(WI, "imprint"))
    add("imprint_31_bytes", with_imprint(imprint(sha256_null, d.octet(dc.digest[:-1]))), dc, py_fail=(WI, "imprint"))
    add("imprint_33_bytes", with_imprint(imprint(sha256_null, d.octet(dc.digest + b"\x00"))), dc, py_fail=(WI, "imprint"))
    add("imprint_algorithm_sha384", with_imprint(imprint(d.alg("2.16.840.1.101.3.4.2.2"), good_digest)), dc, py_fail=(WI, "imprint"))
    add("imprint_algorithm_sha1", with_imprint(imprint(d.alg("1.3.14.3.2.26"), good_digest)), dc, py_fail=(WI, "imprint"))
    add("imprint_params_absent", with_imprint(imprint(sha256_absent, good_digest)), dc, py_fail=(WI, "imprint"),
        note="RFC 3161 allows absent parameters; both checks compare the AlgorithmIdentifier bytes with the NULL form")
    add("imprint_params_not_null", with_imprint(imprint(d.seq(d.oid(SHA256), d.octet(b"")), good_digest)), dc, py_fail=(WI, "imprint"))
    add("imprint_hashed_message_is_bit_string", with_imprint(imprint(sha256_null, d.bitstring(dc.digest))), dc, py_fail=(INV, "malformed"))
    add("imprint_extra_element", with_imprint(d.seq(sha256_null, good_digest, d.null())), dc, py_fail=(INV, "malformed"))
    add("imprint_not_a_sequence", with_imprint(d.set_(sha256_null, good_digest)), dc, py_fail=(INV, "malformed"))
    add("imprint_empty_sequence", with_imprint(d.seq()), dc, py_fail=(INV, "malformed"))

    # -------------------------------------------------------------- genTime
    def with_gt(raw_time: bytes):
        return build(dc, [f[0], f[1], f[2], f[3], raw_time, f[5]])

    def gt(s, tag=0x18):
        return d.tlv(tag, s.encode("ascii"))

    ok_times = [
        ("gen_no_fraction", "20261004135333Z"),
        ("gen_fraction_1_digit", "20261004135333.5Z"),
        ("gen_fraction_2_digits", "20261004135333.05Z"),
        ("gen_fraction_3_digits", "20261004135333.005Z"),
        ("gen_fraction_4_digits_truncated", "20261004135333.1239Z"),
        ("gen_fraction_6_digits_truncated", "20261004135333.123456Z"),
        ("gen_fraction_9_digits_truncated", "20261004135333.987654321Z"),
        ("gen_fraction_sub_ms_is_zero", "20261004135333.0004Z"),
        ("gen_fraction_zero", "20261004135333.0Z"),
        ("gen_fraction_trailing_zeros", "20261004135333.500Z"),
        ("gen_epoch", "19700101000000Z"),
        ("gen_leap_day", "20280229235959Z"),
        ("gen_last_second_of_year", "20261231235959.999Z"),
        ("gen_year_9999", "99991231235959Z"),
    ]
    for name, s in ok_times:
        add(name, with_gt(gt(s)), dc, py_ok=ms_of(s))
    bad_times = [
        ("gen_missing_z", "20261004135333"),
        ("gen_lowercase_z", "20261004135333z"),
        ("gen_offset_plus", "20261004135333+0000"),
        ("gen_offset_two_hours", "20261004135333+0200"),
        ("gen_offset_minus", "20261004135333-0500"),
        ("gen_empty_fraction", "20261004135333.Z"),
        ("gen_comma_fraction", "20261004135333,5Z"),
        ("gen_month_13", "20261304135333Z"),
        ("gen_month_00", "20260004135333Z"),
        ("gen_day_00", "20261000135333Z"),
        ("gen_day_32", "20261032135333Z"),
        ("gen_feb_30", "20260230135333Z"),
        ("gen_feb_29_non_leap", "20270229135333Z"),
        ("gen_hour_24", "20261004245333Z"),
        ("gen_minute_60", "20261004136033Z"),
        ("gen_second_60", "20261004135360Z"),
        ("gen_before_1970", "19691231235959Z"),
        ("gen_year_0050", "00501004135333Z"),
        ("gen_year_0070", "00701004135333Z"),
        ("gen_year_0099", "00991004135333Z"),
        ("gen_13_digits", "2026100413533Z"),
        ("gen_15_digits", "202610041353330Z"),
        ("gen_non_digit", "2026100413533aZ"),
        ("gen_two_digit_year", "261004135333Z"),
        ("gen_leading_space", " 20261004135333Z"),
        ("gen_trailing_space", "20261004135333Z "),
        ("gen_only_z", "Z"),
        ("gen_empty", ""),
    ]
    for name, s in bad_times:
        add(name, with_gt(gt(s)), dc, py_fail=(INV, "gen_time"))
    add("gen_utc_time_tag", with_gt(gt("261004135333Z", 0x17)), dc, py_fail=(INV, "malformed"))
    add("gen_time_is_an_integer", with_gt(d.integer(5)), dc, py_fail=(INV, "malformed"))

    out = {"version": 1, "description": __doc__.strip().splitlines()[0], "cases": cases}
    text = json.dumps(out, indent=1) + "\n"
    (DATA / "structural.json").write_bytes(text.encode("utf-8"))
    print(f"wrote {len(cases)} cases, {len(text)} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
