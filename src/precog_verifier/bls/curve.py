"""BLS12-381 groups G1 (on E: y^2 = x^3 + 4 over Fp) and G2 (on E': y^2 = x^3 + 4(1+u) over Fp2).

Points are Jacobian triples (X, Y, Z) with affine (X/Z^2, Y/Z^3); Z = 0 is the point at infinity. Encoding is
the ZCash / IETF compressed form: flag bits in the top three bits of the first byte (0x80 compressed,
0x40 infinity, 0x20 the larger y), then x big-endian (G2: the Fp2 coefficient of u first, then the constant).

`g1_decode` / `g2_decode` accept an encoding only if it is canonical AND the point is in the order-r subgroup;
whether infinity is acceptable to the caller (it is not for a signature or a public key) is the caller's policy.
Not constant time; the verifier only handles public data.
"""
from . import fields as F
from .errors import BlsError
from .fields import P, R

_HALF = (P - 1) // 2

# ------------------------------------------------------------------ G1
G1_INF = (1, 1, 0)
G1_GEN = (
    0x17F1D3A73197D7942695638C4FA9AC0FC3688C4F9774B905A14E3A3F171BAC586C55E83FF97A1AEFFB3AF00ADB22C6BB,
    0x08B3F481E3AAA0F1A09E30ED741D8AE4FCF5E095D5D00AF600DB18CB2C04B3EDD03CC744A2888AE40CAA232946C5E7E1,
    1,
)


def g1_is_inf(p) -> bool:
    return p[2] == 0


def g1_from_affine(x: int, y: int):
    """No validation: the caller guarantees (x, y) is on the curve."""
    return (x % P, y % P, 1)


def g1_affine(p):
    if p[2] == 0:
        return None
    zi = pow(p[2], -1, P)
    zi2 = zi * zi % P
    return (p[0] * zi2 % P, p[1] * zi2 * zi % P)


def g1_is_on_curve(x: int, y: int) -> bool:
    return 0 <= x < P and 0 <= y < P and (y * y - x * x * x - 4) % P == 0


def g1_neg(p):
    return (p[0], (-p[1]) % P, p[2])


def g1_eq(p, q) -> bool:
    if p[2] == 0 or q[2] == 0:
        return p[2] == 0 and q[2] == 0
    z1, z2 = p[2] * p[2] % P, q[2] * q[2] % P
    return (p[0] * z2 - q[0] * z1) % P == 0 and (p[1] * z2 * q[2] - q[1] * z1 * p[2]) % P == 0


def g1_double(p):
    x, y, z = p
    if z == 0 or y == 0:
        return G1_INF
    a = x * x % P
    b = y * y % P
    c = b * b % P
    d = 2 * ((x + b) * (x + b) - a - c) % P
    e = 3 * a
    f = e * e % P
    x3 = (f - 2 * d) % P
    return (x3, (e * (d - x3) - 8 * c) % P, 2 * y * z % P)


def g1_add(p, q):
    if p[2] == 0:
        return q
    if q[2] == 0:
        return p
    x1, y1, z1 = p
    x2, y2, z2 = q
    z1z1 = z1 * z1 % P
    z2z2 = z2 * z2 % P
    u1 = x1 * z2z2 % P
    u2 = x2 * z1z1 % P
    s1 = y1 * z2 * z2z2 % P
    s2 = y2 * z1 * z1z1 % P
    h = (u2 - u1) % P
    r = 2 * (s2 - s1) % P
    if h == 0:
        return g1_double(p) if r == 0 else G1_INF
    i = 4 * h * h % P
    j = h * i % P
    v = u1 * i % P
    x3 = (r * r - j - 2 * v) % P
    y3 = (r * (v - x3) - 2 * s1 * j) % P
    z3 = ((z1 + z2) * (z1 + z2) - z1z1 - z2z2) * h % P
    return (x3, y3, z3)


def _g1_madd(p, q):
    """p + q where q = (x, y) is affine."""
    if p[2] == 0:
        return (q[0], q[1], 1)
    x1, y1, z1 = p
    x2, y2 = q
    z1z1 = z1 * z1 % P
    u2 = x2 * z1z1 % P
    s2 = y2 * z1 * z1z1 % P
    h = (u2 - x1) % P
    r = 2 * (s2 - y1) % P
    if h == 0:
        return g1_double(p) if r == 0 else G1_INF
    hh = h * h % P
    i = 4 * hh % P
    j = h * i % P
    v = x1 * i % P
    x3 = (r * r - j - 2 * v) % P
    y3 = (r * (v - x3) - 2 * y1 * j) % P
    z3 = ((z1 + h) * (z1 + h) - z1z1 - hh) % P
    return (x3, y3, z3)


def g1_mul(p, k: int):
    if k < 0:
        raise ValueError("negative scalar")
    if k == 0 or p[2] == 0:
        return G1_INF
    base = g1_affine(p)
    acc = G1_INF
    for bit in bin(k)[2:]:
        acc = g1_double(acc)
        if bit == "1":
            acc = _g1_madd(acc, base)
    return acc


def g1_in_subgroup(p) -> bool:
    """True iff p is in the order-r subgroup (p must be on the curve): [r]p = infinity."""
    return p[2] == 0 or g1_mul(p, R)[2] == 0


def g1_encode(p) -> bytes:
    a = g1_affine(p)
    if a is None:
        return b"\xc0" + bytes(47)
    out = bytearray(a[0].to_bytes(48, "big"))
    out[0] |= 0x80 | (0x20 if a[1] > _HALF else 0)
    return bytes(out)


def g1_decode(data) -> tuple:
    """Decode a 48-byte compressed G1 point; raise BlsError(reason) unless it is canonical and in the subgroup."""
    if not isinstance(data, (bytes, bytearray, memoryview)) or len(data) != 48:
        raise BlsError("length", "a G1 point is 48 bytes")
    raw = bytes(data)
    flags = raw[0] & 0xE0
    if not flags & 0x80:
        raise BlsError("flags", "compression flag not set")
    x = int.from_bytes(raw, "big") & ((1 << 381) - 1)
    if flags & 0x40:
        if flags & 0x20 or x != 0:
            raise BlsError("infinity_encoding", "infinity with the sort flag or x bits set")
        return G1_INF
    if x >= P:
        raise BlsError("x_range", "x >= p")
    y = F.fp_sqrt((x * x * x + 4) % P)
    if y is None:
        raise BlsError("not_on_curve", "x has no y")
    if (y > _HALF) != bool(flags & 0x20):
        y = P - y
    pt = (x, y, 1)
    if not g1_in_subgroup(pt):
        raise BlsError("not_in_subgroup", "point is not in G1")
    return pt


# ------------------------------------------------------------------ G2
G2_INF = (F.FP2_ONE, F.FP2_ONE, F.FP2_ZERO)
_B2 = (4, 4)
G2_GEN = (
    (
        0x024AA2B2F08F0A91260805272DC51051C6E47AD4FA403B02B4510B647AE3D1770BAC0326A805BBEFD48056C8C121BDB8,
        0x13E02B6052719F607DACD3A088274F65596BD0D09920B61AB5DA61BBDC7F5049334CF11213945D57E5AC7D055D042B7E,
    ),
    (
        0x0CE5D527727D6E118CC9CDC6DA2E351AADFD9BAA8CBDD3A76D429A695160D12C923AC9CC3BACA289E193548608B82801,
        0x0606C4A02EA734CC32ACD2B02BC28B99CB3E287E85A763AF267492AB572E99AB3F370D275CEC1DA1AAA9075FF05F79BE,
    ),
    F.FP2_ONE,
)


def g2_is_inf(p) -> bool:
    return p[2] == (0, 0)


def g2_from_affine(x, y):
    return (x, y, F.FP2_ONE)


def g2_affine(p):
    if g2_is_inf(p):
        return None
    zi = F.fp2_inv(p[2])
    zi2 = F.fp2_sqr(zi)
    return (F.fp2_mul(p[0], zi2), F.fp2_mul(F.fp2_mul(p[1], zi2), zi))


def g2_is_on_curve(x, y) -> bool:
    if not all(type(c) is int and 0 <= c < P for c in (*x, *y)):
        return False
    return F.fp2_sqr(y) == F.fp2_add(F.fp2_mul(F.fp2_sqr(x), x), _B2)


def g2_neg(p):
    return (p[0], F.fp2_neg(p[1]), p[2])


def g2_eq(p, q) -> bool:
    if g2_is_inf(p) or g2_is_inf(q):
        return g2_is_inf(p) and g2_is_inf(q)
    z1, z2 = F.fp2_sqr(p[2]), F.fp2_sqr(q[2])
    return F.fp2_mul(p[0], z2) == F.fp2_mul(q[0], z1) and F.fp2_mul(F.fp2_mul(p[1], z2), q[2]) == F.fp2_mul(
        F.fp2_mul(q[1], z1), p[2]
    )


def g2_double(p):
    x, y, z = p
    if g2_is_inf(p) or y == (0, 0):
        return G2_INF
    a = F.fp2_sqr(x)
    b = F.fp2_sqr(y)
    c = F.fp2_sqr(b)
    d = F.fp2_sub(F.fp2_sub(F.fp2_sqr(F.fp2_add(x, b)), a), c)
    d = F.fp2_add(d, d)
    e = F.fp2_add(F.fp2_add(a, a), a)
    f = F.fp2_sqr(e)
    x3 = F.fp2_sub(f, F.fp2_add(d, d))
    c8 = F.fp2_scale(c, 8)
    y3 = F.fp2_sub(F.fp2_mul(e, F.fp2_sub(d, x3)), c8)
    z3 = F.fp2_add(F.fp2_mul(y, z), F.fp2_mul(y, z))
    return (x3, y3, z3)


def g2_add(p, q):
    if g2_is_inf(p):
        return q
    if g2_is_inf(q):
        return p
    x1, y1, z1 = p
    x2, y2, z2 = q
    z1z1 = F.fp2_sqr(z1)
    z2z2 = F.fp2_sqr(z2)
    u1 = F.fp2_mul(x1, z2z2)
    u2 = F.fp2_mul(x2, z1z1)
    s1 = F.fp2_mul(F.fp2_mul(y1, z2), z2z2)
    s2 = F.fp2_mul(F.fp2_mul(y2, z1), z1z1)
    h = F.fp2_sub(u2, u1)
    r = F.fp2_sub(s2, s1)
    r = F.fp2_add(r, r)
    if h == (0, 0):
        return g2_double(p) if r == (0, 0) else G2_INF
    i = F.fp2_scale(F.fp2_sqr(h), 4)
    j = F.fp2_mul(h, i)
    v = F.fp2_mul(u1, i)
    x3 = F.fp2_sub(F.fp2_sub(F.fp2_sqr(r), j), F.fp2_add(v, v))
    sj = F.fp2_mul(s1, j)
    y3 = F.fp2_sub(F.fp2_mul(r, F.fp2_sub(v, x3)), F.fp2_add(sj, sj))
    z3 = F.fp2_mul(F.fp2_sub(F.fp2_sub(F.fp2_sqr(F.fp2_add(z1, z2)), z1z1), z2z2), h)
    return (x3, y3, z3)


def g2_mul(p, k: int):
    if k < 0:
        raise ValueError("negative scalar")
    if k == 0 or g2_is_inf(p):
        return G2_INF
    acc = G2_INF
    for bit in bin(k)[2:]:
        acc = g2_double(acc)
        if bit == "1":
            acc = g2_add(acc, p)
    return acc


def g2_in_subgroup(p) -> bool:
    return g2_is_inf(p) or g2_is_inf(g2_mul(p, R))


def _fp2_larger(y) -> bool:
    return y[1] > _HALF if y[1] != 0 else y[0] > _HALF


def g2_encode(p) -> bytes:
    a = g2_affine(p)
    if a is None:
        return b"\xc0" + bytes(95)
    x, y = a
    out = bytearray(x[1].to_bytes(48, "big") + x[0].to_bytes(48, "big"))
    out[0] |= 0x80 | (0x20 if _fp2_larger(y) else 0)
    return bytes(out)


def g2_decode(data) -> tuple:
    """Decode a 96-byte compressed G2 point; raise BlsError(reason) unless it is canonical and in the subgroup."""
    if not isinstance(data, (bytes, bytearray, memoryview)) or len(data) != 96:
        raise BlsError("length", "a G2 point is 96 bytes")
    raw = bytes(data)
    flags = raw[0] & 0xE0
    if not flags & 0x80:
        raise BlsError("flags", "compression flag not set")
    x1 = int.from_bytes(raw[:48], "big") & ((1 << 381) - 1)
    x0 = int.from_bytes(raw[48:], "big")
    if flags & 0x40:
        if flags & 0x20 or x1 != 0 or x0 != 0:
            raise BlsError("infinity_encoding", "infinity with the sort flag or x bits set")
        return G2_INF
    if x1 >= P or x0 >= P:
        raise BlsError("x_range", "a coordinate is >= p")
    x = (x0, x1)
    y = F.fp2_sqrt(F.fp2_add(F.fp2_mul(F.fp2_sqr(x), x), _B2))
    if y is None:
        raise BlsError("not_on_curve", "x has no y")
    if _fp2_larger(y) != bool(flags & 0x20):
        y = F.fp2_neg(y)
    pt = (x, y, F.FP2_ONE)
    if not g2_in_subgroup(pt):
        raise BlsError("not_in_subgroup", "point is not in G2")
    return pt
