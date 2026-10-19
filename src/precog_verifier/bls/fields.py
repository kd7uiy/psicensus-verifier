"""The BLS12-381 field tower, standard library only.

    Fp   : integers mod P                              (a Python int in [0, P))
    Fp2  = Fp[u]  / (u^2 + 1)                          (a, b)            = a + b u
    Fp6  = Fp2[v] / (v^3 - (1 + u))                    (c0, c1, c2)      = c0 + c1 v + c2 v^2
    Fp12 = Fp6[w] / (w^2 - v)                          (c0, c1)          = c0 + c1 w

Every element is an immutable tuple, every function returns a fully reduced value. Functions, not classes: the
pairing spends nearly all its time here and attribute lookups are measurable in CPython.
Not constant time (the verifier handles only public data).
"""

# base field and subgroup order
P = 0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAB
R = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001
_HALF = (P - 1) // 2


# ------------------------------------------------------------------ Fp
def fp_inv(a: int) -> int:
    if a % P == 0:
        raise ZeroDivisionError("inverse of zero")
    return pow(a, -1, P)


def fp_is_square(a: int) -> bool:
    return pow(a, _HALF, P) in (0, 1)


def fp_sqrt(a: int) -> int | None:
    """A square root of a, or None. P = 3 mod 4, so the root is a^((P+1)/4) when it exists."""
    r = pow(a, (P + 1) // 4, P)
    return r if r * r % P == a % P else None


def fp_sgn0(a: int) -> int:
    return a & 1


# ------------------------------------------------------------------ Fp2
FP2_ZERO = (0, 0)
FP2_ONE = (1, 0)


def fp2_add(a, b):
    return ((a[0] + b[0]) % P, (a[1] + b[1]) % P)


def fp2_sub(a, b):
    return ((a[0] - b[0]) % P, (a[1] - b[1]) % P)


def fp2_neg(a):
    return ((-a[0]) % P, (-a[1]) % P)


def fp2_mul(a, b):
    t0 = a[0] * b[0]
    t1 = a[1] * b[1]
    return ((t0 - t1) % P, ((a[0] + a[1]) * (b[0] + b[1]) - t0 - t1) % P)


def fp2_sqr(a):
    return ((a[0] + a[1]) * (a[0] - a[1]) % P, 2 * a[0] * a[1] % P)


def fp2_scale(a, k: int):
    return (a[0] * k % P, a[1] * k % P)


def fp2_conj(a):
    return (a[0], (-a[1]) % P)


def fp2_mul_xi(a):
    """a * (1 + u)."""
    return ((a[0] - a[1]) % P, (a[0] + a[1]) % P)


def fp2_is_zero(a) -> bool:
    return a[0] == 0 and a[1] == 0


def fp2_inv(a):
    n = (a[0] * a[0] + a[1] * a[1]) % P
    if n == 0:
        raise ZeroDivisionError("inverse of zero")
    ni = pow(n, -1, P)
    return (a[0] * ni % P, (-a[1]) * ni % P)


def fp2_pow(a, e: int):
    out = FP2_ONE
    base = a
    while e:
        if e & 1:
            out = fp2_mul(out, base)
        base = fp2_sqr(base)
        e >>= 1
    return out


def fp2_sqrt(a):
    """A square root of a in Fp2, or None. Uses the norm: (x + y u) is a square iff x^2 + y^2 is a square in Fp
    and (x + s)/2 or (x - s)/2 is a square, where s^2 = x^2 + y^2."""
    x, y = a
    if y == 0:
        r = fp_sqrt(x)
        if r is not None:
            return (r, 0)
        r = fp_sqrt(-x % P)  # x is not a square, so -x is (P = 3 mod 4): sqrt(x) = sqrt(-x) u
        return (0, r) if r is not None else None
    s = fp_sqrt((x * x + y * y) % P)
    if s is None:
        return None
    half = pow(2, -1, P)
    for cand in (s, (-s) % P):
        c = (x + cand) * half % P
        t = fp_sqrt(c)
        if t is not None and t != 0:
            root = (t, y * pow(2 * t, -1, P) % P)
            return root if fp2_sqr(root) == (x % P, y % P) else None
    return None


def fp2_is_square(a) -> bool:
    return fp2_sqrt(a) is not None


def fp2_sgn0(a) -> int:
    """RFC 9380 section 4.1: sign_0 OR (zero_0 AND sign_1)."""
    return (a[0] & 1) or ((a[0] == 0) and (a[1] & 1))


# ------------------------------------------------------------------ Fp6
FP6_ZERO = (FP2_ZERO, FP2_ZERO, FP2_ZERO)
FP6_ONE = (FP2_ONE, FP2_ZERO, FP2_ZERO)


def fp6_add(a, b):
    return (fp2_add(a[0], b[0]), fp2_add(a[1], b[1]), fp2_add(a[2], b[2]))


def fp6_sub(a, b):
    return (fp2_sub(a[0], b[0]), fp2_sub(a[1], b[1]), fp2_sub(a[2], b[2]))


def fp6_neg(a):
    return (fp2_neg(a[0]), fp2_neg(a[1]), fp2_neg(a[2]))


def fp6_mul(a, b):
    v0 = fp2_mul(a[0], b[0])
    v1 = fp2_mul(a[1], b[1])
    v2 = fp2_mul(a[2], b[2])
    c0 = fp2_add(v0, fp2_mul_xi(fp2_sub(fp2_sub(fp2_mul(fp2_add(a[1], a[2]), fp2_add(b[1], b[2])), v1), v2)))
    c1 = fp2_add(fp2_sub(fp2_sub(fp2_mul(fp2_add(a[0], a[1]), fp2_add(b[0], b[1])), v0), v1), fp2_mul_xi(v2))
    c2 = fp2_add(fp2_sub(fp2_sub(fp2_mul(fp2_add(a[0], a[2]), fp2_add(b[0], b[2])), v0), v2), v1)
    return (c0, c1, c2)


def fp6_sqr(a):
    return fp6_mul(a, a)


def fp6_mul_v(a):
    """a * v : (c0, c1, c2) -> (xi c2, c0, c1)."""
    return (fp2_mul_xi(a[2]), a[0], a[1])


def fp6_inv(a):
    a0, a1, a2 = a
    t0 = fp2_sub(fp2_sqr(a0), fp2_mul_xi(fp2_mul(a1, a2)))
    t1 = fp2_sub(fp2_mul_xi(fp2_sqr(a2)), fp2_mul(a0, a1))
    t2 = fp2_sub(fp2_sqr(a1), fp2_mul(a0, a2))
    denom = fp2_add(fp2_mul(a0, t0), fp2_mul_xi(fp2_add(fp2_mul(a2, t1), fp2_mul(a1, t2))))
    d = fp2_inv(denom)  # raises ZeroDivisionError for a == 0
    return (fp2_mul(t0, d), fp2_mul(t1, d), fp2_mul(t2, d))


# ------------------------------------------------------------------ Fp12
FP12_ZERO = (FP6_ZERO, FP6_ZERO)
FP12_ONE = (FP6_ONE, FP6_ZERO)


def fp12_add(a, b):
    return (fp6_add(a[0], b[0]), fp6_add(a[1], b[1]))


def fp12_sub(a, b):
    return (fp6_sub(a[0], b[0]), fp6_sub(a[1], b[1]))


def fp12_mul(a, b):
    t0 = fp6_mul(a[0], b[0])
    t1 = fp6_mul(a[1], b[1])
    c1 = fp6_sub(fp6_sub(fp6_mul(fp6_add(a[0], a[1]), fp6_add(b[0], b[1])), t0), t1)
    return (fp6_add(t0, fp6_mul_v(t1)), c1)


def fp12_sqr(a):
    t = fp6_mul(a[0], a[1])
    c0 = fp6_sub(fp6_sub(fp6_mul(fp6_add(a[0], a[1]), fp6_add(a[0], fp6_mul_v(a[1]))), t), fp6_mul_v(t))
    return (c0, fp6_add(t, t))


def fp12_conj(a):
    """a^(P^6): the conjugate over Fp6."""
    return (a[0], fp6_neg(a[1]))


def fp12_inv(a):
    d = fp6_sub(fp6_sqr(a[0]), fp6_mul_v(fp6_sqr(a[1])))
    di = fp6_inv(d)  # raises ZeroDivisionError for a == 0
    return (fp6_mul(a[0], di), fp6_neg(fp6_mul(a[1], di)))


def fp12_pow(a, e: int):
    if e < 0:
        raise ValueError("negative exponent")
    out = FP12_ONE
    base = a
    while e:
        if e & 1:
            out = fp12_mul(out, base)
        base = fp12_sqr(base)
        e >>= 1
    return out


# Frobenius: with w^6 = xi, w^P = w * xi^((P-1)/6), so on the basis w^k (k = 0..5, coefficients in Fp2)
# a_k w^k -> conj(a_k) * GAMMA^k w^k, with GAMMA = xi^((P-1)/6).
_GAMMA = fp2_pow((1, 1), (P - 1) // 6)
_GAMMAS = [FP2_ONE]
for _k in range(1, 6):
    _GAMMAS.append(fp2_mul(_GAMMAS[-1], _GAMMA))


def _frob1(a):
    (c00, c01, c02), (c10, c11, c12) = a
    flat = (c00, c10, c01, c11, c02, c12)  # coefficients of w^0 .. w^5
    f = [fp2_mul(fp2_conj(x), _GAMMAS[k]) for k, x in enumerate(flat)]
    return ((f[0], f[2], f[4]), (f[1], f[3], f[5]))


def fp12_frobenius(a, n: int = 1):
    """a^(P^n)."""
    for _ in range(n % 12):
        a = _frob1(a)
    return a


def fp12_to_coeffs(a) -> list[int]:
    """12 integers [c0.c0.a, c0.c0.b, c0.c1.a, c0.c1.b, c0.c2.a, c0.c2.b, c1.c0.a, ..., c1.c2.b]."""
    return [x for h in a for c in h for x in c]


def fp12_from_coeffs(flat) -> tuple:
    if len(flat) != 12 or any(type(x) is not int or not 0 <= x < P for x in flat):
        raise ValueError("an Fp12 element is 12 integers in [0, P)")
    c = [(flat[i], flat[i + 1]) for i in range(0, 12, 2)]
    return ((c[0], c[1], c[2]), (c[3], c[4], c[5]))
