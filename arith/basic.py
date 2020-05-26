"""Basic functions for arithmetic (and number theory) use."""
import math
import random


def lcm(a: int, b: int):
    return a * b // math.gcd(a, b)


def trailing_zeros(a: int):
    """Return number of trailing zeros in binary representation of a.
    Return 0 when a==0."""

    if a == 0:
        return 0
    i = 0
    while a & (1 << i) == 0:
        i += 1

    return i


def ext_gcd(a: int, b: int):
    """Extended Euclid Algorithm.

    Returns (d, x, y), where d = gcd(a, b) = a*x + b*y.
    """
    # maintain matrix x, y; z, w
    if a > b:
        x = 1
        y = 0
        z = 0
        w = 1
    else:
        x = 0
        y = 1
        z = 1
        w = 0
        a, b = b, a

    if b < 0:
        q, r = divmod(a, b)
        x = x - q * z
        y = y - q * w
        a = r
    while b != 0:
        q, r = divmod(a, b)
        x, z = z, x - q * z
        y, w = w, y - q * w
        a, b = b, r
    return (a, x, y)


def binary_gcd(a: int, b: int):
    a = abs(a)
    b = abs(b)
    if b == 0:
        return a
    elif a == 0:
        return b
    if a < b:
        a, b = b, a
    # a >= b
    r = trailing_zeros(a)
    s = trailing_zeros(b)
    a >>= r
    b >>= s
    s = min(r, s)
    while a != b:
        if a < b:
            b -= a
            b >>= trailing_zeros(b)
        else:
            a -= b
            a >>= trailing_zeros(a)
    return a * (1 << s)


def intlen(a: int):
    return math.floor(math.log2(a)) + 1


def fixedrandbits(k: int, require_odd=False):
    x = random.getrandbits(k - 1)
    x |= 1 << (k - 1)
    if require_odd:
        x |= 1
    return x


def isperfectsuqare(a: int):
    """Check for perfect square using Newton method."""
    n = intlen(a)
    m = (n + 1) >> 1
    x = random.getrandbits(m)
    x |= 1 << (m - 1)
    t = x * x
    bound = (1 << m) + a
    for _ in range(m):
        x = (t + a) / (2 * x)  # x is float
        t = x * x
        if t < bound:
            break
    if c == math.floor(x) ** 2:
        return True
    else:
        return False
