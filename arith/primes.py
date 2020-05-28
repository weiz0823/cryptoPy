"""Primality tests, random prime generation, and things related with prime."""

import sys
import os
import random
import math

sys.path.append(os.path.dirname(sys.path[0])) # parent directory
import common

if "." not in __name__:
    import basic
    import mod
else:
    from . import basic
    from . import mod


def prime_sieve(n: int):
    """Return a list of primes not greater than n."""
    sieve = [True] * (n + 1)
    primes = []
    for i in range(2, n + 1):
        if sieve[i]:
            primes.append(i)
        for p in primes:
            if i * p > n:
                break  # caution out of boundary
            sieve[i * p] = False
            if i % p == 0:
                break  # meet the first prime factor of i
    return primes


def isprime(n: int):
    """Check for primality less than 2^32. Else redirect to Miller-Rabin."""
    if n >= (1 << 32):
        return miller_rabin_quick(n)
    elif n < 65536:
        l = -1
        r = len(prime_list16)
        while r - l > 1:
            m = (l + r) >> 1
            if prime_list16[m] < n:
                l = m
            elif prime_list16[m] > n:
                r = m
            else:
                return True
        return False
    else:
        for p in prime_list16:
            if p * p > n:
                return True
            if n % p == 0:
                return False
        return True


def miller_rabin(w: int, iters=10):
    if w < 0:
        w = -w
    elif w < 2:
        return False
    t = w - 1
    a = basic.trailing_zeros(t)
    m = t >> a
    for _ in range(iters):
        b = random.randint(2, w - 2)
        z = pow(b, m, w)
        if z == 1 or z == t:
            continue
        for j in range(a - 1):
            z = z * z % w
            if z == t:
                break
            elif z == 1:
                return False
        else:
            return False
    return True


def miller_rabin_quick(w: int, iters=10):
    """Miller-Rabin with chosen small primes as base, and do divisions first.
    May not be fast."""
    global prime_list16
    if w < 0:
        w = -w
    elif w < 2:
        return False
    elif w == 2:
        return True
    # check for small factors first
    for i in range(iters):
        b = prime_list16[i]
        if w < b:
            return False
        elif w == b:
            return True
        elif w % b == 0:
            return False
    t = w - 1
    a = basic.trailing_zeros(t)
    m = t >> a
    for i in range(iters):
        b = prime_list16[i]
        z = pow(b, m, w)
        if z == 1 or z == t:
            continue
        for j in range(a - 1):
            z = z * z % w
            if z == t:
                break
            elif z == 1:
                return False
        else:
            return False
    return True


def general_lucas_test(n: int):
    if n & 1 == 0:
        if n == 2:
            return True
        else:
            return False
    if basic.isperfectsuqare(n):
        return False
    # if n is perfect square, there will never be jacobi(d/n) == -1
    # choose d from sequence 5,-7,9,-11,... until jacobi(d/n) == -1
    d = 5
    j = mod.Mod(d, n).jacobi()
    while j != -1:
        if j == 0:
            # that means gcd(d,n) > 1
            return False
        if d > 0:
            d = -d - 2
        else:
            d = -d + 2
        j = mod.Mod(d, n).jacobi()
    m = common.i2osp(n + 1)
    # u[1] and v[1], where P=1
    u = mod.Mod(1, n)
    v = mod.Mod(1, n)
    i = 0
    mask = 0x80
    # find the MSB
    while mask & m[i] == 0:
        mask >>= 1
        if mask == 0:
            mask = 0x80
            i += 1
    mask >>= 1
    for i in range(i, len(m)):
        while mask != 0:
            # k -> 2k
            u, v = u * v, (v * v + d * u * u).half()
            # 2k -> 2k+1
            if mask & m[i] != 0:
                # u=(u+v)/2 is from P=1
                u, v = (u + v).half(), (v + d * u).half()
            mask >>= 1
        mask = 0x80
    return u == 0


def baillie_psw(n: int, iters=10, mriters=1):
    """Baillie-PSW primality test.

    n -- number to be tested
    iters -- iterations of trial division
    mriters -- iterations of Miller-Rabin"""
    global prime_list16
    if n <= prime_list16[mriters - 1]:
        return isprime(n)
    for i in range(mriters, iters):
        if n < prime_list16[i]:
            return False
        elif n == prime_list16[i]:
            return True
        elif n % prime_list16[i] == 0:
            return False
    if not miller_rabin_quick(n, 1):
        # do a M-R on base 2
        return False
    # Lucas pseudoprimes overlap little with Fermat pseudoprimes on base 2
    return general_lucas_test(n)


def to_next_prime(a: int):
    if a <= 2:
        return 2
    a |= 1
    while not miller_rabin_quick(a):
        a += 2
    return a


def random_prime(bitlen: int):
    """Random prime based on miller_rabin and to_next_prime."""
    if bitlen < 2:
        raise ValueError("random prime must be at least 2-bit long")
    elif bitlen == 2:
        return random.randint(2, 3)
    p = 2
    while basic.intlen(p) != bitlen:
        p = basic.fixedrandbits(bitlen, True)
        p = to_next_prime(p)
    return p


def st_random_prime(bitlen: int, factor=None):
    """Shawe-Taylor prime construction.

    factor -- required factor of p-1.
              intlen(factor) SHALL be less than (bitlen-5)/2."""
    if bitlen < 2:
        raise ValueError("random prime must be at least 2-bit long")
    elif bitlen == 2:
        return random.randint(2, 3)
    elif bitlen < 33:
        # brute-force prime generation
        # prime density is about 1/log(n), i.e. 1.44/bitlen
        for i in range(bitlen << 2):
            p = basic.fixedrandbits(bitlen, True)
            if isprime(p):
                return p
        raise RuntimeError("didn't get a prime")
    elif factor is not None:
        if basic.intlen(factor) >= (bitlen - 5) >> 1:
            raise ValueError("required factor too large")
        p0 = st_random_prime((bitlen + 3) >> 1)
        # now p2 contains the factor
        p2 = (p0 + p0) * factor
        t = basic.ceildiv(basic.fixedrandbits(bitlen, False), p2)
        for i in range(bitlen << 2):
            # first p>randint with p==1 mod p2
            # p0*t+1 works, but if t is odd, then it will never be prime
            p = p2 * t + 1
            if basic.intlen(p) != bitlen:
                # if t is too big, fall back to the smallest one
                t = basic.ceildiv(1 << (bitlen - 1), p2)
                p = p2 * t + 1
            a = random.randint(2, p - 2)
            z = pow(a, (t + t) * factor, p)
            if math.gcd(z - 1, p) == 1 and pow(z, p0, p) == 1:
                # proven prime with the help of p0
                return p
            # if fail, don't get a new p0, try a new t instead
            t += 1
        raise RuntimeError("didn't get a prime")
    else:
        # big prime based on smaller prime
        p0 = st_random_prime((bitlen + 3) >> 1)
        p2 = p0 + p0
        t = basic.ceildiv(basic.fixedrandbits(bitlen, False), p2)
        for i in range(bitlen << 2):
            # first p>randint with p==1 mod p2
            # p0*t+1 works, but if t is odd, then it will never be prime
            p = p2 * t + 1
            if basic.intlen(p) != bitlen:
                # if t is too big, fall back to the smallest one
                t = basic.ceildiv(1 << (bitlen - 1), p2)
                p = p2 * t + 1
            a = random.randint(2, p - 2)
            z = pow(a, t + t, p)
            if math.gcd(z - 1, p) == 1 and pow(z, p0, p) == 1:
                # proven prime with the help of p0
                return p
            # if fail, don't get a new p0, try a new t instead
            t += 1
        raise RuntimeError("didn't get a prime")


prime_list16 = prime_sieve(65536)
if __name__ == "__main__":
    print(f"prime test 2, 37, 65533: {isprime(2)}, {isprime(37)}, {isprime(65533)}")
    r = random_prime(256)
    print(f"Random prime: {r}")
    q = st_random_prime(160)
    print(f"ST random prime: {q}")
    p = st_random_prime(512, q)
    print(f"ST random prime with required factor of p-1: {p}")
    print(f"  cross-check prime test: {miller_rabin(p)}, factor test: {(p-1)%q==0}")
    print(
        "General lucas test: {}, {}, {}".format(
            general_lucas_test(r), general_lucas_test(q), general_lucas_test(p)
        )
    )
    print("Tests passed!")
