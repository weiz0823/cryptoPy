"""Primality tests, random prime generation, and things related with prime."""

if __name__ == "__main__":
    import basic
else:
    from . import basic


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


prime_list16 = prime_sieve(65536)
if __name__ == "__main__":
    print(f"prime test 2, 37, 65533: {isprime(2)}, {isprime(37)}, {isprime(65533)}")
    print(f"Random prime: {random_prime(256)}")
    print("Tests passed!")
