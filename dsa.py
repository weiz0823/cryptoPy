from common import *
import warnings
import random
import cryptohash
import asn1
from arith import basic, mod, primes

id_x9_57_alg = asn1.OID("1.2.840.10040.4", "/ISO/Member-Body/US/X9-57/X9Algorithm")
id_dsa = id_x9_57_alg.subnode("1", "DSA")


def secure_ln(strength):
    """Return (L,N)-pair of DSA with security strength not less than required."""
    # SP 800-57 Table 2
    if strength <= 80:
        return 1024, 160
    elif strength <= 112:
        return 2048, 224
    elif strength <= 128:
        return 3072, 256
    elif strength <= 192:
        return 7680, 384
    elif strength <= 256:
        return 15360, 512
    else:
        warnings.warn(
            "maximum security strength for DSA is 256 for (L,N)=(15360,512)",
            SecurityWarning,
        )
        return 15360, 512


class DSADomain:
    def encode(self):
        return asn1.encode_sequence([self.p, self.q, self.g])


class DSAPublicKey:
    def __init__(self, domain, y):
        self.domain = domain
        self.y = y

    def verify(self, msg, sign, hash_alg=cryptohash.alg_sha1):
        # sign=(r,s)
        if sign[0] <= 0 or sign[0] >= self.domain.q:
            return False
        if sign[1] <= 0 or sign[1] >= self.domain.q:
            return False
        w = mod.Mod(sign[1], self.domain.q).inv()
        h = hash_alg(msg)
        klen = self.domain.n >> 3
        if klen < hash_alg.hlen:
            h = h[:klen]
        h = os2ui(h)
        v1 = pow(self.domain.g, (h * w).value, self.domain.p)
        v2 = pow(self.y, (sign[0] * w).value, self.domain.p)
        return v1 * v2 % self.domain.p % self.domain.q == sign[0]

    def encode(self):
        return asn1.encode_int(self.y)


class DSAPrivateKey:
    def get_public_key(self):
        return DSAPublicKey(self.domain, self.y)

    def sign(self, msg, hash_alg=cryptohash.alg_sha1):
        assert pow(self.domain.g, self.x, self.domain.p) == self.y
        assert pow(self.domain.g, self.domain.q, self.domain.p) == 1
        h = hash_alg(msg)
        klen = self.domain.n >> 3
        if klen < hash_alg.hlen:
            h = h[:klen]
        h = os2ui(h)
        r = 0
        s = 0
        while r == 0 or s == 0:
            k = random.randint(1, self.domain.q - 1)
            kinv = mod.Mod(k, self.domain.q).inv()
            r = pow(self.domain.g, k, domain.p) % self.domain.q
            s = (kinv * (self.x * r + h)).value
        return r, s

    def encode(self):
        return asn1.encode_int(self.x)


def domaingen(l, n):
    if l < 1024:
        warnings.warn("length less than 1024 insecure")
    domain = DSADomain()
    domain.l = l
    domain.n = n
    domain.q = primes.st_random_prime(n)
    # p-1 has factor q
    domain.p = primes.st_random_prime(l, domain.q)
    e = (domain.p - 1) // domain.q
    h = random.randint(2, domain.p - 2)
    # g^q=1 mod p
    domain.g = pow(h, e, domain.p)
    while domain.g == 1:
        h = random.randint(2, domain.p - 2)
        domain.g = pow(h, e, domain.p)
    return domain


def keygen(domain):
    key = DSAPrivateKey()
    key.domain = domain
    key.x = random.randint(1, domain.q - 1)
    # y=g^x mod p
    key.y = pow(domain.g, key.x, domain.p)
    return key.get_public_key(), key


if __name__ == "__main__":
    domain = domaingen(1024, 160)
    print("domain gen ok")
    pub, prv = keygen(domain)
    print("key gen ok")
    msg = bytes(input("Message: "), "utf-8")
    sign = prv.sign(msg)
    print(f"Signature: {sign}")
    print(f"Verify: {pub.verify(msg,sign)}")
