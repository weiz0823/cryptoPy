from arith import basic, mod, primes
import mgf
import asn1
import warnings
import random
import textwrap
import cryptohash
import base64
import randomart
from common import *

id_pkcs1 = asn1.OID("1.2.840.113549.1.1", "/ISO/Member-Body/US/RSADSI/PKCS/PKCS-1")


class RSAPublicKey:
    def __init__(self, n=None, e=None):
        self.n = n
        self.e = e
        self.bitlen = basic.intlen(n)
        self.klen = (self.bitlen + 7) >> 3

    def __repr__(self):
        s = f"--- begin RSA-{self.bitlen} public key ---\n"
        s += f"Modulus n = {self.n}\n"
        s += f"Public exponent e = {self.e}\n"
        s += f"--- end RSA-{self.bitlen} public key ---"
        return s

    def __str__(self):
        return repr(self)

    def print(self, wrapper: textwrap.TextWrapper = None):
        if wrapper is None:
            print(str(self))
        else:
            print(*map(wrapper.fill, str(self).splitlines()), sep="\n")

    def rsaep(self, mrepr: int):
        if mrepr < 0 or mrepr >= self.n:
            raise EncryptError("message representative out of range")
        return pow(mrepr, self.e, self.n)

    rsavp = rsaep

    def encrypt_basic(self, msg):
        if isinstance(msg, str):
            return i2osp(self.rsaep(os2ui(bytes(msg, "utf-8"))), self.klen)
        else:
            return i2osp(self.rsaep(os2ui(msg)), self.klen)

    verify_basic = encrypt_basic

    def encode(self, fmt="pkcs1"):
        if fmt == "pkcs1":
            return asn1.encode_sequence([self.n, self.e])
        else:
            raise EncodeError(f"format {fmt} not implemented")

    @classmethod
    def fromlist(cls, ls: list, fmt="pkcs1"):
        if fmt == "pkcs1":
            if len(ls) != 2:
                raise ValueError(f"expect length 2 but get {len(ls)}")
            if not isinstance(ls[0], int) or not isinstance(ls[1], int):
                raise TypeError(
                    f"expect two integers, get {type(ls[0][0])}, {type(ls[1])}"
                )
            return cls(ls[0], ls[1])
        else:
            raise ValueError(f"format {fmt} not implemented")

    def print_fingerprint(self, fmt="pkcs1", hash_alg=cryptohash.alg_sha256):
        b = self.encode(fmt)
        h = hash_alg(b)
        name = hash_alg.oid.description.rsplit(sep="/", maxsplit=1)[-1]
        print(f"RSA public key fingerprint of format {fmt}:")
        print(f"{name} (hex): {h.hex()}")
        print(f"{name} (base64): {base64.b64encode(h).decode('utf-8')}")
        print("randomart image:")
        print(randomart.visualize(h, f"RSA {self.bitlen}", name))


class RSAPrivateKey:
    def get_public_key(self):
        return RSAPublicKey(self.n, self.e)

    def __repr__(self):
        s = f"--- begin RSA-{self.bitlen} private key ---\n"
        s += f"Prime p = {self.p}\n"
        s += f"Prime q = {self.q}\n"
        s += f"Modulus n = {self.n}\n"
        s += f"Exponent modulus m = lambda(n) = {self.m}\n"
        s += f"Public exponent e = {self.e}\n"
        s += f"Private exponent d = {self.d}\n"
        s += "Additional information for CRT:\n"
        s += f"dp = d mod p = {self.dp}\n"
        s += f"dq = d mod q = {self.dq}\n"
        s += f"qinv = q^{-1} mod p = {self.qinv}\n"
        s += f"--- end RSA-{self.bitlen} private key ---"
        return s

    def __str__(self):
        return repr(self)

    def print(self, wrapper: textwrap.TextWrapper = None):
        if wrapper is None:
            print(str(self))
        else:
            print(*map(wrapper.fill, str(self).splitlines()), sep="\n")

    def rsadp_plain(self, crepr: int):
        """Decryption without using CRT."""
        if crepr < 0 or crepr >= self.n:
            raise DecryptError("ciphertext representative out of range")
        return pow(crepr, self.d, self.n)

    def rsadp(self, crepr: int):
        """Decryption using CRT."""
        if crepr < 0 or crepr >= self.n:
            raise DecryptError("ciphertext representative out of range")
        # msg mod p
        mp = mod.Mod(crepr, self.p) ** self.dp
        # msg mod q
        mq = mod.Mod(crepr, self.q) ** self.dq
        return mod.crt(mq, mp, self.qinv).value

    rsasp = rsadp

    def decrypt_basic(self, cipher):
        return i2osp(self.rsadp(os2ui(cipher)))

    sign_basic = decrypt_basic

    def encode(self, fmt="pkcs1"):
        if fmt == "pkcs1":
            return asn1.encode_sequence(
                [0, self.n, self.e, self.d, self.p, self.q, self.dp, self.dq, self.qinv]
            )
        else:
            raise EncodeError(f"format {fmt} not implemented")

    @classmethod
    def fromlist(cls, ls: list, fmt="pkcs1"):
        if fmt == "pkcs1":
            if len(ls) != 9:
                raise ValueError(f"expect length 9 but get {len(ls)}")
            if ls[0] != 0:
                raise ValueError("multi-prime version not implemented")
            for i in range(1, 9):
                if not isinstance(ls[i], int):
                    raise TypeError(f"expect integer at pos {i}")
            obj = cls()
            obj.n = ls[1]
            obj.e = ls[2]
            obj.d = ls[3]
            obj.p = ls[4]
            obj.q = ls[5]
            obj.dp = ls[6]
            obj.dq = ls[7]
            obj.qinv = ls[8]
            obj.bitlen = basic.intlen(ls[1])
            obj.klen = (obj.bitlen + 7) >> 3
            return obj
        else:
            raise ValueError(f"format {fmt} not implemented")


def keygen(bitlen=1024):
    """Return RSA key pair (pub_key, prv_key)"""
    if bitlen < 1024:
        warnings.warn("bitlen less than 1024 is insecure", SecurityWarning)
    key = RSAPrivateKey()
    key.bitlen = bitlen
    key.klen = (key.bitlen + 7) >> 3
    pbit = (bitlen + 1) >> 1
    key.p = primes.random_prime(pbit)
    key.q = primes.random_prime(pbit)
    key.n = key.p * key.q
    while basic.intlen(key.n) != bitlen:
        key.p = primes.random_prime(pbit)
        key.q = primes.random_prime(pbit)
        key.n = key.p * key.q
    key.m = basic.lcm(key.p - 1, key.q - 1)
    key.d = None
    while key.d is None:
        key.e = random.randint(3, 1 << 20)
        if key.e & 1 == 0:
            key.e += 1
        try:
            key.d = mod.Mod(key.e, key.m).inv().value
        except ValueError:
            key.d = None
    key.dp = key.d % (key.p - 1)
    key.dq = key.d % (key.q - 1)
    key.qinv = mod.Mod(key.q, key.p).inv().value
    return key.get_public_key(), key


id_pspecified = id_pkcs1.subnode("9", "PSpecified")


class ASN1_PSpecified(asn1.AlgID):
    """Get constant label."""

    def __init__(self, s=""):
        self.oid = id_pspecified
        self.param = s
        self.func = None

    def __call__(self):
        return self.param


alg_pemptylabel = ASN1_PSpecified()

id_rsassa_pss = id_pkcs1.subnode("10", "RSASSA-PSS")


class ASN1_RSASSA_PSS(asn1.AlgID):
    def __init__(
        self, hash_alg=cryptohash.alg_sha1, mgf_alg=mgf.alg_mgf1sha1, saltlen=20
    ):
        self.oid = id_rsassa_pss
        self.param = [hash_alg, mgf_alg, saltlen, 1]
        self.func = None

    def sign(self, prv_key: RSAPrivateKey, msg):
        emlen = (prv_key.bitlen + 6) >> 3
        hm = self.param[0](msg)
        hlen = self.param[0].hlen
        saltlen = self.param[2]
        if emlen < hlen + saltlen + 2:
            raise EncodeError("key too short, message too long, or salt too long")
        salt = i2osp(random.getrandbits(saltlen << 3), saltlen)
        hh = self.param[0](bytearray(8) + hm + salt)
        em = bytearray(emlen - saltlen - hlen - 2)
        em.append(0x01)
        em += salt
        mask = self.param[1](hh, emlen - hlen - 1)
        for i in range(len(em)):
            em[i] ^= mask[i]
        mov = (emlen << 3) - prv_key.bitlen + 1
        em[0] &= (1 << (8 - mov)) - 1
        em += hh
        em.append(0xBC)
        return prv_key.sign_basic(em)

    def verify(self, pub_key: RSAPublicKey, msg, sign):
        try:
            em = pub_key.verify_basic(sign)
            if pub_key.bitlen & 7 == 1:
                if em[0] != 0:
                    return False
                em = em[1:]
        except EncryptError:
            return False
        emlen = len(em)
        hm = self.param[0](msg)
        hlen = self.param[0].hlen
        saltlen = self.param[2]
        offset = emlen - hlen - 1
        mov = (emlen << 3) - pub_key.bitlen + 1
        if emlen < hlen + saltlen + 2:
            return False
        if em[-1] != 0xBC:
            return False
        db = em[: emlen - hlen - 1]
        if em[0] >> (8 - mov) != 0:
            return False
        mask = self.param[1](em[offset:-1], emlen - hlen - 1)
        for i in range(len(db)):
            db[i] ^= mask[i]
        db[0] &= (1 << (8 - mov)) - 1
        for i in range(emlen - hlen - saltlen - 2):
            if db[i] != 0:
                return False
        if db[i + 1] != 1:
            return False
        hh = self.param[0](bytearray(8) + hm + db[-saltlen:])
        for i in range(hlen):
            if hh[i] != em[offset + i]:
                return False
        return True


if __name__ == "__main__":
    wrapper = textwrap.TextWrapper()

    #  print("\nTest 2048...")
    #  pub, prv = keygen(2048)
    #  pub.print(wrapper)
    #  prv.print(wrapper)

    #  print("\nTest 3072...")
    #  pub, prv = keygen(3072)
    #  pub.print(wrapper)
    #  prv.print(wrapper)

    print("\nSpecial test 511...")
    pub, prv = keygen(511)
    pub.print_fingerprint()

    print("Test 1024...")
    pub, prv = keygen(1024)
    pub.print_fingerprint()
    with open("rsa.txt", "w") as f:
        f.write(textwrap.fill(base64.b64encode(pub.encode("pkcs1")).decode("utf-8")))
        f.write("\n\n")
        f.write(textwrap.fill(base64.b64encode(prv.encode("pkcs1")).decode("utf-8")))
        f.write("\n\n")
        f.write("The tendency of hierarchies in office environments to be diffuse")
        f.write(" and preclude crisp articulation. -- Douglas Coupland\n")

    s = input("Public key: ")
    if s != "":
        key = ""
        while s != "":
            key += s
            s = input()
        pub = RSAPublicKey.fromlist(asn1.decode(base64.b64decode(key))[0], "pkcs1")
    s = input("Private key: ")
    if s != "":
        key = ""
        while s != "":
            key += s
            s = input()
        prv = RSAPrivateKey.fromlist(asn1.decode(base64.b64decode(key))[0], "pkcs1")

    msg = input("Message: ")
    print()
    cipher = pub.encrypt_basic(msg)
    print(textwrap.fill(f"RSA-1024 encrypted: {cipher.hex()}"))
    print(f"Decrypted: {prv.decrypt_basic(cipher).decode('utf-8')}")
    pss = ASN1_RSASSA_PSS()
    sign = pss.sign(prv, bytearray(msg, "utf-8"))
    print(textwrap.fill(f"RSA-1024 signature: {sign.hex()}"))
    print(f"Consistent? {pss.verify(pub, msg, sign)}")
