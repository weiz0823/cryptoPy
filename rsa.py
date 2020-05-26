from arith import basic, mod, primes
import asn1
import warnings
import random
import textwrap
from common import *


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
            raise EncryptionError("message representative out of range")
        return pow(mrepr, self.e, self.n)

    def rsavp(self, srepr: int):
        return self.rsaep(srepr)

    def encrypt_demo(self, msg):
        if isinstance(msg, str):
            return i2osp(self.rsaep(os2ui(bytes(msg, "utf-8"))), self.klen)
        else:
            return i2osp(self.rsaep(os2ui(msg)), self.klen)


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
            raise DecryptionError("ciphertext representative out of range")
        return pow(crepr, self.d, self.n)

    def rsadp(self, crepr: int):
        """Decryption using CRT."""
        if crepr < 0 or crepr >= self.n:
            raise DecryptionError("ciphertext representative out of range")
        # msg mod p
        mp = mod.Mod(crepr, self.p) ** self.dp
        # msg mod q
        mq = mod.Mod(crepr, self.q) ** self.dq
        return mod.crt(mp, mq, self.qinv).value

    def rsasp(self, mrepr: int):
        return self.rsadp(mrepr)

    def decrypt_demo(self, cipher):
        return i2osp(self.rsadp(os2ui(cipher)))


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


if __name__ == "__main__":
    wrapper = textwrap.TextWrapper()

    print("\nTest 2048...")
    pub, prv = keygen(2048)
    pub.print(wrapper)
    prv.print(wrapper)

    #  print("\nTest 3072...")
    #  pub, prv = keygen(3072)
    #  pub.print(wrapper)
    #  prv.print(wrapper)

    print("\nSpecial test 511...")
    pub, prv = keygen(511)
    pub.print(wrapper)
    prv.print(wrapper)

    print("Test 1024...")
    pub, prv = keygen(1024)
    pub.print(wrapper)
    prv.print(wrapper)

    msg = input("Message: ")
    cipher = pub.encrypt_demo(msg)
    print(textwrap.fill(f"RSA-1024 encrypted: {cipher.hex()}"))
    print(f"Decrypted: {prv.decrypt_demo(cipher).decode('utf-8')}")
