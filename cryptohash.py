from common import *
import c_src.cryptohash
import asn1


class ASN1_HashAlg:
    def __init__(self, oid: asn1.OID, param, hash_func=None, hlen: int = None):
        self.oid = oid
        self.param = param
        self.hash_func = hash_func
        self.hlen = hlen

    @classmethod
    def fromlist(cls, ls):
        return cls(ls[0], ls[1])

    def encode(self):
        return asn1.encode_sequence([self.oid, self.param])

    def decode(self, octets, index=0):
        """Decode to self and return end index. Throw DecodeError."""
        ls, index = asn1.decode_sequence(octets, index)
        if len(ls) != 2 or not isinstance(ls[0], asn1.OID):
            raise DecodeError
        self.oid = ls[0]
        self.param = ls[1]
        return index


class ASN1_DigestInfo:
    def __init__(self, algid: ASN1_HashAlg, digest):
        self.algid = algid
        self.digest = digest

    @classmethod
    def fromlist(cls, ls):
        return cls(ASN1_HashAlg.fromlist(ls[0]), ls[1])

    def encode(self):
        return asn1.encode_sequence([self.algid, self.digest])

    def decode(self, octets, index=0):
        """Decode to self and return end index. Throw DecodeError."""
        ls, index = asn1.decode_sequence(octets, index)
        if len(ls) != 2 or not isinstance(ls[0], list) or len(ls[0]) != 2:
            raise DecodeError
        self.algid = ASN1_HashAlg.fromlist(ls[0])
        self.param = ls[1]
        return index


def md5(message):
    if isinstance(message, str):
        return c_src.cryptohash.md5(bytes(message, "utf-8"))
    else:
        return c_src.cryptohash.md5(message)


def sha1(message):
    if isinstance(message, str):
        return c_src.cryptohash.sha1(bytes(message, "utf-8"))
    else:
        return c_src.cryptohash.sha1(message)


def sha224(message):
    if isinstance(message, str):
        return c_src.cryptohash.sha224(bytes(message, "utf-8"))
    else:
        return c_src.cryptohash.sha224(message)


def sha256(message):
    if isinstance(message, str):
        return c_src.cryptohash.sha256(bytes(message, "utf-8"))
    else:
        return c_src.cryptohash.sha256(message)


def sha384(message):
    if isinstance(message, str):
        return c_src.cryptohash.sha384(bytes(message, "utf-8"))
    else:
        return c_src.cryptohash.sha384(message)


def sha512(message):
    if isinstance(message, str):
        return c_src.cryptohash.sha512(bytes(message, "utf-8"))
    else:
        return c_src.cryptohash.sha512(message)


def sha512t(message, t):
    if isinstance(message, str):
        return c_src.cryptohash.sha512t(bytes(message, "utf-8"), t)
    else:
        return c_src.cryptohash.sha512t(message, t)


def sha512_224(message):
    if isinstance(message, str):
        return c_src.cryptohash.sha512_224(bytes(message, "utf-8"))
    else:
        return c_src.cryptohash.sha512_224(message)


def sha512_256(message):
    if isinstance(message, str):
        return c_src.cryptohash.sha512_256(bytes(message, "utf-8"))
    else:
        return c_src.cryptohash.sha512_256(message)


def sha3_224(message):
    if isinstance(message, str):
        return c_src.cryptohash.sha3_224(bytes(message, "utf-8"))
    else:
        return c_src.cryptohash.sha3_224(message)


def sha3_256(message):
    if isinstance(message, str):
        return c_src.cryptohash.sha3_256(bytes(message, "utf-8"))
    else:
        return c_src.cryptohash.sha3_256(message)


def sha3_384(message):
    if isinstance(message, str):
        return c_src.cryptohash.sha3_384(bytes(message, "utf-8"))
    else:
        return c_src.cryptohash.sha3_384(message)


def sha3_512(message):
    if isinstance(message, str):
        return c_src.cryptohash.sha3_512(bytes(message, "utf-8"))
    else:
        return c_src.cryptohash.sha3_512(message)


def shake128(message):
    if isinstance(message, str):
        return c_src.cryptohash.shake128(bytes(message, "utf-8"))
    else:
        return c_src.cryptohash.shake128(message)


def shake256(message):
    if isinstance(message, str):
        return c_src.cryptohash.shake256(bytes(message, "utf-8"))
    else:
        return c_src.cryptohash.shake256(message)


def shake128l(message, l):
    if isinstance(message, str):
        return c_src.cryptohash.shake128l(bytes(message, "utf-8"), l)
    else:
        return c_src.cryptohash.shake128l(message, l)


def shake256l(message, l):
    if isinstance(message, str):
        return c_src.cryptohash.shake256l(bytes(message, "utf-8"), l)
    else:
        return c_src.cryptohash.shake256l(message, l)


def rawshake128l(message, l):
    if isinstance(message, str):
        return c_src.cryptohash.rawshake128l(bytes(message, "utf-8"), l)
    else:
        return c_src.cryptohash.rawshake128l(message, l)


def rawshake256l(message, l):
    if isinstance(message, str):
        return c_src.cryptohash.rawshake256l(bytes(message, "utf-8"), l)
    else:
        return c_src.cryptohash.rawshake256l(message, l)


def keccak_diy(message, l, cap, pad):
    if isinstance(message, str):
        return c_src.cryptohash.keccak_diy(bytes(message, "utf-8"), l, cap, pad)
    else:
        return c_src.cryptohash.keccak_diy(message, l, cap, pad)


id_digest_alg = asn1.OID(
    "1.2.840.113549.2", "/ISO/Member-Body/US/RSADSI/DigestAlgorithm"
)
id_nist_hash = asn1.OID(
    "2.16.840.1.101.3.4.2",
    "/Joint-ISO-ITU-T/Country/US/Organization/gov/CSOR/NISTAlgorithm/HashAlgs",
)
id_secsig_alg = asn1.OID(
    "1.3.14.3.2", "/ISO/Identified-Organization/OIW/SecSIG/Algorithms"
)
id_md5 = id_digest_alg.subnode("5", "MD5")
alg_md5 = ASN1_HashAlg(id_md5, None, md5, 16)
id_sha1 = id_secsig_alg.subnode("26", "SHA1")
alg_sha1 = ASN1_HashAlg(id_sha1, None, sha1, 20)
id_sha224 = id_nist_hash.subnode("4", "SHA224")
alg_sha224 = ASN1_HashAlg(id_sha224, None, sha224, 28)
id_sha256 = id_nist_hash.subnode("1", "SHA256")
alg_sha256 = ASN1_HashAlg(id_sha256, None, sha256, 32)
id_sha384 = id_nist_hash.subnode("2", "SHA384")
alg_sha384 = ASN1_HashAlg(id_sha384, None, sha384, 48)
id_sha512 = id_nist_hash.subnode("3", "SHA512")
alg_sha512 = ASN1_HashAlg(id_sha512, None, sha512, 64)
id_sha512_224 = id_nist_hash.subnode("5", "SHA512-224")
alg_sha512_224 = ASN1_HashAlg(id_sha512_224, None, sha512_224, 28)
id_sha512_256 = id_nist_hash.subnode("6", "SHA512-256")
alg_sha512_256 = ASN1_HashAlg(id_sha512_256, None, sha512_256, 32)


if __name__ == "__main__":
    print("md5:", alg_md5.encode().hex())
    print("sha512/256:", alg_sha512_256.encode().hex())
    a = input("Message: ")
    print(f"utf-8 encoded message length is: {len(a)} bytes")
    print(f"md5: 0x {md5(a).hex()}")
    print(f"sha1: 0x {sha1(a).hex()}")
    print(f"sha224: 0x {sha224(a).hex()}")
    print(f"sha256: 0x {sha256(a).hex()}")
    print(f"sha384: 0x {sha384(a).hex()}")
    print(f"sha512: 0x {sha512(a).hex()}")
    print(f"sha512/t (t=224): 0x {sha512t(a, 224).hex()}")
    print(f"sha512/224: 0x {sha512_224(a).hex()}")
    print(f"sha512/t (t=256): 0x {sha512t(a, 256).hex()}")
    print(f"sha512/256: 0x {sha512_256(a).hex()}")
    print(f"sha3_224: 0x {sha3_224(a).hex()}")
    print(f"sha3_256: 0x {sha3_256(a).hex()}")
    print(f"sha3_384: 0x {sha3_384(a).hex()}")
    print(f"sha3_512: 0x {sha3_512(a).hex()}")
    print(f"shake128: 0x {shake128(a).hex()}")
    print(f"shake128l (l=256): 0x {shake128l(a, 256).hex()}")
    print(f"shake256: 0x {shake256(a).hex()}")
    print(f"shake256l (l=512): 0x {shake256l(a, 512).hex()}")
