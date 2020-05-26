"""Mask generation function MGF1."""
import cryptohash
from common import *
import asn1


def mgf1(seed, masklen, hashalg: cryptohash.ASN1_HashAlg):
    if masklen > hashalg.hlen << 32:
        raise CryptoError("mask too long")
    t = (masklen + hashalg.hlen - 1) // hashalg.hlen
    counter = bytearray(4)
    y = bytearray()
    for i in range(t):
        for j in range(3, -1, -1):
            if counter[j] != 255:
                counter[j] += 1
                break
            else:
                counter[j] = 0
        y += hashalg(seed + counter)
    return y[:masklen]


class ASN1_MGFAlg(asn1.AlgID):
    def __init__(self, oid, hash_alg, func):
        self.oid = oid
        self.param = hash_alg
        self.func = func

    def decode(self, octets, index=0):
        ls = asn1.decode(octets, index)
        if (
            len(ls) != 2
            or not isinstance(ls[0], asn1.OID)
            or not isinstance(ls[1], list)
        ):
            raise DecodeError
        self.oid = ls[0]
        self.hash_alg = cryptohash.ASN1_HashAlg.fromlist(ls[1])

    @classmethod
    def fromlist(cls, ls):
        return cls(ls[0], cryptohash.ASN1_HashAlg.fromlist(ls[1]))

    def __call__(self, seed, masklen):
        return self.func(seed, masklen, self.param)


id_mgf1 = asn1.OID(
    "1.2.840.113549.1.1.8", "/ISO/Member-Body/US/RSADSI/PKCS/PKCS-1/MGF1"
)
alg_mgf1sha1 = ASN1_MGFAlg(id_mgf1, cryptohash.alg_sha1, mgf1)
