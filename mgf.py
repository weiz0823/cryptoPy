"""Mask generation function MGF1."""
import cryptohash
from common import *
from asn1 import OID


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
        y += hashalg.hash_func(seed + counter)
    return y[:masklen]


id_mgf1 = OID("1.2.840.113549.1.1.8", "/ISO/Member-Body/US/RSADSI/PKCS/PKCS-1/MGF1")
