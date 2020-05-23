from common import *
import c_src.cryptohash


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


if __name__ == "__main__":
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
