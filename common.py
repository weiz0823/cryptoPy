def i2osp(i: int):
    osp = bytearray()
    osp.append(i & 0xFF)
    i >>= 8
    if i >= 0:
        while i != 0:
            osp.append(i & 0xFF)
            i >>= 8
        if osp[-1] & 0x80:
            osp.append(0)
    else:
        while i != -1:
            osp.append(i & 0xFF)
            i >>= 8
        if not osp[-1] & 0x80:
            osp.append(0xFF)
    osp.reverse()
    return osp


def os2ip(osp):
    if osp[0] & 0x80:
        i = -1
    else:
        i = 0
    for o in osp:
        i <<= 8
        i |= o
    return i


class CryptoError(Exception):
    """Base class for errors."""

    pass


class EncodeError(CryptoError):
    """Encryption error.

    Attributes:
        message -- explanation of error
    """

    def __init__(self, message=""):
        self.message = message


class DecodeError(CryptoError):
    """Decryption error.

    Attributes:
        message -- explanation of error
    """

    def __init__(self, message=""):
        self.message = message


class EncryptError(CryptoError):
    """Encryption error.

    Attributes:
        message -- explanation of error
    """

    def __init__(self, message=""):
        self.message = message


class DecryptError(CryptoError):
    """Decryption error.

    Attributes:
        message -- explanation of error
    """

    def __init__(self, message=""):
        self.message = message


if __name__ == "__main__":
    raise DecodeError("test of decode error")
