"""Common functions and exception handling."""


def i2osp(i: int, k=None):
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
    l = len(osp)
    if k is not None:
        if k > l:
            return bytearray(k - l) + osp
        elif k < l:
            return osp[-k:]
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

    def __init__(self, message=""):
        self.message = message


class SecurityWarning(Warning):
    """Base class for security warnings."""

    def __init__(self, message=""):
        self.message = message


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


class HashWarning(SecurityWarning):
    """Warnings for undefined (or insecure) hash operations."""

    def __init__(self, message=""):
        self.message = message


if __name__ == "__main__":
    import warnings

    warnings.simplefilter("ignore", SecurityWarning)
    warnings.warn("test of hash warning", HashWarning)
    raise DecodeError("test of decode error")
