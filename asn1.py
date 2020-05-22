from common import *


def encode(value):
    """ASN.1 defined DER encoding. Will choose encoding according to the type of value.

    object -- encoding:
    None -- null
    EOC -- EOC

    type(s) -- encoding:
    int -- int
    str -- utf8string
    bytes, bytearray -- octet string (primitive form)
    OID -- object identifier
    list, Sequence -- sequence
    """
    if value is None:
        return encode_null()
    elif isinstance(value, _EOC):
        return encode_eoc()
    elif isinstance(value, int):
        return encode_int(value)
    elif isinstance(value, str):
        return encode_utf8string(value)
    elif isinstance(value, bytes) or isinstance(value, bytearray):
        return encode_octet_string(value)
    elif isinstance(value, OID):
        return encode_oid(value)
    elif isinstance(value, list):
        return Sequence(value).encode()
    elif isinstance(value, Sequence):
        return value.encode()
    else:
        raise EncodeError("cannot encode type {}".format(type(value)))


class _EOC:
    """Represent a end-of-content in ASN.1."""

    pass


class Sequence:
    """Sequence in ASN.1."""

    def __init__(self, iterable):
        self.ls = iterable

    def encode(self):
        octets = bytearray()
        for i in self.ls:
            octets += encode(i)
        return bytearray([0x30]) + encode_length_octets(len(octets)) + octets


EOC = _EOC()

Null = None


class OID:
    """Object Identifier defined by ASN.1."""

    def __init__(self, identifier: str, description: str):
        self.identifier = identifier
        self.description = description

    def subnode(self, append_identifier: str, append_description: str):
        return OID(
            self.identifier + "." + append_identifier,
            self.description + "/" + append_description,
        )

    def parent_node(self):
        return OID(
            self.identifier.rsplit(".", 1)[0], self.description.rsplit("/", 1)[0]
        )


def encode_id_octets(tag: int, isconstructed=False, class_type=0):
    """Encode identifier octets in ASN.1."""
    id_octets = bytearray()
    if tag < 31:
        id_octets.append(tag)
    else:
        while tag > 0:
            id_octets.append(0x80 | (tag & 0x7F))
            tag >>= 7
        id_octets[0] &= 0x7F
        id_octets.append(0x1F)
        id_octets.reverse()

    if isconstructed:
        id_octets[0] |= 0x20
    id_octets[0] |= class_type << 6
    return id_octets


def decode_id_octets(octets, index=0):
    """Decode identifier octets in ASN.1.

    Return: tag, isconstructed, class_type, end_index
    tag -- tag number
    isconstructed -- 1 for constructed, 0 for primitive
    class_type -- Universal / Application / ...
    end_index -- end of identifier octets
    """
    class_type = (octets[index] & 0xC0) >> 6
    isconstructed = bool(octets[index] & 0x20)
    tag = octets[index] & 0x1F
    end_index = index + 1
    if tag == 0x1F:
        tag = 0
        i = index + 1
        try:
            while octets[i] & 0x80:
                tag |= octets[i] & 0x7F
                tag <<= 7
                i += 1
            tag |= octets[i]
            end_index = i + 1
        except IndexError:
            raise DecodeError("length of octets not enough")
        if tag < 0x1F:
            raise DecodeError("identifier octets not properly encoded")
    return tag, isconstructed, class_type, end_index


def encode_length_octets(length: int):
    """Encode length octets in ASN.1."""
    len_octets = bytearray()
    if length < 0:
        # indefinite form
        len_octets.append(0x80)
    elif length < 0x80:
        # definite short
        len_octets.append(length)
    else:
        # definite long
        while length > 0:
            len_octets.append(length & 0xFF)
            length >>= 8
        len_octets.append(0x80 | len(len_octets))
        len_octets.reverse()
    return len_octets


def decode_length_octets(octets, index=0):
    """Decode length octets in ASN.1. Return length, end_index"""
    if octets[index] == 0x80:
        # indefinite form
        return -1, index + 1
    elif octets[index] & 0x80:
        # definite long
        num = octets[index] & 0x7F
        try:
            octets[index + num - 1]
        except IndexError:
            raise DecodeError("length of octets not enough")
        length = 0
        for i in range(num):
            length <<= 8
            length |= octets[index + 1 + i]
        if length < 0x80:
            raise DecodeError("length {} should be in short form".format(length))
        return length, index + 1 + num
    else:
        # definite short
        return octets[index], index + 1


def encode_eoc():
    return bytearray([0, 0])


def encode_null():
    return bytearray([0x5, 0])


def encode_bool(value):
    if value:
        return bytearray([0x1, 0x1, 0xFF])
    else:
        return bytearray([0x1, 0x1, 0])


def encode_int(value):
    osp = i2osp(value)
    return bytearray([0x2]) + encode_length_octets(len(a)) + osp


def encode_octet_string(value):
    return bytearray([0x4]) + encode_length_octets(len(value)) + value


def encode_oid(value):
    octets = bytearray()
    ls = list(map(int, value.identifier.split(".")))
    if len(ls) < 2:
        raise EncodeError("wrong identifier")
    i = ls[0] * 40 + ls[1]
    if i >= 0x80:
        while i > 0:
            octets.append(0x80 | (i & 0x7F))
            i >>= 7
        octets[-1] &= 0x7F
    else:
        octets.append(i)
    for i in ls[2:]:
        if i >= 0x80:
            while i > 0:
                octets.append(0x80 | (i & 0x7F))
                i >>= 7
            octets[-1] &= 0x7F
        else:
            octets.append(i)
    return bytearray([0x6]) + encode_length_octets(len(octets)) + octets


def decode_oid(octets, index=0):
    ls = []
    if octets[index] != 0x6:
        raise DecodeError("not an object identifier")
    length, index = decode_length_octets(octets, index + 1)
    if length <= 0:
        raise DecodeError("length of encoded OID should be at least 1")
    try:
        octets[index + length - 1]
    except IndexError:
        raise DecodeError("length of octets not enough")
    tmp = 0
    i = 0
    try:
        while octets[index + i] & 0x80:
            tmp |= octets[index + i] & 0x7F
            tmp <<= 7
            i += 1
            if i >= length:
                raise IndexError
        tmp |= octets[index + i]
        i += 1
        if tmp < 40:
            ls += [0, tmp]
        elif tmp < 80:
            ls += [1, tmp - 40]
        else:
            ls += [2, tmp - 80]
    except IndexError:
        raise DecodeError("not properly encoded")

    try:
        while i < length:
            tmp = 0
            while octets[index + i] & 0x80:
                tmp |= octets[index + i] & 0x7F
                tmp <<= 7
                i += 1
                if i >= length:
                    raise IndexError
            tmp |= octets[index + i]
            ls.append(tmp)
            i += 1
    except IndexError:
        raise DecodeError("not properly encoded")
    return OID(".".join(map(str, ls)), "")


def encode_utf8string(value, encode_type=0):
    """BER encoding of utf8string.

    Parameters:
        value -- the string to be encoded
        encode_type -- choice of encoding.
            0) primitive (default)
            1) constructed, definite length
            2) constructed, indefinite length
    """
    if encode_type == 0:
        return bytearray([0xC]) + encode_length_octets(len(value)) + bytes(value)
    elif encode_type == 1:
        octets = encode_octet_string(bytes(value))
        return bytearray([0x2C]) + encode_length_octets(len(octets)) + octets
    elif encode_type == 2:
        return (
            bytearray([0x2C, 0x80]) + encode_octet_string(bytes(value)) + encode_eoc()
        )
    else:
        raise EncodeError("unrecognized type for utf8string encoding")
