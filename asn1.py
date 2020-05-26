"""Abstract Syntac Notation One.

Encode/decode protocol:
(requirement) encode(self) -> bytes/bytearray -- returns the encoded octet string
(suggestion) decode(self, octets, index=0) --
  Return whatever information you like. Common to decode to self and return end_index.
  Will NOT be called by auto-distributing function."""
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
    elif isinstance(value, list) or isinstance(value, Sequence):
        return encode_sequence(value)
    else:
        try:
            return value.encode()
        except ValueError or AttributeError:
            raise EncodeError("cannot encode type {}".format(type(value)))


def decode(octets, index=0):
    try:
        tag = octets[index]
        if tag == 0:
            raise DecodeError("unexpected end-of-content")
        elif tag == 0x1:
            return decode_bool(octets, index)
        elif tag == 0x2:
            return decode_int(octets, index)
        elif tag == 0x4:
            return decode_octet_string(octets, index)
        elif tag == 0x5:
            return decode_null(octets, index)
        elif tag == 0x6:
            return decode_oid(octets, index)
        elif tag == 0x8:
            return decode_utf8string(octets, index)
        elif tag == 0x30:
            return decode_sequence(octets, index)
        elif tag & 0xC0:
            return decode_custom(octets, index)
    except IndexError:
        raise DecodeError("length of octets not enough")


class _EOC:
    """Represent a end-of-content in ASN.1."""

    pass


class Sequence:
    """Sequence in ASN.1."""

    def __init__(self, iterable):
        self.ls = iterable


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

    def __int__(self):
        return os2ip(encode_oid(self))


id_ber_encoding = OID("2.1.1", "/Joint-ISO-ITU-T/ASN.1/Basic-Encoding")
id_cer_encoding = OID(
    "2.1.2.0", "/Joint-ISO-ITU-T/ASN.1/BER-Derived/Canonical-Encoding"
)
id_der_encoding = OID(
    "2.1.2.1", "/Joint-ISO-ITU-T/ASN.1/BER-Derived/Distinguished-Encoding"
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


def decode_null():
    try:
        if octets[index] != 0x5 or octets[index + 1] != 0:
            raise DecodeError("not a null object")
    except IndexError:
        raise DecodeError("length of octets not enough")


def encode_bool(value):
    if value:
        return bytearray([0x1, 0x1, 0xFF])
    else:
        return bytearray([0x1, 0x1, 0])


def decode_bool(octets, index=0):
    try:
        if octets[index] != 0x1 or octets[index + 1] != 0x1:
            raise DecodeError("not a bool object")
        return bool(octets[index + 2])
    except IndexError:
        raise DecodeError("length of octets not enough")


def encode_int(value):
    osp = i2osp(value)
    return bytearray([0x2]) + encode_length_octets(len(a)) + osp


def decode_int(octets, index=0):
    try:
        if octets[index] != 0x2:
            raise DecodeError("not an int object")
        length, index = decode_length_octets(octets, index + 1)
        return os2ip(octets[index : index + length]), index + length
    except IndexError:
        raise DecodeError("length of octets not enough")


def encode_octet_string(value):
    return bytearray([0x4]) + encode_length_octets(len(value)) + value


def decode_octet_string(octets, index=0):
    try:
        if octets[index] != 0x4:
            raise DecodeError("not a octet string object")
        length, index = decode_length_octets(octets, index + 1)
        octets[index + length - 1]  # test for index
        return octets[index : index + length], index + length
    except IndexError:
        raise DecodeError("length of octets not enough")


def encode_oid(value):
    octets = bytearray()
    ls = list(map(int, value.identifier.split(".")))
    if len(ls) < 2:
        raise EncodeError("wrong identifier")
    i = ls[0] * 40 + ls[1]
    if i >= 0x80:
        rev = bytearray()
        while i > 0:
            rev.append(0x80 | (i & 0x7F))
            i >>= 7
        rev[0] &= 0x7F
        rev.reverse()
        octets += rev
    else:
        octets.append(i)
    for i in ls[2:]:
        if i >= 0x80:
            rev = bytearray()
            while i > 0:
                rev.append(0x80 | (i & 0x7F))
                i >>= 7
            rev[0] &= 0x7F
            rev.reverse()
            octets += rev
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
        octets[index + length - 1]  # test for index
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
    return OID(".".join(map(str, ls)), ""), index + length


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


def decode_utf8string(octets, index=0):
    try:
        if octets[index] == 0xC:
            # primitive
            length, index = decode_length_octets(octets, index + 1)
            octets[index + length - 1]  # test for index
            return str(octets[index : index + length]), index + length
        elif octets[index + 1] == 0x80:
            # indefinite
            if octets[index + 2] != 0x4:
                raise DecodeError("wrapped content is not octet string")
            length, index = decode_length_octets(octets, index + 3)
            if octets[index + length] != 0 or octets[index + length + 1] != 0:
                raise DecodeError("indefinite length form not followed by EOC")
            return str(octets[index : index + length]), index + length + 2
        else:
            # definite
            length, index = decode_length_octets(octets, index + 1)
            if octets[index] != 0x4:
                raise DecodeError("wrapped content is not octet string")
            length, index = decode_length_octets(octets, index + 1)
            octets[index + length - 1]  # test for index
            return str(octets[index : index + length]), index + length
    except IndexError:
        raise DecodeError("length of octets not enough")


def encode_sequence(value):
    if isinstance(value, Sequence):
        value = value.ls
    octets = bytearray()
    for i in value:
        octets += encode(i)
    return bytearray([0x30]) + encode_length_octets(len(octets)) + octets


def decode_sequence(octets, index=0):
    ls = []
    try:
        if octets[index] != 0x30:
            raise DecodeError("not a sequence")
        length, index = decode_length_octets(octets, index + 1)
        end_index = index + length
        while index < end_index:
            obj, index = decode(octets, index)
            ls.append(obj)
        if index > end_index:
            raise DecodeError("the last object doesn't end at the right place")
        return ls, end_index
    except IndexError:
        raise DecodeError("length of octets not enough")


def decode_custom(octets, index=0, more_info=None):
    """Decode custom class as a sequence.

    If the custom class is implicit, and of primitive type, decoding may fail.
    """
    ls = []
    try:
        tag, isconstructed, class_type, index = decode_id_octets(octets, index)
        if isinstance(more_info, list):
            more_info.append(tag)
            more_info.append(isconstructed)
            more_info.append(class_type)
        length, index = decode_length_octets(octets, index)
        end_index = index + length
        while index < end_index:
            obj, index = decode(octets, index)
            ls.append(obj)
        if index > end_index:
            raise DecodeError("the last object doesn't end at the right place")
        return ls, end_index
    except IndexError:
        raise DecodeError("length of octets not enough")


if __name__ == "__main__":
    code = encode(id_ber_encoding)
    print(code.hex(), int(id_ber_encoding))
    print(decode(code)[0].identifier)
