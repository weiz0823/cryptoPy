from functools import total_ordering
import math


def trailing_zeros(a: int):
    """Return number of trailing zeros in binary representation of a."""
    i = 0
    while a & (1 << i) == 0:
        i += 1

    return i


def ext_gcd(a: int, b: int):
    """Extended Euclid Algorithm.

    Returns (d, x, y), where d = gcd(a, b) = a*x + b*y.
    """
    # maintain matrix x, y; z, w
    if a > b:
        x = 1
        y = 0
        z = 0
        w = 1
    else:
        x = 0
        y = 1
        z = 1
        w = 0
        a, b = b, a

    if b < 0:
        q, r = divmod(a, b)
        x = x - q * z
        y = y - q * w
        a = r
    while b != 0:
        q, r = divmod(a, b)
        x, z = z, x - q * z
        y, w = w, y - q * w
        a, b = b, r
    return (a, x, y)


@total_ordering
class Mod:
    """Modular arithmetic with better readability.

    Attributes:
        modulus -- modulus of the number, should be a non-zero integer
        value -- the value in modulus, where 0 <= value < modulus

    Operator +, -, *, /, //, ** are defined. / and // are equivalent.
    a/b (mod n) is defined only if a % gcd(b, n) == 0.
      And the modulus of the result is n//gcd(b,n).
    """

    def __init__(self, value: int, modulus: int):
        if modulus == 0:
            raise ZeroDivisionError("modulus is zero")
        self.value = value % modulus
        self.modulus = modulus
        pass

    def __repr__(self):
        return "{} (mod {})".format(self.value, self.modulus)

    __str__ = __repr__

    def __int__(self):
        return self.value

    def __bytes__(self):
        return bytes(self.value)

    def _convert(self, other):
        """Convert other to int with type checking"""
        if isinstance(other, Mod):
            if self.modulus == 0 or other.modulus == 0:
                raise ZeroDivisionError("modulus is zero")
            elif self.modulus == other.modulus:
                return other.value
            else:
                raise ValueError("not the same modulus")
        elif isinstance(other, int):
            return other
        else:
            # for operators usage
            return NotImplemented

    def __eq__(self, other):
        converted = self._convert(other)
        if converted is NotImplemented:
            return NotImplemented
        else:
            return self.value == converted

    def __lt__(self, other):
        converted = self._convert(other)
        if converted is NotImplemented:
            return NotImplemented
        else:
            return self.value < converted

    def __hash__(self):
        return hash((self.value, self.modulus))

    def __bool__(self):
        return bool(value)

    def __pos__(self):
        return Mod(self.value, self.modulus)

    def __neg__(self):
        return Mod(-self.value, self.modulus)

    def __add__(self, other):
        converted = self._convert(other)
        if converted is NotImplemented:
            return NotImplemented
        else:
            return Mod(self.value + converted, self.modulus)

    __radd__ = __add__

    def __sub__(self, other):
        return self + (-other)

    def __rsub__(self, other):
        return (-self) + other

    def __mul__(self, other):
        converted = self._convert(other)
        if converted is NotImplemented:
            return NotImplemented
        else:
            return Mod(self.value * converted, self.modulus)

    __rmul__ = __mul__

    def invertible(self):
        return math.gcd(self.value, self.modulus) == 1

    def inv(self):
        d, x, _ = ext_gcd(self.value, self.modulus)
        if d != 1:
            raise ValueError(
                "gcd({},{}) == {} is not 1, not invertible".format(
                    self.value, self.modulus, d
                )
            )
        else:
            return Mod(x, self.modulus)

    def __truediv__(self, other):
        """Return t: Mod such that self == int(other)*t. Note that the modulus of t may differ."""
        converted = self._convert(other)
        if converted is NotImplemented:
            return NotImplemented
        d = math.gcd(converted, self.modulus)
        q, r = divmod(self.value, d)
        if r != 0:
            raise ValueError(
                "{} / {} (mod {}) is not computable".format(
                    self.value, converted, self.modulus
                )
            )
        return Mod(converted // d, self.modulus // d).inv() * q

    def __rtruediv__(self, other):
        converted = self._convert(other)
        if converted is NotImplemented:
            return NotImplemented
        d = math.gcd(self.value, self.modulus)
        q, r = divmod(converted, d)
        if r != 0:
            raise ValueError(
                "{} / {} (mod {}) is not computable".format(
                    converted, self.value, self.modulus
                )
            )
        return Mod(self.value // d, self.modulus // d).inv() * q

    __floordiv__ = __truediv__
    __rfloordiv__ = __rtruediv__

    def __pow__(self, other: int):
        return Mod(pow(self.value, other, self.modulus), self.modulus)


if __name__ == "__main__":
    a = Mod(-1, 5)
    print(a)
    a = a / 3
    print(a)
    print("Tests passed!")
