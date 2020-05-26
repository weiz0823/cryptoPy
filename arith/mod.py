"""Modular arithmetic with bteer readability with class Mod."""
from functools import total_ordering
import math

if __name__ == "__main__":
    import basic
else:
    from . import basic


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
        d, x, _ = basic.ext_gcd(self.value, self.modulus)
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

    def jacobi(self):
        """Calculate jacobi(value / modulus), return -1, 0, or 1.


        Caution: 0 is defined only when it is Legendre symbol, i.e. modulus is prime.
                 Else, 0 means that symbol is undefined.
                 Note that even modulus is always undefined.
        """
        if self.value == 1 or self.modulus == 1:
            return 1
        elif self.value == 0:
            return 0
        # separate prime factor 2
        e = basic.trailing_zeros(self.value)
        a = self.value >> e
        # calculate jacobi(2^e, modulus)
        t = self.modulus & 7
        if e & 1 == 0:
            s = 1
        elif t & 1 == 0:
            return 0  # undefined for even modulus
        elif t == 1 or t == 7:
            s = 1
        else:  # t == 3 or t == 5
            s = -1
        # now jacobi(value,modulus)=s*jacobi(a,modulus), use QRL to invert it
        # decide the parity of (modulus-1) * (a-1) / 4
        if t & 3 == 3 and a & 3 == 3:
            s = -s
        # reduce like Euclid algorithm and binary gcd
        return s * Mod(self.modulus, a).jacobi()

    def half(self):
        if self.modulus & 1 == 1:
            if self.value & 1 == 1:
                return Mod((self.value + self.modulus) >> 1, self.modulus)
            else:
                return Mod(self.value >> 1, self.modulus)
        else:
            if self.value & 1 == 1:
                raise ValueError(
                    "{} / 2 (mod {}) is not computable".format(self.value, self.modulus)
                )
            else:
                return Mod(self.value >> 1, self.modulus >> 1)


def crt(m1: Mod, m2: Mod, n1inv: int = None):
    """Use CRT to get the same value in new modulus n1*n2.
    Precomputed ninv could be provided as m1.modulus^{-1} mod m2.modulus.
    Require gcd(m1.modulus, m2.modulus) = 1."""
    if n1inv is None:
        try:
            n1inv = Mod(m1.modulus, m2.modulus).inv().value
        except ValueError:
            raise ValueError("modulus not relatively prime, could not perform CRT")
    # knowing CRT holds, we can construct value by whatever means
    h = (m2 - m1.value) * n1inv
    return Mod(m1.value + m1.modulus * h.value, m1.modulus * m2.modulus)


if __name__ == "__main__":
    a = Mod(-1, 5)
    print(a)
    a = a / 3
    print(a)
    print(f"jacobi(5, 3439601197)={Mod(5, 3439601197).jacobi()}")
    print("Tests passed!")
