# coding: utf-8
# PyGOST -- Pure Python GOST cryptographic functions library
# Copyright (C) 2015-2019 Sergey Matveev <stargrave@stargrave.org>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from codecs import getdecoder
from codecs import getencoder
from sys import version_info


xrange = range if version_info[0] == 3 else xrange  # pylint: disable=redefined-builtin


def strxor(a, b):
    """ XOR of two strings

    This function will process only shortest length of both strings,
    ignoring remaining one.
    """
    mlen = min(len(a), len(b))
    a, b, xor = bytearray(a), bytearray(b), bytearray(mlen)
    for i in xrange(mlen):
        xor[i] = a[i] ^ b[i]
    return bytes(xor)


_hexdecoder = getdecoder("hex")
_hexencoder = getencoder("hex")


def hexdec(data):
    """Decode hexadecimal
    """
    return _hexdecoder(data)[0]


def hexenc(data):
    """Encode hexadecimal
    """
    return _hexencoder(data)[0].decode("ascii")


def bytes2long(raw):
    """ Deserialize big-endian bytes into long number

    :param bytes raw: binary string
    :returns: deserialized long number
    :rtype: int
    """
    if isinstance(raw, int):
        return raw

    return int(hexenc(raw), 16)


def long2bytes(n, size=32):
    """ Serialize long number into big-endian bytestring

    :param long n: long number
    :returns: serialized bytestring
    :rtype: bytes
    """
    res = hex(int(n))[2:].rstrip("L")
    if len(res) % 2 != 0:
        res = "0" + res
    s = hexdec(res)
    if len(s) != size:
        s = (size - len(s)) * b"\x00" + s
    return s


def modinvert(a, n):
    """ Modular multiplicative inverse

    :returns: inverse number. -1 if it does not exist

    Realization is taken from:
    https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
    """
    if a < 0:
        # k^-1 = p - (-k)^-1 mod p
        return n - modinvert(-a, n)
    t, newt = 0, 1
    r, newr = n, a
    while newr != 0:
        quotinent = r // newr
        t, newt = newt, t - quotinent * newt
        r, newr = newr, r - quotinent * newr
    if r > 1:
        return -1
    if t < 0:
        t = t + n
    return t
