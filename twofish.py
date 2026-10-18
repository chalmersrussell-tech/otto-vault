"""Pure-Python Twofish block cipher (128-bit block; 128/192/256-bit keys).

Written from the public Twofish specification (Schneier et al., 1998; the
algorithm is unpatented and free to use) for ONE job: reading KeePass 1.x
(.kdb) databases that were saved with the Twofish option. It is slow (about
50 microseconds per block) which is fine for password databases, and it is NOT
constant-time - do not use it for anything else. Verified in the test-suite
against the official known-answer vectors from the specification.
"""
import struct

_MDS_POLY = 0x169
_RS_POLY = 0x14D

_T0 = ((8, 1, 7, 13, 6, 15, 3, 2, 0, 11, 5, 9, 14, 12, 10, 4),
       (14, 12, 11, 8, 1, 2, 3, 5, 15, 4, 10, 6, 7, 0, 9, 13),
       (11, 10, 5, 14, 6, 13, 9, 0, 12, 8, 15, 3, 2, 4, 7, 1),
       (13, 7, 15, 4, 1, 2, 6, 14, 9, 11, 3, 0, 8, 5, 12, 10))
_T1 = ((2, 8, 11, 13, 15, 7, 6, 14, 3, 1, 9, 4, 0, 10, 12, 5),
       (1, 14, 2, 11, 4, 12, 3, 7, 6, 13, 10, 5, 15, 9, 0, 8),
       (4, 12, 7, 5, 1, 6, 9, 10, 0, 14, 13, 8, 2, 11, 3, 15),
       (11, 9, 5, 1, 12, 3, 13, 14, 6, 4, 7, 15, 2, 0, 8, 10))

_MDS = ((0x01, 0xEF, 0x5B, 0x5B), (0x5B, 0xEF, 0xEF, 0x01),
        (0xEF, 0x5B, 0x01, 0xEF), (0xEF, 0x01, 0xEF, 0x5B))
_RS = ((0x01, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E),
       (0xA4, 0x56, 0x82, 0xF3, 0x1E, 0xC6, 0x68, 0xE5),
       (0x02, 0xA1, 0xFC, 0xC1, 0x47, 0xAE, 0x3D, 0x19),
       (0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03))
M32 = 0xFFFFFFFF


def _gf(a, b, poly):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a <<= 1
        if a & 0x100:
            a ^= poly
        b >>= 1
    return r


def _ror4(x, n):
    return ((x >> n) | (x << (4 - n))) & 15


def _make_q(t):
    out = []
    for x in range(256):
        a0, b0 = x >> 4, x & 15
        a1 = a0 ^ b0
        b1 = (a0 ^ _ror4(b0, 1) ^ ((8 * a0) & 15)) & 15
        a2, b2 = t[0][a1], t[1][b1]
        a3 = a2 ^ b2
        b3 = (a2 ^ _ror4(b2, 1) ^ ((8 * a2) & 15)) & 15
        a4, b4 = t[2][a3], t[3][b3]
        out.append((16 * b4) | a4)
    return out


_Q0 = _make_q(_T0)
_Q1 = _make_q(_T1)
_MDS_TAB = [[_gf(m, x, _MDS_POLY) for x in range(256)] for m in (0x01, 0x5B, 0xEF)]


def _rol(x, n):
    return ((x << n) | (x >> (32 - n))) & M32


def _ror(x, n):
    return ((x >> n) | (x << (32 - n))) & M32


def _mds(y):
    out = 0
    for row in range(4):
        v = 0
        for col in range(4):
            v ^= _gf(_MDS[row][col], y[col], _MDS_POLY)
        out |= v << (8 * row)
    return out


def _h(x, L, k):
    y = [(x >> (8 * i)) & 0xFF for i in range(4)]
    lb = [[(w >> (8 * i)) & 0xFF for i in range(4)] for w in L]
    if k == 4:
        y = [_Q1[y[0]] ^ lb[3][0], _Q0[y[1]] ^ lb[3][1], _Q0[y[2]] ^ lb[3][2], _Q1[y[3]] ^ lb[3][3]]
    if k >= 3:
        y = [_Q1[y[0]] ^ lb[2][0], _Q1[y[1]] ^ lb[2][1], _Q0[y[2]] ^ lb[2][2], _Q0[y[3]] ^ lb[2][3]]
    y = [_Q1[_Q0[_Q0[y[0]] ^ lb[1][0]] ^ lb[0][0]],
         _Q0[_Q0[_Q1[y[1]] ^ lb[1][1]] ^ lb[0][1]],
         _Q1[_Q1[_Q0[y[2]] ^ lb[1][2]] ^ lb[0][2]],
         _Q0[_Q1[_Q1[y[3]] ^ lb[1][3]] ^ lb[0][3]]]
    return _mds(y)


class Twofish:
    block_size = 16

    def __init__(self, key):
        if len(key) not in (16, 24, 32):
            raise ValueError("Twofish key must be 16, 24 or 32 bytes")
        k = len(key) // 8
        words = struct.unpack("<%dI" % (2 * k), key)
        me, mo = list(words[0::2]), list(words[1::2])
        s = []
        for i in range(k):
            chunk = key[8 * i:8 * i + 8]
            w = 0
            for r in range(4):
                v = 0
                for c in range(8):
                    v ^= _gf(_RS[r][c], chunk[c], _RS_POLY)
                w |= v << (8 * r)
            s.append(w)
        s.reverse()
        self._S, self._k = s, k
        rho = 0x01010101
        sub = []
        for i in range(20):
            a = _h((2 * i * rho) & M32, me, k)
            b = _rol(_h(((2 * i + 1) * rho) & M32, mo, k), 8)
            sub.append((a + b) & M32)
            sub.append(_rol((a + 2 * b) & M32, 9))
        self._K = sub
        # fast g(): four 256-entry tables built from the key-dependent S-boxes
        self._g = [self._build_g(i) for i in range(4)]

    def _build_g(self, i):
        """Table for byte i of g(): the key-dependent S-box output pushed through
        column i of the MDS matrix (the MDS step is linear over GF(2))."""
        lb = [[(w >> (8 * b)) & 0xFF for b in range(4)] for w in self._S]
        k = self._k
        tab = []
        for x in range(256):
            y = x
            if i == 0:
                if k == 4:
                    y = _Q1[y] ^ lb[3][0]
                if k >= 3:
                    y = _Q1[y] ^ lb[2][0]
                y = _Q1[_Q0[_Q0[y] ^ lb[1][0]] ^ lb[0][0]]
            elif i == 1:
                if k == 4:
                    y = _Q0[y] ^ lb[3][1]
                if k >= 3:
                    y = _Q1[y] ^ lb[2][1]
                y = _Q0[_Q0[_Q1[y] ^ lb[1][1]] ^ lb[0][1]]
            elif i == 2:
                if k == 4:
                    y = _Q0[y] ^ lb[3][2]
                if k >= 3:
                    y = _Q0[y] ^ lb[2][2]
                y = _Q1[_Q1[_Q0[y] ^ lb[1][2]] ^ lb[0][2]]
            else:
                if k == 4:
                    y = _Q1[y] ^ lb[3][3]
                if k >= 3:
                    y = _Q0[y] ^ lb[2][3]
                y = _Q0[_Q1[_Q1[y] ^ lb[1][3]] ^ lb[0][3]]
            vec = [0, 0, 0, 0]
            vec[i] = y
            tab.append(_mds(vec))
        return tab

    def _G(self, x):
        g = self._g
        return g[0][x & 0xFF] ^ g[1][(x >> 8) & 0xFF] ^ g[2][(x >> 16) & 0xFF] ^ g[3][x >> 24]

    def encrypt(self, block):
        if len(block) != 16:
            raise ValueError("block must be 16 bytes")
        K, G = self._K, self._G
        r0, r1, r2, r3 = (w ^ K[i] for i, w in enumerate(struct.unpack("<4I", block)))
        for r in range(16):
            t0 = G(r0)
            t1 = G(_rol(r1, 8))
            f0 = (t0 + t1 + K[2 * r + 8]) & M32
            f1 = (t0 + 2 * t1 + K[2 * r + 9]) & M32
            r2 = _ror(r2 ^ f0, 1)
            r3 = _rol(r3, 1) ^ f1
            r0, r1, r2, r3 = r2, r3, r0, r1
        return struct.pack("<4I", r2 ^ K[4], r3 ^ K[5], r0 ^ K[6], r1 ^ K[7])

    def decrypt(self, block):
        if len(block) != 16:
            raise ValueError("block must be 16 bytes")
        K, G = self._K, self._G
        c0, c1, c2, c3 = struct.unpack("<4I", block)
        r2, r3, r0, r1 = c0 ^ K[4], c1 ^ K[5], c2 ^ K[6], c3 ^ K[7]
        for r in range(15, -1, -1):
            r0, r1, r2, r3 = r2, r3, r0, r1
            t0 = G(r0)
            t1 = G(_rol(r1, 8))
            f0 = (t0 + t1 + K[2 * r + 8]) & M32
            f1 = (t0 + 2 * t1 + K[2 * r + 9]) & M32
            r2 = _rol(r2, 1) ^ f0
            r3 = _ror(r3 ^ f1, 1)
        return struct.pack("<4I", r0 ^ K[0], r1 ^ K[1], r2 ^ K[2], r3 ^ K[3])


def cbc_decrypt(key, iv, data):
    """Twofish-CBC decryption (no padding removal)."""
    if len(data) % 16:
        raise ValueError("ciphertext length must be a multiple of 16")
    tf = Twofish(key)
    out, prev = [], iv
    for i in range(0, len(data), 16):
        blk = data[i:i + 16]
        plain = tf.decrypt(blk)
        out.append(bytes(a ^ b for a, b in zip(plain, prev)))
        prev = blk
    return b"".join(out)


def cbc_encrypt(key, iv, data):
    """Twofish-CBC encryption (data already padded). Used by the tests."""
    if len(data) % 16:
        raise ValueError("plaintext length must be a multiple of 16")
    tf = Twofish(key)
    out, prev = [], iv
    for i in range(0, len(data), 16):
        blk = tf.encrypt(bytes(a ^ b for a, b in zip(data[i:i + 16], prev)))
        out.append(blk)
        prev = blk
    return b"".join(out)
