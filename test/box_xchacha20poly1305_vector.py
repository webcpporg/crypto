#!/usr/bin/env python3
# Copyright (c) 2026 WebCpp.org
#
# Distributed under the Boost Software License, Version 1.0. (See
# accompanying file LICENSE_1_0.txt or copy at
# https://www.boost.org/LICENSE_1_0.txt)

"""Computes the X25519-XChaCha20-Poly1305 box vector of box_sodium_test.cpp.

Usage: python3 -I box_xchacha20poly1305_vector.py

libsodium's tests print no ciphertext for crypto_box_curve25519xchacha20poly1305, so this
script computes one with an implementation of its own, independent of libsodium: X25519
(RFC 7748), HChaCha20, ChaCha20 with djb's 64-bit nonce and Poly1305, put together as
libsodium's construction is: the precomputed key is HChaCha20 of the X25519 shared secret under
a zero nonce, and the box is the XChaCha20-Poly1305 secret box under that key (the first 32
bytes of the key stream are Poly1305's key, the message is XORed with the rest).

Before it computes anything it checks itself: libsodium's three XChaCha20-Poly1305 secret boxes
of test/default/xchacha20.c, and RFC 7748's Alice and Bob, whose two precomputed keys must
agree. Then it prints, for NaCl's keys, nonce and message of libsodium's test/default/box.c,
the precomputed key, the tag and the ciphertext. Its output is the committed vector:
box_sodium_test.cpp's box_xchacha_key and box_xchacha_cases, and the tag of the superproject's
fixture box_xchacha20poly1305_default.
It needs nothing but Python 3, and it reads and writes no file.
"""

import struct
import sys
from typing import List, Tuple

P = 2**255 - 19
MASK = 0xFFFFFFFF
SIGMA = list(struct.unpack('<4I', b'expand 32-byte k'))


def x25519(scalar: bytes, point: bytes) -> bytes:
    """X25519 of RFC 7748, section 5: the Montgomery ladder over the clamped scalar."""
    clamped = bytearray(scalar)
    clamped[0] &= 248
    clamped[31] &= 127
    clamped[31] |= 64
    k = int.from_bytes(clamped, 'little')
    u = int.from_bytes(point, 'little') & ((1 << 255) - 1)
    x1, x2, z2, x3, z3, swap = u, 1, 0, u, 1, 0
    for t in reversed(range(255)):
        bit = (k >> t) & 1
        swap ^= bit
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = bit
        a = x2 + z2
        aa = a * a
        b = x2 - z2
        bb = b * b
        e = aa - bb
        c = x3 + z3
        d = x3 - z3
        da = d * a
        cb = c * b
        x3 = (da + cb) ** 2 % P
        z3 = x1 * (da - cb) ** 2 % P
        x2 = aa * bb % P
        z2 = e * (aa + 121665 * e) % P
    if swap:
        x2, z2 = x3, z3
    return (x2 * pow(z2, P - 2, P) % P).to_bytes(32, 'little')


def rotl(value: int, count: int) -> int:
    """A 32-bit word rotated left by count bits."""
    return ((value << count) & MASK) | (value >> (32 - count))


def quarter_round(state: List[int], a: int, b: int, c: int, d: int) -> None:
    """ChaCha's quarter round on four words of state."""
    state[a] = (state[a] + state[b]) & MASK
    state[d] = rotl(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & MASK
    state[b] = rotl(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & MASK
    state[d] = rotl(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & MASK
    state[b] = rotl(state[b] ^ state[c], 7)


def rounds(state: List[int]) -> None:
    """ChaCha20's twenty rounds, ten column and ten diagonal."""
    for _ in range(10):
        quarter_round(state, 0, 4, 8, 12)
        quarter_round(state, 1, 5, 9, 13)
        quarter_round(state, 2, 6, 10, 14)
        quarter_round(state, 3, 7, 11, 15)
        quarter_round(state, 0, 5, 10, 15)
        quarter_round(state, 1, 6, 11, 12)
        quarter_round(state, 2, 7, 8, 13)
        quarter_round(state, 3, 4, 9, 14)


def hchacha20(key: bytes, nonce: bytes) -> bytes:
    """HChaCha20: the rounds over the key and a 16-byte nonce, words 0-3 and 12-15 out."""
    state = SIGMA + list(struct.unpack('<8I', key)) + list(struct.unpack('<4I', nonce))
    rounds(state)
    return struct.pack('<8I', *(state[0:4] + state[12:16]))


def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    """A block of djb's ChaCha20: a 64-bit counter and an 8-byte nonce."""
    state = (SIGMA + list(struct.unpack('<8I', key)) + [counter & MASK, counter >> 32] +
             list(struct.unpack('<2I', nonce)))
    mixed = state[:]
    rounds(mixed)
    return struct.pack('<16I', *[(x + y) & MASK for x, y in zip(mixed, state)])


def key_stream(key: bytes, nonce: bytes, length: int) -> bytes:
    """length bytes of ChaCha20's key stream from the counter 0."""
    out = b''
    counter = 0
    while len(out) < length:
        out += chacha20_block(key, counter, nonce)
        counter += 1
    return out[:length]


def poly1305(key: bytes, message: bytes) -> bytes:
    """Poly1305 of RFC 8439, section 2.5."""
    r = int.from_bytes(key[:16], 'little') & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:], 'little')
    p = (1 << 130) - 5
    accumulator = 0
    for i in range(0, len(message), 16):
        block = message[i:i + 16] + b'\x01'
        accumulator = (accumulator + int.from_bytes(block, 'little')) * r % p
    return ((accumulator + s) % (1 << 128)).to_bytes(16, 'little')


def secretbox_xchacha20poly1305(key: bytes, nonce: bytes, message: bytes) -> Tuple[bytes, bytes]:
    """libsodium's crypto_secretbox_xchacha20poly1305: the tag and the ciphertext."""
    subkey = hchacha20(key, nonce[:16])
    stream = key_stream(subkey, nonce[16:], 32 + len(message))
    ciphertext = bytes(x ^ y for x, y in zip(message, stream[32:]))
    return poly1305(stream[:32], ciphertext), ciphertext


def box_beforenm(secret_key: bytes, public_key: bytes) -> bytes:
    """crypto_box_curve25519xchacha20poly1305_beforenm: HChaCha20 of the shared secret."""
    return hchacha20(x25519(secret_key, public_key), bytes(16))


# libsodium's test/default/xchacha20.c, its secret boxes: key, nonce, message, tag and ciphertext.
SECRETBOXES = [
    ('065ff46a9dddb1ab047ee5914d6d575a828b8cc1f454b24e8cd0f57efdc49a34',
     'f83262646ce01293b9923a65a073df78c54b2e799cd6c4e5', '', '4c72340416339dcdea01b760db5adaf7'),
    ('d3c71d54e6b13506e07aa2e7b412a17a7a1f34df3d3148cd3f45b91ccaa5f4d9',
     '943b454a853aa514c63cf99b1e197bbb99da24b2e2d93e47',
     '76bd706e07741e713d90efdb34ad202067263f984942aae8bda159f30dfccc72200f8093520b85c5ad124ff7'
     'c8b2d920946e5cfff4b819abf84c7b35a6205ca72c9f8747c3044dd73fb4bebda1b476',
     '0384276f1cfa5c82c3e58f0f2acc1f821c6f526d2c19557cf8bd270fcde43fba1d88890663f7b2f5c6b1d7de'
     'ccf5c91b4df5865dc55cc7e04d6793fc2db8f9e3b418f95cb796d67a7f3f7e097150cb607c435dacf82eac3d'
     '669866e5092ace'),
    ('10c0ad4054b48d7d1de1d9ab6f782ca883d886573e9d18c1d47b6ee6b5208189',
     '977edf57428d0e0247a3c88c9a9ec321bbaae1a4da8353b5',
     '518e4a27949812424b2a381c3efea6055ee5e75eff',
     '0c801a037c2ed0500d6ef68e8d195eceb05a15f8edb68b35773e81ac2aca18e9be53416f9a'),
]

# NaCl's keys, nonce and message, libsodium's test/default/box.c; the public keys are RFC 7748's.
ALICE_SECRET = '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a'
ALICE_PUBLIC = '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a'
BOB_SECRET = '5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb'
BOB_PUBLIC = 'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f'
NONCE = '69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37'
MESSAGE = ('be075fc53c81f2d5cf141316ebeb0c7b5228c52a4c62cbd44b66849b64244ffce5ecbaaf33bd751a1ac728'
           'd45e6c61296cdc3c01233561f41db66cce314adb310e3be8250c46f06dceea3a7fa1348057e2f6556ad6'
           'b1318a024a838f21af1fde048977eb48f59ffd4924ca1c60902e52f0a089bc76897040e082f937763848'
           '645e0705')


def main() -> int:
    for key, nonce, message, expected in SECRETBOXES:
        tag, ciphertext = secretbox_xchacha20poly1305(bytes.fromhex(key), bytes.fromhex(nonce),
                                                      bytes.fromhex(message))
        if (tag + ciphertext).hex() != expected:
            print(f'the secret box of xchacha20.c with the key {key} differs', file=sys.stderr)
            return 1
    base_point = (9).to_bytes(32, 'little')
    if x25519(bytes.fromhex(ALICE_SECRET), base_point).hex() != ALICE_PUBLIC:
        print("RFC 7748's Alice: her public key differs", file=sys.stderr)
        return 1
    alice = box_beforenm(bytes.fromhex(ALICE_SECRET), bytes.fromhex(BOB_PUBLIC))
    bob = box_beforenm(bytes.fromhex(BOB_SECRET), bytes.fromhex(ALICE_PUBLIC))
    if alice != bob:
        print("Alice's and Bob's precomputed keys differ", file=sys.stderr)
        return 1
    tag, ciphertext = secretbox_xchacha20poly1305(alice, bytes.fromhex(NONCE),
                                                  bytes.fromhex(MESSAGE))
    print('beforenm', alice.hex())
    print('tag', tag.hex())
    print('ciphertext', ciphertext.hex())
    return 0


if __name__ == '__main__':
    sys.exit(main())
