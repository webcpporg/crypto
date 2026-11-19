// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A program that calls the secret boxes, the boxes and the sealed boxes on their default
// backend, libsodium on every target, without linking it, stops where it calls each, with the
// line that links libsodium, the one backend that has them (design D32; ruling C22).

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so each
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/crypto/ciphers/aead.hpp:* {{webcpp::crypto: XSalsa20-Poly1305 secret box's default backend on this target is libsodium, which is not linked, and the one backend that has it there. Add /webcpp/crypto//secretbox_xsalsa20poly1305-default, the default's library on every target, to the program's Jamfile, as in: exe app : app.cpp /webcpp/crypto//crypto /webcpp/crypto//secretbox_xsalsa20poly1305-default ; (without b2: define WEBCPP_CRYPTO_HAS_SODIUM=1 and link libsodium built with webcpp's src/canary_sodium.c)}}
// expected-error@webcpp/crypto/ciphers/aead.hpp:* {{webcpp::crypto: XChaCha20-Poly1305 secret box's default backend on this target is libsodium, which is not linked, and the one backend that has it there. Add /webcpp/crypto//secretbox_xchacha20poly1305-default, the default's library on every target, to the program's Jamfile, as in: exe app : app.cpp /webcpp/crypto//crypto /webcpp/crypto//secretbox_xchacha20poly1305-default ; (without b2: define WEBCPP_CRYPTO_HAS_SODIUM=1 and link libsodium built with webcpp's src/canary_sodium.c)}}
// expected-error@webcpp/crypto/hybrid/box.hpp:* {{webcpp::crypto: X25519-XSalsa20-Poly1305 box's default backend on this target is libsodium, which is not linked, and the one backend that has it there. Add /webcpp/crypto//box_xsalsa20poly1305-default, the default's library on every target, to the program's Jamfile, as in: exe app : app.cpp /webcpp/crypto//crypto /webcpp/crypto//box_xsalsa20poly1305-default ; (without b2: define WEBCPP_CRYPTO_HAS_SODIUM=1 and link libsodium built with webcpp's src/canary_sodium.c)}}
// expected-error@webcpp/crypto/hybrid/box.hpp:* {{webcpp::crypto: X25519-XChaCha20-Poly1305 box's default backend on this target is libsodium, which is not linked, and the one backend that has it there. Add /webcpp/crypto//box_xchacha20poly1305-default, the default's library on every target, to the program's Jamfile, as in: exe app : app.cpp /webcpp/crypto//crypto /webcpp/crypto//box_xchacha20poly1305-default ; (without b2: define WEBCPP_CRYPTO_HAS_SODIUM=1 and link libsodium built with webcpp's src/canary_sodium.c)}}
// expected-error@webcpp/crypto/hybrid/sealed_box.hpp:* {{webcpp::crypto: X25519-XSalsa20-Poly1305 sealed box's default backend on this target is libsodium, which is not linked, and the one backend that has it there. Add /webcpp/crypto//sealed_box-default, the default's library on every target, to the program's Jamfile, as in: exe app : app.cpp /webcpp/crypto//crypto /webcpp/crypto//sealed_box-default ; (without b2: define WEBCPP_CRYPTO_HAS_SODIUM=1 and link libsodium built with webcpp's src/canary_sodium.c)}}
// clang-format on

#include <webcpp/crypto/ciphers/secretbox.hpp>
#include <webcpp/crypto/hybrid/box.hpp>
#include <webcpp/crypto/hybrid/sealed_box.hpp>

#include <array>
#include <cstdint>

int main() {
    namespace crypto = webcpp::crypto;
    std::array<std::uint8_t, 32> const key{};
    std::array<std::uint8_t, 48> sealed{};
    return crypto::ciphers::secretbox<>::make(key) &&
                   crypto::ciphers::secretbox_xchacha20poly1305<>::make(key) &&
                   crypto::hybrid::box::make(key, key) &&
                   crypto::hybrid::box_xchacha20poly1305::make(key, key) &&
                   crypto::hybrid::sealed_box::seal(key, {}, sealed)
               ? 0
               : 1;
}
