// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A program that calls the three ChaCha20-Poly1305 AEADs on their default backend, libsodium
// on every target, without linking it, stops where it calls each, with the line that links
// libsodium (design D32; ruling C20).

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so each
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/crypto/ciphers/aead.hpp:* {{webcpp::crypto: ChaCha20-Poly1305's default backend on this target is libsodium, which is not linked, and the one backend that has it there. Add /third_party//sodium to the program's Jamfile, as in: exe app : app.cpp /webcpp/crypto//crypto /third_party//sodium ; (without b2: define WEBCPP_CRYPTO_HAS_SODIUM=1 and link libsodium built with webcpp's src/canary_sodium.c)}}
// expected-error@webcpp/crypto/ciphers/aead.hpp:* {{webcpp::crypto: original ChaCha20-Poly1305's default backend on this target is libsodium, which is not linked, and the one backend that has it there. Add /third_party//sodium to the program's Jamfile, as in: exe app : app.cpp /webcpp/crypto//crypto /third_party//sodium ; (without b2: define WEBCPP_CRYPTO_HAS_SODIUM=1 and link libsodium built with webcpp's src/canary_sodium.c)}}
// expected-error@webcpp/crypto/ciphers/aead.hpp:* {{webcpp::crypto: XChaCha20-Poly1305's default backend on this target is libsodium, which is not linked, and the one backend that has it there. Add /third_party//sodium to the program's Jamfile, as in: exe app : app.cpp /webcpp/crypto//crypto /third_party//sodium ; (without b2: define WEBCPP_CRYPTO_HAS_SODIUM=1 and link libsodium built with webcpp's src/canary_sodium.c)}}
// clang-format on

#include <webcpp/crypto/ciphers/chacha20_poly1305.hpp>

#include <array>
#include <cstdint>

int main() {
    namespace ciphers = webcpp::crypto::ciphers;
    std::array<std::uint8_t, 32> const key{};
    return ciphers::chacha20_poly1305<>::make(key) &&
                   ciphers::chacha20_poly1305_original<>::make(key) &&
                   ciphers::xchacha20_poly1305<>::make(key)
               ? 0
               : 1;
}
