// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The free crypto::sign given a public key, which has no sign, stops at sign's catch-all, which
// says that the first argument is a key pair and that a public key verifies, with that error
// alone.

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so each
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/crypto/signing.hpp:* {{webcpp::crypto: sign: the first argument is a key pair, and the others are its sign's: crypto::sign(key_pair, scheme, input), and on secp256k1 its 32 bytes of extra entropy or auxiliary randomness after the input; a public key verifies, with crypto::verify.}}
// clang-format on
#include <webcpp/crypto/curves/ed25519.hpp>
#include <webcpp/crypto/signing.hpp>

#include <array>
#include <cstdint>

int main() {
    namespace crypto = webcpp::crypto;
    auto const public_key =
        crypto::curves::ed25519::public_key::from_bytes(std::array<std::uint8_t, 32>{});
    std::array<std::uint8_t, 5> const message{'h', 'e', 'l', 'l', 'o'};
    return public_key && crypto::sign(*public_key, crypto::eddsa, message) ? 0 : 1;
}
