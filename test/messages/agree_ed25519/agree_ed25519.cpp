// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The free crypto::agree given an Ed25519 key pair, a signing_keypair that is no
// agreement_keypair, stops at agree's catch-all, which says that Ed25519 key pairs sign and do not
// agree, and names to_x25519(), with that error alone.

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so each
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/crypto/keypair.hpp:* {{webcpp::crypto: agree: Ed25519 key pairs sign; they do not agree: convert one with to_x25519() and agree with the X25519 key pair.}}
// clang-format on
#include <webcpp/crypto/curves/ed25519.hpp>
#include <webcpp/crypto/keypair.hpp>

#include <array>
#include <cstdint>

int main() {
    namespace crypto = webcpp::crypto;
    std::array<std::uint8_t, 32> const seed{1};
    auto const key = crypto::curves::ed25519::keypair::from_secret(seed);
    if (!key) {
        return 1;
    }
    auto const peer = key->public_key();
    return peer && crypto::agree(*key, *peer) ? 0 : 1;
}
