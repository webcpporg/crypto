// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// An Ed25519 key pair given ECDSA's scheme through the free crypto::sign stops at the key pair's
// sign, which crypto::sign calls, with the scheme it has, and with that error alone.

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so each
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/crypto/curves/ed25519.hpp:* {{webcpp::crypto: an Ed25519 key signs with crypto::eddsa.}}
// clang-format on
#include <webcpp/crypto/curves/ed25519.hpp>
#include <webcpp/crypto/signing.hpp>

#include <array>
#include <cstdint>

int main() {
    namespace crypto = webcpp::crypto;
    std::array<std::uint8_t, 32> const seed{};
    auto const key = crypto::curves::ed25519::keypair::from_secret(seed);
    std::array<std::uint8_t, 5> const message{'h', 'e', 'l', 'l', 'o'};
    return key && crypto::sign(*key, crypto::ecdsa_sha256, message) ? 0 : 1;
}
