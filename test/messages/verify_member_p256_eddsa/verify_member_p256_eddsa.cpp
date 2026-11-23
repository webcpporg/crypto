// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A P-256 public key's own verify given Ed25519's scheme stops at its verify with the scheme it
// has, and with that error alone.

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so each
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/crypto/curves/p256.hpp:* {{webcpp::crypto: a P-256 public key verifies crypto::ecdsa_sha256.}}
// clang-format on
#include <webcpp/crypto/backends/bearssl.hpp>
#include <webcpp/crypto/curves/p256.hpp>
#include <webcpp/crypto/signing.hpp>

#include <array>
#include <cstdint>

int main() {
    namespace crypto = webcpp::crypto;
    std::array<std::uint8_t, 32> scalar{};
    scalar.back() = 1;
    auto const key = crypto::curves::p256::keypair::make(scalar);
    if (!key) {
        return 1;
    }
    auto const public_key = key->public_key();
    std::array<std::uint8_t, 64> const signature{};
    std::array<std::uint8_t, 5> const message{'h', 'e', 'l', 'l', 'o'};
    return public_key && public_key->verify(crypto::eddsa, signature, message) ? 0 : 1;
}
