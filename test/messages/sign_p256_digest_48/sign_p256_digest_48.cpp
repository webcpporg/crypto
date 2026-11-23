// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A P-256 key pair asked to sign a 48-byte digest, SHA-384's size, with ECDSA over SHA-256 stops
// at the input's check with the 32-byte digest it takes, and with that error alone.

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so each
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/crypto/signing.hpp:* {{webcpp::crypto: crypto::ecdsa_sha256 takes a 32-byte digest, SHA-256's: crypto::prehashed{digest} of a std::array<std::uint8_t, 32>.}}
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
    auto const key = crypto::curves::p256::keypair::from_secret(scalar);
    return key && key->sign(crypto::ecdsa_sha256, crypto::prehashed{std::array<std::uint8_t, 48>{}})
               ? 0
               : 1;
}
