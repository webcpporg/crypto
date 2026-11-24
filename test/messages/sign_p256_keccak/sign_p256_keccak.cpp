// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A P-256 key pair asked to sign with Ethereum's recoverable ECDSA, a scheme of secp256k1, stops
// at its sign with the one scheme it has, and with that error alone.

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so each
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/crypto/curves/p256.hpp:* {{webcpp::crypto: a P-256 key signs with crypto::ecdsa_sha256.}}
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
    std::array<std::uint8_t, 5> const message{'h', 'e', 'l', 'l', 'o'};
    return key && key->sign(crypto::ecdsa_keccak256_recoverable, message) ? 0 : 1;
}
