// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The spec's wrong curve: a secp256k1 ECDSA signature given to crypto::verify of ECDSA over SHA-256
// with a P-256 public key, though both are 64 bytes, r then s, stops at P-256's verify, which names
// the type it takes and how to make one, and with that error alone (design R1).

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so each
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/crypto/signing.hpp:* {{webcpp::crypto: verify: a P-256 key verifies a curves::p256::ecdsa_signature: make one from 64 bytes with curves::p256::ecdsa_signature::from_bytes.}}
// clang-format on
#include <webcpp/crypto/backends/bearssl.hpp>
#include <webcpp/crypto/curves/p256.hpp>
#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/signing.hpp>

#include <array>
#include <cstdint>

int main() {
    namespace crypto = webcpp::crypto;
    std::array<std::uint8_t, 32> scalar{};
    scalar.back() = 1;
    auto const key = crypto::curves::p256::keypair::from_secret(scalar);
    if (!key) {
        return 1;
    }
    auto const public_key = key->public_key();
    crypto::curves::secp256k1::ecdsa_signature const signature{};
    std::array<std::uint8_t, 5> const message{'h', 'e', 'l', 'l', 'o'};
    return public_key && crypto::verify(crypto::ecdsa_sha256, signature, message, *public_key) ? 0
                                                                                               : 1;
}
