// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// ECDSA's verification given a public key as 33 bytes, not as a parsed key, stops at the
// catch-all verify, which says which key goes with which scheme, and with that error alone:
// bytes never decide between P-256 and secp256k1 under crypto::ecdsa_sha256.

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so each
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/crypto/signing.hpp:* {{webcpp::crypto: verify: this public key does not go with this scheme: crypto::eddsa takes a curves::ed25519::public_key, crypto::ecdsa_sha256 a curves::p256::basic_public_key or a curves::secp256k1::public_key, crypto::schnorr a curves::secp256k1::public_key or a 32-byte x-only key; a crypto::ecdsa_sha256_recoverable signature gives its key to curves::secp256k1::recover.}}
// clang-format on
#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/signing.hpp>

#include <array>
#include <cstdint>

int main() {
    namespace crypto = webcpp::crypto;
    std::array<std::uint8_t, 64> const signature{};
    std::array<std::uint8_t, 5> const message{'h', 'e', 'l', 'l', 'o'};
    return crypto::verify(crypto::ecdsa_sha256, signature, message, std::array<std::uint8_t, 33>{})
               ? 0
               : 1;
}
