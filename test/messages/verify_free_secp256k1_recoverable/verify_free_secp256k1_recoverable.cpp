// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// crypto::verify given the recoverable scheme and a secp256k1 public key, whose signatures give
// their key to recover rather than being verified against one, stops at the catch-all verify,
// which says which key goes with which scheme and where a recoverable signature goes, and with
// that error alone.

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so each
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/crypto/signing.hpp:* {{webcpp::crypto: verify: this public key does not go with this scheme: crypto::eddsa and crypto::eddsa_prehashed take a curves::ed25519::public_key, crypto::ecdsa_sha256 a curves::p256::basic_public_key or a curves::secp256k1::public_key, crypto::schnorr a curves::secp256k1::public_key or a 32-byte x-only key; a crypto::ecdsa_sha256_recoverable or a crypto::ecdsa_keccak256_recoverable signature gives its key to curves::secp256k1::recover.}}
// clang-format on
#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/signing.hpp>

#include <array>
#include <cstdint>

int main() {
    namespace crypto = webcpp::crypto;
    std::array<std::uint8_t, 32> secret_key{};
    secret_key.back() = 1;
    auto const key = crypto::curves::secp256k1::keypair::from_secret(secret_key);
    if (!key) {
        return 1;
    }
    auto const public_key = key->public_key();
    crypto::curves::secp256k1::recoverable_signature const signature{};
    std::array<std::uint8_t, 5> const message{'h', 'e', 'l', 'l', 'o'};
    return public_key &&
                   crypto::verify(crypto::ecdsa_sha256_recoverable, signature, message, *public_key)
               ? 0
               : 1;
}
