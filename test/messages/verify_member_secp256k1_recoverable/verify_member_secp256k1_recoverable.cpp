// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A secp256k1 public key's own verify given the recoverable scheme, whose signatures give their
// key to recover rather than being verified against one, stops at its verify with the two schemes
// it has and the way to recover, and with that error alone.

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so each
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/crypto/curves/secp256k1.hpp:* {{webcpp::crypto: a secp256k1 public key verifies crypto::ecdsa_sha256 or crypto::schnorr; a crypto::ecdsa_sha256_recoverable signature gives its key to curves::secp256k1::recover.}}
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
    return public_key && public_key->verify(crypto::ecdsa_sha256_recoverable, signature, message)
               ? 0
               : 1;
}
