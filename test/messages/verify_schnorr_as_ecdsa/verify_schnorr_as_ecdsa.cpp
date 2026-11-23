// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A BIP340 signature given to crypto::verify of ECDSA over SHA-256 with a secp256k1 public key,
// though both are 64 bytes, stops at secp256k1's ECDSA verify, which names the type it takes and
// how to make one, and with that error alone (design R1).

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so each
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/crypto/signing.hpp:* {{webcpp::crypto: verify: a secp256k1 key verifies a curves::secp256k1::ecdsa_signature under crypto::ecdsa_sha256: make one from 64 bytes with curves::secp256k1::ecdsa_signature::from_bytes.}}
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
    std::array<std::uint8_t, 5> const message{'h', 'e', 'l', 'l', 'o'};
    auto const signature = key->sign(crypto::schnorr, message);
    return public_key && signature &&
                   crypto::verify(crypto::ecdsa_sha256, *signature, message, *public_key)
               ? 0
               : 1;
}
