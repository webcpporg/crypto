// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A secp256k1 key pair asked to sign a 20-byte digest with Ethereum's recoverable ECDSA stops at
// the input's check, which names the scheme and Keccak-256's 32-byte digest it takes, and with
// that error alone.

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so each
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/crypto/signing.hpp:* {{webcpp::crypto: crypto::ecdsa_keccak256_recoverable takes a 32-byte digest, Keccak-256's: crypto::prehashed{digest} of a std::array<std::uint8_t, 32>.}}
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
    return key && key->sign(crypto::ecdsa_keccak256_recoverable,
                            crypto::prehashed{std::array<std::uint8_t, 20>{}})
               ? 0
               : 1;
}
