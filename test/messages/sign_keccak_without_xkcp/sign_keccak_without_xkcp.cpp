// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A secp256k1 key pair asked to sign a message with Ethereum's recoverable ECDSA in a program that
// does not link XKCP stops where the message is hashed with Keccak-256, naming the Jamfile line
// and the digest marker, which needs no XKCP (design R19), and with that error alone.

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so each
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/crypto/curves/secp256k1.hpp:* {{webcpp::crypto: crypto::ecdsa_keccak256_recoverable hashes a message with webcpp::hash's keccak_256, which needs XKCP: add /third_party//xkcp to the program's Jamfile, or sign crypto::prehashed{digest}.}}
// clang-format on
#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/signing.hpp>

#include <array>
#include <cstdint>

int main() {
    namespace crypto = webcpp::crypto;
    std::array<std::uint8_t, 32> secret_key{};
    secret_key.back() = 1;
    std::array<std::uint8_t, 5> const message{'h', 'e', 'l', 'l', 'o'};
    auto const key = crypto::curves::secp256k1::keypair::from_secret(secret_key);
    return key && key->sign(crypto::ecdsa_keccak256_recoverable, message) ? 0 : 1;
}
