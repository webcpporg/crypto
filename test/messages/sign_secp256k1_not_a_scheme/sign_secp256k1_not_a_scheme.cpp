// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A secp256k1 key pair given a first argument that is no scheme tag at all, an int, stops at its
// sign with the schemes it has, as a tag of another curve does, and with that error alone.

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so each
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/crypto/curves/secp256k1.hpp:* {{webcpp::crypto: a secp256k1 key signs with crypto::ecdsa_sha256, crypto::ecdsa_sha256_recoverable or crypto::schnorr.}}
// clang-format on
#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/signing.hpp>

#include <array>
#include <cstdint>

int main() {
    namespace crypto = webcpp::crypto;
    std::array<std::uint8_t, 32> secret{};
    secret.fill(0x42);
    std::array<std::uint8_t, 5> const message{'h', 'e', 'l', 'l', 'o'};
    auto const key = crypto::curves::secp256k1::keypair::from_secret(secret);
    return key && key->sign(0, message) ? 0 : 1;
}
