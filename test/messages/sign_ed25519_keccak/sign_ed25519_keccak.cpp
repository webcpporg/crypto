// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// An Ed25519 key pair asked to sign with Ethereum's recoverable ECDSA, a scheme of secp256k1,
// stops at the scheme's check with the two schemes it has, crypto::eddsa and
// crypto::eddsa_prehashed, and with that error alone.

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so each
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/crypto/curves/ed25519.hpp:* {{webcpp::crypto: an Ed25519 key signs with crypto::eddsa or crypto::eddsa_prehashed.}}
// clang-format on
#include <webcpp/crypto/curves/ed25519.hpp>
#include <webcpp/crypto/signing.hpp>

#include <array>
#include <cstdint>

int main() {
    namespace crypto = webcpp::crypto;
    std::array<std::uint8_t, 32> const seed{};
    std::array<std::uint8_t, 3> const message{1, 2, 3};
    auto const key = crypto::curves::ed25519::keypair::from_secret(seed);
    return key && key->sign(crypto::ecdsa_keccak256_recoverable, message) ? 0 : 1;
}
