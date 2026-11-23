// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The free crypto::agree given a P-256 key pair and a peer's key as bytes, which its agree does
// not take, stops at agree's catch-all, which names the peer each key pair takes, with that error
// alone.

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so each
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/crypto/keypair.hpp:* {{webcpp::crypto: agree: this key pair does not agree with this peer: a P-256 key pair agrees with a curves::p256::basic_public_key of its backend, a secp256k1 key pair with a curves::secp256k1::public_key; an Ed25519 key pair agrees through X25519, its x25519_secret() and curves::x25519::agree.}}
// clang-format on
#include <webcpp/crypto/backends/bearssl.hpp>
#include <webcpp/crypto/curves/p256.hpp>
#include <webcpp/crypto/keypair.hpp>

#include <array>
#include <cstdint>

int main() {
    namespace crypto = webcpp::crypto;
    std::array<std::uint8_t, 32> scalar{};
    scalar.back() = 1;
    auto const key = crypto::curves::p256::keypair::from_secret(scalar);
    std::array<std::uint8_t, 65> const peer{0x04};
    return key && crypto::agree(*key, peer) ? 0 : 1;
}
