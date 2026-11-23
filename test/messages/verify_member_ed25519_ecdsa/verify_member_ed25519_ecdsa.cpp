// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// An Ed25519 public key's own verify given ECDSA's scheme stops at its verify with the scheme it
// has, and with that error alone.

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so each
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/crypto/curves/ed25519.hpp:* {{webcpp::crypto: an Ed25519 public key verifies crypto::eddsa.}}
// clang-format on
#include <webcpp/crypto/curves/ed25519.hpp>
#include <webcpp/crypto/signing.hpp>

#include <array>
#include <cstdint>

int main() {
    namespace crypto = webcpp::crypto;
    auto const public_key =
        crypto::curves::ed25519::public_key::from_bytes(std::array<std::uint8_t, 32>{});
    crypto::curves::ed25519::signature const signature{};
    std::array<std::uint8_t, 5> const message{'h', 'e', 'l', 'l', 'o'};
    return public_key && public_key->verify(crypto::ecdsa_sha256, signature, message) ? 0 : 1;
}
