// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// An Ed25519 key pair asked to sign a digest marked as one, crypto::prehashed{digest}, with
// crypto::eddsa stops at the input's check, which says that pure Ed25519 signs the message itself
// and names Ed25519ph, and with that error alone.

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so each
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/crypto/signing.hpp:* {{webcpp::crypto: crypto::eddsa signs the message itself (RFC 8032's pure Ed25519) and takes no digest; Ed25519ph, which hashes the message, is curves::ed25519::ph.}}
// clang-format on
#include <webcpp/crypto/curves/ed25519.hpp>
#include <webcpp/crypto/signing.hpp>

#include <array>
#include <cstdint>

int main() {
    namespace crypto = webcpp::crypto;
    std::array<std::uint8_t, 32> const seed{};
    std::array<std::uint8_t, 64> const digest{};
    auto const key = crypto::curves::ed25519::keypair::from_secret(seed);
    return key && key->sign(crypto::eddsa, crypto::prehashed{digest}) ? 0 : 1;
}
