// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// An Ed25519 key pair asked to sign a message under crypto::eddsa_prehashed, a 64-byte
// std::array, which is a message although it has a digest's size, stops at the input's check,
// which names crypto::prehashed{digest} of SHA-512's 64 bytes, crypto::eddsa and the streaming
// signer, and with that error alone.

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so each
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/crypto/signing.hpp:* {{webcpp::crypto: crypto::eddsa_prehashed (RFC 8032's Ed25519ph) signs a digest, the message's SHA-512: crypto::prehashed{digest} of a std::array<std::uint8_t, 64>; sign the message itself with crypto::eddsa, or give it in pieces to curves::ed25519::prehashed_signer.}}
// clang-format on
#include <webcpp/crypto/curves/ed25519.hpp>
#include <webcpp/crypto/signing.hpp>

#include <array>
#include <cstdint>

int main() {
    namespace crypto = webcpp::crypto;
    std::array<std::uint8_t, 32> const seed{};
    auto const key = crypto::curves::ed25519::keypair::from_secret(seed);
    return key && key->sign(crypto::eddsa_prehashed, std::array<std::uint8_t, 64>{}) ? 0 : 1;
}
