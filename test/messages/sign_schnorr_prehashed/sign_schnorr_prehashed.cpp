// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A secp256k1 key pair asked to sign a digest marked as one, crypto::prehashed{digest}, with
// BIP340's crypto::schnorr stops at the input's check, which says that Schnorr signs the message
// itself, and with that error alone.

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so each
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/crypto/signing.hpp:* {{webcpp::crypto: crypto::schnorr (BIP340) signs a message of any length and has no prehash mode: pass the message.}}
// clang-format on
#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/signing.hpp>

#include <array>
#include <cstdint>

int main() {
    namespace crypto = webcpp::crypto;
    std::array<std::uint8_t, 32> secret{};
    secret.fill(0x42);
    std::array<std::uint8_t, 32> const digest{};
    auto const key = crypto::curves::secp256k1::keypair::make(secret);
    return key && key->sign(crypto::schnorr, crypto::prehashed{digest}) ? 0 : 1;
}
