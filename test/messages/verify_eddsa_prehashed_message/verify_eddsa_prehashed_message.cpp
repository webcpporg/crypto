// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// crypto::verify under crypto::eddsa_prehashed given a message stops at the input's check, as the
// key pair's sign does, which names crypto::prehashed{digest} of SHA-512's 64 bytes, and with
// that error alone.

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
    auto const public_key =
        crypto::curves::ed25519::public_key::from_bytes(std::array<std::uint8_t, 32>{});
    crypto::curves::ed25519::signature const signature{};
    std::array<std::uint8_t, 5> const message{'h', 'e', 'l', 'l', 'o'};
    return public_key && crypto::verify(crypto::eddsa_prehashed, signature, message, *public_key)
               ? 0
               : 1;
}
