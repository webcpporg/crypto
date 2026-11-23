// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// An Ed25519 public key's own verify given a digest marked as one, crypto::prehashed{digest},
// under crypto::eddsa stops at the input's check, as crypto::verify does, which says that pure
// Ed25519 verifies the message itself and names crypto::eddsa_prehashed (Ed25519ph), and with that
// error alone.

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so each
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/crypto/signing.hpp:* {{webcpp::crypto: crypto::eddsa signs the message itself (RFC 8032's pure Ed25519) and takes no digest; a message's SHA-512 is signed with crypto::eddsa_prehashed (Ed25519ph).}}
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
    std::array<std::uint8_t, 64> const digest{};
    return public_key && public_key->verify(crypto::eddsa, signature, crypto::prehashed{digest})
               ? 0
               : 1;
}
