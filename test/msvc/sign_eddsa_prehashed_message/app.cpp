// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// An Ed25519 key pair asked to sign a message under crypto::eddsa_prehashed, a 64-byte
// std::array, stops at the input's check: on MSVC the compile fails. The text is checked on clang,
// in test/messages/sign_eddsa_prehashed_message.
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
