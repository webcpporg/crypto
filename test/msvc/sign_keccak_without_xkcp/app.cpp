// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A message signed with Ethereum's recoverable ECDSA in a program that does not link XKCP stops
// where it is hashed with Keccak-256: on MSVC the compile fails. The text is checked on clang, in
// test/messages/sign_keccak_without_xkcp.
#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/signing.hpp>

#include <array>
#include <cstdint>

int main() {
    namespace crypto = webcpp::crypto;
    std::array<std::uint8_t, 32> secret_key{};
    secret_key.back() = 1;
    std::array<std::uint8_t, 5> const message{'h', 'e', 'l', 'l', 'o'};
    auto const key = crypto::curves::secp256k1::keypair::from_secret(secret_key);
    return key && key->sign(crypto::ecdsa_keccak256_recoverable, message) ? 0 : 1;
}
