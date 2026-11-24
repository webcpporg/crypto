// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// <webcpp/crypto/curves/secp256k1.hpp> alone, first, in a program that links XKCP: its branch for
// WEBCPP_HASH_HAS_XKCP, which includes <webcpp/hash/keccak.hpp>, compiles with nothing before it,
// and crypto::ecdsa_keccak256_recoverable's sign and recover of a message are instantiated
// through it alone.

#include <webcpp/crypto/curves/secp256k1.hpp>

#include <array>
#include <cstdint>
#include <span>

#ifndef WEBCPP_HASH_HAS_XKCP
#error "the test needs /third_party//xkcp, which defines WEBCPP_HASH_HAS_XKCP"
#endif

namespace crypto = webcpp::crypto;
namespace secp = webcpp::crypto::curves::secp256k1;

static_assert(crypto::can_sign<secp::keypair, crypto::ecdsa_keccak256_recoverable_t,
                               std::span<std::uint8_t const>>);

int main() {
    std::array<std::uint8_t, 32> secret{};
    secret.back() = 1;
    std::array<std::uint8_t, 5> const message{'h', 'e', 'l', 'l', 'o'};
    auto const key = secp::keypair::from_secret(secret);
    if (!key) {
        return 1;
    }
    auto const signature = key->sign(crypto::ecdsa_keccak256_recoverable, message);
    if (!signature) {
        return 1;
    }
    auto const recovered = secp::recover(crypto::ecdsa_keccak256_recoverable, *signature, message);
    return recovered && *recovered == *key->public_key() ? 0 : 1;
}
