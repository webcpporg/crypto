// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// curves::secp256k1 refuses a backend other than libsecp256k1 where it is instantiated, as the
// ciphers refuse a backend without their algorithm.

// clang-format off
// expected-error@webcpp/crypto/curves/secp256k1.hpp:* {{webcpp::crypto: curves::secp256k1 runs on libsecp256k1 alone. Name backends::secp256k1, or leave the backend out, as in curves::secp256k1::keypair.}}
// clang-format on
#include <webcpp/crypto/curves/secp256k1.hpp>

#include <array>
#include <cstdint>

int main() {
    std::array<std::uint8_t, 64> const signature{};
    std::array<std::uint8_t, 32> const hash{};
    std::array<std::uint8_t, 33> const key{};
    auto const verified =
        webcpp::crypto::curves::secp256k1::verify_ecdsa<webcpp::crypto::backends::bearssl>(
            signature, hash, key);
    return verified ? 0 : 1;
}
