// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// curves::secp256k1 named with another backend stops at the family's refusal: on MSVC the compile
// fails. The text is checked on clang, in test/messages/secp256k1_other_backend.
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
