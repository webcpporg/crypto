// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Two translation units that read libsecp256k1's canary under two configurations: this one
// under the large tables' (w15c11x6, the archive's), other.cpp under the small tables'. MSVC's
// linker compares the values of #pragma detect_mismatch and fails with LNK2038 (spec section
// 4.3, the third layer). Elsewhere the program links; it is MSVC's case alone.
#include <webcpp/crypto/curves/secp256k1.hpp>

#include <array>
#include <cstdint>

bool sign_other();

int main() {
    std::array<std::uint8_t, 32> secret{};
    secret.fill(0x42);
    std::array<std::uint8_t, 32> const message{};
    std::array<std::uint8_t, 32> const aux{};
    auto key = webcpp::crypto::curves::secp256k1::keypair::make(secret);
    return key && key->sign_schnorr(message, aux) && sign_other() ? 0 : 1;
}
