// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Two translation units whose default backends differ: main.cpp keeps the default (OpenSSL,
// natively), with.cpp selects BearSSL. MSVC's linker compares the values of aes256_gcm.hpp's
// #pragma detect_mismatch and fails with LNK2038 (spec section 5). Elsewhere the program links;
// it is MSVC's case alone.
#include <webcpp/crypto/aes256_gcm.hpp>

#include <array>
#include <cstdint>

bool seal_with_bearssl();

int main() {
    std::array<std::uint8_t, 32> const key{};
    std::array<std::uint8_t, 12> const iv{};
    std::array<std::uint8_t, 16> data{};
    auto aead = webcpp::crypto::aes256_gcm::make(key);
    return aead && aead->seal(iv, {}, data) && seal_with_bearssl() ? 0 : 1;
}
