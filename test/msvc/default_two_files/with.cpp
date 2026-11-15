// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The second translation unit of default_two_files: it selects BearSSL as the default backend
// before its includes, so its detect_mismatch value differs from main.cpp's.
#define WEBCPP_CRYPTO_DEFAULT_BACKEND_BEARSSL

#include <webcpp/crypto/aes256_gcm.hpp>

#include <array>
#include <cstdint>

bool seal_with_bearssl() {
    std::array<std::uint8_t, 32> const key{};
    std::array<std::uint8_t, 12> const iv{};
    std::array<std::uint8_t, 16> data{};
    auto aead = webcpp::crypto::aes256_gcm::make(key);
    return aead && aead->seal(iv, {}, data);
}
