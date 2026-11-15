// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The second translation unit of canary_two_files: it names a configuration of BearSSL that is
// not MSVC's, so its detect_mismatch value differs from app.cpp's.
#define WEBCPP_CRYPTO_BEARSSL_CANARY_CONFIGURATION getentropy  // lint-world: a canary's name

#include <webcpp/crypto/backends/bearssl.hpp>
#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/crypto/ciphers/gcm.hpp>

#include <array>
#include <cstdint>

bool seal_other() {
    std::array<std::uint8_t, 32> const key{};
    std::array<std::uint8_t, 12> const iv{};
    std::array<std::uint8_t, 16> data{};
    auto aead = webcpp::crypto::ciphers::gcm<
        webcpp::crypto::ciphers::aes256<webcpp::crypto::backends::bearssl>>::make(key);
    return aead && aead->seal(iv, {}, data);
}
