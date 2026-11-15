// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The second translation unit of canary_two_files: it names a configuration of BearSSL that is
// not MSVC's, so its detect_mismatch value differs from app.cpp's. It also defines the canary
// that configuration names, so that the symbol this unit reads is found: the link fails by the
// third layer alone (the pragma, LNK2038), and not by the second (a missing symbol, LNK2001),
// which would fail the link with the pragma removed as well.
#define WEBCPP_CRYPTO_BEARSSL_CANARY_CONFIGURATION getentropy  // lint-world: a canary's name

#include <webcpp/crypto/backends/bearssl.hpp>
#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/crypto/ciphers/gcm.hpp>

#include <array>
#include <cstdint>

// The canary of the configuration above, which no archive defines (the archive of MSVC's BearSSL
// is built noseeder). The header declared it, so this definition has external linkage.
extern "C" const char WEBCPP_CRYPTO_DETAIL_BEARSSL_CANARY = 0;

bool seal_other() {
    std::array<std::uint8_t, 32> const key{};
    std::array<std::uint8_t, 12> const iv{};
    std::array<std::uint8_t, 16> data{};
    auto aead = webcpp::crypto::ciphers::gcm<
        webcpp::crypto::ciphers::aes256<webcpp::crypto::backends::bearssl>>::make(key);
    return aead && aead->seal(iv, {}, data);
}
