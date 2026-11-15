// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// BearSSL's GCM names aes256<backends::bearssl>, makes it and seals: the block cipher's
// refusal, beside it in aes_on_bearssl.cpp, does not reach GCM.

#include <webcpp/crypto/backends/bearssl.hpp>
#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/crypto/ciphers/gcm.hpp>

#include <array>
#include <cstdint>

int main() {
    using aead = webcpp::crypto::ciphers::gcm<
        webcpp::crypto::ciphers::aes256<webcpp::crypto::backends::bearssl>>;
    std::array<std::uint8_t, 32> const key{};
    std::array<std::uint8_t, 12> const iv{};
    std::array<std::uint8_t, 16> data{};
    auto made = aead::make(key);
    return made && made->seal(iv, {}, data) ? 0 : 1;
}
