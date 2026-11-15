// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Two translation units that read BearSSL's canary under two configurations: MSVC's linker
// compares the values of #pragma detect_mismatch and fails with LNK2038 (spec section 4.3, the
// third layer). Elsewhere the program links; it is MSVC's case alone.
#include <webcpp/crypto/aes.hpp>
#include <webcpp/crypto/backends/bearssl.hpp>
#include <webcpp/crypto/gcm.hpp>

#include <array>
#include <cstdint>

bool seal_other();

int main() {
    std::array<std::uint8_t, 32> const key{};
    std::array<std::uint8_t, 12> const iv{};
    std::array<std::uint8_t, 16> data{};
    auto aead =
        webcpp::crypto::gcm<webcpp::crypto::aes256<webcpp::crypto::backends::bearssl>>::make(key);
    return aead && aead->seal(iv, {}, data) && seal_other() ? 0 : 1;
}
