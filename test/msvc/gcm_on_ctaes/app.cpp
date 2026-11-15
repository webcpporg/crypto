// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A GCM on ctaes, which exports the AES block cipher alone: spec section 2.4 refuses it.
#include <webcpp/crypto/aes.hpp>
#include <webcpp/crypto/backends/ctaes.hpp>
#include <webcpp/crypto/gcm.hpp>

#include <array>
#include <cstdint>

int main() {
    std::array<std::uint8_t, 32> const key{};
    auto aead =
        webcpp::crypto::gcm<webcpp::crypto::aes256<webcpp::crypto::backends::ctaes>>::make(key);
    return aead ? 0 : 1;
}
