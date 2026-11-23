// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// ChaCha20-Poly1305 on ctaes, which exports the AES block cipher alone: refused.
#include <webcpp/crypto/backends/ctaes.hpp>
#include <webcpp/crypto/ciphers/chacha20_poly1305.hpp>

#include <array>
#include <cstdint>

int main() {
    std::array<std::uint8_t, 32> const key{};
    auto made =
        webcpp::crypto::ciphers::chacha20_poly1305<webcpp::crypto::backends::ctaes>::from_key(key);
    return made ? 0 : 1;
}
