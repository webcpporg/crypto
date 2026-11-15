// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A program that makes the block cipher on BearSSL, which has none, stops at the static_assert
// that names the backends that export it (spec section 2.3): on MSVC the compile fails. The text
// is checked on clang, in test/messages/aes_on_bearssl.
#include <webcpp/crypto/backends/bearssl.hpp>
#include <webcpp/crypto/ciphers/aes.hpp>

#include <array>
#include <cstdint>

int main() {
    std::array<std::uint8_t, 32> const key{};
    auto const made = webcpp::crypto::ciphers::aes256<webcpp::crypto::backends::bearssl>::make(key);
    return made ? 0 : 1;
}
