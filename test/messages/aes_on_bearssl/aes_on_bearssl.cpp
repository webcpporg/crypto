// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A program that makes the block cipher on BearSSL, which has none, stops with the backends
// that export it (spec section 2.3).

#include <webcpp/crypto/aes.hpp>
#include <webcpp/crypto/backends/bearssl.hpp>

#include <array>
#include <cstdint>

// clang-format off
// expected-error@webcpp/crypto/backends/bearssl.hpp:* {{webcpp::crypto: aes256<backends::bearssl>: BearSSL exports AES only inside its modes, with no block cipher. Name a backend that exports it, as in aes256<backends::ctaes> or aes256<backends::openssl>, and add its library to the program's Jamfile.}}
// clang-format on

int main() {
    std::array<std::uint8_t, 32> const key{};
    auto const made = webcpp::crypto::aes256<webcpp::crypto::backends::bearssl>::make(key);
    return made ? 0 : 1;
}
