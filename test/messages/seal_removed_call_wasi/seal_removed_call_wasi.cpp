// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// What a program that still calls crypto::seal and crypto::open as it did sees on WASI (design
// D11): each call stops the build, although the cipher's header, which brings
// secret_key_encryption::aead::seal and open, is included; clang offers the C library's fopen for
// open, and the corrected call, of fopen's two parameters, adds its own error. Those three errors
// alone; natively, seal_removed_call.

#include <webcpp/crypto/ciphers/chacha20_poly1305.hpp>

#include <array>
#include <cstdint>

namespace {

/** Seals and opens through the removed free forms. */
bool sealed_and_opened(webcpp::crypto::ciphers::chacha20_poly1305<>& cipher) {
    std::array<std::uint8_t, 12> const nonce{};
    std::array<std::uint8_t, 5> data{'h', 'e', 'l', 'l', 'o'};
    std::array<std::uint8_t, 16> const tag{};
    // expected-error@+1 {{no member named 'seal' in namespace 'webcpp::crypto'}}
    bool const sealed = webcpp::crypto::seal(cipher, nonce, {}, data).has_value();
    // clang-format off
    // expected-error@+3 {{no member named 'open' in namespace 'webcpp::crypto'; did you mean 'fopen'?}}
    // expected-error@+2 {{too many arguments to function call, expected 2, have 5}}
    // clang-format on
    bool const opened = webcpp::crypto::open(cipher, nonce, {}, data, tag).has_value();
    return sealed && opened;
}

}  // namespace

// The function is compiled, which is the test; it is never run.
int main() {
    static_cast<void>(&sealed_and_opened);
    return 0;
}
