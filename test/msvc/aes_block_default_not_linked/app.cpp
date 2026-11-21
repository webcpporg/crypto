// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A native program that links ctaes alone and calls aes256<>, whose default is OpenSSL natively
// whatever is linked, stops where it calls it with the line that links OpenSSL (design D3): on
// MSVC the compile fails. The text is checked on clang, in
// test/messages/aes_block_default_not_linked.

#include <webcpp/crypto/ciphers/aes.hpp>

#include <array>
#include <cstdint>

int main() {
    std::array<std::uint8_t, 32> const key{};
    return webcpp::crypto::ciphers::aes256<>::make(key) ? 0 : 1;
}
