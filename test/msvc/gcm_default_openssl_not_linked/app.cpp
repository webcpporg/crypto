// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A native program that links BearSSL alone and calls aes256_gcm, whose default is OpenSSL
// natively whatever is linked, stops where it calls it with the line that links OpenSSL (design
// D32): on MSVC the compile fails. The text is checked on clang, in
// test/messages/gcm_default_openssl_not_linked.
#include <webcpp/crypto/ciphers/aes256_gcm.hpp>

#include <array>
#include <cstdint>

int main() {
    std::array<std::uint8_t, 32> const key{};
    return webcpp::crypto::ciphers::aes256_gcm::make(key) ? 0 : 1;
}
