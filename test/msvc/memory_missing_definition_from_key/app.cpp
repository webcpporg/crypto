// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// MSVC's case of the fixture memory_missing_definition_from_key (spec section 8.6): a program that
// sets the memory option, makes AES-256-GCM on OpenSSL and defines no
// webcpp::crypto::openssl_memory_resource() fails to link on that name, LNK2019 and LNK1120.
// The texts of ld64 and GNU ld are checked by tools/test/crypto_jamfiles_test.py.
#include <webcpp/crypto/backends/openssl.hpp>
#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/crypto/ciphers/gcm.hpp>

#include <array>
#include <cstdint>

int main() {
    std::array<std::uint8_t, 32> const key{};
    auto const aead = webcpp::crypto::ciphers::gcm<
        webcpp::crypto::ciphers::aes256<webcpp::crypto::backends::openssl>>::from_key(key);
    return aead ? 0 : 1;
}
