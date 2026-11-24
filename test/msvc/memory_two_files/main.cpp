// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Two translation units, one compiled with WEBCPP_CRYPTO_OPENSSL_MEMORY_RESOURCE (with.cpp) and
// one without (this file), whose OpenSSL from_key functions differ. MSVC's linker compares the
// values of backends/openssl.hpp's #pragma detect_mismatch and fails with LNK2038 (spec section
// 3.7).
// Elsewhere the program links (the fixture memory_two_files records it); it is MSVC's case alone.
#include <webcpp/crypto/backends/openssl.hpp>
#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/crypto/ciphers/gcm.hpp>

#include <array>
#include <cstdint>

bool make_with_the_option();

int main() {
    std::array<std::uint8_t, 32> const key{};
    auto const aead = webcpp::crypto::ciphers::gcm<
        webcpp::crypto::ciphers::aes256<webcpp::crypto::backends::openssl>>::from_key(key);
    return aead && make_with_the_option() ? 0 : 1;
}
