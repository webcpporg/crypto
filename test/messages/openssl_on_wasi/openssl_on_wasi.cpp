// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A program for wasip2 or wasip3 that links OpenSSL compiles, and names it in the type: OpenSSL
// is refused on Emscripten alone, and AES-GCM's default there stays BearSSL (design D32).

#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/crypto/ciphers/gcm.hpp>
#include <webcpp/crypto/detail/defaults.hpp>
#include <webcpp/crypto/supports.hpp>

#include <type_traits>

namespace crypto = webcpp::crypto;

static_assert(
    crypto::supports_v<crypto::ciphers::gcm<crypto::ciphers::aes256<crypto::backends::openssl>>,
                       crypto::backends::openssl>,
    "OpenSSL has AES-GCM on WASI");
static_assert(
    std::is_same_v<crypto::default_backend_t<crypto::families::gcm>, crypto::backends::bearssl>,
    "linking OpenSSL leaves BearSSL the default");

int main() {
    return 0;
}
