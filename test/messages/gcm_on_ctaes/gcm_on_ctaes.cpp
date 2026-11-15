// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// GCM on ctaes is refused where it is instantiated, with the backends that have one
// (spec section 2.4).

// clang-format off
// expected-error@webcpp/crypto/backends/ctaes.hpp:* {{webcpp::crypto: ciphers::gcm<ciphers::aes256<backends::ctaes>>: ctaes exports the AES block cipher alone, and webcpp builds no GCM on another library's AES. Use a backend that exports GCM: ciphers::gcm<ciphers::aes256<backends::bearssl>> or ciphers::gcm<ciphers::aes256<backends::openssl>>.}}
// clang-format on
#include <webcpp/crypto/backends/ctaes.hpp>
#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/crypto/ciphers/gcm.hpp>

int main() {
    using aead = webcpp::crypto::ciphers::gcm<
        webcpp::crypto::ciphers::aes256<webcpp::crypto::backends::ctaes>>;
    aead* unused = nullptr;
    auto made = aead::make({});
    return unused == nullptr && !made ? 0 : 1;
}
