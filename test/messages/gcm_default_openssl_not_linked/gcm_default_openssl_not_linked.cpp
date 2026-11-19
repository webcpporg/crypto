// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A native program that links BearSSL alone and calls aes256_gcm, whose default backend natively
// is OpenSSL whatever is linked (design D32, the owner's answer Q2), stops where it calls it,
// with the line that links OpenSSL and the type that names BearSSL.

// clang-format off
// expected-error@webcpp/crypto/ciphers/gcm.hpp:* {{webcpp::crypto: AES-GCM's default backend on this target is OpenSSL, which is not linked. Add /webcpp/crypto//gcm-default, the default's library on every target, to the program's Jamfile, as in: exe app : app.cpp /webcpp/crypto//crypto /webcpp/crypto//gcm-default ; or name another backend in the type, as in ciphers::gcm<ciphers::aes256<backends::bearssl>>. The backends that have it: bearssl (native, wasip2, wasip3, emscripten), openssl (native, wasip2, wasip3). (without b2: define WEBCPP_CRYPTO_HAS_OPENSSL=1 and link libcrypto)}}
// clang-format on

#include <webcpp/crypto/ciphers/aes256_gcm.hpp>

#include <array>
#include <cstdint>

int main() {
    std::array<std::uint8_t, 32> const key{};
    return webcpp::crypto::ciphers::aes256_gcm::make(key) ? 0 : 1;
}
