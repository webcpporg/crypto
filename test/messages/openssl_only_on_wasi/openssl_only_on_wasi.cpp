// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A program for wasip2 or wasip3 that links OpenSSL alone and calls aes256_gcm, whose default
// backend on WebAssembly is BearSSL whatever is linked (design D32), stops where it calls it,
// with the line that links BearSSL and the type that names OpenSSL.

// clang-format off
// expected-error@webcpp/crypto/ciphers/gcm.hpp:* {{webcpp::crypto: AES-GCM's default backend on this target is BearSSL, which is not linked. Add /webcpp/crypto//gcm-default, the default's library on every target, to the program's Jamfile, as in: exe app : app.cpp /webcpp/crypto//crypto /webcpp/crypto//gcm-default ; or name another backend in the type, as in ciphers::gcm<ciphers::aes256<backends::openssl>>. The backends that have it: bearssl (native, wasip2, wasip3, emscripten), openssl (native, wasip2, wasip3). (without b2: define WEBCPP_CRYPTO_HAS_BEARSSL=1 and link BearSSL built with webcpp's src/canary_bearssl.c)}}
// clang-format on

#include <webcpp/crypto/ciphers/aes256_gcm.hpp>

#include <array>
#include <cstdint>

int main() {
    std::array<std::uint8_t, 32> const key{};
    return webcpp::crypto::ciphers::aes256_gcm::from_key(key) ? 0 : 1;
}
