// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A wasip2 or wasip3 program that links OpenSSL alone and calls aes256<>, whose default backend on
// WebAssembly is ctaes whatever is linked (design D3), stops where it calls it, with the line
// that links ctaes and the type that names OpenSSL.

// clang-format off
// expected-error@webcpp/crypto/ciphers/aes.hpp:* {{webcpp::crypto: AES block cipher's default backend on this target is ctaes, which is not linked. Add /webcpp/crypto//aes_block-default, the default's library on every target, to the program's Jamfile, as in: exe app : app.cpp /webcpp/crypto//crypto /webcpp/crypto//aes_block-default ; or name another backend in the type, as in ciphers::aes256<backends::openssl>. The backends that have it: openssl (native, wasip2, wasip3), ctaes (native, wasip2, wasip3, emscripten). (without b2: define WEBCPP_CRYPTO_HAS_CTAES=1 and link ctaes.c with webcpp's src/canary_ctaes.c)}}
// clang-format on

#include <webcpp/crypto/ciphers/aes.hpp>

#include <array>
#include <cstdint>

int main() {
    std::array<std::uint8_t, 32> const key{};
    return webcpp::crypto::ciphers::aes256<>::make(key) ? 0 : 1;
}
