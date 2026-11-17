// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A program for wasip2 or wasip3 that links no backend and calls aes256_gcm, whose default
// backend on WebAssembly is BearSSL, stops where it calls it with the line that links BearSSL
// (design D32).

// clang-format off
// expected-error@webcpp/crypto/ciphers/gcm.hpp:* {{webcpp::crypto: AES-GCM's default backend on this target is BearSSL, which is not linked. Add /third_party//bearssl to the program's Jamfile, as in: exe app : app.cpp /webcpp/crypto//crypto /third_party//bearssl ; or name another backend in the type, as in ciphers::gcm<ciphers::aes256<backends::openssl>>. The backends that have it: bearssl (native, wasip2, wasip3, emscripten), openssl (native, wasip2, wasip3).}}
// clang-format on

#include <webcpp/crypto/ciphers/aes256_gcm.hpp>

#include <array>
#include <cstdint>

int main() {
    std::array<std::uint8_t, 32> const key{};
    return webcpp::crypto::ciphers::aes256_gcm::make(key) ? 0 : 1;
}
