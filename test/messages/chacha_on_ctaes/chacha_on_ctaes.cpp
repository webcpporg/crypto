// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// ChaCha20-Poly1305 on ctaes, which exports the AES block cipher alone, is refused where it is
// called, with the backends that have it and their targets (the generated refusal,
// detail/capabilities.hpp).

// clang-format off
// expected-error@webcpp/crypto/ciphers/aead.hpp:* {{webcpp::crypto: ctaes has no ChaCha20-Poly1305. The backends that have it: sodium (native, wasip2, wasip3, emscripten), bearssl (native, wasip2, wasip3, emscripten), openssl (native, wasip2, wasip3).}}
// clang-format on
#include <webcpp/crypto/backends/ctaes.hpp>
#include <webcpp/crypto/ciphers/chacha20_poly1305.hpp>

#include <array>
#include <cstdint>

int main() {
    namespace crypto = webcpp::crypto;
    std::array<std::uint8_t, 32> const key{};
    return crypto::ciphers::chacha20_poly1305<crypto::backends::ctaes>::from_key(key) ? 0 : 1;
}
