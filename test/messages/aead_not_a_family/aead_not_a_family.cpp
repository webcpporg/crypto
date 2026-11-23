// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// ciphers::aead given a family that is no AEAD's, AES-GCM's, stops with the families it
// takes, and with that error alone.

// clang-format off
// expected-error@webcpp/crypto/ciphers/aead.hpp:* {{webcpp::crypto: ciphers::aead takes an AEAD family: families::chacha20_poly1305, families::chacha20_poly1305_original, families::xchacha20_poly1305, families::secretbox_xsalsa20poly1305 or families::secretbox_xchacha20poly1305.}}
// clang-format on
#include <webcpp/crypto/ciphers/aead.hpp>

#include <array>
#include <cstdint>

int main() {
    namespace crypto = webcpp::crypto;
    using aead = crypto::ciphers::aead<crypto::families::gcm, crypto::backends::sodium>;
    std::array<std::uint8_t, 32> const key{};
    return aead::from_key(key) ? 0 : 1;
}
