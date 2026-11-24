// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// ciphers::basic_chacha20_poly1305 given AES-GCM's family, which is no AEAD family of its: refused.
#include <webcpp/crypto/ciphers/aead.hpp>

#include <array>
#include <cstdint>

int main() {
    namespace crypto = webcpp::crypto;
    std::array<std::uint8_t, 32> const key{};
    auto made = crypto::ciphers::basic_chacha20_poly1305<crypto::families::gcm,
                                                         crypto::backends::sodium>::from_key(key);
    return made ? 0 : 1;
}
