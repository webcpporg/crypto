// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// secret_key_encryption::basic_secretbox given a family that is no secret box's, an AEAD's,
// stops with the two families it takes, and with that error alone.

// clang-format off
// expected-error@webcpp/crypto/secret_key_encryption/secretbox.hpp:* {{webcpp::crypto: secret_key_encryption::basic_secretbox takes a secret box family: families::secretbox_xsalsa20poly1305 or families::secretbox_xchacha20poly1305.}}
// clang-format on
#include <webcpp/crypto/secret_key_encryption/secretbox.hpp>

#include <array>
#include <cstdint>

int main() {
    namespace crypto = webcpp::crypto;
    using secretbox =
        crypto::secret_key_encryption::basic_secretbox<crypto::families::xchacha20_poly1305,
                                                       crypto::backends::sodium>;
    std::array<std::uint8_t, 32> const key{};
    return secretbox::from_key(key) ? 0 : 1;
}
