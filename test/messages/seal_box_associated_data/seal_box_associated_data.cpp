// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A secret box takes no associated data (design D5): given to the AEAD form
// crypto::secret_key_encryption::aead::seal, which takes it, it stops with the refusal that names
// the box form, secret_key_encryption::seal(box, nonce, data), and with that error alone. The box
// is a parameter, since making one would run libsodium's engine.

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so each
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/crypto/secret_key_encryption/authenticated_box.hpp:* {{webcpp::crypto: seal: a secret box or a crypto_box takes no associated data: secret_key_encryption::seal(box, nonce, data).}}
// clang-format on
#include <webcpp/crypto/secret_key_encryption/aead.hpp>
#include <webcpp/crypto/secret_key_encryption/secretbox.hpp>

#include <array>
#include <cstdint>

namespace {

namespace crypto = webcpp::crypto;

/** Seals with associated data through the AEAD form. */
bool sealed(crypto::secret_key_encryption::secretbox<>& secretbox) {
    std::array<std::uint8_t, 24> const nonce{};
    std::array<std::uint8_t, 2> const associated_data{'i', 'd'};
    std::array<std::uint8_t, 5> data{'h', 'e', 'l', 'l', 'o'};
    return crypto::secret_key_encryption::aead::seal(secretbox, nonce, associated_data, data)
        .has_value();
}

}  // namespace

// The function is compiled, which is the test; it is never run.
int main() {
    static_cast<void>(&sealed);
    return 0;
}
