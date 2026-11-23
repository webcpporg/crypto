// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// What a program that still names ciphers::secretbox<> as it did sees (design D11): each removed
// name stops the build, clang offering the secret_key_encryption name in its place, with those two
// errors alone. libsodium is linked, so that the corrected type adds no refusal of its own.

#include <webcpp/crypto/ciphers/chacha20_poly1305.hpp>
#include <webcpp/crypto/secret_key_encryption/secretbox.hpp>

#include <array>
#include <cstdint>

int main() {
    namespace crypto = webcpp::crypto;
    std::array<std::uint8_t, 32> const key{};
    // clang-format off
    // expected-error@+2 {{no template named 'secretbox' in namespace 'webcpp::crypto::ciphers'; did you mean 'webcpp::crypto::secret_key_encryption::secretbox'?}}
    // clang-format on
    bool const made = crypto::ciphers::secretbox<>::from_key(key).has_value();
    // clang-format off
    // expected-error@+3 {{no template named 'secretbox_xchacha20poly1305' in namespace 'webcpp::crypto::ciphers'; did you mean 'webcpp::crypto::secret_key_encryption::secretbox_xchacha20poly1305'?}}
    // clang-format on
    bool const made_xchacha =
        crypto::ciphers::secretbox_xchacha20poly1305<>::from_key(key).has_value();
    return made && made_xchacha ? 0 : 1;
}
