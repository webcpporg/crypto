// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The original ChaCha20-Poly1305, its 8-byte nonce, on libsodium, through its default type,
// ciphers::chacha20_poly1305_original<>: libsodium's own cases, every guard, tampering, moves,
// empty inputs and aliasing spans (support/aead_checks.hpp). Its limit, 2^64 - 17 bytes, no
// span reaches.

#include <webcpp/crypto/ciphers/chacha20_poly1305.hpp>
#include <webcpp/crypto/supports.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/aead_checks.hpp"

#include <boost/core/lightweight_test.hpp>

#include <cstdint>
#include <type_traits>

namespace crypto = webcpp::crypto;

using original = crypto::ciphers::chacha20_poly1305_original<>;

static_assert(
    std::is_same_v<crypto::default_backend_t<crypto::families::chacha20_poly1305_original>,
                   crypto::backends::sodium>);
static_assert(
    std::is_same_v<original, crypto::ciphers::aead<crypto::families::chacha20_poly1305_original,
                                                   crypto::backends::sodium>>);
static_assert(std::is_same_v<original::family_type, crypto::families::chacha20_poly1305_original>);
static_assert(std::is_same_v<original::name_type, crypto::families::chacha20_poly1305_original>);
static_assert(crypto::supports_v<original, crypto::backends::sodium>);
static_assert(original::key_size == 32 && original::nonce_size == 8 && original::tag_size == 16);
static_assert(original::max_message_size == ~std::uint64_t{0} - 16);

int main() {
    webcpp::test::check_aead<original>(webcpp::test::chacha20_poly1305_original_cases);
    return webcpp::test::exit_status(boost::report_errors());
}
