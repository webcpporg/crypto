// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// XChaCha20-Poly1305, its 24-byte nonce, on libsodium, through its default type,
// ciphers::xchacha20_poly1305<>: the XChaCha draft's appendix A.3.1 and libsodium's own
// cases, every guard, tampering, moves, empty inputs and aliasing spans
// (support/aead_checks.hpp). Its limit, 2^64 - 17 bytes, no span reaches.

#include <webcpp/crypto/ciphers/chacha20_poly1305.hpp>
#include <webcpp/crypto/supports.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/aead_checks.hpp"

#include <boost/core/lightweight_test.hpp>

#include <cstdint>
#include <type_traits>

namespace crypto = webcpp::crypto;

using xchacha = crypto::ciphers::xchacha20_poly1305<>;

static_assert(std::is_same_v<crypto::default_backend_t<crypto::families::xchacha20_poly1305>,
                             crypto::backends::sodium>);
static_assert(std::is_same_v<xchacha, crypto::ciphers::aead<crypto::families::xchacha20_poly1305,
                                                            crypto::backends::sodium>>);
static_assert(std::is_same_v<xchacha::family_type, crypto::families::xchacha20_poly1305>);
static_assert(std::is_same_v<xchacha::name_type, crypto::families::xchacha20_poly1305>);
static_assert(crypto::supports_v<xchacha, crypto::backends::sodium>);
static_assert(xchacha::key_size == 32 && xchacha::nonce_size == 24 && xchacha::tag_size == 16);
static_assert(xchacha::max_message_size == ~std::uint64_t{0} - 16);

int main() {
    webcpp::test::check_aead<xchacha>(webcpp::test::xchacha20_poly1305_cases);
    return webcpp::test::exit_status(boost::report_errors());
}
