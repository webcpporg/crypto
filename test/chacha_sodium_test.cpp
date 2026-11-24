// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// ChaCha20-Poly1305 (RFC 8439) on libsodium, through its default type,
// ciphers::chacha20_poly1305<>, whose backend is libsodium on every target: RFC 8439's section
// 2.8.2 and appendix A.5 and libsodium's own case, every guard, tampering, moves, empty
// inputs and aliasing spans (support/aead_checks.hpp), and natively the message's limit.

#include <webcpp/crypto/ciphers/chacha20_poly1305.hpp>
#include <webcpp/crypto/supports.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/aead_checks.hpp"

#include <boost/core/lightweight_test.hpp>

#include <cstddef>
#include <cstdint>
#include <type_traits>

namespace crypto = webcpp::crypto;

using chacha = crypto::ciphers::chacha20_poly1305<>;

// The default is libsodium on every target (the owner's answer Q4), and the type names its
// family and its algorithm as the capability table does.
static_assert(std::is_same_v<crypto::default_backend_t<crypto::families::chacha20_poly1305>,
                             crypto::backends::sodium>);
static_assert(
    std::is_same_v<chacha, crypto::ciphers::basic_chacha20_poly1305<
                               crypto::families::chacha20_poly1305, crypto::backends::sodium>>);
static_assert(std::is_same_v<chacha::family_type, crypto::families::chacha20_poly1305>);
static_assert(std::is_same_v<chacha::name_type, crypto::families::chacha20_poly1305>);
static_assert(crypto::supports_v<chacha, crypto::backends::sodium>);
static_assert(chacha::key_size == 32 && chacha::nonce_size == 12 && chacha::tag_size == 16);
static_assert(chacha::max_message_size == (std::uint64_t{1} << 38U) - 64);

int main() {
    webcpp::test::check_aead<chacha>(webcpp::test::chacha20_poly1305_cases);
#if !defined(__wasi__) && !defined(__EMSCRIPTEN__)
    if constexpr (sizeof(std::size_t) == 8) {
        webcpp::test::check_aead_limits<chacha>();
    }
#endif
    return webcpp::test::exit_status(boost::report_errors());
}
