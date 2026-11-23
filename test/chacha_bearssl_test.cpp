// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// ChaCha20-Poly1305 (RFC 8439) on BearSSL, on every target: RFC 8439's section 2.8.2 and
// appendix A.5 and libsodium's own case, every guard, tampering, moves, empty inputs and
// aliasing spans (support/aead_checks.hpp), and natively the message's limit. BearSSL's ChaCha20
// and Poly1305 run in one function over the whole message, the tag compared by equal.

#include <webcpp/crypto/backends/bearssl.hpp>
#include <webcpp/crypto/ciphers/chacha20_poly1305.hpp>
#include <webcpp/crypto/supports.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/aead_checks.hpp"

#include <boost/core/lightweight_test.hpp>

#include <cstddef>
#include <cstdint>
#include <type_traits>

namespace crypto = webcpp::crypto;

using chacha = crypto::ciphers::chacha20_poly1305<crypto::backends::bearssl>;

// The type names its family and its algorithm as the capability table does, and the table
// has the cell on this target.
static_assert(std::is_same_v<chacha, crypto::ciphers::aead<crypto::families::chacha20_poly1305,
                                                           crypto::backends::bearssl>>);
static_assert(std::is_same_v<chacha::family_type, crypto::families::chacha20_poly1305>);
static_assert(crypto::supports_v<chacha, crypto::backends::bearssl>);
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
