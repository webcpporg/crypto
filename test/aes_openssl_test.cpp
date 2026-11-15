// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The AES block cipher on OpenSSL: the block cipher's checks (support/aes_checks.hpp), and
// OpenSSL's known answers, FIPS-197 appendix C and AES-128 of the zero block under the zero key.

#include <webcpp/crypto/backends/openssl.hpp>
#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/aes_checks.hpp"

#include <boost/core/lightweight_test.hpp>

#include <array>
#include <cstdint>

namespace {

namespace crypto = webcpp::crypto;
using crypto::backends::openssl;

}  // namespace

int main() {
    webcpp::test::check_block_cipher<openssl>();
    webcpp::test::check_fips197<openssl>();
    std::array<std::uint8_t, 16> const zero_key{};
    webcpp::test::check_answer<crypto::ciphers::aes128<openssl>>(
        zero_key, "00000000000000000000000000000000", "66e94bd4ef8a2c3b884cfa59ca342b2e");
    return webcpp::test::exit_status(boost::report_errors());
}
