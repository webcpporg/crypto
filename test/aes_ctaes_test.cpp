// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The AES block cipher on ctaes, on every target: the block cipher's checks
// (support/aes_checks.hpp), and FIPS-197 appendix C. NIST's known answers are deferred
// (ruling R5).

#include <webcpp/crypto/backends/ctaes.hpp>
#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/aes_checks.hpp"

#include <boost/core/lightweight_test.hpp>

#include <array>
#include <cstdint>

namespace {

namespace crypto = webcpp::crypto;
using crypto::backends::ctaes;

/** The round trip the guide shows: encrypts a block and decrypts it again. */
bool round_trip() {
    // tag::round_trip[]
    std::array<std::uint8_t, 32> key{};
    std::array<std::uint8_t, 16> block{};
    auto aes = webcpp::crypto::ciphers::aes256<webcpp::crypto::backends::ctaes>::make(key);
    // On success, block holds the plaintext again.
    bool const ok = aes && aes->encrypt(block) && aes->decrypt(block);
    // end::round_trip[]
    return ok;
}

}  // namespace

int main() {
    BOOST_TEST(round_trip());
    webcpp::test::check_block_cipher<ctaes>();
    webcpp::test::check_fips197<ctaes>();
    return webcpp::test::exit_status(boost::report_errors());
}
