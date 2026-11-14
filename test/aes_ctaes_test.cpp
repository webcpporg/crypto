// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The AES block cipher on ctaes: FIPS-197, the guards and moved-from objects
// (support/aes_checks.hpp), on every target. NIST's known answers are deferred (ruling R5).

#include <webcpp/crypto/backends/ctaes.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/aes_checks.hpp"

#include <array>
#include <cstdint>

namespace {

/** The round trip the guide shows: encrypts a block and decrypts it again. */
bool round_trip() {
    // tag::round_trip[]
    std::array<std::uint8_t, 32> key{};
    std::array<std::uint8_t, 16> block{};
    auto aes = webcpp::crypto::aes256<webcpp::crypto::backends::ctaes>::make(key);
    if (aes && aes->encrypt(block) && aes->decrypt(block)) {
        return true;  // block holds the plaintext again
    }
    // end::round_trip[]
    return false;
}

}  // namespace

int main() {
    BOOST_TEST(round_trip());
    using webcpp::crypto::backends::ctaes;
    webcpp::test::check_fips197<ctaes>();
    webcpp::test::check_aes_guards<ctaes>();
    webcpp::test::check_aes_moved_from<ctaes>();
    return webcpp::test::exit_status(boost::report_errors());
}
