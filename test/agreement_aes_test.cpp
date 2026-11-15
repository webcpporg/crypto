// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// ctaes against OpenSSL on the AES block cipher (spec section 8.2, second row): 10,000 random
// keys of each size and a random message of 0 to 64 blocks for each, with a fixed seed and
// with one the system draws, printed first (support/agreement.hpp).

#include <webcpp/crypto/backends/ctaes.hpp>
#include <webcpp/crypto/backends/openssl.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/agreement.hpp"

#include <boost/core/lightweight_test.hpp>

#include <cstdint>
#include <cstdio>
#include <random>

int main() {
    using webcpp::crypto::backends::ctaes;
    using webcpp::crypto::backends::openssl;
    // A fixed seed, so that a failure repeats.
    webcpp::test::agree_aes<ctaes, openssl>(0x5eedae5ULL);
    std::uint64_t const seed = std::random_device{}();
    std::printf("seed %llu\n", static_cast<unsigned long long>(seed));
    webcpp::test::agree_aes<ctaes, openssl>(seed);
    return webcpp::test::exit_status(boost::report_errors());
}
