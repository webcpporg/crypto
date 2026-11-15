// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// BearSSL against OpenSSL on AES-GCM (spec section 8.2), with a fixed seed and with one the
// system draws, printed first. agreement_gcm_portable_test.cpp compiles this source again
// with WEBCPP_CRYPTO_DETAIL_BEARSSL_PORTABLE defined, so that both of BearSSL's code paths
// meet OpenSSL's; each program first checks that BearSSL runs the code the seam says.

#include <webcpp/crypto/backends/bearssl.hpp>
#include <webcpp/crypto/backends/openssl.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/agreement.hpp"

#include <boost/core/lightweight_test.hpp>

#include <cstdint>
#include <cstdio>
#include <random>

namespace {

namespace crypto = webcpp::crypto;

/** Checks that BearSSL runs the code the seam selects. */
void check_code_paths() {
#ifdef WEBCPP_CRYPTO_DETAIL_BEARSSL_PORTABLE
    // On every target the seam keeps the constant-time 64-bit code.
    BOOST_TEST(crypto::detail::bearssl_ctr() == &br_aes_ct64_ctr_vtable);
    BOOST_TEST(crypto::detail::bearssl_ghash() == &br_ghash_ctmul64);
#elif defined(__x86_64__) || defined(_M_X64)
    // Without the seam, an x86-64 CPU with AES-NI and PCLMUL runs them.
    if (br_aes_x86ni_ctr_get_vtable() == nullptr || br_ghash_pclmul_get() == nullptr) {
        // The vtable is null when the CPU lacks the instructions and when BearSSL compiled the
        // code out: in both, the two programs of this test run the same portable path.
        std::printf(
            "AES-NI or PCLMUL unavailable (the CPU or the build): BearSSL runs its "
            "portable code\n");
    } else {
        BOOST_TEST(crypto::detail::bearssl_ctr() == br_aes_x86ni_ctr_get_vtable());
        BOOST_TEST(crypto::detail::bearssl_ghash() == br_ghash_pclmul_get());
    }
#endif
}

}  // namespace

int main() {
    using crypto::backends::bearssl;
    using crypto::backends::openssl;
    check_code_paths();
    // A fixed seed, so that a failure repeats.
    webcpp::test::agree_gcm<bearssl, openssl>(20261011);
    std::uint64_t const seed = std::random_device{}();
    std::printf("seed %llu\n", static_cast<unsigned long long>(seed));
    webcpp::test::agree_gcm<bearssl, openssl>(seed);
    return webcpp::test::exit_status(boost::report_errors());
}
