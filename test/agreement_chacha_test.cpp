// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// ChaCha20-Poly1305 on libsodium, BearSSL and OpenSSL, pairwise (spec section 8.2), with a
// fixed seed and with one the system draws, printed first; on Emscripten, which has no OpenSSL,
// libsodium against BearSSL. agreement_chacha_portable_test.cpp compiles this source again with
// WEBCPP_CRYPTO_DETAIL_BEARSSL_PORTABLE defined, so that both of BearSSL's code paths meet the
// others'; each program first checks that BearSSL runs the code the seam says.

#include <webcpp/crypto/backends/bearssl.hpp>
#include <webcpp/crypto/backends/sodium.hpp>
#ifdef WEBCPP_CRYPTO_HAS_OPENSSL
#include <webcpp/crypto/backends/openssl.hpp>
#endif
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
    // On every target the seam keeps the constant-time portable code.
    BOOST_TEST(crypto::detail::bearssl_chacha20() == &br_chacha20_ct_run);
    BOOST_TEST(crypto::detail::bearssl_poly1305() == &br_poly1305_ctmul_run);
#else
    // Without it, SSE2's ChaCha20 and the 64-bit multiplication's Poly1305 where the CPU and the
    // build have them.
    br_chacha20_run const sse2 = br_chacha20_sse2_get();
    br_poly1305_run const ctmulq = br_poly1305_ctmulq_get();
    BOOST_TEST(crypto::detail::bearssl_chacha20() ==
               (sse2 != nullptr ? sse2 : &br_chacha20_ct_run));
    BOOST_TEST(crypto::detail::bearssl_poly1305() ==
               (ctmulq != nullptr ? ctmulq : &br_poly1305_ctmul_run));
    std::printf("BearSSL's ChaCha20: %s; its Poly1305: %s\n", sse2 != nullptr ? "SSE2" : "ct",
                ctmulq != nullptr ? "ctmulq" : "ctmul");
#endif
}

/** Every pair of the target's backends from one seed. */
void agree(std::uint64_t seed) {
    using crypto::backends::bearssl;
    using crypto::backends::sodium;
    webcpp::test::agree_chacha<sodium, bearssl>(seed);
#ifdef WEBCPP_CRYPTO_HAS_OPENSSL
    using crypto::backends::openssl;
    webcpp::test::agree_chacha<sodium, openssl>(seed);
    webcpp::test::agree_chacha<bearssl, openssl>(seed);
#endif
}

}  // namespace

int main() {
    check_code_paths();
    // A fixed seed, so that a failure repeats.
    agree(20261011);
    std::uint64_t const seed = std::random_device{}();
    std::printf("seed %llu\n", static_cast<unsigned long long>(seed));
    agree(seed);
    return webcpp::test::exit_status(boost::report_errors());
}
