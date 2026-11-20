// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The specification's two scenarios of DIT on libsodium's Ed25519: a thread whose DIT is clear
// signs RFC 8032's TEST 1 and finds it clear again, with the RFC's signature; a thread that set
// DIT itself, as a program can, finds it still set after signing. Where the CPU has no DIT, or
// the guard does not apply, both reduce to DIT never being read set.

#include <webcpp/crypto/backends/sodium.hpp>
#include <webcpp/crypto/curves/ed25519.hpp>
#include <webcpp/crypto/detail/timing.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"

#include <boost/core/lightweight_test.hpp>

#include <algorithm>
#include <cstdint>
#include <span>
#include <string_view>

namespace {

namespace detail = webcpp::crypto::detail;
using keypair = webcpp::crypto::curves::ed25519::basic_keypair<webcpp::crypto::backends::sodium>;

/** RFC 8032 section 7.1, TEST 1: the secret key (the seed); the message is empty. */
constexpr std::string_view rfc8032_seed =
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
/** RFC 8032 section 7.1, TEST 1: the signature. */
constexpr std::string_view rfc8032_signature =
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9"
    "b46bd25bf5f0595bbe24655141438e7a100b";

/**
 * Sets or clears DIT for this thread, as a program can, so that a test starts from a known state;
 * only where the CPU has DIT, since the instruction traps on a CPU without it.
 */
void force_dit([[maybe_unused]] bool set) {
#ifdef WEBCPP_CRYPTO_DETAIL_TIMING_COVERED
    if (!detail::cpu_has_dit()) {
        return;
    }
    detail::write_dit(set ? detail::dit_bit : 0);
#endif
}

/** Signs TEST 1's empty message with TEST 1's key pair and checks the RFC's signature. */
void sign_test_1() {
    auto const seed = webcpp::test::from_hex(rfc8032_seed);
    auto const expected = webcpp::test::from_hex(rfc8032_signature);
    auto const made = keypair::make(seed);
    if (!BOOST_TEST(made.has_value())) {
        return;
    }
    auto const signature = made->sign(std::span<std::uint8_t const>());
    if (BOOST_TEST(signature.has_value())) {
        BOOST_TEST(std::ranges::equal(*signature, expected));
    }
}

// A program that never set DIT signs: DIT is clear again when sign returns.
void sign_clears_state() {
    force_dit(false);
    BOOST_TEST(!detail::dit_is_set());
    sign_test_1();
    BOOST_TEST(!detail::dit_is_set());
}

// A program that set DIT itself signs: DIT is still set when sign returns.
void sign_leaves_set_state() {
    force_dit(true);
    BOOST_TEST_EQ(detail::dit_is_set(), detail::cpu_has_dit());
    sign_test_1();
    BOOST_TEST_EQ(detail::dit_is_set(), detail::cpu_has_dit());
    force_dit(false);
    BOOST_TEST(!detail::dit_is_set());
}

}  // namespace

int main() {
    sign_clears_state();
    sign_leaves_set_state();
    return webcpp::test::exit_status(boost::report_errors());
}
