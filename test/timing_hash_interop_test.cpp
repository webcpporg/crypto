// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The guard of webcpp::crypto and the guard of webcpp::hash are two copies of one design
// (hash's detail/timing.hpp names this test as what keeps them in step). This program runs both:
// they agree on whether the CPU has DIT and on whether it is set; nested, either inside the
// other, DIT is set inside both, still set after the inner guard, and as it was before after the
// outer one, from a clear state and from one the program set itself; Ed25519ph's prehash by
// hash's SHA-512 is unkeyed and enters no guard of hash; and an hkdf of hash beside an Ed25519
// signature of crypto on one thread each enter their own library's guard and leave the state
// as they found it.

#include "support/timing_seam.hpp"

#include <cstddef>

namespace webcpp::test {

/** The number of webcpp::hash::detail::timing_guard objects this thread has constructed. */
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): the seam's counter
inline thread_local std::size_t hash_timing_entries = 0;

}  // namespace webcpp::test

/** Counts the entry into a hash guard; the function it names does not matter to this test. */
#define WEBCPP_HASH_DETAIL_TIMING_ENTERED(where) \
    (static_cast<void>(where), ++::webcpp::test::hash_timing_entries)

#include <webcpp/crypto/backends/sodium.hpp>
#include <webcpp/crypto/curves/ed25519.hpp>
#include <webcpp/crypto/detail/timing.hpp>
#include <webcpp/hash/detail/timing.hpp>
#include <webcpp/hash/hkdf.hpp>
#include <webcpp/hash/hmac.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"

#include <boost/core/lightweight_test.hpp>

#include <array>
#include <cstdint>
#include <span>

namespace {

namespace crypto_detail = webcpp::crypto::detail;
namespace hash_detail = webcpp::hash::detail;
namespace ed25519 = webcpp::crypto::curves::ed25519;
using webcpp::test::hash_timing_entries;
using webcpp::test::timing_entries;

/**
 * Sets or clears DIT for this thread, as a program can, so that a test starts from a known state;
 * only where the CPU has DIT, since the instruction traps on a CPU without it.
 */
void force_dit([[maybe_unused]] bool set) {
#ifdef WEBCPP_CRYPTO_DETAIL_TIMING_COVERED
    if (!crypto_detail::cpu_has_dit()) {
        return;
    }
    crypto_detail::write_dit(set ? crypto_detail::dit_bit : 0);
#endif
}

/** Whether the two copies read the same state of the thread's DIT. */
bool states_agree() {
    return crypto_detail::dit_is_set() == hash_detail::dit_is_set();
}

// The two copies agree on what the CPU offers and on the thread's state, outside and inside each
// guard, from a clear state and from a set one.
void same_cpu() {
    BOOST_TEST_EQ(crypto_detail::cpu_has_dit(), hash_detail::cpu_has_dit());
    for (bool const initial : {false, true}) {
        force_dit(initial);
        BOOST_TEST(states_agree());
        {
            crypto_detail::timing_guard const guard;
            BOOST_TEST(states_agree());
        }
        BOOST_TEST(states_agree());
        {
            hash_detail::timing_guard const guard;
            BOOST_TEST(states_agree());
        }
        BOOST_TEST(states_agree());
    }
    force_dit(false);
}

// Whether DIT is set, in the one place both copies agree it is read.
bool dit_set() {
    return crypto_detail::dit_is_set();
}

// With `inner` nested in `outer`: DIT is set inside both, still set after the inner guard, and as
// it was before after the outer one.
template <class Outer, class Inner>
void nest(bool initially_set) {
    force_dit(initially_set);
    bool const offered = crypto_detail::cpu_has_dit();
    bool const before = dit_set();
    BOOST_TEST_EQ(before, initially_set && offered);
    {
        Outer const outer;
        BOOST_TEST_EQ(dit_set(), offered);
        {
            Inner const inner;
            BOOST_TEST_EQ(dit_set(), offered);
        }
        BOOST_TEST_EQ(dit_set(), offered);
    }
    BOOST_TEST_EQ(dit_set(), before);
    force_dit(false);
}

// A hash guard inside a crypto guard.
void hash_inside_crypto() {
    nest<crypto_detail::timing_guard, hash_detail::timing_guard>(false);
    nest<crypto_detail::timing_guard, hash_detail::timing_guard>(true);
}

// A crypto guard inside a hash guard.
void crypto_inside_hash() {
    nest<hash_detail::timing_guard, crypto_detail::timing_guard>(false);
    nest<hash_detail::timing_guard, crypto_detail::timing_guard>(true);
}

/** RFC 8032 section 7.1, TEST 1: the secret key (the seed). */
constexpr std::string_view seed =
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

// Ed25519ph signs with hash's SHA-512 as its prehash, which is unkeyed (D2): crypto's counter
// rises, hash's does not.
void ed25519ph_uses_hash_unkeyed() {
    using ph = ed25519::ph<webcpp::hash::sha2_512>;
    auto const key = ed25519::basic_keypair<webcpp::crypto::backends::sodium>::make(
        webcpp::test::from_hex(seed));
    if (!BOOST_TEST(key.has_value())) {
        return;
    }
    std::array<std::uint8_t, 3> const piece{1, 2, 3};
    auto signer = ph::begin();
    if (!BOOST_TEST(signer.has_value()) || !BOOST_TEST(signer->update(piece).has_value())) {
        return;
    }
    std::size_t const crypto_before = timing_entries;
    std::size_t const hash_before = hash_timing_entries;
    auto const signature = signer->sign(*key);
    BOOST_TEST(signature.has_value());
    BOOST_TEST_GT(timing_entries, crypto_before);
    BOOST_TEST_EQ(hash_timing_entries, hash_before);
}

// An hkdf of hash, then an Ed25519 signature of crypto, on one thread: each enters only its own
// library's guard, and the thread's DIT is as before after both.
void hkdf_beside_crypto() {
    for (bool const initial : {false, true}) {
        force_dit(initial);
        bool const before = dit_set();
        std::array<std::uint8_t, 32> okm{};
        std::array<std::uint8_t, 16> const salt{};
        std::array<std::uint8_t, 22> const secret{};
        std::array<std::uint8_t, 4> const info{};
        std::size_t crypto_entries = timing_entries;
        std::size_t hash_entries = hash_timing_entries;
        auto const derived =
            webcpp::hash::hkdf<webcpp::hash::hmac_sha2_256>(okm, salt, secret, info);
        BOOST_TEST(derived.has_value());
        BOOST_TEST_GT(hash_timing_entries, hash_entries);
        BOOST_TEST_EQ(timing_entries, crypto_entries);
        BOOST_TEST_EQ(dit_set(), before);

        auto const key = ed25519::basic_keypair<webcpp::crypto::backends::sodium>::make(okm);
        if (!BOOST_TEST(key.has_value())) {
            continue;
        }
        crypto_entries = timing_entries;
        hash_entries = hash_timing_entries;
        auto const signature = key->sign(std::span<std::uint8_t const>(info));
        BOOST_TEST(signature.has_value());
        BOOST_TEST_GT(timing_entries, crypto_entries);
        BOOST_TEST_EQ(hash_timing_entries, hash_entries);
        BOOST_TEST_EQ(dit_set(), before);
    }
    force_dit(false);
}

}  // namespace

int main() {
    same_cpu();
    hash_inside_crypto();
    crypto_inside_hash();
    ed25519ph_uses_hash_unkeyed();
    hkdf_beside_crypto();
    return webcpp::test::exit_status(boost::report_errors());
}
