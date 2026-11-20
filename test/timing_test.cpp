// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// detail::timing_guard, with no backend: its seam fires once per guard on every target; where
// the CPU has DIT, a guard sets it for its scope and clears it after when it was clear, leaves it
// set when it was set, and nests; equal enters a guard. Built with WEBCPP_TEST_TIMING_THREADS
// (timing_threads, native, with threads), a guard on one thread leaves another's DIT clear.

#include "support/timing_seam.hpp"

#include <webcpp/crypto/detail/timing.hpp>
#include <webcpp/crypto/equal.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>
#include <boost/hash2/digest.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#ifdef WEBCPP_TEST_TIMING_THREADS
#include <future>
#include <thread>
#endif

namespace {

namespace detail = webcpp::crypto::detail;

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

// Constructing a guard raises the seam's count by exactly one, on every target.
void seam_fires() {
    std::size_t const before = webcpp::test::timing_entries;
    {
        detail::timing_guard const guard;
        BOOST_TEST_EQ(webcpp::test::timing_entries, before + 1);
    }
    BOOST_TEST_EQ(webcpp::test::timing_entries, before + 1);
}

// From clear: set inside a guard, clear after it. Where the guard does not apply, never set.
void guard_sets_and_clears() {
    force_dit(false);
    BOOST_TEST(!detail::dit_is_set());
    {
        detail::timing_guard const guard;
        BOOST_TEST_EQ(detail::dit_is_set(), detail::cpu_has_dit());
    }
    BOOST_TEST(!detail::dit_is_set());
}

// From set, as a program sets it: still set after a guard.
void guard_leaves_set_bit() {
    force_dit(true);
    BOOST_TEST_EQ(detail::dit_is_set(), detail::cpu_has_dit());
    {
        detail::timing_guard const guard;
        BOOST_TEST_EQ(detail::dit_is_set(), detail::cpu_has_dit());
    }
    BOOST_TEST_EQ(detail::dit_is_set(), detail::cpu_has_dit());
    force_dit(false);
    BOOST_TEST(!detail::dit_is_set());
}

// From clear: set inside both guards and after the inner one, clear after the outer one.
void nested_guards() {
    force_dit(false);
    {
        detail::timing_guard const outer;
        {
            detail::timing_guard const inner;
            BOOST_TEST_EQ(detail::dit_is_set(), detail::cpu_has_dit());
        }
        BOOST_TEST_EQ(detail::dit_is_set(), detail::cpu_has_dit());
    }
    BOOST_TEST(!detail::dit_is_set());
}

// Both overloads of equal enter a guard, and leave DIT as they found it.
void equal_enters() {
    force_dit(false);
    std::array<std::uint8_t, 16> const first{};
    std::array<std::uint8_t, 16> const second{};
    webcpp::test::require_enters("equal(span, span)", [&first, &second] {
        BOOST_TEST(webcpp::crypto::equal(std::span<std::uint8_t const>(first),
                                         std::span<std::uint8_t const>(second)));
    });
    boost::hash2::digest<16> const first_digest{};
    boost::hash2::digest<16> const second_digest{};
    webcpp::test::require_enters("equal(digest, digest)", [&first_digest, &second_digest] {
        BOOST_TEST(webcpp::crypto::equal(first_digest, second_digest));
    });
    BOOST_TEST(!detail::dit_is_set());
}

#ifdef WEBCPP_TEST_TIMING_THREADS
// While a guard holds DIT on this thread, another thread reads it clear. The other thread is
// started before the guard, so that it cannot inherit the state at its creation (Linux's clone
// copies PSTATE), and reads it only once the guard is entered.
void other_thread_untouched() {
    force_dit(false);
    std::promise<void> guard_entered;
    std::promise<bool> other_reading;
    std::thread other([entered = guard_entered.get_future(), &other_reading]() mutable {
        entered.wait();
        other_reading.set_value(detail::dit_is_set());
    });
    {
        detail::timing_guard const guard;
        guard_entered.set_value();
        BOOST_TEST(!other_reading.get_future().get());
        BOOST_TEST_EQ(detail::dit_is_set(), detail::cpu_has_dit());
    }
    other.join();
    BOOST_TEST(!detail::dit_is_set());
}
#endif

}  // namespace

int main() {
    seam_fires();
    guard_sets_and_clears();
    guard_leaves_set_bit();
    nested_guards();
    equal_enters();
#ifdef WEBCPP_TEST_TIMING_THREADS
    other_thread_untouched();
#endif
    return webcpp::test::exit_status(boost::report_errors());
}
