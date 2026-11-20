// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The seam of detail::timing_guard, counted: a test includes this header before any crypto header,
// so that every guard a call enters raises timing_entries, on every target, also where DIT does
// not apply.

#ifndef WEBCPP_TEST_CRYPTO_SUPPORT_TIMING_SEAM_HPP
#define WEBCPP_TEST_CRYPTO_SUPPORT_TIMING_SEAM_HPP

#ifdef WEBCPP_CRYPTO_DETAIL_TIMING_HPP
#error "support/timing_seam.hpp must be included before any crypto header"
#endif

#include <boost/core/lightweight_test.hpp>

#include <cstddef>
#include <string>
#include <utility>

namespace webcpp::test {

/** The number of detail::timing_guard objects this thread has constructed. */
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): the seam's counter
inline thread_local std::size_t timing_entries = 0;

}  // namespace webcpp::test

/** Counts the entry into a detail::timing_guard in webcpp::test::timing_entries. */
#define WEBCPP_CRYPTO_DETAIL_TIMING_ENTERED() (static_cast<void>(++::webcpp::test::timing_entries))

namespace webcpp::test {

/**
 * Runs `call` and reports an error when it entered no detail::timing_guard.
 * @param name What the call is, as the error names it.
 * @param call The call, with its arguments bound.
 */
template <class Call>
void require_enters(char const* name, Call&& call) {
    std::size_t const before = timing_entries;
    std::forward<Call>(call)();
    if (timing_entries == before) {
        std::string const message = std::string(name) + " did not enter detail::timing_guard";
        BOOST_ERROR(message.c_str());
    }
}

}  // namespace webcpp::test

#endif  // WEBCPP_TEST_CRYPTO_SUPPORT_TIMING_SEAM_HPP
