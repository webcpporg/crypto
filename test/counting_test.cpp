// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// support/counting.hpp counts each allocation as it documents, no more: n mallocs are n where
// the C library is counted, an operator new is one, or two where its malloc is counted too,
// and a fresh thread counts the same, so the counter allocates nothing itself (N1).

#include <webcpp/test/exit_status.hpp>

#include "support/counting.hpp"

#include <boost/core/lightweight_test.hpp>

#include <array>
#include <cstddef>
#include <cstdlib>
#if !defined(__EMSCRIPTEN__) && !defined(__wasi__)
#include <thread>
#endif

namespace {

constexpr std::size_t times = 1000;
constexpr std::size_t c_counted = webcpp::test::c_allocations_counted ? 1 : 0;

/** Counts `times` mallocs of each size and `times` operator news, and checks both counts. */
void check_counts() {
    for (std::size_t const size : std::array<std::size_t, 3>{40, 300 * 1024, 1024 * 1024}) {
        std::size_t const before = webcpp::test::allocations();
        for (std::size_t i = 0; i < times; ++i) {
            void* volatile block = std::malloc(size);
            std::free(block);
        }
        BOOST_TEST_EQ(webcpp::test::allocations() - before, times * c_counted);
    }
    std::size_t const before = webcpp::test::allocations();
    for (std::size_t i = 0; i < times; ++i) {
        int* volatile block = new int(0);
        delete block;
    }
    BOOST_TEST_EQ(webcpp::test::allocations() - before, times * (1 + c_counted));
}

}  // namespace

int main() {
    check_counts();
#if !defined(__EMSCRIPTEN__) && !defined(__wasi__)
    // A thread's first allocations: its own state is made by the runtime before the body runs.
    std::thread second(check_counts);
    second.join();
#endif
    return webcpp::test::exit_status(boost::report_errors());
}
