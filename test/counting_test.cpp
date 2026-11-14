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
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <new>
#if !defined(__EMSCRIPTEN__) && !defined(__wasi__)
#include <thread>
#endif

namespace {

constexpr std::size_t times = 1000;
constexpr std::size_t c_counted = webcpp::test::c_allocations_counted ? 1 : 0;

/** Runs `body` `times` times and checks that each run moved the counter by `per`. */
template <class Body>
void expect_delta(std::size_t per, Body body) {
    std::size_t const before = webcpp::test::allocations();
    for (std::size_t i = 0; i < times; ++i) {
        body();
    }
    BOOST_TEST_EQ(webcpp::test::allocations() - before, times * per);
}

constexpr std::size_t new_counted = 1 + c_counted;  // one operator new, and its malloc
constexpr std::size_t big = 64;                     // an alignment above max_align_t on no target
constexpr std::align_val_t aligned{big};

/** The C library's forms: each is one count where the C library is counted. */
void check_c_forms() {
    expect_delta(c_counted, [] {
        void* volatile block = std::calloc(4, 10);
        BOOST_TEST(block != nullptr);
        std::free(block);
    });
    // realloc of a valid block keeps its contents: one count for the malloc, one for the realloc.
    expect_delta(2 * c_counted, [] {
        void* block = std::malloc(16);
        BOOST_TEST(block != nullptr);
        std::memset(block, 0x5a, 16);
        void* volatile grown = std::realloc(block, 4096);
        BOOST_TEST(grown != nullptr);
        BOOST_TEST_EQ(static_cast<unsigned char*>(grown)[15], 0x5aU);
        std::free(grown);
    });
#ifndef _WIN32
    expect_delta(c_counted, [] {
        void* volatile block = std::aligned_alloc(big, big);
        BOOST_TEST(block != nullptr);
        BOOST_TEST_EQ(reinterpret_cast<std::uintptr_t>(block) % big, 0U);
        std::free(block);
    });
    expect_delta(c_counted, [] {
        void* volatile block = nullptr;
        void* out = nullptr;
        BOOST_TEST_EQ(posix_memalign(&out, big, 100), 0);
        block = out;
        BOOST_TEST(block != nullptr);
        BOOST_TEST_EQ(reinterpret_cast<std::uintptr_t>(block) % big, 0U);
        std::free(block);
    });
#endif
}

/** Every form of operator new, with the delete that releases it: one count, and its malloc. */
void check_new_forms() {
    expect_delta(new_counted, [] {
        int* volatile block = new int[4];
        delete[] block;
    });
    expect_delta(new_counted, [] {
        void* volatile block = ::operator new(24);
        ::operator delete(block, std::size_t{24});
    });
    expect_delta(new_counted, [] {
        void* volatile block = ::operator new[](24);
        ::operator delete[](block, std::size_t{24});
    });
    expect_delta(new_counted, [] {
        void* volatile block = ::operator new(24, aligned);
        BOOST_TEST_EQ(reinterpret_cast<std::uintptr_t>(block) % big, 0U);
        ::operator delete(block, aligned);
    });
    expect_delta(new_counted, [] {
        void* volatile block = ::operator new[](24, aligned);
        BOOST_TEST_EQ(reinterpret_cast<std::uintptr_t>(block) % big, 0U);
        ::operator delete[](block, aligned);
    });
    expect_delta(new_counted, [] {
        void* volatile block = ::operator new(24, aligned);
        ::operator delete(block, std::size_t{24}, aligned);
    });
    expect_delta(new_counted, [] {
        void* volatile block = ::operator new[](24, aligned);
        ::operator delete[](block, std::size_t{24}, aligned);
    });
    expect_delta(new_counted, [] {
        void* volatile block = ::operator new(24, std::nothrow);
        BOOST_TEST(block != nullptr);
        ::operator delete(block, std::nothrow);
    });
    expect_delta(new_counted, [] {
        void* volatile block = ::operator new[](24, std::nothrow);
        BOOST_TEST(block != nullptr);
        ::operator delete[](block, std::nothrow);
    });
    expect_delta(new_counted, [] {
        void* volatile block = ::operator new(24, aligned, std::nothrow);
        BOOST_TEST(block != nullptr);
        BOOST_TEST_EQ(reinterpret_cast<std::uintptr_t>(block) % big, 0U);
        ::operator delete(block, aligned, std::nothrow);
    });
    expect_delta(new_counted, [] {
        void* volatile block = ::operator new[](24, aligned, std::nothrow);
        BOOST_TEST(block != nullptr);
        BOOST_TEST_EQ(reinterpret_cast<std::uintptr_t>(block) % big, 0U);
        ::operator delete[](block, aligned, std::nothrow);
    });
}

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
    check_c_forms();
    check_new_forms();
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
