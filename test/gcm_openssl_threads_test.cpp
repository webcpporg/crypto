// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// OpenSSL on two threads: the two start together, each makes its own gcm, gives GCM test
// case 13's tag, seals and opens 1,000 messages of 1 KiB, and finds its own error queue as it
// left it, its one entry first and alone. Then, each on a thread that has never touched
// OpenSSL's error queue, the paths that abandon a message (a second begin_seal, an update past
// the limit, a move during a message) make no allocation through OpenSSL's functions: the
// first ERR_* call of a thread allocates its error state. Built <threading>multi, so that the
// provider has threads.

#include <webcpp/crypto/backends/openssl.hpp>
#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/crypto/ciphers/gcm.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/reserved.hpp"

#include <boost/core/lightweight_test.hpp>

#include <openssl/crypto.h>
#include <openssl/err.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <functional>
#include <latch>
#include <span>
#include <thread>
#include <utility>

namespace {

namespace crypto = webcpp::crypto;
using aead = crypto::ciphers::gcm<crypto::ciphers::aes256<crypto::backends::openssl>>;

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): OpenSSL's allocation count
std::atomic<std::size_t> openssl_allocations{0};

void* counting_malloc(std::size_t size, char const* /*file*/, int /*line*/) {
    ++openssl_allocations;
    return std::malloc(size);  // NOLINT(cppcoreguidelines-no-malloc): OpenSSL's allocator
}

void* counting_realloc(void* p, std::size_t size, char const* /*file*/, int /*line*/) {
    ++openssl_allocations;
    return std::realloc(p, size);  // NOLINT(cppcoreguidelines-no-malloc): OpenSSL's allocator
}

void counting_free(void* p, char const* /*file*/, int /*line*/) {
    std::free(p);  // NOLINT(cppcoreguidelines-no-malloc): OpenSSL's allocator
}

/**
 * Runs `step` on a new thread, which has never called OpenSSL, and returns the allocations
 * OpenSSL made through its functions meanwhile.
 */
template <class Step>
std::size_t on_fresh_thread(Step step) {
    std::size_t const before = openssl_allocations.load();
    std::thread thread(step);
    thread.join();
    return openssl_allocations.load() - before;
}

/** The paths that abandon a message, each on a fresh thread: no allocation. */
void abandon_on_fresh_threads() {
    std::array<std::uint8_t, 32> const key{};
    std::array<std::uint8_t, 12> const iv{};
    auto made = aead::from_key(key);
    if (!BOOST_TEST(made.has_value())) {
        return;
    }
    BOOST_TEST_EQ(on_fresh_thread([&] {
                      BOOST_TEST(made->begin_seal(iv, {}).has_value());
                      BOOST_TEST(made->begin_seal(iv, {}).error() == crypto::error::invalid_state);
                  }),
                  0U);
    auto const huge = webcpp::test::reserved(static_cast<std::size_t>(aead::max_message_size) + 1);
    if (BOOST_TEST(!huge.empty())) {
        BOOST_TEST_EQ(on_fresh_thread([&] {
                          BOOST_TEST(made->begin_seal(iv, {}).has_value());
                          BOOST_TEST(made->update(huge).error() == crypto::error::message_too_long);
                      }),
                      0U);
    }
    BOOST_TEST_EQ(on_fresh_thread([&] {
                      BOOST_TEST(made->begin_seal(iv, {}).has_value());
                      aead moved = std::move(*made);
                      BOOST_TEST(moved.begin_seal(iv, {}).has_value());
                      *made = std::move(moved);
                  }),
                  0U);
}

/** What a thread saw; checked on the main thread, since the test's counters are not atomic. */
struct outcome {
    std::size_t made = 0;
    bool known_answer = false;
    std::size_t round_trips = 0;
    std::size_t entries = 0;
    bool ours_first = false;
};

/** One thread's work: its key, its messages, its queue. */
void work(std::uint8_t seed, std::latch& start, outcome& out) {
    // Both threads make their first gcm, and run their loops, at the same time.
    start.arrive_and_wait();
    // NOLINTNEXTLINE(bugprone-signed-bitwise): OpenSSL's reason macro ORs signed flags
    ERR_raise(ERR_LIB_USER, ERR_R_PASSED_INVALID_ARGUMENT);
    unsigned long const ours = ERR_peek_last_error();
    // GCM test case 13: the zero key, the zero IV, nothing sealed.
    std::array<std::uint8_t, 32> key{};
    std::array<std::uint8_t, 12> const zero_iv{};
    if (auto zero = aead::from_key(key)) {
        auto const tag = zero->seal(zero_iv, {}, std::span<std::uint8_t>());
        constexpr std::array<std::uint8_t, 16> case_13{
            0x53, 0x0f, 0x8a, 0xfb, 0xc7, 0x45, 0x36, 0xb9,
            0xa9, 0x63, 0xb4, 0xf1, 0xc4, 0xcb, 0x73, 0x8b,
        };
        out.known_answer = tag && std::equal(tag->begin(), tag->end(), case_13.begin());
    }
    key.fill(seed);
    auto made = aead::from_key(key);
    if (made) {
        ++out.made;
        std::array<std::uint8_t, 1024> plain{};
        std::array<std::uint8_t, 12> iv{};
        for (std::size_t i = 0; i < 1000; ++i) {
            plain.fill(static_cast<std::uint8_t>(i + seed));
            iv[0] = static_cast<std::uint8_t>(i);
            iv[1] = static_cast<std::uint8_t>(i >> 8U);
            auto data = plain;
            auto const tag = made->seal(iv, {}, data);
            if (tag && data != plain && made->open(iv, {}, data, *tag) && data == plain) {
                ++out.round_trips;
            }
        }
    }
    out.ours_first = ERR_peek_error() == ours;
    while (ERR_get_error() != 0) {
        ++out.entries;
    }
}

}  // namespace

int main() {
    // Before anything: OpenSSL allocates through the test's functions from here on.
    BOOST_TEST(CRYPTO_set_mem_functions(&counting_malloc, &counting_realloc, &counting_free) == 1);
    std::array<outcome, 2> outcomes{};
    std::latch start(2);
    std::thread first(work, std::uint8_t{1}, std::ref(start), std::ref(outcomes[0]));
    std::thread second(work, std::uint8_t{2}, std::ref(start), std::ref(outcomes[1]));
    first.join();
    second.join();
    for (auto const& out : outcomes) {
        BOOST_TEST(out.known_answer);
        BOOST_TEST_EQ(out.made, 1U);
        BOOST_TEST_EQ(out.round_trips, 1000U);
        BOOST_TEST_EQ(out.entries, 1U);
        BOOST_TEST(out.ours_first);
    }
    abandon_on_fresh_threads();
    return webcpp::test::exit_status(boost::report_errors());
}
