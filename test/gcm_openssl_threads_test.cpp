// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// OpenSSL on two threads (spec section 3.3): each thread makes its own gcm, seals and
// opens 1,000 messages of 1 KiB, and finds its own error queue as it left it, its one
// entry first and alone. Built <threading>multi, so that the provider has threads.

#include <webcpp/crypto/aes.hpp>
#include <webcpp/crypto/backends/openssl.hpp>
#include <webcpp/crypto/gcm.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>

#include <openssl/err.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <thread>

namespace {

namespace crypto = webcpp::crypto;
using aead = crypto::gcm<crypto::aes256<crypto::backends::openssl>>;

/** What a thread saw; checked on the main thread, since the test's counters are not atomic. */
struct outcome {
    std::size_t made = 0;
    std::size_t round_trips = 0;
    std::size_t entries = 0;
    bool ours_first = false;
};

/** One thread's work: its key, its messages, its queue. */
void work(std::uint8_t seed, outcome& out) {
    ERR_raise(ERR_LIB_USER, ERR_R_PASSED_INVALID_ARGUMENT);
    unsigned long const ours = ERR_peek_last_error();
    std::array<std::uint8_t, 32> key{};
    key.fill(seed);
    auto made = aead::make(key);
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
    std::array<outcome, 2> outcomes{};
    std::thread first(work, std::uint8_t{1}, std::ref(outcomes[0]));
    std::thread second(work, std::uint8_t{2}, std::ref(outcomes[1]));
    first.join();
    second.join();
    for (auto const& out : outcomes) {
        BOOST_TEST_EQ(out.made, 1U);
        BOOST_TEST_EQ(out.round_trips, 1000U);
        BOOST_TEST_EQ(out.entries, 1U);
        BOOST_TEST(out.ours_first);
    }
    return webcpp::test::exit_status(boost::report_errors());
}
