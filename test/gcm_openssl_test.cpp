// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// gcm on OpenSSL: the GCM specification's cases, the guards, tampering, moved-from
// objects, aliasing spans, the incremental seal and open (support/gcm_checks.hpp), and the
// engine's abandon, which leaves nothing of the abandoned message in the context.

#include <webcpp/crypto/backends/openssl.hpp>
#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/crypto/ciphers/gcm.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/gcm_checks.hpp"
#include "support/hex.hpp"

#include <boost/core/lightweight_test.hpp>
#include <boost/hash2/digest.hpp>

#include <array>
#include <cstdint>

namespace {

namespace crypto = webcpp::crypto;
using crypto::backends::openssl;

/**
 * After abandon, the context holds the message abandon itself starts, the zero IV of 12
 * bytes and one zero byte sealed, and nothing of the message abandoned: the tag a final
 * would give is that message's, whatever the abandoned one's IV, additional data and length.
 */
void check_abandon_forgets_the_message() {
    using engine = crypto::detail::gcm_engine<openssl, 32>;
    std::array<std::uint8_t, 32> const key{};
    std::array<std::uint8_t, 12> const zero_iv{};
    std::array<std::uint8_t, 1> one_byte{};
    auto fresh = crypto::ciphers::gcm<crypto::ciphers::aes256<openssl>>::from_key(key);
    if (!BOOST_TEST(fresh.has_value())) {
        return;
    }
    auto const expected = fresh->seal(zero_iv, {}, one_byte);
    if (!BOOST_TEST(expected.has_value())) {
        return;
    }

    crypto::detail::gcm_state<openssl, 32> state{};
    if (!BOOST_TEST(engine::init(state, key).has_value())) {
        return;
    }
    std::array<std::uint8_t, 20> nonce{};
    nonce.fill(0x11);
    std::array<std::uint8_t, 21> associated_data{};
    associated_data.fill(0x22);
    std::array<std::uint8_t, 37> data{};
    data.fill(0x33);
    BOOST_TEST(engine::start(state, true, nonce, associated_data).has_value());
    BOOST_TEST(engine::run(state, data).has_value());
    engine::abandon(state);
    boost::hash2::digest<16> left{};
    BOOST_TEST(engine::tag(state, left).has_value());
    BOOST_TEST_EQ(webcpp::test::to_hex(left), webcpp::test::to_hex(*expected));
    engine::reset(state);
}

}  // namespace

int main() {
    webcpp::test::check_spec_cases<openssl>();
    webcpp::test::check_guards<openssl>();
    webcpp::test::check_tampering<openssl>();
    webcpp::test::check_moved_from<openssl>();
    webcpp::test::check_edges<openssl>();
    webcpp::test::check_incremental<openssl>();
    webcpp::test::check_machine<openssl>();
    webcpp::test::check_one_shot_during_message<openssl>();
    webcpp::test::check_incremental_open<openssl>();
    check_abandon_forgets_the_message();
    return webcpp::test::exit_status(boost::report_errors());
}
