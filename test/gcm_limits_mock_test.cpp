// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// gcm's limits on the mock backend, natively, where size_t has 64 bits: the checks of
// support/gcm_checks.hpp, which a real backend's test runs as well, and the limit summed
// over many updates, which only a mock that leaves the data unread can reach.

#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/crypto/ciphers/gcm.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/gcm_checks.hpp"
#include "support/mock_backend.hpp"
#include "support/reserved.hpp"

#include <boost/core/lightweight_test.hpp>

#include <array>
#include <cstddef>
#include <cstdint>

namespace crypto = webcpp::crypto;
using webcpp::test::mock;
using webcpp::test::mock_control;

namespace {

using aead = crypto::ciphers::gcm<crypto::ciphers::aes128<mock>>;

// Pieces of 2^35 bytes, which the mock does not read: the second reaches 2^36 bytes, more
// than max_message_size, and is refused, ending the message; a message of exactly the
// limit is accepted.
void check_summed_limit() {
    std::array<std::uint8_t, 16> const key{};
    std::array<std::uint8_t, 12> const nonce{};
    auto made = aead::from_key(key);
    constexpr auto half = std::size_t{1} << 35U;
    auto const piece = webcpp::test::reserved(half);
    if (!BOOST_TEST(made.has_value()) || !BOOST_TEST(!piece.empty())) {
        return;
    }
    mock_control.skip_data = true;
    BOOST_TEST(made->begin_seal(nonce, {}).has_value());
    BOOST_TEST(made->update(piece).has_value());
    BOOST_TEST(made->update(piece).error() == crypto::error::message_too_long);
    BOOST_TEST(made->update({}).error() == crypto::error::invalid_state);

    BOOST_TEST(made->begin_seal(nonce, {}).has_value());
    BOOST_TEST(made->update(piece).has_value());
    BOOST_TEST(made->update(piece.first(half - 32)).has_value());  // exactly the limit
    BOOST_TEST(made->update(piece.first(1)).error() == crypto::error::message_too_long);

    BOOST_TEST(made->begin_seal(nonce, {}).has_value());
    BOOST_TEST(made->update(piece).has_value());
    BOOST_TEST(made->update(piece.first(half - 32)).has_value());
    BOOST_TEST(made->update({}).has_value());  // an empty piece at the limit
    BOOST_TEST(made->result().has_value());
    webcpp::test::mock_clear();
}

}  // namespace

int main() {
    webcpp::test::check_limits<mock, false>();
    check_summed_limit();
    BOOST_TEST_EQ(mock_control.violations, 0);
    return webcpp::test::exit_status(boost::report_errors());
}
