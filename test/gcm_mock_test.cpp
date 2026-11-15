// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// gcm's generic layer on the mock backend (support/mock_backend.hpp): every check of
// support/gcm_checks.hpp against the mock's own answers for the specification's inputs,
// each engine error passed through as it is with a failed open's data zeroed, and the
// engine's contract kept throughout.

#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/crypto/ciphers/gcm.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/gcm_checks.hpp"
#include "support/mock_backend.hpp"

#include <boost/core/lightweight_test.hpp>
#include <boost/system/errc.hpp>

#include <array>
#include <cstdint>

namespace crypto = webcpp::crypto;
using webcpp::test::mock;
using webcpp::test::mock_control;

namespace {

using aead = crypto::ciphers::gcm<crypto::ciphers::aes256<mock>>;

// Spec section 2.4, "GCM sizes": the sizes are constants of the type, whatever the backend.
static_assert(aead::key_size == 32);
static_assert(aead::tag_size == 16);
static_assert(aead::iv_size == 12);
static_assert(aead::max_iv_size == 128);
static_assert(aead::max_message_size == (std::uint64_t{1} << 36U) - 32);
static_assert(aead::max_additional_data_size == (std::uint64_t{1} << 61U) - 1);
static_assert(crypto::ciphers::gcm<crypto::ciphers::aes128<mock>>::key_size == 16);
static_assert(crypto::ciphers::gcm<crypto::ciphers::aes192<mock>>::key_size == 24);

// make returns the engine's error as it is: not_enough_memory, backend_failure.
void check_make_failures() {
    std::array<std::uint8_t, 32> const key{};
    mock_control.init =
        boost::system::errc::make_error_code(boost::system::errc::not_enough_memory);
    BOOST_TEST(aead::make(key).error() == boost::system::errc::not_enough_memory);
    mock_control.init = crypto::error::backend_failure;
    BOOST_TEST(aead::make(key).error() == crypto::error::backend_failure);
    BOOST_TEST(aead::make(std::span(key).first(16)).error() == crypto::error::invalid_key_size);
    webcpp::test::mock_clear();
    BOOST_TEST(aead::make(key).has_value());
}

// Each engine call that fails makes seal and open fail with its error; a failed open zeroes
// its data, a guard's refusal does not, and the object works once the engine does.
void check_one_shot_failures(webcpp::test::gcm_cases cases) {
    std::array<std::uint8_t, 32> const key{};
    std::array<std::uint8_t, 12> const iv{};
    auto made = aead::make(key);
    if (!BOOST_TEST(made.has_value())) {
        return;
    }
    auto const& one_block = cases[13];
    auto const ciphertext = webcpp::test::from_hex(one_block.ciphertext);
    auto const tag = webcpp::test::from_hex(one_block.tag);
    boost::system::error_code const failed = crypto::error::backend_failure;

    for (auto* knob : {&mock_control.start, &mock_control.run, &mock_control.tag}) {
        *knob = failed;
        std::array<std::uint8_t, 16> data{};
        BOOST_TEST(made->seal(iv, {}, data).error() == failed);
        webcpp::test::mock_clear();
    }
    for (auto* knob : {&mock_control.start, &mock_control.run, &mock_control.check}) {
        *knob = failed;
        auto data = ciphertext;
        BOOST_TEST(made->open(iv, {}, data, tag).error() == failed);
        BOOST_TEST(webcpp::test::all_zero(data));
        webcpp::test::mock_clear();
    }
    // A guard refuses before the engine fails: the data is untouched.
    mock_control.start = failed;
    auto data = ciphertext;
    BOOST_TEST(made->open(iv, {}, data, std::span(tag).first(8)).error() ==
               crypto::error::invalid_tag_size);
    BOOST_TEST(data == ciphertext);
    webcpp::test::mock_clear();

    BOOST_TEST(made->open(iv, {}, data, tag).has_value());
    BOOST_TEST(webcpp::test::all_zero(data));  // case 14's plaintext, one zero block
}

// An engine error in begin_seal, update or result ends the message, abandoned through the
// engine, and the object begins the next one.
void check_incremental_failures(webcpp::test::gcm_cases cases) {
    std::array<std::uint8_t, 32> const key{};
    std::array<std::uint8_t, 12> const iv{};
    auto made = aead::make(key);
    if (!BOOST_TEST(made.has_value())) {
        return;
    }
    boost::system::error_code const failed = crypto::error::backend_failure;
    std::array<std::uint8_t, 16> data{};

    auto abandons = mock_control.abandons;
    mock_control.start = failed;
    BOOST_TEST(made->begin_seal(iv, {}).error() == failed);
    webcpp::test::mock_clear();
    BOOST_TEST_EQ(mock_control.abandons, abandons + 1);
    BOOST_TEST(made->update(data).error() == crypto::error::invalid_state);

    abandons = mock_control.abandons;
    BOOST_TEST(made->begin_seal(iv, {}).has_value());
    mock_control.run = failed;
    BOOST_TEST(made->update(data).error() == failed);
    webcpp::test::mock_clear();
    BOOST_TEST_EQ(mock_control.abandons, abandons + 1);
    BOOST_TEST(made->update(data).error() == crypto::error::invalid_state);
    BOOST_TEST(made->result().error() == crypto::error::invalid_state);

    abandons = mock_control.abandons;
    BOOST_TEST(made->begin_seal(iv, {}).has_value());
    mock_control.tag = failed;
    BOOST_TEST(made->result().error() == failed);
    webcpp::test::mock_clear();
    BOOST_TEST_EQ(mock_control.abandons, abandons + 1);
    BOOST_TEST(made->result().error() == crypto::error::invalid_state);

    // A refused begin_seal during a message abandons it through the engine as well.
    abandons = mock_control.abandons;
    BOOST_TEST(made->begin_seal(iv, {}).has_value());
    BOOST_TEST(made->begin_seal(iv, {}).error() == crypto::error::invalid_state);
    BOOST_TEST_EQ(mock_control.abandons, abandons + 1);

    data.fill(0);
    BOOST_TEST(made->begin_seal(iv, {}).has_value());
    BOOST_TEST(made->update(data).has_value());
    auto const tag = made->result();
    BOOST_TEST_EQ(webcpp::test::to_hex(data), cases[13].ciphertext);
    BOOST_TEST(tag && webcpp::test::to_hex(*tag) == cases[13].tag);
}

// A move abandons a message in progress through the engine before it moves the state, so
// the destination carries nothing of it: the move constructor, and a move assignment from
// an object in a message.
void check_move_abandons(webcpp::test::gcm_cases cases) {
    std::array<std::uint8_t, 32> const key{};
    std::array<std::uint8_t, 12> const iv{};
    auto made = aead::make(key);
    auto other = aead::make(key);
    if (!BOOST_TEST(made.has_value()) || !BOOST_TEST(other.has_value())) {
        return;
    }
    std::array<std::uint8_t, 16> data{};
    auto const carried = mock_control.carried;

    auto abandons = mock_control.abandons;
    BOOST_TEST(made->begin_seal(iv, {}).has_value());
    BOOST_TEST(made->update(std::span(data).first(5)).has_value());
    aead moved = std::move(*made);
    BOOST_TEST_EQ(mock_control.abandons, abandons + 1);
    BOOST_TEST_EQ(mock_control.carried, carried);

    abandons = mock_control.abandons;
    BOOST_TEST(other->begin_seal(iv, {}).has_value());
    BOOST_TEST(other->update(std::span(data).first(7)).has_value());
    moved = std::move(*other);
    BOOST_TEST_EQ(mock_control.abandons, abandons + 1);
    BOOST_TEST_EQ(mock_control.carried, carried);

    // The destination's next message is whole: case 14's answer.
    data.fill(0);
    BOOST_TEST(moved.begin_seal(iv, {}).has_value());
    BOOST_TEST(moved.update(data).has_value());
    auto const tag = moved.result();
    BOOST_TEST_EQ(webcpp::test::to_hex(data), cases[13].ciphertext);
    BOOST_TEST(tag && webcpp::test::to_hex(*tag) == cases[13].tag);
}

}  // namespace

int main() {
    webcpp::test::mock_cases const cases;
    webcpp::test::check_spec_cases<mock>(cases.view());
    webcpp::test::check_guards<mock>();
    webcpp::test::check_tampering<mock>(cases.view());
    webcpp::test::check_moved_from<mock>(cases.view());
    webcpp::test::check_edges<mock>(cases.view());
    webcpp::test::check_incremental<mock>(cases.view());
    webcpp::test::check_machine<mock>(cases.view());
    webcpp::test::check_one_shot_during_message<mock>(cases.view());
    check_make_failures();
    check_one_shot_failures(cases.view());
    check_incremental_failures(cases.view());
    check_move_abandons(cases.view());
    BOOST_TEST_EQ(mock_control.violations, 0);
    BOOST_TEST_EQ(mock_control.carried, 0);  // no check's move carried a message
    return webcpp::test::exit_status(boost::report_errors());
}
