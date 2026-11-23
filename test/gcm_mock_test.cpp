// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// gcm's generic layer on the mock backend (support/mock_backend.hpp): every check of
// support/gcm_checks.hpp against the mock's own answers for the specification's inputs,
// each engine error passed through as it is, with the data of a failed seal, open, update
// or decrypt zeroed, and the engine's contract kept throughout.

#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/crypto/ciphers/gcm.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/gcm_checks.hpp"
#include "support/mock_backend.hpp"
#if !defined(__wasi__) && !defined(__EMSCRIPTEN__)
#include "support/reserved.hpp"
#endif

#include <boost/core/lightweight_test.hpp>
#include <boost/system/errc.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <span>
#include <vector>

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

// from_key returns the engine's error as it is: not_enough_memory, backend_failure.
void check_make_failures() {
    std::array<std::uint8_t, 32> const key{};
    mock_control.init =
        boost::system::errc::make_error_code(boost::system::errc::not_enough_memory);
    BOOST_TEST(aead::from_key(key).error() == boost::system::errc::not_enough_memory);
    mock_control.init = crypto::error::backend_failure;
    BOOST_TEST(aead::from_key(key).error() == crypto::error::backend_failure);
    BOOST_TEST(aead::from_key(std::span(key).first(16)).error() == crypto::error::invalid_key_size);
    webcpp::test::mock_clear();
    BOOST_TEST(aead::from_key(key).has_value());
}

// Each engine call that fails makes seal and open fail with its error; a failed open zeroes
// its data, a guard's refusal does not, and the object works once the engine does.
void check_one_shot_failures(webcpp::test::gcm_cases cases) {
    std::array<std::uint8_t, 32> const key{};
    std::array<std::uint8_t, 12> const nonce{};
    auto made = aead::from_key(key);
    if (!BOOST_TEST(made.has_value())) {
        return;
    }
    auto const& one_block = cases[13];
    auto const ciphertext = webcpp::test::from_hex(one_block.ciphertext);
    auto const tag = webcpp::test::from_hex(one_block.tag);
    boost::system::error_code const failed = crypto::error::backend_failure;

    // An engine's failure ends the message through the engine, as the incremental seal's does.
    for (auto* knob : {&mock_control.start, &mock_control.run, &mock_control.tag}) {
        *knob = failed;
        auto const abandons = mock_control.abandons;
        std::array<std::uint8_t, 16> data{};
        data.fill(0x5A);
        BOOST_TEST(made->seal(nonce, {}, data).error() == failed);
        BOOST_TEST(webcpp::test::all_zero(data));
        webcpp::test::mock_clear();
        BOOST_TEST_EQ(mock_control.abandons, abandons + 1);
    }
    // A guard refuses before the engine fails: the seal's data is untouched.
    {
        mock_control.start = failed;
        std::array<std::uint8_t, 129> const long_iv{};
        std::array<std::uint8_t, 16> data{};
        data.fill(0x5A);
        BOOST_TEST(made->seal(long_iv, {}, data).error() == crypto::error::invalid_iv_size);
        BOOST_TEST(std::ranges::all_of(data, [](std::uint8_t byte) { return byte == 0x5A; }));
        webcpp::test::mock_clear();
    }
    for (auto* knob : {&mock_control.start, &mock_control.run, &mock_control.check}) {
        *knob = failed;
        auto const abandons = mock_control.abandons;
        auto data = ciphertext;
        BOOST_TEST(made->open(nonce, {}, data, tag).error() == failed);
        BOOST_TEST(webcpp::test::all_zero(data));
        webcpp::test::mock_clear();
        BOOST_TEST_EQ(mock_control.abandons, abandons + 1);
    }
    // So does a tag that does not match.
    {
        auto const abandons = mock_control.abandons;
        auto data = ciphertext;
        auto wrong = tag;
        wrong[0] ^= 1U;
        BOOST_TEST(made->open(nonce, {}, data, wrong).error() ==
                   crypto::error::authentication_failed);
        BOOST_TEST_EQ(mock_control.abandons, abandons + 1);
    }
    // A guard refuses before the engine fails: the data is untouched.
    mock_control.start = failed;
    auto data = ciphertext;
    BOOST_TEST(made->open(nonce, {}, data, std::span(tag).first(8)).error() ==
               crypto::error::invalid_tag_size);
    BOOST_TEST(data == ciphertext);
    webcpp::test::mock_clear();

    BOOST_TEST(made->open(nonce, {}, data, tag).has_value());
    BOOST_TEST(webcpp::test::all_zero(data));  // case 14's plaintext, one zero block
}

// An engine error in begin_seal, update or result ends the message, abandoned through the
// engine: update's piece is zeroed.
void check_seal_engine_failures(aead& made, std::span<std::uint8_t const> nonce) {
    boost::system::error_code const failed = crypto::error::backend_failure;
    std::array<std::uint8_t, 16> data{};

    auto abandons = mock_control.abandons;
    mock_control.start = failed;
    BOOST_TEST(made.begin_seal(nonce, {}).error() == failed);
    webcpp::test::mock_clear();
    BOOST_TEST_EQ(mock_control.abandons, abandons + 1);
    BOOST_TEST(made.update(data).error() == crypto::error::invalid_state);

    abandons = mock_control.abandons;
    BOOST_TEST(made.begin_seal(nonce, {}).has_value());
    mock_control.run = failed;
    data.fill(0x5A);
    BOOST_TEST(made.update(data).error() == failed);
    BOOST_TEST(webcpp::test::all_zero(data));
    data.fill(0);
    webcpp::test::mock_clear();
    BOOST_TEST_EQ(mock_control.abandons, abandons + 1);
    BOOST_TEST(made.update(data).error() == crypto::error::invalid_state);
    BOOST_TEST(made.result().error() == crypto::error::invalid_state);

    abandons = mock_control.abandons;
    BOOST_TEST(made.begin_seal(nonce, {}).has_value());
    mock_control.tag = failed;
    BOOST_TEST(made.result().error() == failed);
    webcpp::test::mock_clear();
    BOOST_TEST_EQ(mock_control.abandons, abandons + 1);
    BOOST_TEST(made.result().error() == crypto::error::invalid_state);
}

// An engine error in begin_seal, update or result ends the message, abandoned through the
// engine, and the object begins the next one.
void check_incremental_failures(webcpp::test::gcm_cases cases) {
    std::array<std::uint8_t, 32> const key{};
    std::array<std::uint8_t, 12> const nonce{};
    auto made = aead::from_key(key);
    if (!BOOST_TEST(made.has_value())) {
        return;
    }
    check_seal_engine_failures(*made, nonce);
    std::array<std::uint8_t, 16> data{};

#if !defined(__wasi__) && !defined(__EMSCRIPTEN__)
    // An update refused for its size ends the message and leaves its piece untouched (the
    // reserved piece faults on any access, so a wipe would end the program).
    if constexpr (sizeof(std::size_t) == 8) {
        auto const huge =
            webcpp::test::reserved(static_cast<std::size_t>(aead::max_message_size) + 1);
        if (BOOST_TEST(!huge.empty()) && BOOST_TEST(made->begin_seal(nonce, {}).has_value())) {
            BOOST_TEST(made->update(huge).error() == crypto::error::message_too_long);
            BOOST_TEST(made->result().error() == crypto::error::invalid_state);
        }
    }
#endif

    // A refused begin_seal during a message abandons it through the engine as well.
    auto const abandons = mock_control.abandons;
    BOOST_TEST(made->begin_seal(nonce, {}).has_value());
    BOOST_TEST(made->begin_seal(nonce, {}).error() == crypto::error::invalid_state);
    BOOST_TEST_EQ(mock_control.abandons, abandons + 1);

    data.fill(0);
    BOOST_TEST(made->begin_seal(nonce, {}).has_value());
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
    std::array<std::uint8_t, 12> const nonce{};
    auto made = aead::from_key(key);
    auto other = aead::from_key(key);
    if (!BOOST_TEST(made.has_value()) || !BOOST_TEST(other.has_value())) {
        return;
    }
    std::array<std::uint8_t, 16> data{};
    auto const carried = mock_control.carried;

    auto abandons = mock_control.abandons;
    BOOST_TEST(made->begin_seal(nonce, {}).has_value());
    BOOST_TEST(made->update(std::span(data).first(5)).has_value());
    aead moved = std::move(*made);
    BOOST_TEST_EQ(mock_control.abandons, abandons + 1);
    BOOST_TEST_EQ(mock_control.carried, carried);

    abandons = mock_control.abandons;
    BOOST_TEST(other->begin_seal(nonce, {}).has_value());
    BOOST_TEST(other->update(std::span(data).first(7)).has_value());
    moved = std::move(*other);
    BOOST_TEST_EQ(mock_control.abandons, abandons + 1);
    BOOST_TEST_EQ(mock_control.carried, carried);

    // The destination's next message is whole: case 14's answer.
    data.fill(0);
    BOOST_TEST(moved.begin_seal(nonce, {}).has_value());
    BOOST_TEST(moved.update(data).has_value());
    auto const tag = moved.result();
    BOOST_TEST_EQ(webcpp::test::to_hex(data), cases[13].ciphertext);
    BOOST_TEST(tag && webcpp::test::to_hex(*tag) == cases[13].tag);
}

// An engine error before the first pass ends ends the message, abandoned through the engine:
// in begin_open; in authenticate, the caller's piece unchanged; in verify, the check's error or
// the second start's returned, and decrypt refused with its piece unchanged.
void check_first_pass_failures(aead& made, std::span<std::uint8_t const> nonce,
                               std::vector<std::uint8_t> const& ciphertext,
                               std::vector<std::uint8_t> const& tag) {
    boost::system::error_code const failed = crypto::error::backend_failure;

    auto abandons = mock_control.abandons;
    mock_control.start = failed;
    BOOST_TEST(made.begin_open(nonce, {}).error() == failed);
    webcpp::test::mock_clear();
    BOOST_TEST_EQ(mock_control.abandons, abandons + 1);
    BOOST_TEST(made.authenticate(ciphertext).error() == crypto::error::invalid_state);

    abandons = mock_control.abandons;
    auto piece = ciphertext;
    BOOST_TEST(made.begin_open(nonce, {}).has_value());
    mock_control.run = failed;
    BOOST_TEST(made.authenticate(piece).error() == failed);
    webcpp::test::mock_clear();
    BOOST_TEST(piece == ciphertext);
    BOOST_TEST_EQ(mock_control.abandons, abandons + 1);
    BOOST_TEST(made.verify(tag).error() == crypto::error::invalid_state);

    for (auto* knob : {&mock_control.check, &mock_control.start}) {
        abandons = mock_control.abandons;
        BOOST_TEST(made.begin_open(nonce, {}).has_value());
        BOOST_TEST(made.authenticate(ciphertext).has_value());
        *knob = failed;
        BOOST_TEST(made.verify(tag).error() == failed);
        webcpp::test::mock_clear();
        // The check's failure abandons once; the second start's after verify's own abandon.
        BOOST_TEST_EQ(mock_control.abandons, abandons + (knob == &mock_control.check ? 1 : 2));
        piece = ciphertext;
        BOOST_TEST(made.decrypt(piece).error() == crypto::error::invalid_state);
        BOOST_TEST(piece == ciphertext);
    }
}

// An engine error during the incremental open ends the message, abandoned through the
// engine: in authenticate, the caller's piece is unchanged; in decrypt, it is zeroed; in
// verify, the check's error or the second start's is returned. The object opens afresh.
void check_open_failures(webcpp::test::gcm_cases cases) {
    std::array<std::uint8_t, 32> const key{};
    std::array<std::uint8_t, 12> const nonce{};
    auto made = aead::from_key(key);
    if (!BOOST_TEST(made.has_value())) {
        return;
    }
    auto const& one_block = cases[13];
    auto const ciphertext = webcpp::test::from_hex(one_block.ciphertext);
    auto const tag = webcpp::test::from_hex(one_block.tag);
    boost::system::error_code const failed = crypto::error::backend_failure;
    check_first_pass_failures(*made, nonce, ciphertext, tag);

    auto const abandons = mock_control.abandons;
    auto piece = ciphertext;
    BOOST_TEST(made->begin_open(nonce, {}).has_value());
    BOOST_TEST(made->authenticate(ciphertext).has_value());
    BOOST_TEST(made->verify(tag).has_value());
    mock_control.run = failed;
    piece = ciphertext;
    BOOST_TEST(made->decrypt(piece).error() == failed);
    webcpp::test::mock_clear();
    BOOST_TEST(webcpp::test::all_zero(piece));
    BOOST_TEST_EQ(mock_control.abandons, abandons + 2);  // verify's, then the failure's
    BOOST_TEST(made->end_open().error() == crypto::error::invalid_state);

    piece = ciphertext;
    BOOST_TEST(made->begin_open(nonce, {}).has_value());
    BOOST_TEST(made->authenticate(piece).has_value());
    BOOST_TEST(made->verify(tag).has_value());
    BOOST_TEST(made->decrypt(piece).has_value());
    BOOST_TEST(made->end_open().has_value());
    BOOST_TEST(webcpp::test::all_zero(piece));  // case 14's plaintext, one zero block
}

// A move during the open abandons it through the engine before it moves the state.
void check_open_move_abandons(webcpp::test::gcm_cases cases) {
    std::array<std::uint8_t, 32> const key{};
    std::array<std::uint8_t, 12> const nonce{};
    auto made = aead::from_key(key);
    if (!BOOST_TEST(made.has_value())) {
        return;
    }
    auto const ciphertext = webcpp::test::from_hex(cases[13].ciphertext);
    auto const tag = webcpp::test::from_hex(cases[13].tag);
    auto const carried = mock_control.carried;
    auto const abandons = mock_control.abandons;
    BOOST_TEST(made->begin_open(nonce, {}).has_value());
    BOOST_TEST(made->authenticate(std::span(ciphertext).first(5)).has_value());
    aead moved = std::move(*made);
    BOOST_TEST_EQ(mock_control.abandons, abandons + 1);
    BOOST_TEST_EQ(mock_control.carried, carried);
    BOOST_TEST(moved.verify(tag).error() == crypto::error::invalid_state);
    auto data = ciphertext;
    BOOST_TEST(moved.begin_open(nonce, {}).has_value());
    BOOST_TEST(moved.authenticate(data).has_value());
    BOOST_TEST(moved.verify(tag).has_value());
    BOOST_TEST(moved.decrypt(data).has_value());
    BOOST_TEST(moved.end_open().has_value());
    BOOST_TEST(webcpp::test::all_zero(data));
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
    webcpp::test::check_incremental_open<mock>(cases.view());
    check_open_failures(cases.view());
    check_open_move_abandons(cases.view());
    BOOST_TEST_EQ(mock_control.violations, 0);
    BOOST_TEST_EQ(mock_control.carried, 0);  // no check's move carried a message
    return webcpp::test::exit_status(boost::report_errors());
}
