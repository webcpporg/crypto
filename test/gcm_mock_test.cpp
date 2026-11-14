// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// gcm's generic layer on the mock backend (support/mock_backend.hpp): every check of
// support/gcm_checks.hpp against the mock's own answers for the specification's inputs,
// each engine error passed through as it is with a failed open's data zeroed, and the
// engine's contract kept throughout.

#include <webcpp/crypto/aes.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/gcm.hpp>
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

using aead = crypto::gcm<crypto::aes256<mock>>;

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

}  // namespace

int main() {
    webcpp::test::mock_cases const cases;
    webcpp::test::check_spec_cases<mock>(cases.view());
    webcpp::test::check_guards<mock>();
    webcpp::test::check_tampering<mock>(cases.view());
    webcpp::test::check_moved_from<mock>(cases.view());
    webcpp::test::check_edges<mock>(cases.view());
    check_make_failures();
    check_one_shot_failures(cases.view());
    BOOST_TEST_EQ(mock_control.violations, 0);
    return webcpp::test::exit_status(boost::report_errors());
}
