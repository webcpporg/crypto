// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// detail::timing_guard around a public operation, on a stand-in backend that records whether DIT
// was set when it ran: the backend runs with DIT set where the CPU has it, and the thread finds
// DIT clear again after the call; a call refused before the backend is reached (a key of the
// wrong size) still enters the guard and leaves DIT as it found it.

#include "support/timing_seam.hpp"

#include <webcpp/crypto/ciphers/aead.hpp>
#include <webcpp/crypto/detail/timing.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>
#include <boost/hash2/digest.hpp>
#include <boost/system/result.hpp>

#include <array>
#include <cstdint>
#include <span>

namespace webcpp::test {
namespace {

/** A backend tag for a generic layer's guard alone. */
struct timing_stand_in {};

/** Whether DIT was set when the stand-in's seal last ran. */
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): what the stand-in records
bool dit_during_seal = false;

}  // namespace
}  // namespace webcpp::test

namespace webcpp::crypto::detail {

/** The stand-in's ChaCha20-Poly1305: seal records whether DIT is set; every call succeeds. */
template <>
struct aead_engine<families::chacha20_poly1305, test::timing_stand_in> {
    /** Succeeds. */
    [[nodiscard]] static boost::system::result<void> init(
        aead_state<families::chacha20_poly1305, test::timing_stand_in>& /*state*/,
        std::span<std::uint8_t const> /*key_bytes*/) noexcept {
        return {};
    }

    /** Records whether DIT is set, then succeeds. */
    [[nodiscard]] static boost::system::result<void> seal(
        aead_state<families::chacha20_poly1305, test::timing_stand_in>& /*state*/,
        std::span<std::uint8_t const> /*iv_bytes*/,
        std::span<std::uint8_t const> /*additional_data_bytes*/, std::span<std::uint8_t> /*data*/,
        boost::hash2::digest<16>& /*tag*/) noexcept {
        test::dit_during_seal = dit_is_set();
        return {};
    }

    /** Succeeds. */
    [[nodiscard]] static boost::system::result<void> open(
        aead_state<families::chacha20_poly1305, test::timing_stand_in>& /*state*/,
        std::span<std::uint8_t const> /*iv_bytes*/,
        std::span<std::uint8_t const> /*additional_data_bytes*/, std::span<std::uint8_t> /*data*/,
        std::array<std::uint8_t, 16> const& /*tag*/) noexcept {
        return {};
    }

    /** Nothing to move. */
    static void move(
        aead_state<families::chacha20_poly1305, test::timing_stand_in>& /*to*/,
        aead_state<families::chacha20_poly1305, test::timing_stand_in>& /*from*/) noexcept {}

    /** Nothing to wipe. */
    static void reset(
        aead_state<families::chacha20_poly1305, test::timing_stand_in>& /*state*/) noexcept {}
};

}  // namespace webcpp::crypto::detail

namespace {

namespace crypto = webcpp::crypto;
using aead =
    crypto::ciphers::aead<crypto::families::chacha20_poly1305, webcpp::test::timing_stand_in>;

// From clear: the backend's seal runs with DIT set where the CPU has it, and DIT is clear after.
void backend_runs_with_dit() {
    BOOST_TEST(!crypto::detail::dit_is_set());
    std::array<std::uint8_t, aead::key_size> const key{};
    auto made = aead::make(key);
    if (!BOOST_TEST(made.has_value())) {
        return;
    }
    BOOST_TEST(!crypto::detail::dit_is_set());
    std::array<std::uint8_t, aead::iv_size> const iv{};
    std::array<std::uint8_t, 8> data{};
    webcpp::test::dit_during_seal = !crypto::detail::cpu_has_dit();
    webcpp::test::require_enters(
        "aead::seal", [&made, &iv, &data] { BOOST_TEST(made->seal(iv, {}, data).has_value()); });
    BOOST_TEST_EQ(webcpp::test::dit_during_seal, crypto::detail::cpu_has_dit());
    BOOST_TEST(!crypto::detail::dit_is_set());
}

// A key of 31 bytes is refused before the backend is reached; the guard is entered all the same
// and DIT is clear after.
void early_error_restores_state() {
    BOOST_TEST(!crypto::detail::dit_is_set());
    std::array<std::uint8_t, aead::key_size - 1> const short_key{};
    webcpp::test::require_enters("aead::make with a 31-byte key", [&short_key] {
        BOOST_TEST(aead::make(short_key).error() == crypto::error::invalid_key_size);
    });
    BOOST_TEST(!crypto::detail::dit_is_set());
}

}  // namespace

int main() {
    backend_runs_with_dit();
    early_error_restores_state();
    return webcpp::test::exit_status(boost::report_errors());
}
