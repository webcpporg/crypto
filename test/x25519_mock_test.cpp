// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// X25519's generic layer on a stand-in backend whose engine reports success for every shared
// secret: a key pair's agree, member and free, refuses an all-zero result itself (design D8), as
// libsodium does, so that a backend that does not refuse it gives the same answer; any other
// result is the shared secret, and an engine's error is passed on, by agree and by from_secret.

#include <webcpp/crypto/curves/x25519.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/keypair.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>
#include <boost/system/result.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <span>

namespace webcpp::test {
namespace {

/** A backend tag for X25519's generic layer alone. */
struct x25519_stand_in {};

/** What the stand-in's agree writes, or the error it returns instead. */
struct x25519_stand_in_knobs {
    /** The byte every byte of the shared secret is set to. */
    std::uint8_t fill = 0;
    /** The error base and agree return, when set. */
    boost::system::error_code error;
};

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): the knobs a test turns
x25519_stand_in_knobs x25519_stand_in_control{};

}  // namespace
}  // namespace webcpp::test

namespace webcpp::crypto::detail {

/** The stand-in's engine: agree writes the knob's byte and succeeds, as a backend that does
 *  not refuse an all-zero shared secret would. */
template <>
struct x25519_engine<families::x25519, test::x25519_stand_in> {
    /** Writes the knob's byte, or returns the knob's error. */
    [[nodiscard]] static boost::system::result<void> base(
        std::span<std::uint8_t const, 32> /*secret_key*/,
        std::span<std::uint8_t, 32> out) noexcept {
        if (test::x25519_stand_in_control.error) {
            return test::x25519_stand_in_control.error;
        }
        std::ranges::fill(out, test::x25519_stand_in_control.fill);
        return {};
    }

    /** Writes the knob's byte, or returns the knob's error. */
    [[nodiscard]] static boost::system::result<void> agree(
        std::span<std::uint8_t const, 32> /*secret_key*/,
        std::span<std::uint8_t const, 32> /*peer_public_key*/,
        std::span<std::uint8_t, 32> out) noexcept {
        if (test::x25519_stand_in_control.error) {
            return test::x25519_stand_in_control.error;
        }
        std::ranges::fill(out, test::x25519_stand_in_control.fill);
        return {};
    }
};

}  // namespace webcpp::crypto::detail

namespace {

namespace crypto = webcpp::crypto;
namespace test = webcpp::test;
using stand_in = crypto::curves::x25519::basic_keypair<test::x25519_stand_in>;

/** The stand-in's key pair of the secret key {9}, made while the knobs are clear. */
stand_in made_keypair() {
    test::x25519_stand_in_control = {};
    std::array<std::uint8_t, 32> const key{9};
    return stand_in::from_secret(key).value();
}

/** The peer key {9}. */
crypto::curves::x25519::public_key peer_key() {
    std::array<std::uint8_t, 32> const key{9};
    return crypto::curves::x25519::public_key::from_bytes(key).value();
}

void all_zero_refused() {
    auto const key = made_keypair();
    test::x25519_stand_in_control = {};
    auto const shared = key.agree(peer_key());
    BOOST_TEST(!shared.has_value());
    if (!shared) {
        BOOST_TEST(shared.error() == crypto::error::weak_public_key);
    }
    auto const free_shared = crypto::agree(key, peer_key());
    BOOST_TEST(!free_shared.has_value());
    if (!free_shared) {
        BOOST_TEST(free_shared.error() == crypto::error::weak_public_key);
    }
}

void other_result_kept() {
    auto const key = made_keypair();
    test::x25519_stand_in_control = {.fill = 0x5a, .error = {}};
    auto const shared = key.agree(peer_key());
    BOOST_TEST(shared.has_value());
    if (shared) {
        auto const bytes = shared->bytes();
        BOOST_TEST(std::ranges::all_of(bytes, [](std::uint8_t byte) { return byte == 0x5a; }));
    }
}

void engine_error_passed_on() {
    auto const key = made_keypair();
    test::x25519_stand_in_control = {.fill = 0, .error = crypto::error::backend_failure};
    auto const shared = key.agree(peer_key());
    BOOST_TEST(!shared.has_value());
    if (!shared) {
        BOOST_TEST(shared.error() == crypto::error::backend_failure);
    }
    std::array<std::uint8_t, 32> const secret_key{9};
    auto const refused = stand_in::from_secret(secret_key);
    BOOST_TEST(!refused.has_value());
    if (!refused) {
        BOOST_TEST(refused.error() == crypto::error::backend_failure);
    }
}

}  // namespace

int main() {
    all_zero_refused();
    other_result_kept();
    engine_error_passed_on();
    return test::exit_status(boost::report_errors());
}
