// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// ciphers::aead's, secret_key_encryption::basic_secretbox's and public_key_encryption::basic_box's
// generic layer on a stand-in backend whose seal and open write into the data before they fail,
// as OpenSSL can once it began to encrypt: a seal that fails zeroes the data as a failed open
// does, so that neither the plaintext nor bytes that look sealed stay behind; a guard's refusal
// leaves it untouched; an engine's error is passed on. The box's key pair is X25519's on the same
// stand-in, whose engine answers with fixed bytes.

#include <webcpp/crypto/ciphers/aead.hpp>
#include <webcpp/crypto/curves/x25519.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/public_key_encryption/box.hpp>
#include <webcpp/crypto/secret_key_encryption/secretbox.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>
#include <boost/system/result.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <span>

namespace webcpp::test {
namespace {

/** A backend tag for the AEAD's and the box's generic layer alone. */
struct aead_stand_in {};

/** The error the stand-in's seal and open return after they write, when set. */
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): the knob a test turns
boost::system::error_code aead_stand_in_error{};

/** The byte the stand-in writes over the data before it fails or succeeds. */
constexpr std::uint8_t written_byte = 0xA5;

/** Writes the stand-in's byte over data, then returns the knob's error or success. */
[[nodiscard]] boost::system::result<void> write_then_answer(std::span<std::uint8_t> data) noexcept {
    std::ranges::fill(data, written_byte);
    if (aead_stand_in_error) {
        return aead_stand_in_error;
    }
    return {};
}

}  // namespace
}  // namespace webcpp::test

namespace webcpp::crypto::detail {

/** The stand-in's ChaCha20-Poly1305: every call writes the data first, then answers. */
template <>
struct aead_engine<families::chacha20_poly1305, test::aead_stand_in> {
    /** Succeeds. */
    [[nodiscard]] static boost::system::result<void> init(
        aead_state<families::chacha20_poly1305, test::aead_stand_in>& /*state*/,
        std::span<std::uint8_t const> /*key_bytes*/) noexcept {
        return {};
    }

    /** Writes the data, then answers. */
    [[nodiscard]] static boost::system::result<void> seal(
        aead_state<families::chacha20_poly1305, test::aead_stand_in>& /*state*/,
        std::span<std::uint8_t const> /*nonce_bytes*/,
        std::span<std::uint8_t const> /*associated_data_bytes*/, std::span<std::uint8_t> data,
        boost::hash2::digest<16>& /*tag*/) noexcept {
        return test::write_then_answer(data);
    }

    /** Writes the data, then answers. */
    [[nodiscard]] static boost::system::result<void> open(
        aead_state<families::chacha20_poly1305, test::aead_stand_in>& /*state*/,
        std::span<std::uint8_t const> /*nonce_bytes*/,
        std::span<std::uint8_t const> /*associated_data_bytes*/, std::span<std::uint8_t> data,
        std::array<std::uint8_t, 16> const& /*tag*/) noexcept {
        return test::write_then_answer(data);
    }

    /** Nothing to move. */
    static void move(
        aead_state<families::chacha20_poly1305, test::aead_stand_in>& /*to*/,
        aead_state<families::chacha20_poly1305, test::aead_stand_in>& /*from*/) noexcept {}

    /** Nothing to wipe. */
    static void reset(
        aead_state<families::chacha20_poly1305, test::aead_stand_in>& /*state*/) noexcept {}
};

/** The stand-in's X25519, for the box's key pair: any secret key has a public key of 9s. */
template <>
struct x25519_engine<families::x25519, test::aead_stand_in> {
    /** Writes a public key of 9s. */
    [[nodiscard]] static boost::system::result<void> base(
        std::span<std::uint8_t const, 32> /*secret_key*/,
        std::span<std::uint8_t, 32> public_bytes) noexcept {
        std::ranges::fill(public_bytes, std::uint8_t{9});
        return {};
    }

    /** Never called by the box, which agrees through its own engine. */
    [[nodiscard]] static boost::system::result<void> agree(
        std::span<std::uint8_t const, 32> /*secret_key*/,
        std::span<std::uint8_t const, 32> /*peer_public_key*/,
        std::span<std::uint8_t, 32> /*shared_bytes*/) noexcept {
        return error::backend_failure;
    }
};

/** The stand-in's XSalsa20-Poly1305 box: every call writes the data first, then answers. */
template <>
struct box_engine<families::box_xsalsa20poly1305, test::aead_stand_in> {
    /** Succeeds. */
    [[nodiscard]] static boost::system::result<void> init(
        box_state<families::box_xsalsa20poly1305, test::aead_stand_in>& /*state*/,
        std::span<std::uint8_t const, 32> /*secret_key*/,
        std::span<std::uint8_t const, 32> /*peer_public_key*/) noexcept {
        return {};
    }

    /** Writes the data, then answers. */
    [[nodiscard]] static boost::system::result<void> seal(
        box_state<families::box_xsalsa20poly1305, test::aead_stand_in>& /*state*/,
        std::span<std::uint8_t const, 24> /*nonce_bytes*/, std::span<std::uint8_t> data,
        boost::hash2::digest<16>& /*tag*/) noexcept {
        return test::write_then_answer(data);
    }

    /** Writes the data, then answers. */
    [[nodiscard]] static boost::system::result<void> open(
        box_state<families::box_xsalsa20poly1305, test::aead_stand_in>& /*state*/,
        std::span<std::uint8_t const, 24> /*nonce_bytes*/, std::span<std::uint8_t> data,
        std::array<std::uint8_t, 16> const& /*tag*/) noexcept {
        return test::write_then_answer(data);
    }

    /** Nothing to move. */
    static void move(
        box_state<families::box_xsalsa20poly1305, test::aead_stand_in>& /*to*/,
        box_state<families::box_xsalsa20poly1305, test::aead_stand_in>& /*from*/) noexcept {}

    /** Nothing to wipe. */
    static void reset(
        box_state<families::box_xsalsa20poly1305, test::aead_stand_in>& /*state*/) noexcept {}
};

/** The stand-in's XSalsa20-Poly1305 secret box: every call writes the data first, then answers. */
template <>
struct secretbox_engine<families::secretbox_xsalsa20poly1305, test::aead_stand_in> {
    /** The state, the primary's: nothing. */
    using state = secretbox_state<families::secretbox_xsalsa20poly1305, test::aead_stand_in>;

    /** Succeeds. */
    [[nodiscard]] static boost::system::result<void> init(
        state& /*state*/, std::span<std::uint8_t const> /*key_bytes*/) noexcept {
        return {};
    }

    /** Writes the data, then answers. */
    [[nodiscard]] static boost::system::result<void> seal(
        state& /*state*/, std::span<std::uint8_t const, 24> /*nonce_bytes*/,
        std::span<std::uint8_t> data, boost::hash2::digest<16>& /*tag*/) noexcept {
        return test::write_then_answer(data);
    }

    /** Writes the data, then answers. */
    [[nodiscard]] static boost::system::result<void> open(
        state& /*state*/, std::span<std::uint8_t const, 24> /*nonce_bytes*/,
        std::span<std::uint8_t> data, std::array<std::uint8_t, 16> const& /*tag*/) noexcept {
        return test::write_then_answer(data);
    }

    /** Nothing to move. */
    static void move(state& /*to*/, state& /*from*/) noexcept {}

    /** Nothing to wipe. */
    static void reset(state& /*state*/) noexcept {}
};

}  // namespace webcpp::crypto::detail

namespace {

namespace crypto = webcpp::crypto;
using stand_in = webcpp::test::aead_stand_in;

bool all_equal(std::span<std::uint8_t const> bytes, std::uint8_t value) {
    return std::ranges::all_of(bytes, [value](std::uint8_t byte) { return byte == value; });
}

// A seal and an open that fail after they wrote zero the data; a guard's refusal leaves it as
// it was; a seal that succeeds keeps what the engine wrote.
template <class Seal, class Open>
void check_failures(Seal seal, Open open) {
    boost::system::error_code const failed = crypto::error::backend_failure;
    std::array<std::uint8_t, 24> data{};

    webcpp::test::aead_stand_in_error = failed;
    data.fill(0x11);
    BOOST_TEST(seal(std::span<std::uint8_t const>{}, data).error() ==
               crypto::error::invalid_nonce_size);
    BOOST_TEST(all_equal(data, 0x11));

    std::array<std::uint8_t, 24> const nonce{};
    BOOST_TEST(seal(nonce, data).error() == failed);
    BOOST_TEST(all_equal(data, 0));
    data.fill(0x11);
    BOOST_TEST(open(nonce, data).error() == failed);
    BOOST_TEST(all_equal(data, 0));

    webcpp::test::aead_stand_in_error = {};
    data.fill(0x11);
    BOOST_TEST(seal(nonce, data).has_value());
    BOOST_TEST(all_equal(data, webcpp::test::written_byte));
}

void check_aead() {
    using aead = crypto::ciphers::aead<crypto::families::chacha20_poly1305, stand_in>;
    std::array<std::uint8_t, aead::key_size> const key{};
    auto made = aead::from_key(key);
    if (!BOOST_TEST(made.has_value())) {
        return;
    }
    std::array<std::uint8_t, aead::tag_size> const tag{};
    check_failures(
        [&made](std::span<std::uint8_t const> nonce, std::span<std::uint8_t> data) {
            return made->seal(nonce.first(std::min(nonce.size(), aead::nonce_size)), {}, data);
        },
        [&made, &tag](std::span<std::uint8_t const> nonce, std::span<std::uint8_t> data) {
            return made->open(nonce.first(aead::nonce_size), {}, data, tag);
        });
}

void check_secretbox() {
    using secretbox =
        crypto::secret_key_encryption::basic_secretbox<crypto::families::secretbox_xsalsa20poly1305,
                                                       stand_in>;
    std::array<std::uint8_t, secretbox::key_size> const key{};
    auto made = secretbox::from_key(key);
    if (!BOOST_TEST(made.has_value())) {
        return;
    }
    std::array<std::uint8_t, secretbox::tag_size> const tag{};
    check_failures(
        [&made](std::span<std::uint8_t const> nonce, std::span<std::uint8_t> data) {
            return made->seal(nonce, data);
        },
        [&made, &tag](std::span<std::uint8_t const> nonce, std::span<std::uint8_t> data) {
            return made->open(nonce, data, tag);
        });
}

void check_box() {
    using box =
        crypto::public_key_encryption::basic_box<crypto::families::box_xsalsa20poly1305, stand_in>;
    std::array<std::uint8_t, box::key_size> const key{};
    auto const own = crypto::curves::x25519::basic_keypair<stand_in>::from_secret(key);
    auto const peer = crypto::curves::x25519::public_key::from_bytes(key);
    if (!BOOST_TEST(own.has_value()) || !BOOST_TEST(peer.has_value())) {
        return;
    }
    auto made = box::from_keys(*own, *peer);
    if (!BOOST_TEST(made.has_value())) {
        return;
    }
    std::array<std::uint8_t, box::tag_size> const tag{};
    check_failures(
        [&made](std::span<std::uint8_t const> nonce, std::span<std::uint8_t> data) {
            return made->seal(nonce, data);
        },
        [&made, &tag](std::span<std::uint8_t const> nonce, std::span<std::uint8_t> data) {
            return made->open(nonce, data, tag);
        });
}

}  // namespace

int main() {
    check_aead();
    check_secretbox();
    check_box();
    return webcpp::test::exit_status(boost::report_errors());
}
