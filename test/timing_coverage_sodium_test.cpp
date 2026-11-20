// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Every public function that runs libsodium's code enters detail::timing_guard and leaves the
// thread's DIT as it found it, on every target, also where DIT does not apply, each with valid
// input and with input refused before the backend (support/timing_coverage.hpp). One section per
// part of the library: the ciphers (ChaCha20-Poly1305, its original form, XChaCha20-Poly1305 and
// both secret boxes), the boxes (both boxes and the sealed box), and PEM.

#include "support/timing_seam.hpp"

#include <webcpp/crypto/backends/sodium.hpp>
#include <webcpp/crypto/ciphers/chacha20_poly1305.hpp>
#include <webcpp/crypto/ciphers/secretbox.hpp>
#include <webcpp/crypto/curves/x25519.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/hybrid/box.hpp>
#include <webcpp/crypto/hybrid/sealed_box.hpp>
#include <webcpp/crypto/pem.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/timing_coverage.hpp"

#include <boost/core/lightweight_test.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace {

namespace crypto = webcpp::crypto;
using crypto::backends::sodium;
using webcpp::test::covered;

// ---------------------------------------------------------------------------------------------
// The ciphers.
// ---------------------------------------------------------------------------------------------

/** ChaCha20-Poly1305, its original form, XChaCha20-Poly1305 and both secret boxes. */
void cover_ciphers() {
    webcpp::test::cover_aead<crypto::ciphers::chacha20_poly1305<sodium>>("chacha20_poly1305",
                                                                         "sodium");
    webcpp::test::cover_aead<crypto::ciphers::chacha20_poly1305_original<sodium>>(
        "chacha20_poly1305_original", "sodium");
    webcpp::test::cover_aead<crypto::ciphers::xchacha20_poly1305<sodium>>("xchacha20_poly1305",
                                                                          "sodium");
    webcpp::test::cover_aead<crypto::ciphers::secretbox<sodium>>("secretbox", "sodium");
    webcpp::test::cover_aead<crypto::ciphers::secretbox_xchacha20poly1305<sodium>>(
        "secretbox_xchacha20poly1305", "sodium");
}

// ---------------------------------------------------------------------------------------------
// The boxes.
// ---------------------------------------------------------------------------------------------

/** An X25519 key pair whose secret key is `fill` repeated, for the boxes. */
struct coverage_keypair {
    /** The secret key. */
    std::array<std::uint8_t, 32> secret_key{};
    /** Its public key. */
    std::array<std::uint8_t, 32> public_key{};
};

/** The key pair of the secret key of 32 bytes `fill`; its public key, derived outside a check. */
coverage_keypair make_keypair(std::uint8_t fill) {
    coverage_keypair made;
    made.secret_key.fill(fill);
    auto const derived = crypto::curves::x25519::public_key<sodium>(made.secret_key);
    if (BOOST_TEST(derived.has_value())) {
        made.public_key = *derived;
    }
    return made;
}

/**
 * A box's guarded functions: `make`, a secret key of the wrong size included, `seal` and `open`,
 * a nonce of the wrong size included.
 *
 * @tparam Box `basic_box<Family, sodium>`.
 * @param family The family's name, as the public alias spells it.
 */
template <class Box>
void cover_box(std::string const& family) {
    std::string const on = " on sodium";
    auto const alice = make_keypair(0x41);
    auto const bob = make_keypair(0x42);
    covered(family + "::make" + on,
            [&] { BOOST_TEST(Box::make(alice.secret_key, bob.public_key).has_value()); });
    covered(family + "::make with a short secret key" + on, [&] {
        BOOST_TEST(Box::make(std::span(alice.secret_key).first(31), bob.public_key).error() ==
                   crypto::error::invalid_key_size);
    });
    auto made = Box::make(alice.secret_key, bob.public_key);
    if (!BOOST_TEST(made.has_value())) {
        return;
    }
    std::array<std::uint8_t, Box::iv_size> const iv{};
    std::array<std::uint8_t, 40> data{};
    typename Box::result_type tag{};
    covered(family + "::seal" + on, [&] {
        auto const sealed = made->seal(iv, data);
        if (BOOST_TEST(sealed.has_value())) {
            tag = *sealed;
        }
    });
    covered(family + "::open" + on, [&] {
        BOOST_TEST(made->open(iv, data, std::span(tag.data(), tag.size())).has_value());
    });
    covered(family + "::seal with a short nonce" + on, [&] {
        BOOST_TEST(made->seal(std::span(iv).first(Box::iv_size - 1), data).error() ==
                   crypto::error::invalid_iv_size);
    });
    covered(family + "::open with a short nonce" + on, [&] {
        BOOST_TEST(made->open(std::span(iv).first(Box::iv_size - 1), data,
                              std::span(tag.data(), tag.size()))
                       .error() == crypto::error::invalid_iv_size);
    });
}

/** The sealed box's `seal` and `open`, an output of the wrong size included. */
void cover_sealed_box() {
    using sealed_box = crypto::hybrid::basic_sealed_box<sodium>;
    auto const bob = make_keypair(0x42);
    std::array<std::uint8_t, 8> const message{1, 2, 3, 4, 5, 6, 7, 8};
    std::array<std::uint8_t, message.size() + sealed_box::overhead> sealed{};
    std::array<std::uint8_t, message.size()> opened{};
    covered("sealed_box::seal on sodium",
            [&] { BOOST_TEST(sealed_box::seal(bob.public_key, message, sealed).has_value()); });
    covered("sealed_box::open on sodium", [&] {
        BOOST_TEST(sealed_box::open(bob.public_key, bob.secret_key, sealed, opened).has_value());
    });
    covered("sealed_box::seal into a short output on sodium", [&] {
        BOOST_TEST(sealed_box::seal(bob.public_key, message, std::span(sealed).first(1)).error() ==
                   crypto::error::invalid_input_size);
    });
    covered("sealed_box::open into a short output on sodium", [&] {
        BOOST_TEST(
            sealed_box::open(bob.public_key, bob.secret_key, sealed, std::span(opened).first(1))
                .error() == crypto::error::invalid_input_size);
    });
}

/** Both boxes and the sealed box. */
void cover_boxes() {
    cover_box<crypto::hybrid::basic_box<crypto::families::box_xsalsa20poly1305, sodium>>("box");
    cover_box<crypto::hybrid::basic_box<crypto::families::box_xchacha20poly1305, sodium>>(
        "box_xchacha20poly1305");
    cover_sealed_box();
}

// ---------------------------------------------------------------------------------------------
// PEM.
// ---------------------------------------------------------------------------------------------

/** `algorithm<sodium>::armour` and `unarmour`, and the free functions, a refusal of each. */
void cover_pem() {
    namespace pem = crypto::pem;
    std::string_view const label = pem::public_key_label;
    std::array<std::uint8_t, 44> const der = webcpp::test::coverage_key<44>();
    std::string text(pem::armoured_size(label.size(), der.size()), ' ');
    std::array<std::uint8_t, der.size()> out{};
    covered("pem::algorithm::armour on sodium",
            [&] { BOOST_TEST(pem::algorithm<sodium>::armour(label, der, text).has_value()); });
    covered("pem::algorithm::unarmour on sodium",
            [&] { BOOST_TEST(pem::algorithm<sodium>::unarmour(label, text, out).has_value()); });
    covered("pem::armour on sodium",
            [&] { BOOST_TEST(pem::armour<sodium>(label, der, text).has_value()); });
    covered("pem::unarmour on sodium",
            [&] { BOOST_TEST(pem::unarmour<sodium>(label, text, out).has_value()); });
    covered("pem::algorithm::armour into a short output on sodium", [&] {
        BOOST_TEST(pem::algorithm<sodium>::armour(label, der, std::span(text).first(1)).error() ==
                   crypto::error::invalid_input_size);
    });
    covered("pem::algorithm::unarmour of a text without lines on sodium", [&] {
        BOOST_TEST(pem::algorithm<sodium>::unarmour(label, "PEM", out).error() ==
                   crypto::error::invalid_encoding);
    });
    covered("pem::armour into a short output on sodium", [&] {
        BOOST_TEST(pem::armour<sodium>(label, der, std::span(text).first(1)).error() ==
                   crypto::error::invalid_input_size);
    });
    covered("pem::unarmour of a text without lines on sodium", [&] {
        BOOST_TEST(pem::unarmour<sodium>(label, "PEM", out).error() ==
                   crypto::error::invalid_encoding);
    });
}

}  // namespace

int main() {
    cover_ciphers();
    cover_boxes();
    cover_pem();
    return webcpp::test::exit_status(boost::report_errors());
}
