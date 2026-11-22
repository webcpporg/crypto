// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Every public function that runs libsodium's code enters its own detail::timing_guard and leaves
// the thread's DIT as it found it, on every target, also where DIT does not apply, each with valid
// input and with input refused before the backend (support/timing_coverage.hpp). One section per
// part of the library: the ciphers, the boxes, PEM and the curves.
// A check fails, naming itself, when its call enters no guard or when the first guard it enters is
// not the one of the function it names (support/timing_seam.hpp), so that a function that forgot
// its own guard fails although it calls another guarded function.
//
// What it covers, by family; a family libsodium gains adds its line and its checks:
// - ChaCha20-Poly1305, its original form, XChaCha20-Poly1305 and both secret boxes, aead: make,
//   seal, open; the free crypto::make, crypto::seal and crypto::open.
// - Both boxes, basic_box: make, seal, open. The sealed box, basic_sealed_box: seal, open.
// - PEM: algorithm::armour, algorithm::unarmour, and the free armour and unarmour, which forward.
// - Ed25519, basic_keypair: make, generate, public_key, secret, sign, x25519_secret; public_key:
//   verify; the free crypto::verify and to_x25519_public, and the free synchronous forms of the
//   members, crypto::make, crypto::generate and crypto::sign, which enter their own guard before
//   the member's. Ed25519ph, ph: begin, update, sign, verify. Its formats: decode_spki,
//   decode_pkcs8 (the encoders call no backend and hold no guard, ruling R4; nor do
//   public_key::make and bytes).
// - Ed25519's asynchronous functions: async_make, async_generate, async_sign, async_verify.
// - X25519, algorithm: public_key, agree; the free public_key and agree, which forward, and
//   the asynchronous async_agree. Its formats: decode_spki, decode_pkcs8.
// - crypto_kx, kx_keypair: make, generate, client_session_keys, server_session_keys.

#include "support/timing_seam.hpp"

#include <webcpp/crypto/backends/sodium.hpp>
#include <webcpp/crypto/ciphers/chacha20_poly1305.hpp>
#include <webcpp/crypto/ciphers/secretbox.hpp>
#include <webcpp/crypto/curves/ed25519.hpp>
#include <webcpp/crypto/curves/ed25519/formats.hpp>
#include <webcpp/crypto/curves/x25519.hpp>
#include <webcpp/crypto/curves/x25519/formats.hpp>
#include <webcpp/crypto/curves/x25519/kx.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/hybrid/box.hpp>
#include <webcpp/crypto/hybrid/sealed_box.hpp>
#include <webcpp/crypto/keypair.hpp>
#include <webcpp/crypto/pem.hpp>
#include <webcpp/crypto/signing.hpp>
#include <webcpp/hash/algorithms.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/timing_coverage.hpp"

#include <boost/core/lightweight_test.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <utility>

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
    covered(family + "::make" + on, "basic_box::make",
            [&] { BOOST_TEST(Box::make(alice.secret_key, bob.public_key).has_value()); });
    covered(family + "::make with a short secret key" + on, "basic_box::make", [&] {
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
    covered(family + "::seal" + on, "basic_box::seal", [&] {
        auto const sealed = made->seal(iv, data);
        if (BOOST_TEST(sealed.has_value())) {
            tag = *sealed;
        }
    });
    covered(family + "::open" + on, "basic_box::open", [&] {
        BOOST_TEST(made->open(iv, data, std::span(tag.data(), tag.size())).has_value());
    });
    covered(family + "::seal with a short nonce" + on, "basic_box::seal", [&] {
        BOOST_TEST(made->seal(std::span(iv).first(Box::iv_size - 1), data).error() ==
                   crypto::error::invalid_iv_size);
    });
    covered(family + "::open with a short nonce" + on, "basic_box::open", [&] {
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
    covered("sealed_box::seal on sodium", "basic_sealed_box::seal",
            [&] { BOOST_TEST(sealed_box::seal(bob.public_key, message, sealed).has_value()); });
    covered("sealed_box::open on sodium", "basic_sealed_box::open", [&] {
        BOOST_TEST(sealed_box::open(bob.public_key, bob.secret_key, sealed, opened).has_value());
    });
    covered("sealed_box::seal into a short output on sodium", "basic_sealed_box::seal", [&] {
        BOOST_TEST(sealed_box::seal(bob.public_key, message, std::span(sealed).first(1)).error() ==
                   crypto::error::invalid_input_size);
    });
    covered("sealed_box::open into a short output on sodium", "basic_sealed_box::open", [&] {
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

// ---------------------------------------------------------------------------------------------
// The curves.
// ---------------------------------------------------------------------------------------------

/**
 * Ed25519's key pair: `make`, a seed of the wrong size included, `generate` (the system's
 * entropy), and `public_key`, `secret`, `sign` and `x25519_secret`, each of a moved-from key pair
 * too.
 */
void cover_ed25519_keypair() {
    using keypair = crypto::curves::ed25519::basic_keypair<sodium>;
    auto const seed = webcpp::test::coverage_key<keypair::seed_size>();
    std::array<std::uint8_t, 3> const message{1, 2, 3};
    covered("ed25519::basic_keypair::make on sodium",
            [&] { BOOST_TEST(keypair::make(seed).has_value()); });
    covered("ed25519::basic_keypair::make with a short seed on sodium", [&] {
        BOOST_TEST(keypair::make(std::span(seed).first(31)).error() ==
                   crypto::error::invalid_key_size);
    });
    covered("ed25519::basic_keypair::generate on sodium",
            [] { BOOST_TEST(keypair::generate().has_value()); });
    auto made = keypair::make(seed);
    if (!BOOST_TEST(made.has_value())) {
        return;
    }
    covered("ed25519::basic_keypair::public_key on sodium",
            [&] { BOOST_TEST(made->public_key().has_value()); });
    covered("ed25519::basic_keypair::secret on sodium",
            [&] { BOOST_TEST(made->secret().has_value()); });
    covered("ed25519::basic_keypair::sign on sodium",
            [&] { BOOST_TEST(made->sign(crypto::eddsa, message).has_value()); });
    covered("ed25519::basic_keypair::x25519_secret on sodium",
            [&] { BOOST_TEST(made->x25519_secret().has_value()); });
    [[maybe_unused]] keypair const taken(std::move(*made));
    covered("ed25519::basic_keypair::public_key moved from on sodium", [&] {
        // NOLINTNEXTLINE(bugprone-use-after-move): the moved-from key pair's refusal
        BOOST_TEST(made->public_key().error() == crypto::error::invalid_state);
    });
    covered("ed25519::basic_keypair::secret moved from on sodium", [&] {
        // NOLINTNEXTLINE(bugprone-use-after-move): the moved-from key pair's refusal
        BOOST_TEST(made->secret().error() == crypto::error::invalid_state);
    });
    covered("ed25519::basic_keypair::sign moved from on sodium", [&] {
        // NOLINTNEXTLINE(bugprone-use-after-move): the moved-from key pair's refusal
        BOOST_TEST(made->sign(crypto::eddsa, message).error() == crypto::error::invalid_state);
    });
    covered("ed25519::basic_keypair::x25519_secret moved from on sodium", [&] {
        // NOLINTNEXTLINE(bugprone-use-after-move): the moved-from key pair's refusal
        BOOST_TEST(made->x25519_secret().error() == crypto::error::invalid_state);
    });
}

/**
 * Ed25519's free synchronous forms, crypto::make, crypto::generate and crypto::sign, each entering
 * its own guard before the member's, and refused once before libsodium (a short seed, a moved-from
 * key pair).
 */
void cover_ed25519_free_forms() {
    using keypair = crypto::curves::ed25519::basic_keypair<sodium>;
    auto const seed = webcpp::test::coverage_key<keypair::seed_size>();
    std::array<std::uint8_t, 3> const message{1, 2, 3};
    covered("ed25519 crypto::make on sodium", "crypto::make",
            [&] { BOOST_TEST(crypto::make<keypair>(seed).has_value()); });
    covered("ed25519 crypto::make with a short seed on sodium", "crypto::make", [&] {
        BOOST_TEST(crypto::make<keypair>(std::span(seed).first(31)).error() ==
                   crypto::error::invalid_key_size);
    });
    covered("ed25519 crypto::generate on sodium", "crypto::generate",
            [] { BOOST_TEST(crypto::generate<keypair>().has_value()); });
    auto made = keypair::make(seed);
    if (!BOOST_TEST(made.has_value())) {
        return;
    }
    covered("ed25519 crypto::sign on sodium", "crypto::sign",
            [&] { BOOST_TEST(crypto::sign(*made, crypto::eddsa, message).has_value()); });
    [[maybe_unused]] keypair const taken(std::move(*made));
    covered("ed25519 crypto::sign moved from on sodium", "crypto::sign", [&] {
        // NOLINTNEXTLINE(bugprone-use-after-move): the moved-from key pair's refusal
        BOOST_TEST(crypto::sign(*made, crypto::eddsa, message).error() ==
                   crypto::error::invalid_state);
    });
}

/**
 * Ed25519's `crypto::verify` and `public_key::verify`, a signature of the wrong size included,
 * and `to_x25519_public`, a key of small order included.
 */
void cover_ed25519_free() {
    namespace ed25519 = crypto::curves::ed25519;
    auto const made = ed25519::basic_keypair<sodium>::make(webcpp::test::coverage_key<32>());
    std::array<std::uint8_t, 3> const message{1, 2, 3};
    if (!BOOST_TEST(made.has_value())) {
        return;
    }
    auto const public_key = made->public_key();
    auto const signature = made->sign(crypto::eddsa, message);
    if (!BOOST_TEST(public_key.has_value()) || !BOOST_TEST(signature.has_value())) {
        return;
    }
    covered("ed25519 crypto::verify on sodium", "crypto::verify", [&] {
        BOOST_TEST((
            crypto::verify<sodium>(crypto::eddsa, *signature, message, *public_key, ed25519::strict)
                .has_value()));
    });
    covered("ed25519 crypto::verify with a short signature on sodium", "crypto::verify", [&] {
        BOOST_TEST((crypto::verify<sodium>(crypto::eddsa, std::span(*signature).first(63), message,
                                           *public_key, ed25519::strict)
                        .error() == crypto::error::invalid_signature));
    });
    covered("ed25519::public_key::verify on sodium", [&] {
        BOOST_TEST(public_key->verify(crypto::eddsa, *signature, message).has_value());
    });
    covered("ed25519::public_key::verify with a short signature on sodium", [&] {
        BOOST_TEST(
            public_key->verify(crypto::eddsa, std::span(*signature).first(63), message).error() ==
            crypto::error::invalid_signature);
    });
    covered("ed25519::to_x25519_public on sodium",
            [&] { BOOST_TEST(ed25519::to_x25519_public<sodium>(*public_key).has_value()); });
    // The identity's encoding, 01 then zeros, a point of small order.
    std::array<std::uint8_t, 32> identity{};
    identity[0] = 0x01;
    auto const small_order = ed25519::public_key::make(identity);
    if (!BOOST_TEST(small_order.has_value())) {
        return;
    }
    covered("ed25519::to_x25519_public with a key of small order on sodium", [&] {
        BOOST_TEST(ed25519::to_x25519_public<sodium>(*small_order).error() ==
                   crypto::error::invalid_public_key);
    });
}

/** Ed25519ph's `begin`, `update`, `sign` and `verify` of a message, a valid one. */
void cover_ed25519ph() {
    namespace ed25519 = crypto::curves::ed25519;
    using ph = ed25519::ph<webcpp::hash::sha2_512, sodium>;
    auto const key = ed25519::basic_keypair<sodium>::make(webcpp::test::coverage_key<32>());
    std::array<std::uint8_t, 3> const piece{1, 2, 3};
    covered("ed25519::ph::begin on sodium", [] { BOOST_TEST(ph::begin().has_value()); });
    auto signer = ph::begin();
    auto verifier = ph::begin();
    if (!BOOST_TEST(key.has_value()) || !BOOST_TEST(signer.has_value()) ||
        !BOOST_TEST(verifier.has_value()) || !BOOST_TEST(verifier->update(piece).has_value())) {
        return;
    }
    auto const public_key = key->public_key();
    if (!BOOST_TEST(public_key.has_value())) {
        return;
    }
    covered("ed25519::ph::update on sodium",
            [&] { BOOST_TEST(signer->update(piece).has_value()); });
    std::array<std::uint8_t, ph::signature_size> signature{};
    covered("ed25519::ph::sign on sodium", [&] {
        auto const signed_message = signer->sign(*key);
        if (BOOST_TEST(signed_message.has_value())) {
            signature = *signed_message;
        }
    });
    covered("ed25519::ph::verify on sodium",
            [&] { BOOST_TEST(verifier->verify(signature, *public_key).has_value()); });
}

/**
 * Ed25519ph's `update`, `sign` and `verify` of an ended message, refused before the backend, and
 * `verify` with a signature of the wrong size.
 */
void cover_ed25519ph_refusals() {
    namespace ed25519 = crypto::curves::ed25519;
    using ph = ed25519::ph<webcpp::hash::sha2_512, sodium>;
    auto const key = ed25519::basic_keypair<sodium>::make(webcpp::test::coverage_key<32>());
    std::array<std::uint8_t, ph::signature_size> const signature{};
    std::array<std::uint8_t, 3> const piece{1, 2, 3};
    auto ended = ph::begin();
    auto short_signature = ph::begin();
    if (!BOOST_TEST(key.has_value()) || !BOOST_TEST(ended.has_value()) ||
        !BOOST_TEST(short_signature.has_value()) || !BOOST_TEST(ended->sign(*key).has_value())) {
        return;
    }
    auto const public_key = key->public_key();
    if (!BOOST_TEST(public_key.has_value())) {
        return;
    }
    covered("ed25519::ph::update of an ended message on sodium",
            [&] { BOOST_TEST(ended->update(piece).error() == crypto::error::invalid_state); });
    covered("ed25519::ph::sign of an ended message on sodium",
            [&] { BOOST_TEST(ended->sign(*key).error() == crypto::error::invalid_state); });
    covered("ed25519::ph::verify of an ended message on sodium", [&] {
        BOOST_TEST(ended->verify(signature, *public_key).error() == crypto::error::invalid_state);
    });
    covered("ed25519::ph::verify with a short signature on sodium", [&] {
        BOOST_TEST(short_signature->verify(std::span(signature).first(63), *public_key).error() ==
                   crypto::error::invalid_signature);
    });
}

/** Ed25519's `decode_spki` and `decode_pkcs8`, an encoding of the wrong size of each included. */
void cover_ed25519_formats() {
    namespace ed25519 = crypto::curves::ed25519;
    auto const key = ed25519::basic_keypair<sodium>::make(webcpp::test::coverage_key<32>());
    if (!BOOST_TEST(key.has_value())) {
        return;
    }
    auto const public_key = key->public_key();
    std::array<std::uint8_t, ed25519::max_spki_size> spki{};
    std::array<std::uint8_t, ed25519::max_pkcs8_size> pkcs8{};
    if (!BOOST_TEST(public_key.has_value()) ||
        !BOOST_TEST(ed25519::encode_spki<sodium>(*public_key, spki).has_value()) ||
        !BOOST_TEST(ed25519::encode_pkcs8<sodium>(*key, pkcs8).has_value())) {
        return;
    }
    covered("ed25519::decode_spki on sodium",
            [&] { BOOST_TEST(ed25519::decode_spki<sodium>(spki).has_value()); });
    covered("ed25519::decode_pkcs8 on sodium",
            [&] { BOOST_TEST(ed25519::decode_pkcs8<sodium>(pkcs8).has_value()); });
    covered("ed25519::decode_spki of a short encoding on sodium", [&] {
        BOOST_TEST(ed25519::decode_spki<sodium>(std::span(spki).first(43)).error() ==
                   crypto::error::invalid_encoding);
    });
    covered("ed25519::decode_pkcs8 of a short encoding on sodium", [&] {
        BOOST_TEST(ed25519::decode_pkcs8<sodium>(std::span(pkcs8).first(47)).error() ==
                   crypto::error::invalid_encoding);
    });
}

/**
 * X25519's `algorithm<sodium>::public_key` and `agree`, and the free functions, a key of the
 * wrong size of each included.
 */
void cover_x25519() {
    namespace x25519 = crypto::curves::x25519;
    using algorithm = x25519::algorithm<sodium>;
    auto const alice = make_keypair(0x41);
    auto const bob = make_keypair(0x42);
    auto const short_key = std::span(alice.secret_key).first(31);
    covered("x25519::algorithm::public_key on sodium",
            [&] { BOOST_TEST(algorithm::public_key(alice.secret_key).has_value()); });
    covered("x25519::algorithm::agree on sodium",
            [&] { BOOST_TEST(algorithm::agree(alice.secret_key, bob.public_key).has_value()); });
    covered("x25519::public_key on sodium",
            [&] { BOOST_TEST(x25519::public_key<sodium>(alice.secret_key).has_value()); });
    covered("x25519::agree on sodium", [&] {
        BOOST_TEST(x25519::agree<sodium>(alice.secret_key, bob.public_key).has_value());
    });
    covered("x25519::algorithm::public_key with a short key on sodium", [&] {
        BOOST_TEST(algorithm::public_key(short_key).error() == crypto::error::invalid_key_size);
    });
    covered("x25519::algorithm::agree with a short key on sodium", [&] {
        BOOST_TEST(algorithm::agree(short_key, bob.public_key).error() ==
                   crypto::error::invalid_key_size);
    });
    covered("x25519::public_key with a short key on sodium", [&] {
        BOOST_TEST(x25519::public_key<sodium>(short_key).error() ==
                   crypto::error::invalid_key_size);
    });
    covered("x25519::agree with a short key on sodium", [&] {
        BOOST_TEST(x25519::agree<sodium>(short_key, bob.public_key).error() ==
                   crypto::error::invalid_key_size);
    });
}

/** X25519's `decode_spki` and `decode_pkcs8`, an encoding of the wrong size of each included. */
void cover_x25519_formats() {
    namespace x25519 = crypto::curves::x25519;
    auto const alice = make_keypair(0x41);
    std::array<std::uint8_t, x25519::max_spki_size> spki{};
    std::array<std::uint8_t, x25519::max_pkcs8_size> pkcs8{};
    if (!BOOST_TEST(x25519::encode_spki<sodium>(alice.public_key, spki).has_value()) ||
        !BOOST_TEST(x25519::encode_pkcs8<sodium>(alice.secret_key, pkcs8).has_value())) {
        return;
    }
    covered("x25519::decode_spki on sodium",
            [&] { BOOST_TEST(x25519::decode_spki<sodium>(spki).has_value()); });
    covered("x25519::decode_pkcs8 on sodium",
            [&] { BOOST_TEST(x25519::decode_pkcs8<sodium>(pkcs8).has_value()); });
    covered("x25519::decode_spki of a short encoding on sodium", [&] {
        BOOST_TEST(x25519::decode_spki<sodium>(std::span(spki).first(43)).error() ==
                   crypto::error::invalid_encoding);
    });
    covered("x25519::decode_pkcs8 of a short encoding on sodium", [&] {
        BOOST_TEST(x25519::decode_pkcs8<sodium>(std::span(pkcs8).first(47)).error() ==
                   crypto::error::invalid_encoding);
    });
}

/**
 * crypto_kx's key pair: `make`, a seed of the wrong size included, `generate` (the system's
 * entropy), and `client_session_keys` and `server_session_keys`, a peer key of the wrong size
 * included. `public_key` copies bytes and holds no guard (ruling R4).
 */
void cover_kx() {
    using kx_keypair = crypto::curves::x25519::kx_keypair<sodium>;
    auto const seed = webcpp::test::coverage_key<kx_keypair::seed_size>();
    covered("x25519::kx_keypair::make on sodium",
            [&] { BOOST_TEST(kx_keypair::make(seed).has_value()); });
    covered("x25519::kx_keypair::make with a short seed on sodium", [&] {
        BOOST_TEST(kx_keypair::make(std::span(seed).first(31)).error() ==
                   crypto::error::invalid_key_size);
    });
    covered("x25519::kx_keypair::generate on sodium",
            [] { BOOST_TEST(kx_keypair::generate().has_value()); });
    auto const client = kx_keypair::make(seed);
    auto const server = kx_keypair::generate();
    if (!BOOST_TEST(client.has_value()) || !BOOST_TEST(server.has_value())) {
        return;
    }
    auto const client_public = client->public_key();
    auto const server_public = server->public_key();
    if (!BOOST_TEST(client_public.has_value()) || !BOOST_TEST(server_public.has_value())) {
        return;
    }
    covered("x25519::kx_keypair::client_session_keys on sodium",
            [&] { BOOST_TEST(client->client_session_keys(*server_public).has_value()); });
    covered("x25519::kx_keypair::server_session_keys on sodium",
            [&] { BOOST_TEST(server->server_session_keys(*client_public).has_value()); });
    covered("x25519::kx_keypair::client_session_keys with a short key on sodium", [&] {
        BOOST_TEST(client->client_session_keys(std::span(*server_public).first(31)).error() ==
                   crypto::error::invalid_public_key);
    });
    covered("x25519::kx_keypair::server_session_keys with a short key on sodium", [&] {
        BOOST_TEST(server->server_session_keys(std::span(*client_public).first(31)).error() ==
                   crypto::error::invalid_public_key);
    });
}

/** Ed25519, Ed25519ph, X25519, crypto_kx, and the decoders of the key formats. */
void cover_curves() {
    cover_ed25519_keypair();
    webcpp::test::cover_async_ed25519<crypto::curves::ed25519::basic_keypair<sodium>>("sodium");
    webcpp::test::cover_async_x25519<sodium>("sodium");
    cover_ed25519_free();
    cover_ed25519_free_forms();
    cover_ed25519ph();
    cover_ed25519ph_refusals();
    cover_ed25519_formats();
    cover_x25519();
    cover_x25519_formats();
    cover_kx();
}

}  // namespace

int main() {
    cover_ciphers();
    cover_boxes();
    cover_pem();
    cover_curves();
    return webcpp::test::exit_status(boost::report_errors());
}
