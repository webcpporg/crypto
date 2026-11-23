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
// - ChaCha20-Poly1305, its original form, XChaCha20-Poly1305 and both secret boxes, aead:
//   from_key, seal, open; the free crypto::from_key, crypto::seal and crypto::open.
// - Both boxes, basic_box: from_keys, of a moved-from key pair too, seal, open. The sealed box,
//   basic_sealed_box: seal, open, of a moved-from key pair too.
// - PEM: algorithm::armour, algorithm::unarmour, and the free armour and unarmour, which forward.
// - Ed25519, basic_keypair: from_secret, generate, public_key, secret, sign, to_x25519;
//   public_key: verify, to_x25519; the free crypto::verify, and the free synchronous forms of the
//   members, crypto::from_secret, crypto::generate, crypto::sign and crypto::to_x25519 (of a key
//   pair and of a public key), which enter their own guard before the member's, and
//   crypto::from_bytes of a public key, which enters none, as its member does not. Ed25519ph, the
//   scheme eddsa_prehashed: basic_keypair::sign, the free crypto::sign, public_key::verify,
//   crypto::verify, and their asynchronous forms, async_sign and async_verify, member and free;
//   prehashed_signer: begin, update, sign, verify. Its formats: decode_spki, decode_pkcs8 (the
//   encoders call no backend and hold no guard, ruling R4; nor do public_key::from_bytes and
//   bytes). Its signature, signature: from_bytes, member and free, and bytes, which call no backend
//   and enter no guard.
// - Ed25519's asynchronous functions: async_from_secret, async_generate, async_sign, async_verify,
//   free and as the members basic_keypair::async_from_secret, async_generate, async_sign and
//   public_key::async_verify, which the free ones call.
// - X25519, basic_keypair: from_secret, generate, agree, each of a moved-from key pair too where
//   it applies; public_key and secret, which copy, and public_key's from_bytes and bytes, which
//   enter none; the free crypto::from_secret, crypto::generate and crypto::agree, and crypto::
//   from_bytes, which enters none; the asynchronous async_from_secret, async_generate and
//   async_agree, member and free. Its formats: decode_spki, decode_pkcs8.
// - crypto_kx, kx_keypair: from_keypair, derive_from_seed, generate, client_session_keys,
//   server_session_keys, each of a moved-from key pair too where it applies; keypair and
//   public_key, which call no backend and enter none.

#include "support/timing_seam.hpp"

#include <webcpp/crypto/async.hpp>
#include <webcpp/crypto/backends/sodium.hpp>
#include <webcpp/crypto/ciphers/chacha20_poly1305.hpp>
#include <webcpp/crypto/ciphers/secretbox.hpp>
#include <webcpp/crypto/curves/ed25519.hpp>
#include <webcpp/crypto/curves/ed25519/formats.hpp>
#include <webcpp/crypto/curves/x25519.hpp>
#include <webcpp/crypto/curves/x25519/formats.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/key_exchange/kx.hpp>
#include <webcpp/crypto/keypair.hpp>
#include <webcpp/crypto/pem.hpp>
#include <webcpp/crypto/public_key_encryption/box.hpp>
#include <webcpp/crypto/public_key_encryption/sealed_box.hpp>
#include <webcpp/crypto/signing.hpp>
#include <webcpp/hash/algorithms.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/timing_coverage.hpp"

#include <webcpp/asio/io_context.hpp>

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

/** An X25519 key pair's bytes, its secret key `fill` repeated, for X25519's own checks. */
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
    auto const derived =
        crypto::curves::x25519::basic_keypair<sodium>::from_secret(made.secret_key);
    if (BOOST_TEST(derived.has_value())) {
        made.public_key = derived->public_key().value().bytes();
    }
    return made;
}

/**
 * The typed X25519 key pair whose secret key is 32 bytes `fill`, made outside a check, for the
 * boxes and crypto_kx.
 */
crypto::curves::x25519::basic_keypair<sodium> typed_keypair(std::uint8_t fill) {
    std::array<std::uint8_t, 32> secret_key{};
    secret_key.fill(fill);
    return crypto::curves::x25519::basic_keypair<sodium>::from_secret(secret_key).value();
}

/**
 * A box's guarded functions: `from_keys`, a moved-from key pair included, `seal` and `open`, a
 * nonce of the wrong size included.
 *
 * @tparam Box `basic_box<Family, sodium>`.
 * @param family The family's name, as the public alias spells it.
 */
template <class Box>
void cover_box(std::string const& family) {
    std::string const on = " on sodium";
    auto alice = typed_keypair(0x41);
    auto const bob_public = typed_keypair(0x42).public_key().value();
    covered(family + "::from_keys" + on, "basic_box::from_keys",
            [&] { BOOST_TEST(Box::from_keys(alice, bob_public).has_value()); });
    auto made = Box::from_keys(alice, bob_public);
    if (!BOOST_TEST(made.has_value())) {
        return;
    }
    auto const kept = std::move(alice);
    // NOLINTBEGIN(bugprone-use-after-move,clang-analyzer-cplusplus.Move): the refusal
    covered(family + "::from_keys of a moved-from key pair" + on, "basic_box::from_keys", [&] {
        BOOST_TEST(Box::from_keys(alice, bob_public).error() == crypto::error::invalid_state);
    });
    // NOLINTEND(bugprone-use-after-move,clang-analyzer-cplusplus.Move)
    std::array<std::uint8_t, Box::nonce_size> const nonce{};
    std::array<std::uint8_t, 40> data{};
    typename Box::result_type tag{};
    covered(family + "::seal" + on, "basic_box::seal", [&] {
        auto const sealed = made->seal(nonce, data);
        if (BOOST_TEST(sealed.has_value())) {
            tag = *sealed;
        }
    });
    covered(family + "::open" + on, "basic_box::open", [&] {
        BOOST_TEST(made->open(nonce, data, std::span(tag.data(), tag.size())).has_value());
    });
    covered(family + "::seal with a short nonce" + on, "basic_box::seal", [&] {
        BOOST_TEST(made->seal(std::span(nonce).first(Box::nonce_size - 1), data).error() ==
                   crypto::error::invalid_nonce_size);
    });
    covered(family + "::open with a short nonce" + on, "basic_box::open", [&] {
        BOOST_TEST(made->open(std::span(nonce).first(Box::nonce_size - 1), data,
                              std::span(tag.data(), tag.size()))
                       .error() == crypto::error::invalid_nonce_size);
    });
}

/**
 * The sealed box's `seal` and `open`, an output of the wrong size and a moved-from key pair
 * included.
 */
void cover_sealed_box() {
    using sealed_box = crypto::public_key_encryption::basic_sealed_box<sodium>;
    auto bob = typed_keypair(0x42);
    auto const bob_public = bob.public_key().value();
    std::array<std::uint8_t, 8> const message{1, 2, 3, 4, 5, 6, 7, 8};
    std::array<std::uint8_t, message.size() + sealed_box::overhead> sealed{};
    std::array<std::uint8_t, message.size()> opened{};
    covered("sealed_box::seal on sodium", "basic_sealed_box::seal",
            [&] { BOOST_TEST(sealed_box::seal(bob_public, message, sealed).has_value()); });
    covered("sealed_box::open on sodium", "basic_sealed_box::open",
            [&] { BOOST_TEST(sealed_box::open(bob, sealed, opened).has_value()); });
    covered("sealed_box::seal into a short output on sodium", "basic_sealed_box::seal", [&] {
        BOOST_TEST(sealed_box::seal(bob_public, message, std::span(sealed).first(1)).error() ==
                   crypto::error::invalid_input_size);
    });
    covered("sealed_box::open into a short output on sodium", "basic_sealed_box::open", [&] {
        BOOST_TEST(sealed_box::open(bob, sealed, std::span(opened).first(1)).error() ==
                   crypto::error::invalid_input_size);
    });
    auto const kept = std::move(bob);
    // NOLINTBEGIN(bugprone-use-after-move,clang-analyzer-cplusplus.Move): the refusal
    covered("sealed_box::open of a moved-from key pair on sodium", "basic_sealed_box::open", [&] {
        BOOST_TEST(sealed_box::open(bob, sealed, opened).error() == crypto::error::invalid_state);
    });
    // NOLINTEND(bugprone-use-after-move,clang-analyzer-cplusplus.Move)
}

/** Both boxes and the sealed box. */
void cover_boxes() {
    cover_box<
        crypto::public_key_encryption::basic_box<crypto::families::box_xsalsa20poly1305, sodium>>(
        "box");
    cover_box<
        crypto::public_key_encryption::basic_box<crypto::families::box_xchacha20poly1305, sodium>>(
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
 * Ed25519's key pair: `from_secret`, a seed of the wrong size included, `generate` (the system's
 * entropy), and `public_key`, `secret`, `sign` and `to_x25519`, each of a moved-from key pair
 * too.
 */
void cover_ed25519_keypair() {
    using keypair = crypto::curves::ed25519::basic_keypair<sodium>;
    auto const seed = webcpp::test::coverage_key<keypair::seed_size>();
    std::array<std::uint8_t, 3> const message{1, 2, 3};
    covered("ed25519::basic_keypair::from_secret on sodium",
            [&] { BOOST_TEST(keypair::from_secret(seed).has_value()); });
    covered("ed25519::basic_keypair::from_secret with a short seed on sodium", [&] {
        BOOST_TEST(keypair::from_secret(std::span(seed).first(31)).error() ==
                   crypto::error::invalid_key_size);
    });
    covered("ed25519::basic_keypair::generate on sodium",
            [] { BOOST_TEST(keypair::generate().has_value()); });
    auto made = keypair::from_secret(seed);
    if (!BOOST_TEST(made.has_value())) {
        return;
    }
    covered("ed25519::basic_keypair::public_key on sodium",
            [&] { BOOST_TEST(made->public_key().has_value()); });
    covered("ed25519::basic_keypair::secret on sodium",
            [&] { BOOST_TEST(made->secret().has_value()); });
    covered("ed25519::basic_keypair::sign on sodium",
            [&] { BOOST_TEST(made->sign(crypto::eddsa, message).has_value()); });
    covered("ed25519::basic_keypair::to_x25519 on sodium",
            [&] { BOOST_TEST(made->to_x25519().has_value()); });
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
    covered("ed25519::basic_keypair::to_x25519 moved from on sodium", [&] {
        // NOLINTNEXTLINE(bugprone-use-after-move): the moved-from key pair's refusal
        BOOST_TEST(made->to_x25519().error() == crypto::error::invalid_state);
    });
}

/**
 * Ed25519's free synchronous forms, crypto::from_secret, crypto::generate, crypto::sign and
 * crypto::to_x25519 of a key pair, each entering its own guard before the member's, and refused
 * once before libsodium (a short seed, a moved-from key pair); crypto::from_bytes of a public key
 * enters none, as its member does not.
 */
void cover_ed25519_free_forms() {
    using keypair = crypto::curves::ed25519::basic_keypair<sodium>;
    auto const seed = webcpp::test::coverage_key<keypair::seed_size>();
    std::array<std::uint8_t, 3> const message{1, 2, 3};
    covered("ed25519 crypto::from_secret on sodium", "crypto::from_secret",
            [&] { BOOST_TEST(crypto::from_secret<keypair>(seed).has_value()); });
    covered("ed25519 crypto::from_secret with a short seed on sodium", "crypto::from_secret", [&] {
        BOOST_TEST(crypto::from_secret<keypair>(std::span(seed).first(31)).error() ==
                   crypto::error::invalid_key_size);
    });
    std::array<std::uint8_t, 32> const key_bytes = seed;
    webcpp::test::uncovered("ed25519 crypto::from_bytes of a public key on sodium", [&] {
        BOOST_TEST(crypto::from_bytes<crypto::curves::ed25519::public_key>(key_bytes).has_value());
    });
    webcpp::test::uncovered("ed25519 crypto::from_bytes of a short public key on sodium", [&] {
        BOOST_TEST(
            crypto::from_bytes<crypto::curves::ed25519::public_key>(std::span(key_bytes).first(31))
                .error() == crypto::error::invalid_public_key);
    });
    covered("ed25519 crypto::generate on sodium", "crypto::generate",
            [] { BOOST_TEST(crypto::generate<keypair>().has_value()); });
    auto made = keypair::from_secret(seed);
    if (!BOOST_TEST(made.has_value())) {
        return;
    }
    covered("ed25519 crypto::sign on sodium", "crypto::sign",
            [&] { BOOST_TEST(crypto::sign(*made, crypto::eddsa, message).has_value()); });
    covered("ed25519 crypto::to_x25519 of a key pair on sodium", "crypto::to_x25519",
            [&] { BOOST_TEST(crypto::to_x25519(*made).has_value()); });
    [[maybe_unused]] keypair const taken(std::move(*made));
    covered("ed25519 crypto::sign moved from on sodium", "crypto::sign", [&] {
        // NOLINTNEXTLINE(bugprone-use-after-move): the moved-from key pair's refusal
        BOOST_TEST(crypto::sign(*made, crypto::eddsa, message).error() ==
                   crypto::error::invalid_state);
    });
    covered("ed25519 crypto::to_x25519 of a key pair moved from on sodium", "crypto::to_x25519",
            [&] {
                // NOLINTNEXTLINE(bugprone-use-after-move): the moved-from key pair's refusal
                BOOST_TEST(crypto::to_x25519(*made).error() == crypto::error::invalid_state);
            });
}

/**
 * Ed25519's `crypto::verify` and `public_key::verify`, a signature of the wrong size included,
 * and `public_key::to_x25519` and the free `crypto::to_x25519` of a public key, a key of small
 * order included.
 */
void cover_ed25519_free() {
    namespace ed25519 = crypto::curves::ed25519;
    auto const made = ed25519::basic_keypair<sodium>::from_secret(webcpp::test::coverage_key<32>());
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
    // A signature of another size is refused by from_bytes, which calls no backend; one that does
    // not verify is the backend's refusal.
    ed25519::signature const zero_signature{};
    covered("ed25519 crypto::verify with a zero signature on sodium", "crypto::verify", [&] {
        BOOST_TEST((crypto::verify<sodium>(crypto::eddsa, zero_signature, message, *public_key,
                                           ed25519::strict)
                        .error() == crypto::error::invalid_signature));
    });
    covered("ed25519::public_key::verify on sodium", [&] {
        BOOST_TEST(public_key->verify(crypto::eddsa, *signature, message).has_value());
    });
    covered("ed25519::public_key::verify with a zero signature on sodium", [&] {
        BOOST_TEST(public_key->verify(crypto::eddsa, zero_signature, message).error() ==
                   crypto::error::invalid_signature);
    });
    covered("ed25519::public_key::to_x25519 on sodium",
            [&] { BOOST_TEST(public_key->to_x25519<sodium>().has_value()); });
    covered("ed25519 crypto::to_x25519 of a public key on sodium", "crypto::to_x25519",
            [&] { BOOST_TEST(crypto::to_x25519(*public_key).has_value()); });
    // The identity's encoding, 01 then zeros, a point of small order.
    std::array<std::uint8_t, 32> identity{};
    identity[0] = 0x01;
    auto const small_order = ed25519::public_key::from_bytes(identity);
    if (!BOOST_TEST(small_order.has_value())) {
        return;
    }
    covered("ed25519::public_key::to_x25519 with a key of small order on sodium", [&] {
        BOOST_TEST(small_order->to_x25519<sodium>().error() == crypto::error::invalid_public_key);
    });
    covered("ed25519 crypto::to_x25519 of a public key of small order on sodium",
            "crypto::to_x25519", [&] {
                BOOST_TEST(crypto::to_x25519(*small_order).error() ==
                           crypto::error::invalid_public_key);
            });
}

/**
 * Ed25519ph under the scheme `eddsa_prehashed`: the key pair's `sign` and the free `crypto::sign`,
 * the key's `verify` and the free `crypto::verify` (each entering its own overload's guard first),
 * a moved-from key pair and a zero signature refused, and their asynchronous forms, member and
 * free.
 */
void cover_ed25519_prehashed() {
    namespace ed25519 = crypto::curves::ed25519;
    using keypair = ed25519::basic_keypair<sodium>;
    auto made = keypair::from_secret(webcpp::test::coverage_key<32>());
    std::array<std::uint8_t, 64> digest{};
    digest.fill(0x5a);
    crypto::prehashed const marker{digest};
    if (!BOOST_TEST(made.has_value())) {
        return;
    }
    auto const public_key = made->public_key();
    auto const signature = made->sign(crypto::eddsa_prehashed, marker);
    if (!BOOST_TEST(public_key.has_value()) || !BOOST_TEST(signature.has_value())) {
        return;
    }
    ed25519::signature const zero_signature{};
    covered("ed25519::basic_keypair::sign under eddsa_prehashed on sodium",
            [&] { BOOST_TEST(made->sign(crypto::eddsa_prehashed, marker).has_value()); });
    covered("ed25519 crypto::sign under eddsa_prehashed on sodium", "crypto::sign",
            [&] { BOOST_TEST(crypto::sign(*made, crypto::eddsa_prehashed, marker).has_value()); });
    covered("ed25519 crypto::verify under eddsa_prehashed on sodium",
            "crypto::verify(eddsa_prehashed_t", [&] {
                BOOST_TEST(crypto::verify<sodium>(crypto::eddsa_prehashed, *signature, marker,
                                                  *public_key, ed25519::strict)
                               .has_value());
            });
    covered(
        "ed25519 crypto::verify under eddsa_prehashed with a zero signature on sodium",
        "crypto::verify(eddsa_prehashed_t", [&] {
            BOOST_TEST(crypto::verify(crypto::eddsa_prehashed, zero_signature, marker, *public_key)
                           .error() == crypto::error::invalid_signature);
        });
    covered(
        "ed25519::public_key::verify under eddsa_prehashed on sodium",
        "ed25519::public_key::verify(eddsa_prehashed_t", [&] {
            BOOST_TEST(public_key->verify(crypto::eddsa_prehashed, *signature, marker).has_value());
        });
    covered("ed25519::public_key::verify under eddsa_prehashed with a zero signature on sodium",
            "ed25519::public_key::verify(eddsa_prehashed_t", [&] {
                BOOST_TEST(
                    public_key->verify(crypto::eddsa_prehashed, zero_signature, marker).error() ==
                    crypto::error::invalid_signature);
            });

    webcpp::asio::io_context context;
    auto const executor = context.get_executor();
    int completions = 0;
    webcpp::test::async_completion_counter<ed25519::signature> const counted{
        .completions = &completions,
    };
    auto const deliver = [&context] {
        context.restart();
        context.run();  // lint-run: the test's event loop
    };
    covered("ed25519::basic_keypair::async_sign under eddsa_prehashed on sodium", [&] {
        made->async_sign(executor, crypto::eddsa_prehashed, marker, counted);
        deliver();
    });
    covered("ed25519 crypto::async_sign under eddsa_prehashed on sodium", "crypto::async_sign",
            [&] {
                crypto::async_sign(executor, *made, crypto::eddsa_prehashed, marker, counted);
                deliver();
            });
    covered("ed25519::public_key::async_verify under eddsa_prehashed on sodium", [&] {
        public_key->async_verify<sodium>(executor, crypto::eddsa_prehashed, *signature, marker,
                                         counted);
        deliver();
    });
    covered("ed25519::public_key::async_verify under eddsa_prehashed with its policy on sodium",
            [&] {
                public_key->async_verify<sodium>(executor, crypto::eddsa_prehashed, *signature,
                                                 marker, ed25519::strict, counted);
                deliver();
            });
    covered("ed25519 crypto::async_verify under eddsa_prehashed on sodium",
            "crypto::async_verify(eddsa_prehashed_t", [&] {
                crypto::async_verify<sodium>(executor, crypto::eddsa_prehashed, *signature, marker,
                                             *public_key, counted);
                deliver();
            });
    covered("ed25519 crypto::async_verify under eddsa_prehashed with its policy on sodium",
            "crypto::async_verify(eddsa_prehashed_t", [&] {
                crypto::async_verify<sodium>(executor, crypto::eddsa_prehashed, zero_signature,
                                             marker, *public_key, ed25519::strict, counted);
                deliver();
            });
    BOOST_TEST_EQ(completions, 6);

    [[maybe_unused]] keypair const taken(std::move(*made));
    covered("ed25519::basic_keypair::sign under eddsa_prehashed moved from on sodium", [&] {
        // NOLINTNEXTLINE(bugprone-use-after-move): the moved-from key pair's refusal
        BOOST_TEST(made->sign(crypto::eddsa_prehashed, marker).error() ==
                   crypto::error::invalid_state);
    });
}

/** Ed25519ph's `begin`, `update`, `sign` and `verify` of a message, a valid one. */
void cover_ed25519ph() {
    namespace ed25519 = crypto::curves::ed25519;
    using signer_type = ed25519::prehashed_signer<webcpp::hash::sha2_512, sodium>;
    auto const key = ed25519::basic_keypair<sodium>::from_secret(webcpp::test::coverage_key<32>());
    std::array<std::uint8_t, 3> const piece{1, 2, 3};
    covered("ed25519::prehashed_signer::begin on sodium",
            [] { BOOST_TEST(signer_type::begin().has_value()); });
    auto signer = signer_type::begin();
    auto verifier = signer_type::begin();
    if (!BOOST_TEST(key.has_value()) || !BOOST_TEST(signer.has_value()) ||
        !BOOST_TEST(verifier.has_value()) || !BOOST_TEST(verifier->update(piece).has_value())) {
        return;
    }
    auto const public_key = key->public_key();
    if (!BOOST_TEST(public_key.has_value())) {
        return;
    }
    covered("ed25519::prehashed_signer::update on sodium",
            [&] { BOOST_TEST(signer->update(piece).has_value()); });
    ed25519::signature signature{};
    covered("ed25519::prehashed_signer::sign on sodium", [&] {
        auto const signed_message = signer->sign(*key);
        if (BOOST_TEST(signed_message.has_value())) {
            signature = *signed_message;
        }
    });
    covered("ed25519::prehashed_signer::verify on sodium",
            [&] { BOOST_TEST(verifier->verify(signature, *public_key).has_value()); });
}

/**
 * Ed25519ph's `update`, `sign` and `verify` of an ended message, refused before the backend, and
 * `verify` of a signature that does not verify, refused by the backend.
 */
void cover_ed25519ph_refusals() {
    namespace ed25519 = crypto::curves::ed25519;
    using signer_type = ed25519::prehashed_signer<webcpp::hash::sha2_512, sodium>;
    auto const key = ed25519::basic_keypair<sodium>::from_secret(webcpp::test::coverage_key<32>());
    ed25519::signature const signature{};
    std::array<std::uint8_t, 3> const piece{1, 2, 3};
    auto ended = signer_type::begin();
    auto refused = signer_type::begin();
    if (!BOOST_TEST(key.has_value()) || !BOOST_TEST(ended.has_value()) ||
        !BOOST_TEST(refused.has_value()) || !BOOST_TEST(ended->sign(*key).has_value())) {
        return;
    }
    auto const public_key = key->public_key();
    if (!BOOST_TEST(public_key.has_value())) {
        return;
    }
    covered("ed25519::prehashed_signer::update of an ended message on sodium",
            [&] { BOOST_TEST(ended->update(piece).error() == crypto::error::invalid_state); });
    covered("ed25519::prehashed_signer::sign of an ended message on sodium",
            [&] { BOOST_TEST(ended->sign(*key).error() == crypto::error::invalid_state); });
    covered("ed25519::prehashed_signer::verify of an ended message on sodium", [&] {
        BOOST_TEST(ended->verify(signature, *public_key).error() == crypto::error::invalid_state);
    });
    covered("ed25519::prehashed_signer::verify with a zero signature on sodium", [&] {
        BOOST_TEST(refused->verify(signature, *public_key).error() ==
                   crypto::error::invalid_signature);
    });
}

/** Ed25519's `decode_spki` and `decode_pkcs8`, an encoding of the wrong size of each included. */
void cover_ed25519_formats() {
    namespace ed25519 = crypto::curves::ed25519;
    auto const key = ed25519::basic_keypair<sodium>::from_secret(webcpp::test::coverage_key<32>());
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
 * X25519's key pair: `from_secret`, a secret key of the wrong size included, `generate` (the
 * system's entropy) and `agree`, each entering its own guard; and `public_key` and `secret`, which
 * copy, and the public key's `from_bytes` and `bytes`, which enter none.
 */
void cover_x25519() {
    namespace x25519 = crypto::curves::x25519;
    using keypair = x25519::basic_keypair<sodium>;
    auto const alice = make_keypair(0x41);
    auto const bob = make_keypair(0x42);
    auto const short_key = std::span(alice.secret_key).first(31);
    covered("x25519::basic_keypair::from_secret on sodium",
            [&] { BOOST_TEST(keypair::from_secret(alice.secret_key).has_value()); });
    covered("x25519::basic_keypair::from_secret with a short key on sodium", [&] {
        BOOST_TEST(keypair::from_secret(short_key).error() == crypto::error::invalid_key_size);
    });
    covered("x25519::basic_keypair::generate on sodium",
            [] { BOOST_TEST(keypair::generate().has_value()); });
    auto made = keypair::from_secret(alice.secret_key);
    auto const peer = x25519::public_key::from_bytes(bob.public_key);
    if (!BOOST_TEST(made.has_value()) || !BOOST_TEST(peer.has_value())) {
        return;
    }
    covered("x25519::basic_keypair::agree on sodium",
            [&] { BOOST_TEST(made->agree(*peer).has_value()); });
    webcpp::test::uncovered("x25519::basic_keypair::public_key on sodium",
                            [&] { BOOST_TEST(made->public_key().has_value()); });
    webcpp::test::uncovered("x25519::basic_keypair::secret on sodium",
                            [&] { BOOST_TEST(made->secret().has_value()); });
    webcpp::test::uncovered("x25519::public_key::from_bytes on sodium", [&] {
        BOOST_TEST(x25519::public_key::from_bytes(bob.public_key).has_value());
    });
    webcpp::test::uncovered("x25519::public_key::from_bytes of a short key on sodium", [&] {
        BOOST_TEST(x25519::public_key::from_bytes(short_key).error() ==
                   crypto::error::invalid_public_key);
    });
    webcpp::test::uncovered("x25519::public_key::bytes on sodium",
                            [&] { BOOST_TEST(peer->bytes() == bob.public_key); });
}

/**
 * X25519's moved-from key pair: `agree` enters its guard and refuses; `public_key` and `secret`
 * refuse with none.
 */
void cover_x25519_moved_from() {
    namespace x25519 = crypto::curves::x25519;
    using keypair = x25519::basic_keypair<sodium>;
    auto const alice = make_keypair(0x41);
    auto const bob = make_keypair(0x42);
    auto made = keypair::from_secret(alice.secret_key);
    auto const peer = x25519::public_key::from_bytes(bob.public_key);
    if (!BOOST_TEST(made.has_value()) || !BOOST_TEST(peer.has_value())) {
        return;
    }
    [[maybe_unused]] keypair const taken(std::move(*made));
    covered("x25519::basic_keypair::agree moved from on sodium", [&] {
        // NOLINTNEXTLINE(bugprone-use-after-move): the moved-from key pair's refusal
        BOOST_TEST(made->agree(*peer).error() == crypto::error::invalid_state);
    });
    webcpp::test::uncovered("x25519::basic_keypair::public_key moved from on sodium", [&] {
        // NOLINTNEXTLINE(bugprone-use-after-move): the moved-from key pair's refusal
        BOOST_TEST(made->public_key().error() == crypto::error::invalid_state);
    });
    webcpp::test::uncovered("x25519::basic_keypair::secret moved from on sodium", [&] {
        // NOLINTNEXTLINE(bugprone-use-after-move): the moved-from key pair's refusal
        BOOST_TEST(made->secret().error() == crypto::error::invalid_state);
    });
}

/**
 * X25519's free synchronous forms, crypto::from_secret, crypto::generate and crypto::agree, each
 * entering its own guard before the member's, a short secret key included; crypto::from_bytes of a
 * public key enters none, as its member does not.
 */
void cover_x25519_free_forms() {
    namespace x25519 = crypto::curves::x25519;
    using keypair = x25519::basic_keypair<sodium>;
    auto const alice = make_keypair(0x41);
    auto const bob = make_keypair(0x42);
    covered("x25519 crypto::from_secret on sodium", "crypto::from_secret",
            [&] { BOOST_TEST(crypto::from_secret<keypair>(alice.secret_key).has_value()); });
    covered("x25519 crypto::from_secret with a short key on sodium", "crypto::from_secret", [&] {
        BOOST_TEST(crypto::from_secret<keypair>(std::span(alice.secret_key).first(31)).error() ==
                   crypto::error::invalid_key_size);
    });
    covered("x25519 crypto::generate on sodium", "crypto::generate",
            [] { BOOST_TEST(crypto::generate<keypair>().has_value()); });
    webcpp::test::uncovered("x25519 crypto::from_bytes of a public key on sodium", [&] {
        BOOST_TEST(crypto::from_bytes<x25519::public_key>(bob.public_key).has_value());
    });
    auto const made = keypair::from_secret(alice.secret_key);
    auto const peer = x25519::public_key::from_bytes(bob.public_key);
    if (!BOOST_TEST(made.has_value()) || !BOOST_TEST(peer.has_value())) {
        return;
    }
    covered("x25519 crypto::agree on sodium", "crypto::agree",
            [&] { BOOST_TEST(crypto::agree(*made, *peer).has_value()); });
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
 * crypto_kx's session keys: `client_session_keys` and `server_session_keys`, of a moved-from key
 * pair too. `keypair` and `public_key` call no backend and enter none.
 */
void cover_kx_sessions() {
    using kx_keypair = crypto::key_exchange::kx_keypair<sodium>;
    auto client = kx_keypair::derive_from_seed(webcpp::test::coverage_key<kx_keypair::seed_size>());
    auto const server = kx_keypair::generate();
    if (!BOOST_TEST(client.has_value()) || !BOOST_TEST(server.has_value())) {
        return;
    }
    webcpp::test::uncovered("key_exchange::kx_keypair::keypair on sodium",
                            [&] { BOOST_TEST(client->keypair().public_key().has_value()); });
    webcpp::test::uncovered("key_exchange::kx_keypair::public_key on sodium",
                            [&] { BOOST_TEST(client->public_key().has_value()); });
    auto const client_public = client->public_key();
    auto const server_public = server->public_key();
    if (!BOOST_TEST(client_public.has_value()) || !BOOST_TEST(server_public.has_value())) {
        return;
    }
    covered("key_exchange::kx_keypair::client_session_keys on sodium",
            [&] { BOOST_TEST(client->client_session_keys(*server_public).has_value()); });
    covered("key_exchange::kx_keypair::server_session_keys on sodium",
            [&] { BOOST_TEST(server->server_session_keys(*client_public).has_value()); });
    auto const moved = std::move(*client);
    // NOLINTBEGIN(bugprone-use-after-move,clang-analyzer-cplusplus.Move): the refusals
    covered("key_exchange::kx_keypair::client_session_keys of a moved-from key pair on sodium",
            [&] {
                BOOST_TEST(client->client_session_keys(*server_public).error() ==
                           crypto::error::invalid_state);
            });
    covered("key_exchange::kx_keypair::server_session_keys of a moved-from key pair on sodium",
            [&] {
                BOOST_TEST(client->server_session_keys(*server_public).error() ==
                           crypto::error::invalid_state);
            });
    // NOLINTEND(bugprone-use-after-move,clang-analyzer-cplusplus.Move)
}

/**
 * crypto_kx's key pair: `from_keypair`, a moved-from X25519 key pair included,
 * `derive_from_seed`, a seed of the wrong size included, and `generate` (the system's entropy);
 * then its session keys.
 */
void cover_kx() {
    using kx_keypair = crypto::key_exchange::kx_keypair<sodium>;
    auto const seed = webcpp::test::coverage_key<kx_keypair::seed_size>();
    auto fresh = typed_keypair(0x43);
    covered("key_exchange::kx_keypair::from_keypair on sodium",
            [&] { BOOST_TEST(kx_keypair::from_keypair(std::move(fresh)).has_value()); });
    auto inner = typed_keypair(0x44);
    auto const kept = std::move(inner);
    // NOLINTBEGIN(bugprone-use-after-move,clang-analyzer-cplusplus.Move): the refusal
    covered("key_exchange::kx_keypair::from_keypair of a moved-from key pair on sodium", [&] {
        BOOST_TEST(kx_keypair::from_keypair(std::move(inner)).error() ==
                   crypto::error::invalid_state);
    });
    // NOLINTEND(bugprone-use-after-move,clang-analyzer-cplusplus.Move)
    covered("key_exchange::kx_keypair::derive_from_seed on sodium",
            [&] { BOOST_TEST(kx_keypair::derive_from_seed(seed).has_value()); });
    covered("key_exchange::kx_keypair::derive_from_seed with a short seed on sodium", [&] {
        BOOST_TEST(kx_keypair::derive_from_seed(std::span(seed).first(31)).error() ==
                   crypto::error::invalid_key_size);
    });
    covered("key_exchange::kx_keypair::generate on sodium",
            [] { BOOST_TEST(kx_keypair::generate().has_value()); });
    cover_kx_sessions();
}

/** Ed25519, Ed25519ph, X25519, crypto_kx, and the decoders of the key formats. */
void cover_curves() {
    cover_ed25519_keypair();
    webcpp::test::cover_async_ed25519<crypto::curves::ed25519::basic_keypair<sodium>>("sodium");
    webcpp::test::cover_async_x25519<crypto::curves::x25519::basic_keypair<sodium>>("sodium");
    cover_ed25519_free();
    cover_ed25519_free_forms();
    webcpp::test::cover_signature<crypto::curves::ed25519::signature>("ed25519::signature",
                                                                      "sodium");
    cover_ed25519_prehashed();
    cover_ed25519ph();
    cover_ed25519ph_refusals();
    cover_ed25519_formats();
    cover_x25519();
    cover_x25519_moved_from();
    cover_x25519_free_forms();
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
