// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// On libsodium nothing allocates: make, seal and open of the three ChaCha20-Poly1305 AEADs and
// of the two secret boxes, a failed open included; Ed25519's key pair, signature, strict
// verification, Ed25519ph and the conversion to X25519; X25519's public key and agreement, a
// refused one included; crypto_kx's key pairs and session keys, a refused peer included; RFC
// 8410's SPKI and PKCS#8 of both curves and their PEM, both ways; the two boxes' make, seal and
// open, a refused peer key and a failed open included; and the sealed boxes' seal and open, a
// failed open included, make no call of operator new, nor of the C library's allocator where the
// target lets a program count it; a control proves the counter moves. Each later family on
// libsodium adds its calls here.

#include <webcpp/crypto/backends/sodium.hpp>
#include <webcpp/crypto/ciphers/chacha20_poly1305.hpp>
#include <webcpp/crypto/ciphers/secretbox.hpp>
#include <webcpp/crypto/curves/ed25519.hpp>
#include <webcpp/crypto/curves/ed25519/formats.hpp>
#include <webcpp/crypto/curves/x25519.hpp>
#include <webcpp/crypto/curves/x25519/formats.hpp>
#include <webcpp/crypto/curves/x25519/kx.hpp>
#include <webcpp/crypto/hybrid/box.hpp>
#include <webcpp/crypto/hybrid/sealed_box.hpp>
#include <webcpp/crypto/pem.hpp>
#include <webcpp/crypto/signing.hpp>
#include <webcpp/hash/algorithms.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/counting.hpp"

#include <boost/core/lightweight_test.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <span>
#include <string_view>
#include <utility>

namespace {

namespace crypto = webcpp::crypto;

/**
 * Makes an AEAD, seals, opens, and opens a forged message: none of it allocates. A family
 * without additional data (a secret box) is given none.
 */
template <class Aead>
void expect_no_allocation() {
    std::array<std::uint8_t, Aead::key_size> key{};
    key.fill(3);
    std::array<std::uint8_t, Aead::iv_size> const iv{};
    std::array<std::uint8_t, 13> const some_additional_data{};
    auto const additional_data = std::span<std::uint8_t const>(some_additional_data)
                                     .first(Aead::max_additional_data_size == 0 ? 0 : 13);
    std::array<std::uint8_t, 4096> data{};
    std::size_t const before = webcpp::test::allocations();
    {
        auto made = Aead::make(key);
        BOOST_TEST(made.has_value());
        auto const tag = made->seal(iv, additional_data, data);
        BOOST_TEST(tag.has_value());
        BOOST_TEST(made->open(iv, additional_data, data, *tag).has_value());
        std::array<std::uint8_t, Aead::tag_size> const forged{};
        BOOST_TEST(made->open(iv, additional_data, data, forged).error() ==
                   crypto::error::authentication_failed);
        Aead const moved = std::move(*made);
    }
    BOOST_TEST_EQ(webcpp::test::allocations(), before);
}

/**
 * Makes and draws Ed25519 key pairs, signs, verifies strictly, refuses a forged signature,
 * signs and verifies with Ed25519ph in two pieces, and converts both keys to X25519: none of
 * it allocates.
 */
void expect_no_allocation_ed25519() {
    using keypair = crypto::curves::ed25519::basic_keypair<crypto::backends::sodium>;
    using ph = crypto::curves::ed25519::ph<webcpp::hash::sha2_512, crypto::backends::sodium>;
    // Strict verification on libsodium, named once: a call's commas would split a macro's
    // argument.
    auto const verify = [](auto const& signature, auto const& message, auto const& public_key) {
        return crypto::verify<crypto::backends::sodium>(
            crypto::eddsa, signature, message, public_key, crypto::curves::ed25519::strict);
    };
    std::array<std::uint8_t, 32> seed{};
    seed.fill(5);
    std::array<std::uint8_t, 100> const message{};
    std::size_t const before = webcpp::test::allocations();
    {
        auto made = keypair::make(seed);
        BOOST_TEST(made.has_value());
        auto const drawn = keypair::generate();
        BOOST_TEST(drawn.has_value());
        auto const public_key = made->public_key();
        BOOST_TEST(public_key.has_value());
        auto const signature = made->sign(crypto::eddsa, message);
        BOOST_TEST(signature.has_value());
        auto const verified = verify(*signature, message, *public_key);
        BOOST_TEST(verified.has_value());
        std::array<std::uint8_t, 64> const forged{};
        BOOST_TEST(verify(forged, message, *public_key).error() ==
                   crypto::error::invalid_signature);
        auto signer = ph::begin();
        BOOST_TEST(signer.has_value());
        BOOST_TEST(signer->update(std::span(message).first(40)).has_value());
        BOOST_TEST(signer->update(std::span(message).subspan(40)).has_value());
        auto const ph_signature = signer->sign(*made);
        BOOST_TEST(ph_signature.has_value());
        auto verifier = ph::begin();
        BOOST_TEST(verifier.has_value());
        BOOST_TEST(verifier->update(message).has_value());
        BOOST_TEST(verifier->verify(*ph_signature, public_key->bytes()).has_value());
        auto const x25519_secret = made->x25519_secret();
        BOOST_TEST(x25519_secret.has_value());
        auto const exported = made->secret();
        BOOST_TEST(exported.has_value());
        BOOST_TEST(
            crypto::curves::ed25519::to_x25519_public<crypto::backends::sodium>(public_key->bytes())
                .has_value());
        keypair const moved = std::move(*made);
    }
    BOOST_TEST_EQ(webcpp::test::allocations(), before);
}

/**
 * Computes two X25519 public keys, agrees both ways, and refuses a peer key of low order (the
 * all-zero point): none of it allocates.
 */
void expect_no_allocation_x25519() {
    using x25519 = crypto::curves::x25519::algorithm<crypto::backends::sodium>;
    std::array<std::uint8_t, x25519::key_size> alice{};
    alice.fill(7);
    std::array<std::uint8_t, x25519::key_size> bob{};
    bob.fill(9);
    std::array<std::uint8_t, x25519::key_size> const low_order{};
    std::size_t const before = webcpp::test::allocations();
    {
        auto const alice_public = x25519::public_key(alice);
        BOOST_TEST(alice_public.has_value());
        auto const bob_public = x25519::public_key(bob);
        BOOST_TEST(bob_public.has_value());
        auto const alice_shared = x25519::agree(alice, *bob_public);
        BOOST_TEST(alice_shared.has_value());
        auto const bob_shared = x25519::agree(bob, *alice_public);
        BOOST_TEST(bob_shared.has_value());
        BOOST_TEST(x25519::agree(alice, low_order).error() == crypto::error::weak_public_key);
    }
    BOOST_TEST_EQ(webcpp::test::allocations(), before);
}

/**
 * Makes a box of each family from two key pairs, both ways, seals, opens, opens a forged
 * message, and refuses a peer key of small order (the all-zero point): none of it allocates.
 */
template <class Box>
void expect_no_allocation_box() {
    std::array<std::uint8_t, 32> alice{};
    alice.fill(7);
    std::array<std::uint8_t, 32> bob{};
    bob.fill(9);
    std::array<std::uint8_t, 32> const low_order{};
    std::array<std::uint8_t, Box::iv_size> const iv{};
    std::array<std::uint8_t, 4096> data{};
    auto const alice_public = crypto::curves::x25519::public_key<crypto::backends::sodium>(alice);
    auto const bob_public = crypto::curves::x25519::public_key<crypto::backends::sodium>(bob);
    if (!BOOST_TEST(alice_public.has_value()) || !BOOST_TEST(bob_public.has_value())) {
        return;
    }
    std::size_t const before = webcpp::test::allocations();
    {
        auto sender = Box::make(alice, *bob_public);
        auto receiver = Box::make(bob, *alice_public);
        BOOST_TEST(sender.has_value() && receiver.has_value());
        auto const tag = sender->seal(iv, data);
        BOOST_TEST(tag.has_value());
        BOOST_TEST(receiver->open(iv, data, *tag).has_value());
        std::array<std::uint8_t, Box::tag_size> const forged{};
        BOOST_TEST(receiver->open(iv, data, forged).error() ==
                   crypto::error::authentication_failed);
        BOOST_TEST(Box::make(alice, low_order).error() == crypto::error::weak_public_key);
        Box const moved = std::move(*sender);
    }
    BOOST_TEST_EQ(webcpp::test::allocations(), before);
}

/**
 * Seals a message to a public key, which draws a key pair from libsodium's generator, opens it,
 * and opens a changed one: none of it allocates.
 */
void expect_no_allocation_sealed_box() {
    using sealed_box = crypto::hybrid::basic_sealed_box<crypto::backends::sodium>;
    std::array<std::uint8_t, 32> bob{};
    bob.fill(11);
    auto const bob_public = crypto::curves::x25519::public_key<crypto::backends::sodium>(bob);
    if (!BOOST_TEST(bob_public.has_value())) {
        return;
    }
    std::array<std::uint8_t, 1000> const message{};
    std::array<std::uint8_t, message.size() + sealed_box::overhead> sealed{};
    std::array<std::uint8_t, message.size()> opened{};
    std::size_t const before = webcpp::test::allocations();
    {
        BOOST_TEST(sealed_box::seal(*bob_public, message, sealed).has_value());
        BOOST_TEST(sealed_box::open(*bob_public, bob, sealed, opened).has_value());
        sealed[40] ^= 1U;
        BOOST_TEST(sealed_box::open(*bob_public, bob, sealed, opened).error() ==
                   crypto::error::authentication_failed);
    }
    BOOST_TEST_EQ(webcpp::test::allocations(), before);
}

/**
 * Encodes and decodes an Ed25519 key pair's and an X25519 key's SPKI and PKCS#8, armours each as
 * PEM and reads it back, and refuses a PKCS#8 of the other curve: none of it allocates.
 */
void expect_no_allocation_formats() {
    namespace ed25519 = crypto::curves::ed25519;
    namespace x25519 = crypto::curves::x25519;
    namespace pem = crypto::pem;
    std::array<std::uint8_t, 32> key{};
    key.fill(11);
    std::size_t const before = webcpp::test::allocations();
    {
        auto const pair = ed25519::basic_keypair<crypto::backends::sodium>::make(key);
        BOOST_TEST(pair.has_value());
        std::array<std::uint8_t, ed25519::max_pkcs8_size> pkcs8{};
        BOOST_TEST(ed25519::encode_pkcs8(*pair, pkcs8).has_value());
        BOOST_TEST(ed25519::decode_pkcs8<crypto::backends::sodium>(pkcs8).has_value());
        std::array<std::uint8_t, ed25519::max_spki_size> spki{};
        auto const public_key = pair->public_key();
        BOOST_TEST(public_key.has_value());
        BOOST_TEST(ed25519::encode_spki<crypto::backends::sodium>(*public_key, spki).has_value());
        BOOST_TEST(ed25519::decode_spki<crypto::backends::sodium>(spki).has_value());
        BOOST_TEST(x25519::encode_pkcs8<crypto::backends::sodium>(key, pkcs8).has_value());
        BOOST_TEST(x25519::decode_pkcs8<crypto::backends::sodium>(pkcs8).has_value());
        BOOST_TEST(ed25519::decode_pkcs8<crypto::backends::sodium>(pkcs8).error() ==
                   crypto::error::invalid_encoding);
        BOOST_TEST(x25519::encode_spki<crypto::backends::sodium>(key, spki).has_value());
        BOOST_TEST(x25519::decode_spki<crypto::backends::sodium>(spki).has_value());
        std::array<char, pem::armoured_size(11, ed25519::max_pkcs8_size)> text{};
        auto const written =
            pem::armour<crypto::backends::sodium>(pem::private_key_label, pkcs8, text);
        BOOST_TEST(written.has_value());
        std::array<std::uint8_t, ed25519::max_pkcs8_size> again{};
        BOOST_TEST(pem::unarmour<crypto::backends::sodium>(
                       pem::private_key_label, std::string_view(text.data(), text.size()), again)
                       .has_value());
    }
    BOOST_TEST_EQ(webcpp::test::allocations(), before);
}

/**
 * Makes and draws crypto_kx key pairs, computes the client's and the server's session keys, and
 * refuses a peer key of low order (the all-zero point): none of it allocates.
 */
void expect_no_allocation_kx() {
    using kx_keypair = crypto::curves::x25519::kx_keypair<crypto::backends::sodium>;
    std::array<std::uint8_t, kx_keypair::seed_size> client_seed{};
    client_seed.fill(11);
    std::array<std::uint8_t, kx_keypair::seed_size> server_seed{};
    server_seed.fill(13);
    std::array<std::uint8_t, kx_keypair::public_key_size> const low_order{};
    std::size_t const before = webcpp::test::allocations();
    {
        auto client = kx_keypair::make(client_seed);
        BOOST_TEST(client.has_value());
        auto const server = kx_keypair::make(server_seed);
        BOOST_TEST(server.has_value());
        auto const drawn = kx_keypair::generate();
        BOOST_TEST(drawn.has_value());
        auto const client_public = client->public_key();
        BOOST_TEST(client_public.has_value());
        auto const server_public = server->public_key();
        BOOST_TEST(server_public.has_value());
        auto const client_keys = client->client_session_keys(*server_public);
        BOOST_TEST(client_keys.has_value());
        auto const server_keys = server->server_session_keys(*client_public);
        BOOST_TEST(server_keys.has_value());
        BOOST_TEST(client->client_session_keys(low_order).error() ==
                   crypto::error::weak_public_key);
        kx_keypair const moved = std::move(*client);
    }
    BOOST_TEST_EQ(webcpp::test::allocations(), before);
}

}  // namespace

int main() {
    // The control: a malloc of the C library's moves the counter where it is counted.
    std::size_t const control = webcpp::test::allocations();
    void* volatile block = std::malloc(40);
    std::free(block);
    // A constant condition: `if constexpr`, which MSVC's C4127 (an error under /W4 /WX) leaves be.
    if constexpr (webcpp::test::c_allocations_counted) {
        BOOST_TEST_EQ(webcpp::test::allocations() - control, 1U);
    } else {
        BOOST_TEST_EQ(webcpp::test::allocations() - control, 0U);
        std::printf("the C library's allocations are not counted on this target\n");
    }
    // libsodium's initialisation, the first make's, is counted too.
    expect_no_allocation<crypto::ciphers::chacha20_poly1305<crypto::backends::sodium>>();
    expect_no_allocation<crypto::ciphers::chacha20_poly1305_original<crypto::backends::sodium>>();
    expect_no_allocation<crypto::ciphers::xchacha20_poly1305<crypto::backends::sodium>>();
    expect_no_allocation_ed25519();
    expect_no_allocation_x25519();
    expect_no_allocation<crypto::ciphers::secretbox<crypto::backends::sodium>>();
    expect_no_allocation<crypto::ciphers::secretbox_xchacha20poly1305<crypto::backends::sodium>>();
    expect_no_allocation_box<crypto::hybrid::basic_box<crypto::families::box_xsalsa20poly1305,
                                                       crypto::backends::sodium>>();
    expect_no_allocation_box<crypto::hybrid::basic_box<crypto::families::box_xchacha20poly1305,
                                                       crypto::backends::sodium>>();
    expect_no_allocation_sealed_box();
    expect_no_allocation_formats();
    expect_no_allocation_kx();
    return webcpp::test::exit_status(boost::report_errors());
}
