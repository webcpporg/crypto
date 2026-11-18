// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// On libsodium nothing allocates: make, seal and open of the three ChaCha20-Poly1305 AEADs,
// a failed open included; Ed25519's key pair, signature, strict verification, Ed25519ph and
// the conversion to X25519; and X25519's public key and agreement, a refused one included,
// make no call of operator new, nor of the C library's allocator where the target lets a
// program count it; a control proves the counter moves. Each later family on libsodium adds
// its calls here.

#include <webcpp/crypto/backends/sodium.hpp>
#include <webcpp/crypto/ciphers/chacha20_poly1305.hpp>
#include <webcpp/crypto/curves/ed25519.hpp>
#include <webcpp/crypto/curves/x25519.hpp>
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
#include <utility>

namespace {

namespace crypto = webcpp::crypto;

/** Makes an AEAD, seals, opens, and opens a forged message: none of it allocates. */
template <class Aead>
void expect_no_allocation() {
    std::array<std::uint8_t, Aead::key_size> key{};
    key.fill(3);
    std::array<std::uint8_t, Aead::iv_size> const iv{};
    std::array<std::uint8_t, 13> const additional_data{};
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
    // Strict verification on libsodium, named once: a template's commas would split a macro's
    // argument.
    auto const verify = [](auto const& public_key, auto const& message, auto const& signature) {
        return crypto::curves::ed25519::verify<crypto::curves::ed25519::strict,
                                               crypto::backends::sodium>(public_key, message,
                                                                         signature);
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
        auto const signature = made->sign(message);
        BOOST_TEST(signature.has_value());
        auto const verified = verify(*public_key, message, *signature);
        BOOST_TEST(verified.has_value());
        std::array<std::uint8_t, 64> const forged{};
        BOOST_TEST(verify(*public_key, message, forged).error() ==
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
        BOOST_TEST(verifier->verify(*public_key, *ph_signature).has_value());
        auto const x25519_secret = made->x25519_secret();
        BOOST_TEST(x25519_secret.has_value());
        BOOST_TEST(crypto::curves::ed25519::to_x25519_public<crypto::backends::sodium>(*public_key)
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
    return webcpp::test::exit_status(boost::report_errors());
}
