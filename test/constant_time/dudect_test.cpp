// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// dudect's statistics (spec section 8.3): BearSSL's AES-GCM and ChaCha20-Poly1305 seal's time
// against its key, open's against its tag (the failure's zeroing included), ctaes's block
// encryption's against its key, equal's against its second argument, and P-256's ECDSA signing
// and ECDH's x against the key pair's scalar (one fixed scalar, against random ones; the digest
// and the peer's public key fixed), each key pair made before its measurement, unmeasured;
// natively and under wasmtime, where the engine's compiler decides whether BearSSL's 64-bit
// multiplication stays constant time.

#include "dudect.hpp"

#include <webcpp/crypto/backends/bearssl.hpp>
#include <webcpp/crypto/backends/ctaes.hpp>
#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/crypto/ciphers/chacha20_poly1305.hpp>
#include <webcpp/crypto/ciphers/gcm.hpp>
#include <webcpp/crypto/curves/p256.hpp>
#include <webcpp/crypto/equal.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <utility>

namespace {

constexpr std::size_t count = 2'000'000;

/** The |t| of an AEAD's seal and of its open. */
struct seal_and_open {
    /** The seal's, against its key. */
    double seal = 0;
    /** The open's, against its tag. */
    double open = 0;
};

/**
 * Times an AEAD's seal, whose two classes differ only in the key (all zero, against random keys),
 * and its open, whose two classes both fail (the right tag with its last byte flipped, against
 * random wrong tags), the classic probe of an early exit; a success and a failure differ by
 * design (the failure zeroes data and returns another way), and that difference is public.
 */
template <class Aead>
seal_and_open measure_aead() {
    std::array<std::uint8_t, 32> const zero_key{};
    std::array<std::uint8_t, 32> key{};
    std::array<std::uint8_t, Aead::iv_size> const iv{};
    std::array<std::uint8_t, 64> data{};
    std::optional<Aead> made;

    seal_and_open t;
    t.seal = webcpp::test::twice(
        count,
        [&](int which, auto& generator) {
            webcpp::test::choose(which, generator, zero_key, key);
            made.emplace(*Aead::make(key));
        },
        [&] { static_cast<void>(made->seal(iv, {}, data)); });

    key.fill(0x42);
    made.emplace(*Aead::make(key));
    std::array<std::uint8_t, 64> const plaintext{};
    std::array<std::uint8_t, 64> ciphertext = plaintext;
    auto const right = *made->seal(iv, {}, ciphertext);
    std::array<std::uint8_t, 16> nearly_right{};
    std::copy(right.data(), right.data() + right.size(), nearly_right.begin());
    nearly_right[15] ^= 1U;
    std::array<std::uint8_t, 16> tag{};
    t.open = webcpp::test::twice(
        count,
        [&](int which, auto& generator) {
            data = ciphertext;
            webcpp::test::choose(which, generator, nearly_right, tag);
            if (std::equal(tag.begin(), tag.end(), right.data())) {
                tag[15] ^= 1U;  // a random tag equal to the right one, which never happens
            }
        },
        [&] { static_cast<void>(made->open(iv, {}, data, tag)); });
    return t;
}

/** The |t| of P-256's two operations on BearSSL. */
struct p256_times {
    /** ECDSA signing's, against the scalar. */
    double sign = 0;
    /** ECDH's x's, against the scalar. */
    double ecdh_x = 0;
};

/**
 * Times P-256's ECDSA signing of a fixed digest and its ECDH's x with a fixed peer, the two
 * classes differing only in the key pair's scalar: a fixed one, against random ones, each key
 * pair made before its measurement, unmeasured.
 */
p256_times measure_p256() {
    using keypair = webcpp::crypto::curves::p256::basic_keypair<webcpp::crypto::backends::bearssl>;
    // Signing takes about 190 microseconds and the ECDH 145 natively (a release build on an Apple
    // M5 Max under load, 2026-11-21); with 100,000 measurements of each, the whole program ran in
    // about three minutes natively and two under wasmtime, well within wasmtime's 600 seconds.
    constexpr std::size_t p256_count = 100'000;
    std::array<std::uint8_t, 32> fixed{};
    fixed.fill(0x42);
    std::array<std::uint8_t, 32> scalar{};
    std::array<std::uint8_t, 32> digest{};
    digest.fill(0x17);
    std::array<std::uint8_t, 32> peer_scalar{};
    peer_scalar.fill(0x24);
    auto const peer = keypair::make(peer_scalar);
    auto const peer_key = peer ? peer->public_key() : peer.error();
    if (!peer_key) {
        std::printf("the peer's key pair was refused\n");
        return {.sign = 1e9, .ecdh_x = 1e9};
    }
    std::optional<keypair> pair;
    auto const prepare = [&](int which, auto& generator) {
        webcpp::test::choose(which, generator, fixed, scalar);
        // A random scalar is 0 or not below n only with probability about 2^-32.
        auto made = keypair::make(scalar);
        if (!made) {
            made = keypair::make(fixed);
        }
        pair.emplace(std::move(*made));
    };
    p256_times t;
    t.sign = webcpp::test::twice(p256_count, prepare,
                                 [&] { static_cast<void>(pair->sign_ecdsa(digest)); });
    t.ecdh_x = webcpp::test::twice(p256_count, prepare,
                                   [&] { static_cast<void>(pair->ecdh_x(*peer_key)); });
    return t;
}

}  // namespace

int main() {
    if (!webcpp::test::report_data_independent_timing()) {
        return 1;
    }
    namespace crypto = webcpp::crypto;
    using block_cipher = crypto::ciphers::aes256<crypto::backends::ctaes>;
    auto const gcm =
        measure_aead<crypto::ciphers::gcm<crypto::ciphers::aes256<crypto::backends::bearssl>>>();
    auto const chacha =
        measure_aead<crypto::ciphers::chacha20_poly1305<crypto::backends::bearssl>>();

    std::array<std::uint8_t, 32> const zero_key{};
    std::array<std::uint8_t, 32> key{};
    std::optional<block_cipher> block_made;
    std::array<std::uint8_t, 16> block{};
    double const block_t = webcpp::test::twice(
        count,
        [&](int which, auto& generator) {
            webcpp::test::choose(which, generator, zero_key, key);
            block_made.emplace(*block_cipher::make(key));
            block.fill(0);
        },
        [&] { static_cast<void>(block_made->encrypt(block)); });

    std::array<std::uint8_t, 16> const a{};
    std::array<std::uint8_t, 16> b{};
    bool volatile sink = false;  // keeps the comparison from being optimised away
    // The classes differ only in the second argument: equal to the first, against random.
    double const equal_t = webcpp::test::twice(
        count, [&](int which, auto& generator) { webcpp::test::choose(which, generator, a, b); },
        [&] { sink = crypto::equal(a, b); });

    auto const p256 = measure_p256();

    std::printf(
        "|t| seal %.2f, open %.2f, chacha seal %.2f, chacha open %.2f, ctaes %.2f, equal %.2f, "
        "p256 sign %.2f, p256 ecdh_x %.2f (threshold 10)\n",
        gcm.seal, gcm.open, chacha.seal, chacha.open, block_t, equal_t, p256.sign, p256.ecdh_x);
    return webcpp::test::verdict(gcm.seal < 10 && gcm.open < 10 && chacha.seal < 10 &&
                                 chacha.open < 10 && block_t < 10 && equal_t < 10 &&
                                 p256.sign < 10 && p256.ecdh_x < 10);
}
