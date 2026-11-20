// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// dudect's statistics (spec section 8.3): BearSSL's AES-GCM and ChaCha20-Poly1305 seal's time
// against its key, open's against its tag (the failure's zeroing included), ctaes's block
// encryption's against its key, and equal's against its second argument; natively and under
// wasmtime, where the engine's compiler decides whether BearSSL's 64-bit multiplication stays
// constant time.

#include "dudect.hpp"

#include <webcpp/crypto/backends/bearssl.hpp>
#include <webcpp/crypto/backends/ctaes.hpp>
#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/crypto/ciphers/chacha20_poly1305.hpp>
#include <webcpp/crypto/ciphers/gcm.hpp>
#include <webcpp/crypto/equal.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <optional>

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

}  // namespace

int main() {
    if (!webcpp::test::enter_data_independent_timing()) {
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

    std::printf(
        "|t| seal %.2f, open %.2f, chacha seal %.2f, chacha open %.2f, ctaes %.2f, equal %.2f "
        "(threshold 10)\n",
        gcm.seal, gcm.open, chacha.seal, chacha.open, block_t, equal_t);
    return webcpp::test::verdict(gcm.seal < 10 && gcm.open < 10 && chacha.seal < 10 &&
                                 chacha.open < 10 && block_t < 10 && equal_t < 10);
}
