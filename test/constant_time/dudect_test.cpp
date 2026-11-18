// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// dudect's statistics (spec section 8.3): BearSSL's AES-GCM seal's time against its key, open's
// against its tag (the failure's zeroing included), ctaes's block encryption's against its key,
// and equal's against its second argument; natively and under wasmtime, where the engine's
// compiler decides whether BearSSL's 64-bit multiplication stays constant time.

#include "dudect.hpp"

#include <webcpp/crypto/backends/bearssl.hpp>
#include <webcpp/crypto/backends/ctaes.hpp>
#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/crypto/ciphers/gcm.hpp>
#include <webcpp/crypto/equal.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <optional>

namespace {

/**
 * Draws `Size` bytes, then copies into `input` either `fixed`, for class 0, or the drawn bytes,
 * for class 1. Both classes draw the same bytes and store the same way: the source is chosen
 * through a volatile pointer, which the compiler cannot see through, so that it cannot split
 * the copy by class into a store of constants for one and of drawn bytes for the other. Such
 * a split, which an optimiser makes of `which == 0 ? 0 : drawn`, leaks the class into the
 * measured call (measured natively on an Apple M5, 2026-11-18: |t| 16 to 18 on equal and 9 to
 * 26 on open with the split, below 3 for both through this copy).
 * @param which The class, 0 or 1.
 * @param generator The seeded generator.
 * @param fixed The class 0 input.
 * @param input Where the input of the class is copied.
 */
template <std::size_t Size, class Generator>
void choose(int which, Generator& generator, std::array<std::uint8_t, Size> const& fixed,
            std::array<std::uint8_t, Size>& input) {
    std::array<std::uint8_t, Size> drawn{};
    for (auto& byte : drawn) {
        byte = static_cast<std::uint8_t>(generator());
    }
    std::uint8_t const* volatile chosen = which == 0 ? fixed.data() : drawn.data();
    std::uint8_t const* const source = chosen;
    std::copy(source, source + Size, input.begin());
}

}  // namespace

int main() {
    namespace crypto = webcpp::crypto;
    using aead = crypto::ciphers::gcm<crypto::ciphers::aes256<crypto::backends::bearssl>>;
    using block_cipher = crypto::ciphers::aes256<crypto::backends::ctaes>;
    constexpr std::size_t count = 2'000'000;
    std::array<std::uint8_t, 32> const zero_key{};
    std::array<std::uint8_t, 32> key{};
    std::array<std::uint8_t, 12> const iv{};
    std::array<std::uint8_t, 64> data{};
    std::optional<aead> made;

    // The classes differ only in the key: all zero, against random keys.
    double const seal_t = webcpp::test::twice(
        count,
        [&](int which, auto& generator) {
            choose(which, generator, zero_key, key);
            made.emplace(*aead::make(key));
        },
        [&] { static_cast<void>(made->seal(iv, {}, data)); });

    key.fill(0x42);
    made.emplace(*aead::make(key));
    std::array<std::uint8_t, 64> const plaintext{};
    std::array<std::uint8_t, 64> ciphertext = plaintext;
    auto const right = *made->seal(iv, {}, ciphertext);
    // Both classes fail: the right tag with its last byte flipped, against random wrong tags,
    // the classic probe of an early exit; a success and a failure differ by design (the
    // failure zeroes data and returns another way), and that difference is public.
    std::array<std::uint8_t, 16> nearly_right{};
    std::copy(right.data(), right.data() + right.size(), nearly_right.begin());
    nearly_right[15] ^= 1U;
    std::array<std::uint8_t, 16> tag{};
    double const open_t = webcpp::test::twice(
        count,
        [&](int which, auto& generator) {
            data = ciphertext;
            choose(which, generator, nearly_right, tag);
            if (std::equal(tag.begin(), tag.end(), right.data())) {
                tag[15] ^= 1U;  // a random tag equal to the right one, which never happens
            }
        },
        [&] { static_cast<void>(made->open(iv, {}, data, tag)); });

    std::optional<block_cipher> block_made;
    std::array<std::uint8_t, 16> block{};
    double const block_t = webcpp::test::twice(
        count,
        [&](int which, auto& generator) {
            choose(which, generator, zero_key, key);
            block_made.emplace(*block_cipher::make(key));
            block.fill(0);
        },
        [&] { static_cast<void>(block_made->encrypt(block)); });

    std::array<std::uint8_t, 16> const a{};
    std::array<std::uint8_t, 16> b{};
    bool volatile sink = false;  // keeps the comparison from being optimised away
    // The classes differ only in the second argument: equal to the first, against random.
    double const equal_t = webcpp::test::twice(
        count, [&](int which, auto& generator) { choose(which, generator, a, b); },
        [&] { sink = crypto::equal(a, b); });

    std::printf("|t| seal %.2f, open %.2f, ctaes %.2f, equal %.2f (threshold 10)\n", seal_t, open_t,
                block_t, equal_t);
    return seal_t < 10 && open_t < 10 && block_t < 10 && equal_t < 10 ? 0 : 1;
}
