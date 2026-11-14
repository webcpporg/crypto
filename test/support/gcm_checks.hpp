// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The checks of gcm on one backend: the GCM specification's 18 cases, every guard and
// its order, tampering with every byte, the zeroing of a failed open, moved-from
// objects, and aliasing spans (spec sections 2.4 and 8.1; Review Focus 2 and 3).
//
// Each check takes the 18 cases it compares with, by default the specification's, which
// a real backend's test keeps; the mock backend passes its own (support/mock_backend.hpp),
// the same inputs with its ciphertexts and tags. The checks that need one known answer use
// case 13 (AES-256, empty) or case 14 (AES-256, one zero block, zero key and IV).

#ifndef WEBCPP_TEST_CRYPTO_SUPPORT_GCM_CHECKS_HPP
#define WEBCPP_TEST_CRYPTO_SUPPORT_GCM_CHECKS_HPP

#include "gcm_spec_vectors.hpp"
#include "hex.hpp"

#include <webcpp/crypto/aes.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/gcm.hpp>

#include <boost/core/lightweight_test.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>
#include <vector>

namespace webcpp::test {

namespace crypto = webcpp::crypto;

/** The cases a check compares with: the specification's, or a mock's. */
using gcm_cases = std::span<gcm_case const>;

/** Whether every byte is zero. */
inline bool all_zero(std::span<std::uint8_t const> bytes) {
    return std::all_of(bytes.begin(), bytes.end(), [](std::uint8_t b) { return b == 0; });
}

/** Runs f with the gcm of the key's size on Backend: 16, 24 or 32 bytes. */
template <class Backend, class F>
void with_gcm(std::span<std::uint8_t const> key, F&& f) {
    switch (key.size()) {
        case 16: f(crypto::gcm<crypto::aes128<Backend>>::make(key)); break;
        case 24: f(crypto::gcm<crypto::aes192<Backend>>::make(key)); break;
        default: f(crypto::gcm<crypto::aes256<Backend>>::make(key)); break;
    }
}

/** Seals and opens each of the 18 cases one shot, and checks ciphertext and tag. */
template <class Backend>
void check_spec_cases(gcm_cases cases = gcm_spec_cases) {
    BOOST_TEST_EQ(cases.size(), gcm_spec_cases.size());
    for (auto const& c : cases) {
        auto const key = from_hex(c.key);
        auto const iv = from_hex(c.iv);
        auto const additional_data = from_hex(c.additional_data);
        auto const plaintext = from_hex(c.plaintext);
        auto const tag = from_hex(c.tag);
        with_gcm<Backend>(key, [&](auto made) {
            if (!BOOST_TEST(made.has_value())) {
                return;
            }
            auto data = plaintext;
            auto const sealed = made->seal(iv, additional_data, data);
            BOOST_TEST(sealed.has_value());
            BOOST_TEST_EQ(to_hex(data), c.ciphertext);
            BOOST_TEST(sealed && to_hex(*sealed) == c.tag);
            BOOST_TEST(made->open(iv, additional_data, data, tag).has_value());
            BOOST_TEST_EQ(to_hex(data), c.plaintext);
        });
    }
}

/** Every guard of spec section 2.4, in its order, each leaving data untouched. */
template <class Backend>
void check_guards() {
    using aead = crypto::gcm<crypto::aes256<Backend>>;
    std::array<std::uint8_t, 31> const short_key{};
    BOOST_TEST(aead::make(short_key).error() == crypto::error::invalid_key_size);
    std::array<std::uint8_t, 16> const key16{};
    BOOST_TEST(aead::make(key16).error() == crypto::error::invalid_key_size);
    BOOST_TEST(aead::make({}).error() == crypto::error::invalid_key_size);

    std::array<std::uint8_t, 32> const key{};
    auto made = aead::make(key);
    if (!BOOST_TEST(made.has_value())) {
        return;
    }
    std::array<std::uint8_t, 20> data{};
    data.fill(0x33);
    auto const untouched = data;
    std::array<std::uint8_t, 129> const long_iv{};
    std::array<std::uint8_t, 16> const tag{};
    std::array<std::uint8_t, 17> const long_tag{};

    BOOST_TEST(made->seal({}, {}, data).error() == crypto::error::invalid_iv_size);
    BOOST_TEST(made->seal(long_iv, {}, data).error() == crypto::error::invalid_iv_size);
    BOOST_TEST(made->open({}, {}, data, tag).error() == crypto::error::invalid_iv_size);
    BOOST_TEST(made->open(long_iv, {}, data, tag).error() == crypto::error::invalid_iv_size);
    BOOST_TEST(
        made->open(std::span(long_iv).first(12), {}, data, std::span(tag).first(15)).error() ==
        crypto::error::invalid_tag_size);
    BOOST_TEST(made->open(std::span(long_iv).first(12), {}, data, long_tag).error() ==
               crypto::error::invalid_tag_size);
    BOOST_TEST(made->open(std::span(long_iv).first(12), {}, data, {}).error() ==
               crypto::error::invalid_tag_size);
    // The IV is checked before the tag: both wrong gives the IV's error.
    BOOST_TEST(made->open(long_iv, {}, data, std::span(tag).first(15)).error() ==
               crypto::error::invalid_iv_size);
    BOOST_TEST(data == untouched);
    // IVs of 1 and of 128 bytes are accepted (spec section 2.4, LEDGER:22), and open.
    for (std::size_t const size : {std::size_t{1}, std::size_t{128}}) {
        auto const iv = std::span(long_iv).first(size);
        auto const sealed = made->seal(iv, {}, data);
        BOOST_TEST(sealed.has_value());
        BOOST_TEST(sealed && made->open(iv, {}, data, *sealed).has_value());
        BOOST_TEST(data == untouched);
    }
}

/** Changing any byte of ciphertext, tag, IV or additional data fails, and zeroes data. */
template <class Backend>
void check_tampering(gcm_cases cases = gcm_spec_cases) {
    using aead = crypto::gcm<crypto::aes128<Backend>>;
    if (!BOOST_TEST_EQ(cases.size(), gcm_spec_cases.size())) {
        return;
    }
    auto const& c = cases[3];  // case 4: plaintext and additional data
    auto const key = from_hex(c.key);
    auto const iv = from_hex(c.iv);
    auto const additional_data = from_hex(c.additional_data);
    auto const ciphertext = from_hex(c.ciphertext);
    auto const tag = from_hex(c.tag);
    auto made = aead::make(key);
    if (!BOOST_TEST(made.has_value())) {
        return;
    }
    for (std::size_t i = 0; i < ciphertext.size(); ++i) {
        auto data = ciphertext;
        data[i] ^= 1;
        BOOST_TEST(made->open(iv, additional_data, data, tag).error() ==
                   crypto::error::authentication_failed);
        BOOST_TEST(all_zero(data));
    }
    for (std::size_t i = 0; i < tag.size(); ++i) {
        auto data = ciphertext;
        auto bad = tag;
        bad[i] ^= 0x80;
        BOOST_TEST(made->open(iv, additional_data, data, bad).error() ==
                   crypto::error::authentication_failed);
        BOOST_TEST(all_zero(data));
    }
    for (std::size_t i = 0; i < additional_data.size(); ++i) {
        auto data = ciphertext;
        auto bad = additional_data;
        bad[i] ^= 2;
        BOOST_TEST(made->open(iv, bad, data, tag).error() == crypto::error::authentication_failed);
        BOOST_TEST(all_zero(data));
    }
    for (std::size_t i = 0; i < iv.size(); ++i) {
        auto data = ciphertext;
        auto bad = iv;
        bad[i] ^= 4;
        BOOST_TEST(made->open(bad, additional_data, data, tag).error() ==
                   crypto::error::authentication_failed);
        BOOST_TEST(all_zero(data));
    }
    // A ciphertext one byte shorter, its tag unchanged, fails too.
    {
        auto data = ciphertext;
        BOOST_TEST(
            made->open(iv, additional_data, std::span(data).first(data.size() - 1), tag).error() ==
            crypto::error::authentication_failed);
        BOOST_TEST(all_zero(std::span(data).first(data.size() - 1)));
    }
    // The object works after failures.
    auto data = ciphertext;
    BOOST_TEST(made->open(iv, additional_data, data, tag).has_value());
    BOOST_TEST_EQ(to_hex(data), c.plaintext);
}

/** A moved-from gcm answers invalid_state to everything but assignment and destruction. */
template <class Backend>
void check_moved_from(gcm_cases cases = gcm_spec_cases) {
    using aead = crypto::gcm<crypto::aes256<Backend>>;
    if (!BOOST_TEST_EQ(cases.size(), gcm_spec_cases.size())) {
        return;
    }
    auto const& one_block = cases[13];  // case 14: AES-256, one zero block
    std::array<std::uint8_t, 32> const key{};
    auto made = aead::make(key);
    if (!BOOST_TEST(made.has_value())) {
        return;
    }
    aead moved = std::move(*made);
    std::array<std::uint8_t, 12> const iv{};
    std::array<std::uint8_t, 16> data{};
    data.fill(0x6c);  // a guard's refusal leaves this pattern, not only zeroes, untouched
    auto const untouched = data;
    std::array<std::uint8_t, 16> const tag{};
    auto const all_refused = [&](aead& empty) {
        BOOST_TEST(empty.seal(iv, {}, data).error() == crypto::error::invalid_state);
        BOOST_TEST(empty.open(iv, {}, data, tag).error() == crypto::error::invalid_state);
        // The state is checked before the IV and the tag.
        BOOST_TEST(empty.seal({}, {}, data).error() == crypto::error::invalid_state);
        BOOST_TEST(empty.open({}, {}, data, {}).error() == crypto::error::invalid_state);
        BOOST_TEST(data == untouched);
    };
    all_refused(*made);
    // Moving an object that was moved from gives an empty object, and crashes nothing (I1).
    aead again = std::move(*made);
    all_refused(again);
    all_refused(*made);
    again = std::move(*made);
    all_refused(again);
    // The destination works: case 14.
    data.fill(0);
    auto const sealed = moved.seal(iv, {}, data);
    BOOST_TEST_EQ(to_hex(data), one_block.ciphertext);
    BOOST_TEST(sealed && to_hex(*sealed) == one_block.tag);
    // A swap of an empty object and a live one moves the key, both ways.
    std::swap(again, moved);
    BOOST_TEST(sealed && again.open(iv, {}, data, *sealed).has_value());
    data.fill(0x6c);
    all_refused(moved);
    // Assignment back makes the source whole again.
    std::array<std::uint8_t, 16> block{};
    *made = std::move(again);
    auto const resealed = made->seal(iv, {}, block);
    BOOST_TEST(resealed && to_hex(*resealed) == one_block.tag);
    all_refused(again);
    // Self-move-assignment leaves the key in place.
    auto& self = *made;
    *made = std::move(self);
    block.fill(0);
    auto const self_sealed = made->seal(iv, {}, block);
    BOOST_TEST(self_sealed && to_hex(*self_sealed) == one_block.tag);
}

/** Empty inputs, and spans that touch or overlap (Review Focus 2 and 3). */
template <class Backend>
void check_edges(gcm_cases cases = gcm_spec_cases) {
    using aead = crypto::gcm<crypto::aes256<Backend>>;
    if (!BOOST_TEST_EQ(cases.size(), gcm_spec_cases.size())) {
        return;
    }
    std::array<std::uint8_t, 32> const key{};
    auto made = aead::make(key);
    if (!BOOST_TEST(made.has_value())) {
        return;
    }
    std::array<std::uint8_t, 12> const iv{};
    // Case 13: empty plaintext and additional data, through spans whose data() is null.
    auto const empty = made->seal(iv, std::span<std::uint8_t const>(), std::span<std::uint8_t>());
    BOOST_TEST(empty && to_hex(*empty) == cases[12].tag);
    BOOST_TEST(empty && made->open(iv, {}, std::span<std::uint8_t>(), *empty).has_value());
    std::array<std::uint8_t, 16> const zero_tag{};
    BOOST_TEST(made->open(iv, {}, std::span<std::uint8_t>(), zero_tag).error() ==
               crypto::error::authentication_failed);

    // A wire buffer: ciphertext then tag, the tag a subspan right after the data; the open
    // gives the plaintext back and leaves the tag's bytes as they were.
    std::array<std::uint8_t, 32> wire{};
    std::fill(wire.begin(), wire.begin() + 16, 0x33);
    auto const sealed = made->seal(iv, {}, std::span(wire).first(16));
    if (!BOOST_TEST(sealed.has_value())) {
        return;
    }
    std::copy(sealed->begin(), sealed->end(), wire.begin() + 16);
    BOOST_TEST(made->open(iv, {}, std::span(wire).first(16), std::span(wire).last(16)).has_value());
    BOOST_TEST(
        std::all_of(wire.begin(), wire.begin() + 16, [](std::uint8_t b) { return b == 0x33; }));
    BOOST_TEST(std::equal(sealed->begin(), sealed->end(), wire.begin() + 16));

    // A tag that overlaps the data's end fails cleanly: the data is zeroed, and the bytes
    // after the data, which only the tag covers, are as they were.
    std::array<std::uint8_t, 24> overlap{};
    overlap.fill(0x5a);
    BOOST_TEST(
        made->open(iv, {}, std::span(overlap).first(20), std::span(overlap).last(16)).error() ==
        crypto::error::authentication_failed);
    BOOST_TEST(all_zero(std::span(overlap).first(20)));
    BOOST_TEST(
        std::all_of(overlap.begin() + 20, overlap.end(), [](std::uint8_t b) { return b == 0x5a; }));

    // An IV and additional data inside the sealed buffer itself give what copies of them give:
    // both are consumed before the first byte of data is written.
    std::array<std::uint8_t, 44> buffer{};
    for (std::size_t i = 0; i < buffer.size(); ++i) {
        buffer[i] = static_cast<std::uint8_t>(i * 7 + 1);
    }
    std::array<std::uint8_t, 12> iv_copy{};
    std::array<std::uint8_t, 16> additional_copy{};
    auto data_copy = buffer;
    std::copy(buffer.begin(), buffer.begin() + 12, iv_copy.begin());
    std::copy(buffer.begin() + 12, buffer.begin() + 28, additional_copy.begin());
    auto const expected = made->seal(iv_copy, additional_copy, data_copy);
    auto const in_place =
        made->seal(std::span(buffer).first(12), std::span(buffer).subspan(12, 16), buffer);
    BOOST_TEST(expected && in_place && to_hex(*expected) == to_hex(*in_place));
    BOOST_TEST(data_copy == buffer);
}

}  // namespace webcpp::test

#endif
