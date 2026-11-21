// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The checks of gcm on one backend: the GCM specification's 18 cases, every guard and
// its order, tampering with every byte, the zeroing of a failed open, moved-from
// objects, aliasing spans (spec sections 2.4 and 8.1; Review Focus 2 and 3), and the
// incremental seal and open, each with its machine.
//
// Each check takes the 18 cases it compares with, by default the specification's, which
// a real backend's test keeps; the mock backend passes its own (support/mock_backend.hpp),
// the same inputs with its ciphertexts and tags. The checks that need one known answer use
// case 13 (AES-256, empty) or case 14 (AES-256, one zero block, zero key and IV).

#ifndef WEBCPP_TEST_CRYPTO_SUPPORT_GCM_CHECKS_HPP
#define WEBCPP_TEST_CRYPTO_SUPPORT_GCM_CHECKS_HPP

#include "gcm_spec_vectors.hpp"
#include "hex.hpp"

#if !defined(__wasi__) && !defined(__EMSCRIPTEN__)
#include "reserved.hpp"
#endif

#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/crypto/ciphers/gcm.hpp>
#include <webcpp/crypto/equal.hpp>
#include <webcpp/crypto/error.hpp>

#include <boost/core/lightweight_test.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace webcpp::test {

namespace crypto = webcpp::crypto;

/** The cases a check compares with: the specification's, or a mock's. */
using gcm_cases = std::span<gcm_case const>;

/** Whether every byte is zero. */
inline bool all_zero(std::span<std::uint8_t const> bytes) {
    return std::ranges::all_of(bytes, [](std::uint8_t b) { return b == 0; });
}

/** Runs f with the gcm of the key's size on Backend: 16, 24 or 32 bytes. */
template <class Backend, class F>
void with_gcm(std::span<std::uint8_t const> key, F&& f) {
    switch (key.size()) {
        case 16: f(crypto::ciphers::gcm<crypto::ciphers::aes128<Backend>>::make(key)); break;
        case 24: f(crypto::ciphers::gcm<crypto::ciphers::aes192<Backend>>::make(key)); break;
        default: f(crypto::ciphers::gcm<crypto::ciphers::aes256<Backend>>::make(key)); break;
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
            BOOST_TEST(sealed && crypto::equal(*sealed, std::span<std::uint8_t const>(tag)));
            BOOST_TEST(made->open(iv, additional_data, data, tag).has_value());
            BOOST_TEST_EQ(to_hex(data), c.plaintext);
        });
    }
}

/** Every guard of spec section 2.4, in its order, each leaving data untouched. */
template <class Backend>
void check_guards() {
    using checked_aead = crypto::ciphers::gcm<crypto::ciphers::aes256<Backend>>;
    std::array<std::uint8_t, 31> const short_key{};
    BOOST_TEST(checked_aead::make(short_key).error() == crypto::error::invalid_key_size);
    std::array<std::uint8_t, 16> const key16{};
    BOOST_TEST(checked_aead::make(key16).error() == crypto::error::invalid_key_size);
    BOOST_TEST(checked_aead::make({}).error() == crypto::error::invalid_key_size);

    std::array<std::uint8_t, 32> const key{};
    auto made = checked_aead::make(key);
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

/** An open of a changed message fails with authentication_failed and zeroes data. */
template <class Aead>
void expect_tampered(Aead& made, std::span<std::uint8_t const> iv,
                     std::span<std::uint8_t const> additional_data, std::span<std::uint8_t> data,
                     std::span<std::uint8_t const> tag) {
    BOOST_TEST(made.open(iv, additional_data, data, tag).error() ==
               crypto::error::authentication_failed);
    BOOST_TEST(all_zero(data));
}

/** Changing any byte of ciphertext, tag, IV or additional data fails, and zeroes data. */
template <class Backend>
void check_tampering(gcm_cases cases = gcm_spec_cases) {
    using checked_aead = crypto::ciphers::gcm<crypto::ciphers::aes128<Backend>>;
    if (!BOOST_TEST_EQ(cases.size(), gcm_spec_cases.size())) {
        return;
    }
    auto const& c = cases[3];  // case 4: plaintext and additional data
    auto const key = from_hex(c.key);
    auto const iv = from_hex(c.iv);
    auto const additional_data = from_hex(c.additional_data);
    auto const ciphertext = from_hex(c.ciphertext);
    auto const tag = from_hex(c.tag);
    auto made = checked_aead::make(key);
    if (!BOOST_TEST(made.has_value())) {
        return;
    }
    for (std::size_t i = 0; i < ciphertext.size(); ++i) {
        auto data = ciphertext;
        data[i] ^= 1U;
        expect_tampered(*made, iv, additional_data, data, tag);
    }
    for (std::size_t i = 0; i < tag.size(); ++i) {
        auto data = ciphertext;
        auto bad = tag;
        bad[i] ^= 0x80U;
        expect_tampered(*made, iv, additional_data, data, bad);
    }
    for (std::size_t i = 0; i < additional_data.size(); ++i) {
        auto data = ciphertext;
        auto bad = additional_data;
        bad[i] ^= 2U;
        expect_tampered(*made, iv, bad, data, tag);
    }
    for (std::size_t i = 0; i < iv.size(); ++i) {
        auto data = ciphertext;
        auto bad = iv;
        bad[i] ^= 4U;
        expect_tampered(*made, bad, additional_data, data, tag);
    }
    // A ciphertext one byte shorter, its tag unchanged, fails too.
    {
        auto data = ciphertext;
        expect_tampered(*made, iv, additional_data, std::span(data).first(data.size() - 1), tag);
    }
    // The object works after failures.
    auto data = ciphertext;
    BOOST_TEST(made->open(iv, additional_data, data, tag).has_value());
    BOOST_TEST_EQ(to_hex(data), c.plaintext);
}

/** Every call of an empty gcm is refused with invalid_state, and leaves data untouched. */
template <class Aead>
void expect_all_refused(Aead& empty, std::span<std::uint8_t const> iv, std::span<std::uint8_t> data,
                        std::span<std::uint8_t const> tag,
                        std::span<std::uint8_t const> untouched) {
    BOOST_TEST(empty.seal(iv, {}, data).error() == crypto::error::invalid_state);
    BOOST_TEST(empty.open(iv, {}, data, tag).error() == crypto::error::invalid_state);
    // The state is checked before the IV and the tag.
    BOOST_TEST(empty.seal({}, {}, data).error() == crypto::error::invalid_state);
    BOOST_TEST(empty.open({}, {}, data, {}).error() == crypto::error::invalid_state);
    BOOST_TEST(empty.begin_seal(iv, {}).error() == crypto::error::invalid_state);
    BOOST_TEST(empty.begin_seal({}, {}).error() == crypto::error::invalid_state);
    BOOST_TEST(empty.update(data).error() == crypto::error::invalid_state);
    BOOST_TEST(empty.update({}).error() == crypto::error::invalid_state);
    BOOST_TEST(empty.result().error() == crypto::error::invalid_state);
    BOOST_TEST(empty.begin_open(iv, {}).error() == crypto::error::invalid_state);
    BOOST_TEST(empty.begin_open({}, {}).error() == crypto::error::invalid_state);
    BOOST_TEST(empty.authenticate(data).error() == crypto::error::invalid_state);
    BOOST_TEST(empty.verify(tag).error() == crypto::error::invalid_state);
    BOOST_TEST(empty.decrypt(data).error() == crypto::error::invalid_state);
    BOOST_TEST(empty.end_open().error() == crypto::error::invalid_state);
    BOOST_TEST(std::ranges::equal(data, untouched));
}

/** A moved-from gcm answers invalid_state to everything but assignment and destruction. */
template <class Backend>
void check_moved_from(gcm_cases cases = gcm_spec_cases) {
    using checked_aead = crypto::ciphers::gcm<crypto::ciphers::aes256<Backend>>;
    if (!BOOST_TEST_EQ(cases.size(), gcm_spec_cases.size())) {
        return;
    }
    auto const& one_block = cases[13];  // case 14: AES-256, one zero block
    std::array<std::uint8_t, 32> const key{};
    auto made = checked_aead::make(key);
    if (!BOOST_TEST(made.has_value())) {
        return;
    }
    checked_aead moved = std::move(*made);
    std::array<std::uint8_t, 12> const iv{};
    std::array<std::uint8_t, 16> data{};
    data.fill(0x6c);  // a guard's refusal leaves this pattern, not only zeroes, untouched
    auto const untouched = data;
    std::array<std::uint8_t, 16> const tag{};
    auto const all_refused = [&](checked_aead& empty) {
        expect_all_refused(empty, iv, data, tag, untouched);
    };
    all_refused(*made);
    // Moving an object that was moved from gives an empty object, and crashes nothing (I1).
    checked_aead again = std::move(*made);
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

/** Case 13: an empty message, through spans whose data() is null. */
template <class Aead>
void check_edge_empty(Aead& made, std::span<std::uint8_t const> iv, std::string_view tag_hex) {
    // Case 13: empty plaintext and additional data, through spans whose data() is null.
    auto const empty = made.seal(iv, std::span<std::uint8_t const>(), std::span<std::uint8_t>());
    BOOST_TEST(empty && to_hex(*empty) == tag_hex);
    BOOST_TEST(empty && made.open(iv, {}, std::span<std::uint8_t>(), *empty).has_value());
    std::array<std::uint8_t, 16> const zero_tag{};
    BOOST_TEST(made.open(iv, {}, std::span<std::uint8_t>(), zero_tag).error() ==
               crypto::error::authentication_failed);
}

/** A tag right after the data in one buffer. */
template <class Aead>
void check_edge_wire_tag(Aead& made, std::span<std::uint8_t const> iv) {
    // A wire buffer: ciphertext then tag, the tag a subspan right after the data; the open
    // gives the plaintext back and leaves the tag's bytes as they were.
    std::array<std::uint8_t, 32> wire{};
    std::fill(wire.begin(), wire.begin() + 16, 0x33);
    auto const sealed = made.seal(iv, {}, std::span(wire).first(16));
    if (!BOOST_TEST(sealed.has_value())) {
        return;
    }
    std::copy(sealed->begin(), sealed->end(), wire.begin() + 16);
    BOOST_TEST(made.open(iv, {}, std::span(wire).first(16), std::span(wire).last(16)).has_value());
    BOOST_TEST(
        std::all_of(wire.begin(), wire.begin() + 16, [](std::uint8_t b) { return b == 0x33; }));
    BOOST_TEST(std::equal(sealed->begin(), sealed->end(), wire.begin() + 16));
}

/** A tag that overlaps the data's end. */
template <class Aead>
void check_edge_overlap(Aead& made, std::span<std::uint8_t const> iv) {
    // A tag that overlaps the data's end fails cleanly: the data is zeroed, and the bytes
    // after the data, which only the tag covers, are as they were.
    std::array<std::uint8_t, 24> overlap{};
    overlap.fill(0x5a);
    BOOST_TEST(
        made.open(iv, {}, std::span(overlap).first(20), std::span(overlap).last(16)).error() ==
        crypto::error::authentication_failed);
    BOOST_TEST(all_zero(std::span(overlap).first(20)));
    BOOST_TEST(
        std::all_of(overlap.begin() + 20, overlap.end(), [](std::uint8_t b) { return b == 0x5a; }));
}

/** An IV and additional data inside the sealed buffer. */
template <class Aead>
void check_edge_in_place(Aead& made) {
    // An IV and additional data inside the sealed buffer itself give what copies of them give:
    // both are consumed before the first byte of data is written.
    std::array<std::uint8_t, 44> buffer{};
    for (std::size_t i = 0; i < buffer.size(); ++i) {
        buffer[i] = static_cast<std::uint8_t>((i * 7) + 1);
    }
    std::array<std::uint8_t, 12> iv_copy{};
    std::array<std::uint8_t, 16> additional_copy{};
    auto data_copy = buffer;
    std::copy(buffer.begin(), buffer.begin() + 12, iv_copy.begin());
    std::copy(buffer.begin() + 12, buffer.begin() + 28, additional_copy.begin());
    auto const expected = made.seal(iv_copy, additional_copy, data_copy);
    auto const in_place =
        made.seal(std::span(buffer).first(12), std::span(buffer).subspan(12, 16), buffer);
    BOOST_TEST(expected && in_place && to_hex(*expected) == to_hex(*in_place));
    BOOST_TEST(data_copy == buffer);
}

/** A wire buffer opened in place with spans into it. */
template <class Aead>
void check_edge_wire_open(Aead& made) {
    // A wire buffer [IV | additional data | ciphertext], opened in place with spans into it,
    // gives what an open of copies gives, and leaves the IV and the additional data as they
    // were.
    std::array<std::uint8_t, 12> wire_iv{};
    std::array<std::uint8_t, 16> wire_additional{};
    std::array<std::uint8_t, 32> wire_plain{};
    for (std::size_t i = 0; i < wire_plain.size(); ++i) {
        wire_plain[i] = static_cast<std::uint8_t>((i * 11) + 3);
    }
    wire_iv.fill(0x17);
    wire_additional.fill(0x29);
    auto wire_data = wire_plain;
    auto const wire_sealed = made.seal(wire_iv, wire_additional, wire_data);
    if (!BOOST_TEST(wire_sealed.has_value())) {
        return;
    }
    std::array<std::uint8_t, 60> message{};
    std::ranges::copy(wire_iv, message.begin());
    std::ranges::copy(wire_additional, message.begin() + 12);
    std::ranges::copy(wire_data, message.begin() + 28);
    auto copy_data = wire_data;
    BOOST_TEST(made.open(wire_iv, wire_additional, copy_data, *wire_sealed).has_value());
    BOOST_TEST(made.open(std::span(message).first(12), std::span(message).subspan(12, 16),
                         std::span(message).subspan(28), *wire_sealed)
                   .has_value());
    BOOST_TEST(std::equal(copy_data.begin(), copy_data.end(), message.begin() + 28));
    BOOST_TEST(copy_data == wire_plain);
    BOOST_TEST(std::equal(wire_iv.begin(), wire_iv.end(), message.begin()));
    BOOST_TEST(std::equal(wire_additional.begin(), wire_additional.end(), message.begin() + 12));
}

/** Empty inputs, and spans that touch or overlap (Review Focus 2 and 3). */
template <class Backend>
void check_edges(gcm_cases cases = gcm_spec_cases) {
    using checked_aead = crypto::ciphers::gcm<crypto::ciphers::aes256<Backend>>;
    if (!BOOST_TEST_EQ(cases.size(), gcm_spec_cases.size())) {
        return;
    }
    std::array<std::uint8_t, 32> const key{};
    auto made = checked_aead::make(key);
    if (!BOOST_TEST(made.has_value())) {
        return;
    }
    std::array<std::uint8_t, 12> const iv{};
    check_edge_empty(*made, iv, cases[12].tag);
    check_edge_wire_tag(*made, iv);
    check_edge_overlap(*made, iv);
    check_edge_in_place(*made);
    check_edge_wire_open(*made);
}

/**
 * Seals `plaintext` through the incremental seal in pieces of `piece` bytes (and one empty
 * piece), checks the ciphertext and the tag against the expected hex, and opens the result
 * one shot (spec 8.1: every case sealed incrementally as well).
 */
template <class Aead>
void check_in_pieces(Aead& made, std::span<std::uint8_t const> iv,
                     std::span<std::uint8_t const> additional_data,
                     std::vector<std::uint8_t> const& plaintext, std::string_view ciphertext,
                     std::string_view tag_hex, std::size_t piece) {
    auto data = plaintext;
    BOOST_TEST(made.begin_seal(iv, additional_data).has_value());
    for (std::size_t at = 0; at < data.size(); at += piece) {
        auto const size = (std::min)(piece, data.size() - at);
        BOOST_TEST(made.update(std::span(data).subspan(at, size)).has_value());
    }
    BOOST_TEST(made.update(std::span<std::uint8_t>()).has_value());  // an empty piece
    auto const tag = made.result();
    BOOST_TEST_EQ(to_hex(data), ciphertext);
    BOOST_TEST(tag && to_hex(*tag) == tag_hex);
    BOOST_TEST(tag && made.open(iv, additional_data, data, *tag).has_value());
    BOOST_TEST(data == plaintext);
}

/** Every piece size from 1 to the whole message, the whole included (at least 1). */
template <class Aead>
void check_every_piece(Aead& made, std::span<std::uint8_t const> iv,
                       std::span<std::uint8_t const> additional_data,
                       std::vector<std::uint8_t> const& plaintext, std::string_view ciphertext,
                       std::string_view tag_hex) {
    for (std::size_t piece = 1; piece <= (std::max)(plaintext.size(), std::size_t{1}); ++piece) {
        check_in_pieces(made, iv, additional_data, plaintext, ciphertext, tag_hex, piece);
    }
}

/** The 18 cases, each sealed in pieces of every size. */
template <class Backend>
void check_incremental(gcm_cases cases = gcm_spec_cases) {
    BOOST_TEST_EQ(cases.size(), gcm_spec_cases.size());
    for (auto const& c : cases) {
        auto const iv = from_hex(c.iv);
        auto const additional_data = from_hex(c.additional_data);
        auto const plaintext = from_hex(c.plaintext);
        with_gcm<Backend>(from_hex(c.key), [&](auto made) {
            if (BOOST_TEST(made.has_value())) {
                check_every_piece(*made, iv, additional_data, plaintext, c.ciphertext, c.tag);
            }
        });
    }
}

/** A fresh message of case 14 (AES-256, one zero block) seals as the specification says. */
template <class Aead>
void expect_fresh_message(Aead& made, std::span<std::uint8_t const> iv, gcm_case const& one_block) {
    std::array<std::uint8_t, 16> data{};
    BOOST_TEST(made.begin_seal(iv, {}).has_value());
    BOOST_TEST(made.update(data).has_value());
    auto const tag = made.result();
    BOOST_TEST_EQ(to_hex(data), one_block.ciphertext);
    BOOST_TEST(tag && to_hex(*tag) == one_block.tag);
}

/**
 * A source moved from during a message is empty and in no message: each call of the machine is
 * refused, and none reaches the engine with the source's wiped state.
 */
template <class Aead>
void expect_source_refuses(Aead& source, std::span<std::uint8_t const> iv) {
    std::array<std::uint8_t, 16> data{};
    BOOST_TEST(source.begin_seal(iv, {}).error() == crypto::error::invalid_state);
    BOOST_TEST(source.update(data).error() == crypto::error::invalid_state);
    BOOST_TEST(source.result().error() == crypto::error::invalid_state);
    BOOST_TEST(source.begin_seal(iv, {}).error() == crypto::error::invalid_state);
    BOOST_TEST(source.begin_open(iv, {}).error() == crypto::error::invalid_state);
    BOOST_TEST(source.authenticate(data).error() == crypto::error::invalid_state);
    BOOST_TEST(source.verify(data).error() == crypto::error::invalid_state);
    BOOST_TEST(source.decrypt(data).error() == crypto::error::invalid_state);
    BOOST_TEST(source.end_open().error() == crypto::error::invalid_state);
}

/** The machine's wrong calls, each followed by a fresh message. */
template <class Aead>
void check_machine_calls(Aead& made, std::span<std::uint8_t const> iv, gcm_case const& one_block) {
    std::array<std::uint8_t, 16> data{};
    BOOST_TEST(made.update(data).error() == crypto::error::invalid_state);
    BOOST_TEST(made.result().error() == crypto::error::invalid_state);
    expect_fresh_message(made, iv, one_block);
    BOOST_TEST(made.result().error() == crypto::error::invalid_state);      // a second result
    BOOST_TEST(made.update(data).error() == crypto::error::invalid_state);  // after result

    BOOST_TEST(made.begin_seal(iv, {}).has_value());
    BOOST_TEST(made.begin_seal(iv, {}).error() == crypto::error::invalid_state);
    BOOST_TEST(made.result().error() == crypto::error::invalid_state);  // the error ended it
    expect_fresh_message(made, iv, one_block);

    BOOST_TEST(made.begin_seal(iv, {}).has_value());
    std::array<std::uint8_t, 129> const long_iv{};
    BOOST_TEST(made.begin_seal(long_iv, {}).error() == crypto::error::invalid_state);
    expect_fresh_message(made, iv, one_block);
    BOOST_TEST(made.begin_seal(long_iv, {}).error() == crypto::error::invalid_iv_size);
    BOOST_TEST(made.begin_seal({}, {}).error() == crypto::error::invalid_iv_size);
    BOOST_TEST(made.update(data).error() == crypto::error::invalid_state);  // none began
    expect_fresh_message(made, iv, one_block);

    // A message abandoned halfway leaves nothing behind: the next one is whole.
    BOOST_TEST(made.begin_seal(iv, {}).has_value());
    BOOST_TEST(made.update(std::span(data).first(7)).has_value());
    BOOST_TEST(made.begin_seal(iv, {}).error() == crypto::error::invalid_state);
    expect_fresh_message(made, iv, one_block);
}

/** A fresh incremental open of case 14 (AES-256, one zero block) gives its zero block. */
template <class Aead>
void expect_fresh_open(Aead& made, std::span<std::uint8_t const> iv, gcm_case const& one_block) {
    auto data = from_hex(one_block.ciphertext);
    auto const tag = from_hex(one_block.tag);
    BOOST_TEST(made.begin_open(iv, {}).has_value());
    BOOST_TEST(made.authenticate(data).has_value());
    BOOST_TEST(made.verify(tag).has_value());
    BOOST_TEST(made.decrypt(data).has_value());
    BOOST_TEST(made.end_open().has_value());
    BOOST_TEST(all_zero(data));
}

/** Begins an open and authenticates the data: the first pass, before its tag is verified. */
template <class Aead>
void begin_authenticated(Aead& made, std::span<std::uint8_t const> iv,
                         std::span<std::uint8_t const> data) {
    BOOST_TEST(made.begin_open(iv, {}).has_value());
    BOOST_TEST(made.authenticate(data).has_value());
}

/** Begins an open, authenticates the data and verifies its tag: the second pass is next. */
template <class Aead>
void begin_verified(Aead& made, std::span<std::uint8_t const> iv,
                    std::span<std::uint8_t const> data, std::span<std::uint8_t const> tag) {
    begin_authenticated(made, iv, data);
    BOOST_TEST(made.verify(tag).has_value());
}

/**
 * The incremental open's machine before its second pass: without a message each call only
 * answers, and a second begin_open, end_open before verify, or a seal's call ends the first
 * pass; each is followed by a fresh open.
 */
template <class Aead>
void check_machine_first_pass_calls(Aead& made, std::span<std::uint8_t const> iv,
                                    gcm_case const& one_block) {
    auto data = from_hex(one_block.ciphertext);
    auto const tag = from_hex(one_block.tag);
    // Without a message, each call only answers.
    BOOST_TEST(made.authenticate(data).error() == crypto::error::invalid_state);
    BOOST_TEST(made.verify(tag).error() == crypto::error::invalid_state);
    BOOST_TEST(made.decrypt(data).error() == crypto::error::invalid_state);
    BOOST_TEST(made.end_open().error() == crypto::error::invalid_state);
    expect_fresh_open(made, iv, one_block);
    // A second begin_open, and end_open before verify, end the first pass.
    begin_authenticated(made, iv, data);
    BOOST_TEST(made.begin_open(iv, {}).error() == crypto::error::invalid_state);
    BOOST_TEST(made.verify(tag).error() == crypto::error::invalid_state);
    expect_fresh_open(made, iv, one_block);
    begin_authenticated(made, iv, data);
    BOOST_TEST(made.end_open().error() == crypto::error::invalid_state);
    BOOST_TEST(made.verify(tag).error() == crypto::error::invalid_state);
    expect_fresh_open(made, iv, one_block);
    // The seal's calls in the first pass end it as well.
    begin_authenticated(made, iv, data);
    BOOST_TEST(made.result().error() == crypto::error::invalid_state);
    BOOST_TEST(made.verify(tag).error() == crypto::error::invalid_state);
    expect_fresh_message(made, iv, one_block);
}

/**
 * The incremental open's machine in its second pass: authenticate, verify, begin_open,
 * begin_seal, update and result end it, and each is followed by a fresh open.
 */
template <class Aead>
void check_machine_second_pass_calls(Aead& made, std::span<std::uint8_t const> iv,
                                     gcm_case const& one_block) {
    auto data = from_hex(one_block.ciphertext);
    auto const tag = from_hex(one_block.tag);
    begin_verified(made, iv, data, tag);
    BOOST_TEST(made.authenticate(data).error() == crypto::error::invalid_state);
    BOOST_TEST(made.decrypt(data).error() == crypto::error::invalid_state);
    expect_fresh_open(made, iv, one_block);
    begin_verified(made, iv, data, tag);
    BOOST_TEST(made.verify(tag).error() == crypto::error::invalid_state);
    BOOST_TEST(made.end_open().error() == crypto::error::invalid_state);
    expect_fresh_open(made, iv, one_block);
    begin_verified(made, iv, data, tag);
    BOOST_TEST(made.begin_open(iv, {}).error() == crypto::error::invalid_state);
    BOOST_TEST(made.decrypt(data).error() == crypto::error::invalid_state);
    expect_fresh_open(made, iv, one_block);
    begin_verified(made, iv, data, tag);
    BOOST_TEST(made.begin_seal(iv, {}).error() == crypto::error::invalid_state);
    BOOST_TEST(made.result().error() == crypto::error::invalid_state);
    BOOST_TEST(made.decrypt(data).error() == crypto::error::invalid_state);
    expect_fresh_open(made, iv, one_block);
    begin_verified(made, iv, data, tag);
    BOOST_TEST(made.update(data).error() == crypto::error::invalid_state);
    BOOST_TEST(made.decrypt(data).error() == crypto::error::invalid_state);
    expect_fresh_open(made, iv, one_block);
}

/**
 * The incremental open's machine: each call outside its phase is refused, ends an open in
 * progress, and is followed by a fresh open.
 */
template <class Aead>
void check_machine_open_calls(Aead& made, std::span<std::uint8_t const> iv,
                              gcm_case const& one_block) {
    check_machine_first_pass_calls(made, iv, one_block);
    check_machine_second_pass_calls(made, iv, one_block);
}

/** A move abandons the message on both sides, and leaves the source refusing every call. */
template <class Aead>
void check_machine_moves(Aead& made, std::span<std::uint8_t const> key,
                         std::span<std::uint8_t const> iv, gcm_case const& one_block) {
    BOOST_TEST(made.begin_seal(iv, {}).has_value());
    Aead moved = std::move(made);  // a move abandons the message on both sides
    BOOST_TEST(moved.result().error() == crypto::error::invalid_state);
    expect_source_refuses(made, iv);
    made = std::move(moved);
    expect_fresh_message(made, iv, one_block);

    // A move assignment from an object in a message: the same for its source.
    auto other = Aead::make(key);
    if (!BOOST_TEST(other.has_value())) {
        return;
    }
    BOOST_TEST(other->begin_seal(iv, {}).has_value());
    made = std::move(*other);
    BOOST_TEST(made.result().error() == crypto::error::invalid_state);
    expect_source_refuses(*other, iv);
    expect_fresh_message(made, iv, one_block);

    // A move assignment over an object in a message abandons that message too.
    BOOST_TEST(made.begin_seal(iv, {}).has_value());
    auto third = Aead::make(key);
    if (!BOOST_TEST(third.has_value())) {
        return;
    }
    made = std::move(*third);
    BOOST_TEST(made.result().error() == crypto::error::invalid_state);
    expect_source_refuses(*third, iv);
    expect_fresh_message(made, iv, one_block);
}

/**
 * The incremental seal's machine (spec section 2.4) and the incremental open's: each wrong
 * call, then a fresh message.
 */
template <class Backend>
void check_machine(gcm_cases cases = gcm_spec_cases) {
    using checked_aead = crypto::ciphers::gcm<crypto::ciphers::aes256<Backend>>;
    if (!BOOST_TEST_EQ(cases.size(), gcm_spec_cases.size())) {
        return;
    }
    auto const& one_block = cases[13];  // case 14: AES-256, one zero block
    std::array<std::uint8_t, 32> const key{};
    std::array<std::uint8_t, 12> const iv{};
    auto made = checked_aead::make(key);
    if (!BOOST_TEST(made.has_value())) {
        return;
    }
    check_machine_calls(*made, iv, one_block);
    check_machine_open_calls(*made, iv, one_block);
    check_machine_moves(*made, key, iv, one_block);
}

/** A one-shot seal or open during an incremental message is refused (Review Focus 1). */
template <class Backend>
void check_one_shot_during_message(gcm_cases cases = gcm_spec_cases) {
    using checked_aead = crypto::ciphers::gcm<crypto::ciphers::aes256<Backend>>;
    if (!BOOST_TEST_EQ(cases.size(), gcm_spec_cases.size())) {
        return;
    }
    auto const& one_block = cases[13];  // case 14: AES-256, one zero block
    std::array<std::uint8_t, 32> const key{};
    std::array<std::uint8_t, 12> const iv{};
    auto made = checked_aead::make(key);
    if (!BOOST_TEST(made.has_value())) {
        return;
    }
    std::array<std::uint8_t, 16> message{};
    BOOST_TEST(made->begin_seal(iv, {}).has_value());
    BOOST_TEST(made->update(std::span(message).first(5)).has_value());
    std::array<std::uint8_t, 16> other{};
    other.fill(9);
    auto const untouched = other;
    std::array<std::uint8_t, 16> const tag{};
    BOOST_TEST(made->seal(iv, {}, other).error() == crypto::error::invalid_state);
    BOOST_TEST(made->open(iv, {}, other, tag).error() == crypto::error::invalid_state);
    // The message is checked before the IV and the tag.
    BOOST_TEST(made->seal({}, {}, other).error() == crypto::error::invalid_state);
    BOOST_TEST(made->open(iv, {}, other, {}).error() == crypto::error::invalid_state);
    BOOST_TEST(made->open({}, {}, other, {}).error() == crypto::error::invalid_state);
    BOOST_TEST(other == untouched);
    BOOST_TEST(made->update(std::span(message).subspan(5)).has_value());
    auto const result = made->result();
    BOOST_TEST_EQ(to_hex(message), one_block.ciphertext);
    BOOST_TEST(result && to_hex(*result) == one_block.tag);
}

/**
 * Opens `ciphertext` through the incremental open: `begin_open`, `authenticate` in pieces of
 * `piece` bytes (and one empty piece), `verify`, then `decrypt` in pieces of 5 bytes, the last
 * one the rest, and `end_open`. Every call must have a value; the plaintext is returned.
 */
template <class Aead>
std::vector<std::uint8_t> open_in_two_passes(Aead& made, std::span<std::uint8_t const> iv,
                                             std::span<std::uint8_t const> additional_data,
                                             std::vector<std::uint8_t> data,
                                             std::span<std::uint8_t const> tag, std::size_t piece) {
    BOOST_TEST(made.begin_open(iv, additional_data).has_value());
    for (std::size_t at = 0; at < data.size(); at += piece) {
        auto const size = (std::min)(piece, data.size() - at);
        BOOST_TEST(made.authenticate(std::span(data).subspan(at, size)).has_value());
    }
    BOOST_TEST(made.authenticate(std::span<std::uint8_t const>()).has_value());
    BOOST_TEST(made.verify(tag).has_value());
    for (std::size_t at = 0; at < data.size(); at += 5) {
        auto const size = (std::min)(std::size_t{5}, data.size() - at);
        BOOST_TEST(made.decrypt(std::span(data).subspan(at, size)).has_value());
    }
    BOOST_TEST(made.end_open().has_value());
    return data;
}

/**
 * Each of the 18 cases, sealed one shot, opened in two passes with pieces of 1, 7, 16 and 17
 * bytes and the whole message, then decrypted in pieces of 5 bytes.
 */
template <class Backend>
void incremental_open_pieces(gcm_cases cases = gcm_spec_cases) {
    BOOST_TEST_EQ(cases.size(), gcm_spec_cases.size());
    for (auto const& c : cases) {
        auto const iv = from_hex(c.iv);
        auto const additional_data = from_hex(c.additional_data);
        auto const plaintext = from_hex(c.plaintext);
        with_gcm<Backend>(from_hex(c.key), [&](auto made) {
            if (!BOOST_TEST(made.has_value())) {
                return;
            }
            auto ciphertext = plaintext;
            auto const tag = made->seal(iv, additional_data, ciphertext);
            if (!BOOST_TEST(tag.has_value())) {
                return;
            }
            for (std::size_t const piece : {
                     std::size_t{1},
                     std::size_t{7},
                     std::size_t{16},
                     std::size_t{17},
                     (std::max)(plaintext.size(), std::size_t{1}),
                 }) {
                auto const opened =
                    open_in_two_passes(*made, iv, additional_data, ciphertext, *tag, piece);
                BOOST_TEST(opened == plaintext);
            }
        });
    }
}

/** A tag with one bit changed: `verify` refuses it, and nothing is decrypted after it. */
template <class Backend>
void incremental_open_wrong_tag(gcm_cases cases = gcm_spec_cases) {
    auto const& c = cases[13];
    with_gcm<Backend>(from_hex(c.key), [&](auto made) {
        if (!BOOST_TEST(made.has_value())) {
            return;
        }
        auto const iv = from_hex(c.iv);
        auto ciphertext = from_hex(c.ciphertext);
        auto const kept = ciphertext;
        auto tag = from_hex(c.tag);
        tag[0] ^= 1U;
        BOOST_TEST(made->begin_open(iv, {}).has_value());
        BOOST_TEST(made->authenticate(ciphertext).has_value());
        BOOST_TEST(made->verify(tag).error() == crypto::error::authentication_failed);
        BOOST_TEST(ciphertext == kept);
        BOOST_TEST(made->decrypt(ciphertext).error() == crypto::error::invalid_state);
        BOOST_TEST(ciphertext == kept);
        BOOST_TEST(made->end_open().error() == crypto::error::invalid_state);
        BOOST_TEST(made->begin_open(iv, {}).has_value());
    });
}

/** `decrypt` before `verify` is refused, its piece untouched, and ends the message. */
template <class Backend>
void incremental_open_decrypt_before_verify(gcm_cases cases = gcm_spec_cases) {
    auto const& c = cases[13];
    with_gcm<Backend>(from_hex(c.key), [&](auto made) {
        if (!BOOST_TEST(made.has_value())) {
            return;
        }
        auto const iv = from_hex(c.iv);
        auto ciphertext = from_hex(c.ciphertext);
        auto const kept = ciphertext;
        auto const tag = from_hex(c.tag);
        BOOST_TEST(made->begin_open(iv, {}).has_value());
        BOOST_TEST(made->authenticate(ciphertext).has_value());
        BOOST_TEST(made->decrypt(ciphertext).error() == crypto::error::invalid_state);
        BOOST_TEST(ciphertext == kept);
        BOOST_TEST(made->verify(tag).error() == crypto::error::invalid_state);  // it ended
    });
}

/** Seals 32 bytes of case 14's key and IV one shot: the ciphertext, then its tag. */
template <class Aead>
std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>> sealed_32(
    Aead& made, std::span<std::uint8_t const> iv) {
    std::vector<std::uint8_t> data(32);
    for (std::size_t i = 0; i < data.size(); ++i) {
        data[i] = static_cast<std::uint8_t>((i * 13) + 5);
    }
    auto const tag = made.seal(iv, {}, data);
    BOOST_TEST(tag.has_value());
    std::vector<std::uint8_t> tag_bytes(16);
    if (tag) {
        std::ranges::copy(*tag, tag_bytes.begin());
    }
    return {data, tag_bytes};
}

/** A second pass longer than the first: refused, its piece untouched, the message ended. */
template <class Backend>
void incremental_open_longer_second_pass(gcm_cases cases = gcm_spec_cases) {
    auto const& c = cases[13];
    with_gcm<Backend>(from_hex(c.key), [&](auto made) {
        if (!BOOST_TEST(made.has_value())) {
            return;
        }
        auto const iv = from_hex(c.iv);
        auto [ciphertext, tag] = sealed_32(*made, iv);
        ciphertext.push_back(0x77);
        auto const kept = ciphertext;
        BOOST_TEST(made->begin_open(iv, {}).has_value());
        BOOST_TEST(made->authenticate(std::span(ciphertext).first(32)).has_value());
        BOOST_TEST(made->verify(tag).has_value());
        BOOST_TEST(made->decrypt(ciphertext).error() == crypto::error::invalid_input_size);
        BOOST_TEST(ciphertext == kept);
        BOOST_TEST(made->end_open().error() == crypto::error::invalid_state);  // it ended
    });
}

/** A second pass shorter than the first: `end_open` refuses it. */
template <class Backend>
void incremental_open_shorter_second_pass(gcm_cases cases = gcm_spec_cases) {
    auto const& c = cases[13];
    with_gcm<Backend>(from_hex(c.key), [&](auto made) {
        if (!BOOST_TEST(made.has_value())) {
            return;
        }
        auto const iv = from_hex(c.iv);
        auto [ciphertext, tag] = sealed_32(*made, iv);
        BOOST_TEST(made->begin_open(iv, {}).has_value());
        BOOST_TEST(made->authenticate(ciphertext).has_value());
        BOOST_TEST(made->verify(tag).has_value());
        BOOST_TEST(made->decrypt(std::span(ciphertext).first(31)).has_value());
        BOOST_TEST(made->end_open().error() == crypto::error::invalid_input_size);
        BOOST_TEST(made->end_open().error() == crypto::error::invalid_state);  // it ended
        BOOST_TEST(made->begin_open(iv, {}).has_value());
    });
}

/**
 * The incremental open's length guard: a piece longer than a message may be is refused by its
 * size before a byte of it is read, and ends the message.
 */
template <class Aead>
void incremental_open_too_long([[maybe_unused]] Aead& made,
                               [[maybe_unused]] std::span<std::uint8_t const> iv,
                               [[maybe_unused]] std::span<std::uint8_t const> tag) {
#if !defined(__wasi__) && !defined(__EMSCRIPTEN__)
    if constexpr (sizeof(std::size_t) == 8) {
        // Faults on any access: refused by its size before a byte is read.
        auto const huge = reserved(static_cast<std::size_t>(Aead::max_message_size) + 1);
        if (BOOST_TEST(!huge.empty()) && BOOST_TEST(made.begin_open(iv, {}).has_value())) {
            BOOST_TEST(made.authenticate(huge).error() == crypto::error::message_too_long);
            BOOST_TEST(made.verify(tag).error() == crypto::error::invalid_state);
        }
    }
#endif
}

/** The guards of the incremental open on a made gcm: the IV, the tag, the state and the length. */
template <class Aead>
void incremental_open_guards_of(Aead& made, gcm_case const& c) {
    auto const iv = from_hex(c.iv);
    auto const ciphertext = from_hex(c.ciphertext);
    auto const tag = from_hex(c.tag);
    std::array<std::uint8_t, 129> const long_iv{};
    BOOST_TEST(made.begin_open({}, {}).error() == crypto::error::invalid_iv_size);
    BOOST_TEST(made.begin_open(long_iv, {}).error() == crypto::error::invalid_iv_size);
    BOOST_TEST(made.authenticate(ciphertext).error() == crypto::error::invalid_state);
    BOOST_TEST(made.begin_open(iv, {}).has_value());
    BOOST_TEST(made.authenticate(ciphertext).has_value());
    BOOST_TEST(made.verify(std::span(tag).first(15)).error() == crypto::error::invalid_tag_size);
    BOOST_TEST(made.verify(tag).error() == crypto::error::invalid_state);  // it ended
    incremental_open_too_long(made, iv, tag);
    auto const opened = open_in_two_passes(made, iv, {}, ciphertext, tag, 16);
    BOOST_TEST_EQ(to_hex(opened), c.plaintext);
}

/** The guards of the incremental open: the IV, the tag, the state and the length. */
template <class Backend>
void incremental_open_guards(gcm_cases cases = gcm_spec_cases) {
    auto const& c = cases[13];
    with_gcm<Backend>(from_hex(c.key), [&](auto made) {
        if (BOOST_TEST(made.has_value())) {
            incremental_open_guards_of(*made, c);
        }
    });
}

/** A one-shot seal or open during an incremental open is refused, and leaves the open going. */
template <class Aead>
void incremental_open_beside_one_shot(Aead& made, gcm_case const& c) {
    auto const iv = from_hex(c.iv);
    auto const tag = from_hex(c.tag);
    std::array<std::uint8_t, 16> other{};
    other.fill(9);
    auto const untouched = other;
    auto data = from_hex(c.ciphertext);
    BOOST_TEST(made.begin_open(iv, {}).has_value());
    BOOST_TEST(made.authenticate(data).has_value());
    BOOST_TEST(made.seal(iv, {}, other).error() == crypto::error::invalid_state);
    BOOST_TEST(made.open(iv, {}, other, tag).error() == crypto::error::invalid_state);
    BOOST_TEST(made.verify(tag).has_value());
    BOOST_TEST(made.seal(iv, {}, other).error() == crypto::error::invalid_state);
    BOOST_TEST(made.open(iv, {}, other, tag).error() == crypto::error::invalid_state);
    BOOST_TEST(other == untouched);
    BOOST_TEST(made.decrypt(data).has_value());
    BOOST_TEST(made.end_open().has_value());
    BOOST_TEST_EQ(to_hex(data), c.plaintext);
}

/**
 * The incremental seal's calls during an open: begin_seal, update and result are refused and end
 * it; begin_open during a seal ends the seal. A fresh open follows.
 */
template <class Aead>
void incremental_open_beside_seal(Aead& made, gcm_case const& c) {
    auto const iv = from_hex(c.iv);
    auto const ciphertext = from_hex(c.ciphertext);
    auto const tag = from_hex(c.tag);
    std::array<std::uint8_t, 16> other{};
    other.fill(9);
    auto const untouched = other;

    // begin_seal ends it.
    BOOST_TEST(made.begin_open(iv, {}).has_value());
    BOOST_TEST(made.begin_seal(iv, {}).error() == crypto::error::invalid_state);
    BOOST_TEST(made.authenticate(ciphertext).error() == crypto::error::invalid_state);

    // update and result are refused, and end it.
    BOOST_TEST(made.begin_open(iv, {}).has_value());
    BOOST_TEST(made.update(other).error() == crypto::error::invalid_state);
    BOOST_TEST(other == untouched);
    BOOST_TEST(made.authenticate(ciphertext).error() == crypto::error::invalid_state);
    BOOST_TEST(made.begin_open(iv, {}).has_value());
    BOOST_TEST(made.result().error() == crypto::error::invalid_state);
    BOOST_TEST(made.authenticate(ciphertext).error() == crypto::error::invalid_state);

    // begin_open during a seal ends the seal.
    BOOST_TEST(made.begin_seal(iv, {}).has_value());
    BOOST_TEST(made.begin_open(iv, {}).error() == crypto::error::invalid_state);
    BOOST_TEST(made.result().error() == crypto::error::invalid_state);

    auto const opened = open_in_two_passes(made, iv, {}, ciphertext, tag, 7);
    BOOST_TEST_EQ(to_hex(opened), c.plaintext);
}

/** Other calls during an open, and an open begun during a seal. */
template <class Backend>
void incremental_open_interleaved(gcm_cases cases = gcm_spec_cases) {
    auto const& c = cases[13];
    with_gcm<Backend>(from_hex(c.key), [&](auto made) {
        if (BOOST_TEST(made.has_value())) {
            incremental_open_beside_one_shot(*made, c);
            incremental_open_beside_seal(*made, c);
        }
    });
}

/** A gcm moved during `authenticate`: the destination has no message, and opens afresh. */
template <class Backend>
void incremental_open_moved(gcm_cases cases = gcm_spec_cases) {
    auto const& c = cases[13];
    with_gcm<Backend>(from_hex(c.key), [&](auto made) {
        if (!BOOST_TEST(made.has_value())) {
            return;
        }
        auto const iv = from_hex(c.iv);
        auto const ciphertext = from_hex(c.ciphertext);
        auto const tag = from_hex(c.tag);
        BOOST_TEST(made->begin_open(iv, {}).has_value());
        BOOST_TEST(made->authenticate(std::span(ciphertext).first(5)).has_value());
        auto moved = std::move(*made);
        BOOST_TEST(moved.verify(tag).error() == crypto::error::invalid_state);
        BOOST_TEST(made->verify(tag).error() == crypto::error::invalid_state);
        BOOST_TEST(made->begin_open(iv, {}).error() == crypto::error::invalid_state);
        auto const opened = open_in_two_passes(moved, iv, {}, ciphertext, tag, 16);
        BOOST_TEST_EQ(to_hex(opened), c.plaintext);
    });
}

/** The incremental open (the requirement "GCM: the incremental open, in two passes"). */
template <class Backend>
void check_incremental_open(gcm_cases cases = gcm_spec_cases) {
    if (!BOOST_TEST_EQ(cases.size(), gcm_spec_cases.size())) {
        return;
    }
    incremental_open_pieces<Backend>(cases);
    incremental_open_wrong_tag<Backend>(cases);
    incremental_open_decrypt_before_verify<Backend>(cases);
    incremental_open_longer_second_pass<Backend>(cases);
    incremental_open_shorter_second_pass<Backend>(cases);
    incremental_open_guards<Backend>(cases);
    incremental_open_interleaved<Backend>(cases);
    incremental_open_moved<Backend>(cases);
}

#if !defined(__wasi__) && !defined(__EMSCRIPTEN__)
/**
 * The message's limit, refused before any byte is read: in one call to seal and open, and
 * summed over update. The additional data's own limit (2^61 - 1 bytes) cannot be reached by
 * a span a guard refuses before reading; it is pinned by detail::exceeds's test. A real backend
 * (`Specified`) then seals a fresh message as the specification says.
 */
template <class Backend, bool Specified = true>
void check_limits() {
    using checked_aead = crypto::ciphers::gcm<crypto::ciphers::aes256<Backend>>;
    static_assert(sizeof(std::size_t) == 8, "the limits are reachable only with 64-bit sizes");
    std::array<std::uint8_t, 32> const key{};
    std::array<std::uint8_t, 12> const iv{};
    auto made = checked_aead::make(key);
    auto const huge = reserved(static_cast<std::size_t>(checked_aead::max_message_size) + 1);
    if (!BOOST_TEST(made.has_value()) || !BOOST_TEST(!huge.empty())) {
        return;
    }
    BOOST_TEST(made->seal(iv, {}, huge).error() == crypto::error::message_too_long);
    std::array<std::uint8_t, 16> const tag{};
    BOOST_TEST(made->open(iv, {}, huge, tag).error() == crypto::error::message_too_long);
    std::array<std::uint8_t, 16> first{};
    BOOST_TEST(made->begin_seal(iv, {}).has_value());
    BOOST_TEST(made->update(first).has_value());
    BOOST_TEST(
        made->update(huge.first(static_cast<std::size_t>(checked_aead::max_message_size) - 15))
            .error() == crypto::error::message_too_long);
    BOOST_TEST(made->result().error() == crypto::error::invalid_state);  // the error ended it
    // The error ends the message, not the object: a fresh message seals as the specification
    // says (case 14: AES-256, the zero key and IV, one zero block). The mock answers its own.
    if constexpr (Specified) {
        expect_fresh_message(*made, iv, gcm_spec_cases[13]);
    }
}
#endif

}  // namespace webcpp::test

#endif
