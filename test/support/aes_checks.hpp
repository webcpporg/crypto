// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The checks of the block cipher on one backend that exports it, whatever its algorithm:
// the guards and their order, the round trip, blocks that are independent, and moved-from
// objects (spec section 2.3), and FIPS-197 appendix C's known answers, which every backend
// that exports the block cipher must give.

#ifndef WEBCPP_TEST_CRYPTO_SUPPORT_AES_CHECKS_HPP
#define WEBCPP_TEST_CRYPTO_SUPPORT_AES_CHECKS_HPP

#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/crypto/error.hpp>

#include "hex.hpp"

#include <boost/core/lightweight_test.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <utility>

namespace webcpp::test {

/** A key of the cipher's size whose bytes differ from one another. */
template <class Cipher>
std::array<std::uint8_t, Cipher::key_size> block_key() {
    std::array<std::uint8_t, Cipher::key_size> key{};
    for (std::size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<std::uint8_t>((i * 13) + 7);
    }
    return key;
}

/** Every guard of spec section 2.3, in its order, each leaving the data untouched. */
template <class Cipher>
void check_block_guards() {
    std::array<std::uint8_t, Cipher::key_size + 1> const long_key{};
    BOOST_TEST(Cipher::from_key(std::span(long_key).first(Cipher::key_size - 1)).error() ==
               webcpp::crypto::error::invalid_key_size);
    BOOST_TEST(Cipher::from_key(long_key).error() == webcpp::crypto::error::invalid_key_size);
    BOOST_TEST(Cipher::from_key({}).error() == webcpp::crypto::error::invalid_key_size);

    auto made = Cipher::from_key(block_key<Cipher>());
    if (!BOOST_TEST(made.has_value())) {
        return;
    }
    std::array<std::uint8_t, 33> data{};
    data.fill(0x3c);
    auto const untouched = data;
    for (std::size_t const size :
         {std::size_t{1}, std::size_t{15}, std::size_t{17}, std::size_t{31}, std::size_t{33}}) {
        BOOST_TEST(made->encrypt(std::span(data).first(size)).error() ==
                   webcpp::crypto::error::invalid_input_size);
        BOOST_TEST(made->decrypt(std::span(data).first(size)).error() ==
                   webcpp::crypto::error::invalid_input_size);
    }
    BOOST_TEST(data == untouched);
    // No block at all is a whole number of blocks, through a span whose data() is null.
    BOOST_TEST(made->encrypt(std::span<std::uint8_t>()).has_value());
    BOOST_TEST(made->decrypt(std::span<std::uint8_t>()).has_value());
}

/** Encryption changes the blocks, decryption gives them back, and blocks are independent. */
template <class Cipher>
void check_block_round_trip() {
    auto made = Cipher::from_key(block_key<Cipher>());
    if (!BOOST_TEST(made.has_value())) {
        return;
    }
    std::array<std::uint8_t, 48> blocks{};
    for (std::size_t i = 0; i < blocks.size(); ++i) {
        blocks[i] = static_cast<std::uint8_t>((i * 5) + 1);
    }
    auto const plain = blocks;
    BOOST_TEST(made->encrypt(blocks).has_value());
    BOOST_TEST(blocks != plain);
    // Each block encrypted alone gives what the three together give.
    auto one_by_one = plain;
    for (std::size_t at = 0; at < one_by_one.size(); at += Cipher::block_size) {
        BOOST_TEST(
            made->encrypt(std::span(one_by_one).subspan(at, Cipher::block_size)).has_value());
    }
    BOOST_TEST(one_by_one == blocks);
    BOOST_TEST(made->decrypt(blocks).has_value());
    BOOST_TEST(blocks == plain);

    // Another key gives other blocks.
    auto other_key = block_key<Cipher>();
    other_key[0] ^= 1U;
    auto other = Cipher::from_key(other_key);
    if (!BOOST_TEST(other.has_value())) {
        return;
    }
    auto under_other = plain;
    BOOST_TEST(other->encrypt(under_other).has_value());
    BOOST_TEST(under_other != one_by_one);
}

/** A moved-from cipher answers invalid_state to everything but assignment and destruction. */
template <class Cipher>
void check_block_moved_from() {
    auto made = Cipher::from_key(block_key<Cipher>());
    if (!BOOST_TEST(made.has_value())) {
        return;
    }
    std::array<std::uint8_t, 16> expected{};
    BOOST_TEST(made->encrypt(expected).has_value());

    Cipher moved = std::move(*made);
    std::array<std::uint8_t, 16> data{};
    data.fill(0x6c);
    auto const untouched = data;
    auto const all_refused = [&](Cipher& empty) {
        BOOST_TEST(empty.encrypt(data).error() == webcpp::crypto::error::invalid_state);
        BOOST_TEST(empty.decrypt(data).error() == webcpp::crypto::error::invalid_state);
        // The state is checked before the size.
        BOOST_TEST(empty.encrypt(std::span(data).first(3)).error() ==
                   webcpp::crypto::error::invalid_state);
        BOOST_TEST(data == untouched);
    };
    all_refused(*made);
    // Moving an object that was moved from gives an empty object, and crashes nothing (I1).
    Cipher again = std::move(*made);
    all_refused(again);
    all_refused(*made);
    again = std::move(*made);
    all_refused(again);
    // The destination has the key.
    std::array<std::uint8_t, 16> block{};
    BOOST_TEST(moved.encrypt(block).has_value());
    BOOST_TEST(block == expected);
    // A swap of an empty object and a live one moves the key, both ways.
    std::swap(again, moved);
    block.fill(0);
    BOOST_TEST(again.encrypt(block).has_value());
    BOOST_TEST(block == expected);
    all_refused(moved);
    // Assignment over a live object replaces its key; assignment back makes the source whole.
    *made = std::move(again);
    block.fill(0);
    BOOST_TEST(made->encrypt(block).has_value());
    BOOST_TEST(block == expected);
    all_refused(again);
    // Self-move-assignment leaves the key in place.
    auto& self = *made;
    *made = std::move(self);
    block.fill(0);
    BOOST_TEST(made->encrypt(block).has_value());
    BOOST_TEST(block == expected);
}

/** Every check of the block cipher, for aes128, aes192 and aes256 on Backend. */
template <class Backend>
void check_block_cipher() {
    check_block_guards<webcpp::crypto::ciphers::aes128<Backend>>();
    check_block_guards<webcpp::crypto::ciphers::aes192<Backend>>();
    check_block_guards<webcpp::crypto::ciphers::aes256<Backend>>();
    check_block_round_trip<webcpp::crypto::ciphers::aes128<Backend>>();
    check_block_round_trip<webcpp::crypto::ciphers::aes192<Backend>>();
    check_block_round_trip<webcpp::crypto::ciphers::aes256<Backend>>();
    check_block_moved_from<webcpp::crypto::ciphers::aes128<Backend>>();
    check_block_moved_from<webcpp::crypto::ciphers::aes192<Backend>>();
    check_block_moved_from<webcpp::crypto::ciphers::aes256<Backend>>();
}

/** Encrypts `plain` with `Cipher` under `key`, checks `expected`, and decrypts it back. */
template <class Cipher>
void check_answer(std::span<std::uint8_t const> key, std::string_view plain,
                  std::string_view expected) {
    auto made = Cipher::from_key(key);
    if (!BOOST_TEST(made.has_value())) {
        return;
    }
    auto const plaintext = from_hex(plain);
    auto block = plaintext;
    BOOST_TEST(made->encrypt(block).has_value());
    BOOST_TEST_EQ(to_hex(block), expected);
    BOOST_TEST(made->decrypt(block).has_value());
    BOOST_TEST(block == plaintext);
}

/** FIPS-197 appendix C.1, C.2 and C.3: the key 00 01 02 ..., the block 00 11 22 ... ff. */
template <class Backend>
void check_fips197() {
    std::array<std::uint8_t, 32> key{};
    for (std::size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<std::uint8_t>(i);
    }
    constexpr std::string_view plain = "00112233445566778899aabbccddeeff";
    check_answer<webcpp::crypto::ciphers::aes128<Backend>>(std::span(key).first(16), plain,
                                                           "69c4e0d86a7b0430d8cdb78070b4c55a");
    check_answer<webcpp::crypto::ciphers::aes192<Backend>>(std::span(key).first(24), plain,
                                                           "dda97ca4864cdfe06eaf70a0ec0d7191");
    check_answer<webcpp::crypto::ciphers::aes256<Backend>>(key, plain,
                                                           "8ea2b7ca516745bfeafc49904b496089");
}

}  // namespace webcpp::test

#endif
