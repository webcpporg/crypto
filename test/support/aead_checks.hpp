// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The checks of a ciphers::aead on one family and backend: the family's known answers, every
// guard in its order (the state, the IV's size, the tag's size, the length) each leaving the
// data untouched, tampering with every byte of the ciphertext, the tag, the additional data
// and the IV, each failing with authentication_failed and the data zeroed, moves of empty
// objects, empty inputs, and spans that touch or overlap (the genesis's Review Focus 2, 3
// and 6). The checks reach the object through an adapter (aead_calls), so that an object of
// another shape, as public_key_encryption::box, which has no additional data and is made of two
// keys, runs those that apply to it (ruling C35).
//
// The known answers: RFC 8439's section 2.8.2 and appendix A.5 for ChaCha20-Poly1305, the
// XChaCha draft's appendix A.3.1 for XChaCha20-Poly1305, and the cases of libsodium's own
// tests (test/default/aead_chacha20poly1305.exp and aead_xchacha20poly1305.exp) for the
// three.

#ifndef WEBCPP_TEST_CRYPTO_SUPPORT_AEAD_CHECKS_HPP
#define WEBCPP_TEST_CRYPTO_SUPPORT_AEAD_CHECKS_HPP

#include "gcm_checks.hpp"
#include "hex.hpp"

#if !defined(__wasi__) && !defined(__EMSCRIPTEN__)
#include "reserved.hpp"
#endif

#include <webcpp/crypto/ciphers/aead.hpp>
#include <webcpp/crypto/constant_time_equal.hpp>
#include <webcpp/crypto/error.hpp>

#include <boost/core/lightweight_test.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

namespace webcpp::test {

/** One known answer of an AEAD, every field in hex. */
struct aead_case {
    /** The key. */
    std::string_view key;
    /** The IV (the nonce). */
    std::string_view iv;
    /** The additional data. */
    std::string_view additional_data;
    /** The plaintext. */
    std::string_view plaintext;
    /** The ciphertext. */
    std::string_view ciphertext;
    /** The tag. */
    std::string_view tag;
};

/** "Ladies and Gentlemen of the class of '99: ...", the plaintext of RFC 8439 section 2.8.2. */
inline constexpr std::string_view sunscreen =
    "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a20"
    "4966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f722074686520"
    "6675747572652c2073756e73637265656e20776f756c642062652069742e";

/**
 * ChaCha20-Poly1305's known answers: RFC 8439 section 2.8.2, appendix A.5, and libsodium's
 * second case, section 2.8.2's without the additional data.
 */
inline constexpr std::array<aead_case, 3> chacha20_poly1305_cases{
    aead_case{
        .key = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
        .iv = "070000004041424344454647",
        .additional_data = "50515253c0c1c2c3c4c5c6c7",
        .plaintext = sunscreen,
        .ciphertext =
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fa"
            "fb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4"
            "fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116",
        .tag = "1ae10b594f09e26a7e902ecbd0600691",
    },
    aead_case{
        .key = "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
        .iv = "000000000102030405060708",
        .additional_data = "f33388860000000000004e91",
        .plaintext =
            "496e7465726e65742d4472616674732061726520647261667420646f63756d656e74732076616c696420"
            "666f722061206d6178696d756d206f6620736978206d6f6e74687320616e64206d617920626520757064"
            "617465642c207265706c616365642c206f72206f62736f6c65746564206279206f7468657220646f6375"
            "6d656e747320617420616e792074696d652e20497420697320696e617070726f70726961746520746f20"
            "75736520496e7465726e65742d447261667473206173207265666572656e6365206d6174657269616c20"
            "6f7220746f2063697465207468656d206f74686572207468616e206173202fe2809c776f726b20696e20"
            "70726f67726573732e2fe2809d",
        .ciphertext =
            "64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb24c6cfc18755d43eea09e"
            "e94e382d26b0bdb7b73c321b0100d4f03b7f355894cf332f830e710b97ce98c8a84abd0b948114ad176e"
            "008d33bd60f982b1ff37c8559797a06ef4f0ef61c186324e2b3506383606907b6a7c02b0f9f6157b53c8"
            "67e4b9166c767b804d46a59b5216cde7a4e99040c5a40433225ee282a1b0a06c523eaf4534d7f83fa115"
            "5b0047718cbc546a0d072b04b3564eea1b422273f548271a0bb2316053fa76991955ebd63159434ecebb"
            "4e466dae5a1073a6727627097a1049e617d91d361094fa68f0ff77987130305beaba2eda04df997b714d"
            "6c6f2c29a6ad5cb4022b02709b",
        .tag = "eead9d67890cbb22392336fea1851f38",
    },
    aead_case{
        .key = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
        .iv = "070000004041424344454647",
        .additional_data = "",
        .plaintext = sunscreen,
        .ciphertext =
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fa"
            "fb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4"
            "fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116",
        .tag = "6a23a4681fd59456aea1d29f82477216",
    },
};

/**
 * The original ChaCha20-Poly1305's known answers: libsodium's two, with and without the
 * additional data.
 */
inline constexpr std::array<aead_case, 2> chacha20_poly1305_original_cases{
    aead_case{
        .key = "4290bcb154173531f314af57f3be3b5006da371ece272afa1b5dbdd1100a1007",
        .iv = "cd7cf67be39c794a",
        .additional_data = "87e229d4500845a079c0",
        .plaintext = "86d09974840bded2a5ca",
        .ciphertext = "e3e446f7ede9a19b62a4",
        .tag = "677dabf4e3d24b876bb284753896e1d6",
    },
    aead_case{
        .key = "4290bcb154173531f314af57f3be3b5006da371ece272afa1b5dbdd1100a1007",
        .iv = "cd7cf67be39c794a",
        .additional_data = "",
        .plaintext = "86d09974840bded2a5ca",
        .ciphertext = "e3e446f7ede9a19b62a4",
        .tag = "69e7789bcd954e658ed38423e23161dc",
    },
};

/**
 * XChaCha20-Poly1305's known answers: the draft's appendix A.3.1, and libsodium's two, with
 * and without the additional data.
 */
inline constexpr std::array<aead_case, 3> xchacha20_poly1305_cases{
    aead_case{
        .key = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
        .iv = "404142434445464748494a4b4c4d4e4f5051525354555657",
        .additional_data = "50515253c0c1c2c3c4c5c6c7",
        .plaintext = sunscreen,
        .ciphertext =
            "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3"
            "a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2b"
            "c369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52e",
        .tag = "c0875924c1c7987947deafd8780acf49",
    },
    aead_case{
        .key = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
        .iv = "07000000404142434445464748494a4b4c4d4e4f50515253",
        .additional_data = "50515253c0c1c2c3c4c5c6c7",
        .plaintext = sunscreen,
        .ciphertext =
            "f8ebea4875044066fc162a0604e171feecfb3d20425248563bcfd5a155dcc47bbda70b86e5ab9b55002b"
            "d1274c02db35321acd7af8b2e2d25015e136b7679458e9f43243bf719d639badb5feac03f80a19a96ef1"
            "0cb1d15333a837b90946ba3854ee74da3f2585efc7e1e170e17e15e563e7",
        .tag = "7601f4f85cafa8e5877614e143e68420",
    },
    aead_case{
        .key = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
        .iv = "07000000404142434445464748494a4b4c4d4e4f50515253",
        .additional_data = "",
        .plaintext = sunscreen,
        .ciphertext =
            "f8ebea4875044066fc162a0604e171feecfb3d20425248563bcfd5a155dcc47bbda70b86e5ab9b55002b"
            "d1274c02db35321acd7af8b2e2d25015e136b7679458e9f43243bf719d639badb5feac03f80a19a96ef1"
            "0cb1d15333a837b90946ba3854ee74da3f2585efc7e1e170e17e15e563e7",
        .tag = "e096e033d91b63f7ac92e9972e0d43e5",
    },
};

/**
 * How the checks reach a `ciphers::aead`: made from `key_size` bytes, its calls its own. The
 * checks take such an adapter, so that an object of another shape runs those that apply to it:
 * `Calls` gives the object's type `object`, its sizes, `from_key(key)`, `seal(object&, iv,
 * additional_data, data)` and `open(object&, iv, additional_data, data, tag)`, and says whether
 * the object takes additional data (`has_additional_data`), whether it is made of one key of
 * `key_size` bytes (`one_key`, whose sizes the guards check) and whether its calls take
 * additional data at all (`takes_additional_data`, false for one whose calls have none).
 *
 * @tparam Aead A `ciphers::aead`.
 */
template <class Aead>
struct aead_calls {
    /** The object the checks make. */
    using object = Aead;
    /** The key's size. */
    static constexpr std::size_t key_size = Aead::key_size;
    /** The nonce's size. */
    static constexpr std::size_t iv_size = Aead::iv_size;
    /** The tag's size. */
    static constexpr std::size_t tag_size = Aead::tag_size;
    /** Whether a message carries additional data: not for a family whose limit is 0. */
    static constexpr bool has_additional_data = Aead::max_additional_data_size != 0;
    /** The calls take additional data, which a family whose limit is 0 refuses unless empty. */
    static constexpr bool takes_additional_data = true;
    /** Made of one key of `key_size` bytes. */
    static constexpr bool one_key = true;

    /** `Aead::from_key`. */
    static auto from_key(std::span<std::uint8_t const> key) { return Aead::from_key(key); }

    /** `seal`. */
    static auto seal(Aead& made, std::span<std::uint8_t const> iv,
                     std::span<std::uint8_t const> additional_data, std::span<std::uint8_t> data) {
        return made.seal(iv, additional_data, data);
    }

    /** `open`. */
    static auto open(Aead& made, std::span<std::uint8_t const> iv,
                     std::span<std::uint8_t const> additional_data, std::span<std::uint8_t> data,
                     std::span<std::uint8_t const> tag) {
        return made.open(iv, additional_data, data, tag);
    }
};

/** A key of the adapter's size, its bytes counting up from `first`. */
template <class Calls>
std::array<std::uint8_t, Calls::key_size> aead_key(std::uint8_t first = 1) {
    std::array<std::uint8_t, Calls::key_size> key{};
    for (std::size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<std::uint8_t>(first + i);
    }
    return key;
}

/** Seals and opens each known answer, and checks ciphertext and tag. */
template <class Calls>
void check_aead_cases(std::span<aead_case const> cases) {
    for (auto const& c : cases) {
        auto made = Calls::from_key(from_hex(c.key));
        if (!BOOST_TEST(made.has_value())) {
            continue;
        }
        auto const iv = from_hex(c.iv);
        auto const additional_data = from_hex(c.additional_data);
        auto const plaintext = from_hex(c.plaintext);
        auto const tag = from_hex(c.tag);
        auto data = plaintext;
        auto const sealed = Calls::seal(*made, iv, additional_data, data);
        BOOST_TEST(sealed.has_value());
        BOOST_TEST_EQ(to_hex(data), c.ciphertext);
        BOOST_TEST(sealed &&
                   crypto::constant_time_equal(*sealed, std::span<std::uint8_t const>(tag)));
        BOOST_TEST(Calls::open(*made, iv, additional_data, data, tag).has_value());
        BOOST_TEST_EQ(to_hex(data), c.plaintext);
    }
}

/** The key's size, for an object made of one key: any other is refused with invalid_key_size. */
template <class Calls>
void check_aead_key_sizes() {
    for (std::size_t const size : {std::size_t{0}, Calls::key_size - 1, Calls::key_size + 1}) {
        std::vector<std::uint8_t> const wrong_key(size, 7);
        BOOST_TEST(Calls::from_key(wrong_key).error() == crypto::error::invalid_key_size);
    }
}

/** The IV's size, then the tag's: each refused, the IV's before the tag's. */
template <class Calls>
void check_aead_iv_and_tag_sizes(typename Calls::object& made, std::span<std::uint8_t> data) {
    std::vector<std::uint8_t> const iv(Calls::iv_size, 9);
    std::array<std::uint8_t, Calls::tag_size> const tag{};
    // Every IV size but the family's: none, one byte less and more, and the other families'.
    std::array<std::size_t, 6> const sizes{0, Calls::iv_size - 1, Calls::iv_size + 1, 8, 12, 24};
    for (std::size_t const size : sizes) {
        if (size == Calls::iv_size) {
            continue;
        }
        std::vector<std::uint8_t> const wrong_iv(size, 9);
        BOOST_TEST(Calls::seal(made, wrong_iv, {}, data).error() == crypto::error::invalid_iv_size);
        BOOST_TEST(Calls::open(made, wrong_iv, {}, data, tag).error() ==
                   crypto::error::invalid_iv_size);
    }
    for (std::size_t const size : {std::size_t{0}, Calls::tag_size - 1, Calls::tag_size + 1}) {
        std::vector<std::uint8_t> const wrong_tag(size);
        BOOST_TEST(Calls::open(made, iv, {}, data, wrong_tag).error() ==
                   crypto::error::invalid_tag_size);
    }
    // The IV is checked before the tag: both wrong gives the IV's error.
    BOOST_TEST(Calls::open(made, {}, {}, data, std::span(tag).first(Calls::tag_size - 1)).error() ==
               crypto::error::invalid_iv_size);
}

/**
 * A family that takes no additional data refuses a non-empty one with invalid_input_size,
 * after the IV and the tag.
 */
template <class Calls>
void check_aead_no_additional_data(typename Calls::object& made, std::span<std::uint8_t> data) {
    std::vector<std::uint8_t> const iv(Calls::iv_size, 9);
    std::array<std::uint8_t, Calls::tag_size> const tag{};
    std::array<std::uint8_t, 1> const additional_data{5};
    BOOST_TEST(Calls::seal(made, iv, additional_data, data).error() ==
               crypto::error::invalid_input_size);
    BOOST_TEST(Calls::open(made, iv, additional_data, data, tag).error() ==
               crypto::error::invalid_input_size);
    BOOST_TEST(Calls::seal(made, {}, additional_data, data).error() ==
               crypto::error::invalid_iv_size);
    BOOST_TEST(Calls::open(made, iv, additional_data, data, std::span(tag).first(1)).error() ==
               crypto::error::invalid_tag_size);
}

/**
 * Every guard but the length's, in its order: the key's size, for an object of one key; the
 * state before the IV, the tag and, for a family that takes no additional data, a non-empty
 * one; the IV's size before the tag's; for such a family, a non-empty additional data refused
 * with invalid_input_size, after the IV and the tag.
 * Each refusal leaves the data untouched.
 */
template <class Calls>
void check_aead_guards() {
    if constexpr (Calls::one_key) {
        check_aead_key_sizes<Calls>();
    }
    auto made = Calls::from_key(aead_key<Calls>());
    if (!BOOST_TEST(made.has_value())) {
        return;
    }
    std::array<std::uint8_t, 20> data{};
    data.fill(0x33);
    auto const untouched = data;
    check_aead_iv_and_tag_sizes<Calls>(*made, data);
    if constexpr (Calls::takes_additional_data && !Calls::has_additional_data) {
        check_aead_no_additional_data<Calls>(*made, data);
    }
    BOOST_TEST(data == untouched);
    // The state is checked before the IV and the tag.
    typename Calls::object const moved = std::move(*made);
    BOOST_TEST(Calls::seal(*made, {}, {}, data).error() == crypto::error::invalid_state);
    BOOST_TEST(Calls::open(*made, {}, {}, data, {}).error() == crypto::error::invalid_state);
    if constexpr (Calls::takes_additional_data && !Calls::has_additional_data) {
        // And before the additional data a family that takes none refuses.
        std::array<std::uint8_t, 1> const additional_data{5};
        BOOST_TEST(Calls::seal(*made, {}, additional_data, data).error() ==
                   crypto::error::invalid_state);
        BOOST_TEST(Calls::open(*made, {}, additional_data, data, {}).error() ==
                   crypto::error::invalid_state);
    }
    BOOST_TEST(data == untouched);
}

/** An open of a changed message fails with authentication_failed and zeroes the data. */
template <class Calls>
void expect_aead_tampered(typename Calls::object& made, std::span<std::uint8_t const> iv,
                          std::span<std::uint8_t const> additional_data,
                          std::span<std::uint8_t> data, std::span<std::uint8_t const> tag) {
    BOOST_TEST(Calls::open(made, iv, additional_data, data, tag).error() ==
               crypto::error::authentication_failed);
    BOOST_TEST(all_zero(data));
}

/**
 * Changing any byte of the ciphertext, the tag, the additional data (where the family has it)
 * or the IV of a known answer fails, and zeroes the data; so does a ciphertext one byte
 * shorter. The object works after the failures.
 */
template <class Calls>
void check_aead_tampering(aead_case const& c) {
    auto const key = from_hex(c.key);
    auto const iv = from_hex(c.iv);
    auto const additional_data = from_hex(c.additional_data);
    auto const ciphertext = from_hex(c.ciphertext);
    auto const tag = from_hex(c.tag);
    auto made = Calls::from_key(key);
    if (!BOOST_TEST(made.has_value()) || !BOOST_TEST(!ciphertext.empty()) ||
        !BOOST_TEST(additional_data.empty() != Calls::has_additional_data)) {
        return;
    }
    for (std::size_t i = 0; i < ciphertext.size(); ++i) {
        auto data = ciphertext;
        data[i] ^= 1U;
        expect_aead_tampered<Calls>(*made, iv, additional_data, data, tag);
    }
    // The tag, the additional data and the IV are each copied once, and each byte of the copy
    // is changed, then changed back.
    {
        auto bad = tag;
        for (std::size_t i = 0; i < bad.size(); ++i) {
            auto data = ciphertext;
            bad[i] ^= 0x80U;
            expect_aead_tampered<Calls>(*made, iv, additional_data, data, bad);
            bad[i] ^= 0x80U;
        }
    }
    {
        auto bad = additional_data;
        for (std::size_t i = 0; i < bad.size(); ++i) {
            auto data = ciphertext;
            bad[i] ^= 2U;
            expect_aead_tampered<Calls>(*made, iv, bad, data, tag);
            bad[i] ^= 2U;
        }
    }
    {
        auto bad = iv;
        for (std::size_t i = 0; i < bad.size(); ++i) {
            auto data = ciphertext;
            bad[i] ^= 4U;
            expect_aead_tampered<Calls>(*made, bad, additional_data, data, tag);
            bad[i] ^= 4U;
        }
    }
    {
        auto data = ciphertext;
        expect_aead_tampered<Calls>(*made, iv, additional_data,
                                    std::span(data).first(data.size() - 1), tag);
    }
    if constexpr (Calls::has_additional_data) {
        // Without its additional data, the message does not open either.
        auto data = ciphertext;
        expect_aead_tampered<Calls>(*made, iv, {}, data, tag);
    }
    auto data = ciphertext;
    BOOST_TEST(Calls::open(*made, iv, additional_data, data, tag).has_value());
    BOOST_TEST_EQ(to_hex(data), c.plaintext);
}

/** Every call of an empty AEAD is refused with invalid_state, and leaves the data untouched. */
template <class Calls>
void expect_aead_refused(typename Calls::object& empty, std::span<std::uint8_t const> iv,
                         std::span<std::uint8_t> data, std::span<std::uint8_t const> tag,
                         std::span<std::uint8_t const> untouched) {
    BOOST_TEST(Calls::seal(empty, iv, {}, data).error() == crypto::error::invalid_state);
    BOOST_TEST(Calls::open(empty, iv, {}, data, tag).error() == crypto::error::invalid_state);
    BOOST_TEST(Calls::seal(empty, iv, {}, {}).error() == crypto::error::invalid_state);
    BOOST_TEST(Calls::open(empty, iv, {}, {}, tag).error() == crypto::error::invalid_state);
    BOOST_TEST(std::ranges::equal(data, untouched));
}

/**
 * Moves (Review Focus 6): a moved-from AEAD answers invalid_state to everything but assignment
 * and destruction; moving it, empty, gives an empty one; the destination, a swap and an
 * assignment back carry the key; a self-move keeps it.
 */
template <class Calls>
void check_aead_moves(aead_case const& c) {
    using object = Calls::object;
    auto const iv = from_hex(c.iv);
    auto const additional_data = from_hex(c.additional_data);
    auto const plaintext = from_hex(c.plaintext);
    auto made = Calls::from_key(from_hex(c.key));
    if (!BOOST_TEST(made.has_value())) {
        return;
    }
    // Seals the case's plaintext with an AEAD, which gives the case's ciphertext and tag.
    auto const seals_the_case = [&](object& aead) {
        auto data = plaintext;
        auto const sealed = Calls::seal(aead, iv, additional_data, data);
        return sealed && to_hex(data) == c.ciphertext && to_hex(*sealed) == c.tag;
    };
    object moved = std::move(*made);
    std::array<std::uint8_t, Calls::tag_size> const tag{};
    std::array<std::uint8_t, 16> data{};
    data.fill(0x6c);  // a guard's refusal leaves this pattern, not only zeroes, untouched
    auto const untouched = data;
    auto const all_refused = [&](object& empty) {
        expect_aead_refused<Calls>(empty, iv, data, tag, untouched);
    };
    all_refused(*made);
    BOOST_TEST(seals_the_case(moved));
    // Moving an object that was moved from gives an empty object.
    object again = std::move(*made);
    all_refused(again);
    all_refused(*made);
    again = std::move(*made);
    all_refused(again);
    all_refused(*made);
    // A swap of an empty object and a live one moves the key, both ways.
    std::swap(again, moved);
    BOOST_TEST(seals_the_case(again));
    all_refused(moved);
    std::swap(again, moved);
    BOOST_TEST(seals_the_case(moved));
    all_refused(again);
    // An assignment over a live object from an empty one leaves it empty.
    auto other = Calls::from_key(from_hex(c.key));
    if (!BOOST_TEST(other.has_value())) {
        return;
    }
    *other = std::move(again);
    all_refused(*other);
    // An assignment back makes the source whole again.
    *made = std::move(moved);
    BOOST_TEST(seals_the_case(*made));
    all_refused(moved);
    // A self-move-assignment leaves the key in place.
    auto& self = *made;
    *made = std::move(self);
    BOOST_TEST(seals_the_case(*made));
}

/**
 * Empty inputs (Review Focus 3): an empty message and empty additional data, through spans
 * whose data() is null, seal and open; a zero tag does not open them; each of the two empty
 * alone seals and opens (the additional data alone where the family has it).
 */
template <class Calls>
void check_aead_empty(typename Calls::object& made, std::span<std::uint8_t const> iv) {
    auto const empty =
        Calls::seal(made, iv, std::span<std::uint8_t const>(), std::span<std::uint8_t>());
    BOOST_TEST(empty.has_value());
    BOOST_TEST(empty && Calls::open(made, iv, {}, std::span<std::uint8_t>(), *empty).has_value());
    std::array<std::uint8_t, Calls::tag_size> const zero_tag{};
    BOOST_TEST(Calls::open(made, iv, {}, std::span<std::uint8_t>(), zero_tag).error() ==
               crypto::error::authentication_failed);
    if constexpr (Calls::has_additional_data) {
        std::array<std::uint8_t, 5> const additional_data{1, 2, 3, 4, 5};
        auto const only_additional =
            Calls::seal(made, iv, additional_data, std::span<std::uint8_t>());
        BOOST_TEST(only_additional && empty &&
                   !crypto::constant_time_equal(*only_additional, *empty));
        BOOST_TEST(only_additional && Calls::open(made, iv, additional_data,
                                                  std::span<std::uint8_t>(), *only_additional)
                                          .has_value());
        BOOST_TEST(only_additional &&
                   Calls::open(made, iv, {}, std::span<std::uint8_t>(), *only_additional).error() ==
                       crypto::error::authentication_failed);
    }
    std::array<std::uint8_t, 7> data{};
    data.fill(0x42);
    auto const original = data;
    auto const only_data = Calls::seal(made, iv, {}, data);
    BOOST_TEST(only_data.has_value() && data != original);
    BOOST_TEST(only_data && Calls::open(made, iv, {}, data, *only_data).has_value());
    BOOST_TEST(data == original);
}

/** A tag right after the data in one buffer: the open leaves the tag's bytes as they were. */
template <class Calls>
void check_aead_wire_tag(typename Calls::object& made, std::span<std::uint8_t const> iv) {
    std::array<std::uint8_t, 16 + Calls::tag_size> wire{};
    std::fill(wire.begin(), wire.begin() + 16, 0x33);
    auto const sealed = Calls::seal(made, iv, {}, std::span(wire).first(16));
    if (!BOOST_TEST(sealed.has_value())) {
        return;
    }
    std::ranges::copy(*sealed, wire.begin() + 16);
    BOOST_TEST(
        Calls::open(made, iv, {}, std::span(wire).first(16), std::span(wire).last(Calls::tag_size))
            .has_value());
    BOOST_TEST(
        std::all_of(wire.begin(), wire.begin() + 16, [](std::uint8_t b) { return b == 0x33; }));
    BOOST_TEST(std::equal(sealed->begin(), sealed->end(), wire.begin() + 16));
}

/**
 * A tag that overlaps the data's end fails cleanly (Review Focus 2): the data is zeroed, and
 * the bytes after the data, which only the tag covers, are as they were.
 */
template <class Calls>
void check_aead_overlap(typename Calls::object& made, std::span<std::uint8_t const> iv) {
    std::array<std::uint8_t, 24> overlap{};
    overlap.fill(0x5a);
    BOOST_TEST(Calls::open(made, iv, {}, std::span(overlap).first(20),
                           std::span(overlap).last(Calls::tag_size))
                   .error() == crypto::error::authentication_failed);
    BOOST_TEST(all_zero(std::span(overlap).first(20)));
    BOOST_TEST(
        std::all_of(overlap.begin() + 20, overlap.end(), [](std::uint8_t b) { return b == 0x5a; }));
}

/**
 * An IV inside the sealed buffer, and additional data (where the family has it) just before it
 * in the same buffer, give what copies of them give: the IV is read before the first byte of
 * the data is written, and the additional data, which may touch the data but not overlap it,
 * is left as it was.
 */
template <class Calls>
void check_aead_in_place(typename Calls::object& made) {
    constexpr std::size_t additional_size = Calls::has_additional_data ? 16 : 0;
    std::array<std::uint8_t, additional_size + Calls::iv_size + 16> buffer{};
    for (std::size_t i = 0; i < buffer.size(); ++i) {
        buffer[i] = static_cast<std::uint8_t>((i * 7) + 1);
    }
    auto const original = buffer;
    std::array<std::uint8_t, Calls::iv_size> iv_copy{};
    std::array<std::uint8_t, additional_size> additional_copy{};
    std::copy_n(buffer.begin(), additional_size, additional_copy.begin());
    std::copy_n(buffer.begin() + additional_size, Calls::iv_size, iv_copy.begin());
    std::array<std::uint8_t, Calls::iv_size + 16> data_copy{};
    std::copy_n(buffer.begin() + additional_size, data_copy.size(), data_copy.begin());
    auto const expected = Calls::seal(made, iv_copy, additional_copy, data_copy);
    auto const data = std::span(buffer).subspan(additional_size);
    auto const in_place = Calls::seal(made, data.first(Calls::iv_size),
                                      std::span(buffer).first(additional_size), data);
    BOOST_TEST(expected && in_place && to_hex(*expected) == to_hex(*in_place));
    BOOST_TEST(std::equal(data_copy.begin(), data_copy.end(), data.begin()));
    BOOST_TEST(std::equal(original.begin(), original.begin() + additional_size, buffer.begin()));
}

/**
 * A wire buffer [IV | additional data | ciphertext], the additional data where the family has
 * it, opened in place with spans into it, gives what an open of copies gives, and leaves the IV
 * and the additional data as they were.
 */
template <class Calls>
void check_aead_wire_open(typename Calls::object& made) {
    constexpr std::size_t additional_size = Calls::has_additional_data ? 16 : 0;
    std::array<std::uint8_t, Calls::iv_size> wire_iv{};
    std::array<std::uint8_t, additional_size> wire_additional{};
    std::array<std::uint8_t, 32> wire_plain{};
    for (std::size_t i = 0; i < wire_plain.size(); ++i) {
        wire_plain[i] = static_cast<std::uint8_t>((i * 11) + 3);
    }
    wire_iv.fill(0x17);
    wire_additional.fill(0x29);
    auto wire_data = wire_plain;
    auto const wire_sealed = Calls::seal(made, wire_iv, wire_additional, wire_data);
    if (!BOOST_TEST(wire_sealed.has_value())) {
        return;
    }
    constexpr std::size_t data_at = Calls::iv_size + additional_size;
    std::array<std::uint8_t, data_at + 32> message{};
    std::ranges::copy(wire_iv, message.begin());
    std::ranges::copy(wire_additional, message.begin() + Calls::iv_size);
    std::ranges::copy(wire_data, message.begin() + data_at);
    auto copy_data = wire_data;
    BOOST_TEST(Calls::open(made, wire_iv, wire_additional, copy_data, *wire_sealed).has_value());
    BOOST_TEST(Calls::open(made, std::span(message).first(Calls::iv_size),
                           std::span(message).subspan(Calls::iv_size, additional_size),
                           std::span(message).subspan(data_at), *wire_sealed)
                   .has_value());
    BOOST_TEST(std::equal(copy_data.begin(), copy_data.end(), message.begin() + data_at));
    BOOST_TEST(copy_data == wire_plain);
    BOOST_TEST(std::equal(wire_iv.begin(), wire_iv.end(), message.begin()));
    BOOST_TEST(std::equal(wire_additional.begin(), wire_additional.end(),
                          message.begin() + Calls::iv_size));
}

/** Empty inputs, and spans that touch or overlap (Review Focus 2 and 3). */
template <class Calls>
void check_aead_edges() {
    auto made = Calls::from_key(aead_key<Calls>());
    if (!BOOST_TEST(made.has_value())) {
        return;
    }
    std::array<std::uint8_t, Calls::iv_size> iv{};
    iv.fill(0x24);
    check_aead_empty<Calls>(*made, iv);
    check_aead_wire_tag<Calls>(*made, iv);
    check_aead_overlap<Calls>(*made, iv);
    check_aead_in_place<Calls>(*made);
    check_aead_wire_open<Calls>(*made);
}

/** Every check of this file on one object, through its adapter, against its known answers. */
template <class Calls>
void check_aead_with(std::span<aead_case const> cases) {
    check_aead_cases<Calls>(cases);
    check_aead_guards<Calls>();
    check_aead_tampering<Calls>(cases.front());
    check_aead_moves<Calls>(cases.front());
    check_aead_edges<Calls>();
}

/** Every check of this file on one `ciphers::aead`, against the family's known answers. */
template <class Aead>
void check_aead(std::span<aead_case const> cases) {
    check_aead_with<aead_calls<Aead>>(cases);
}

#if !defined(__wasi__) && !defined(__EMSCRIPTEN__)
/**
 * The message's limit, the last guard, refused before any byte is read, where a span can pass
 * it: natively, on 64-bit targets, for a family whose limit is below the largest size, as
 * ChaCha20-Poly1305's 2^38 - 64 bytes. Each earlier guard is still checked first. The other
 * families' limits, 2^64 - 17 bytes, and the additional data's, 2^64 - 1, no span reaches.
 */
template <class Aead>
void check_aead_limits() {
    static_assert(sizeof(std::size_t) == 8, "the limits are reachable only with 64-bit sizes");
    static_assert(Aead::max_message_size < std::numeric_limits<std::size_t>::max());
    auto made = Aead::from_key(aead_key<Aead>());
    auto const huge = reserved(static_cast<std::size_t>(Aead::max_message_size) + 1);
    if (!BOOST_TEST(made.has_value()) || !BOOST_TEST(!huge.empty())) {
        return;
    }
    std::array<std::uint8_t, Aead::iv_size> const iv{};
    std::array<std::uint8_t, Aead::tag_size> const tag{};
    BOOST_TEST(made->seal(iv, {}, huge).error() == crypto::error::message_too_long);
    BOOST_TEST(made->open(iv, {}, huge, tag).error() == crypto::error::message_too_long);
    // The IV and the tag are checked before the length.
    BOOST_TEST(made->seal({}, {}, huge).error() == crypto::error::invalid_iv_size);
    BOOST_TEST(made->open(iv, {}, huge, std::span(tag).first(Aead::tag_size - 1)).error() ==
               crypto::error::invalid_tag_size);
    // The error ends nothing: the object seals afterwards.
    std::array<std::uint8_t, 16> data{};
    BOOST_TEST(made->seal(iv, {}, data).has_value());
    // The state is checked before the length.
    Aead const moved = std::move(*made);
    BOOST_TEST(made->seal(iv, {}, huge).error() == crypto::error::invalid_state);
}
#endif

}  // namespace webcpp::test

#endif
