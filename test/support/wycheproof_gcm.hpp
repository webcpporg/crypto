// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Wycheproof's 316 AES-GCM tests at 12fd3aaf (spec section 8.1): the 307 with an IV of 1
// to 128 bytes seal and open, the 226 valid matching and the 81 invalid failing with
// authentication_failed and data zeroed; the 6 with an empty IV give invalid_iv_size; the
// 3 with a 257-byte IV (tcId 268, 272, 276), valid in Wycheproof, give invalid_iv_size
// with data untouched, by the cap of section 2.4.

#ifndef WEBCPP_TEST_CRYPTO_SUPPORT_WYCHEPROOF_GCM_HPP
#define WEBCPP_TEST_CRYPTO_SUPPORT_WYCHEPROOF_GCM_HPP

#include "gcm_checks.hpp"
#include "hex.hpp"
#include "test_data.hpp"

#include <boost/json/parse.hpp>
#include <boost/json/value.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace webcpp::test {

/** The bytes of one of a test's hex fields. */
inline std::vector<std::uint8_t> wycheproof_bytes(boost::json::value const& test,
                                                  std::string_view field) {
    auto const& hex = test.at(field).as_string();
    return from_hex(std::string_view(hex.data(), hex.size()));
}

/** The counts of Wycheproof's AES-GCM tests, by how each ended. */
struct wycheproof_gcm_counts {
    /** Valid, opened and sealed, one shot and in pieces. */
    std::size_t valid = 0;
    /** Invalid, refused with authentication_failed and data zeroed. */
    std::size_t invalid = 0;
    /** An empty IV, refused with invalid_iv_size. */
    std::size_t empty_iv = 0;
    /** An IV over max_iv_size, refused with invalid_iv_size. */
    std::size_t over_cap = 0;
};

/** One of Wycheproof's AES-GCM tests, its fields as bytes. */
struct wycheproof_gcm_test {
    /** The key, 16, 24 or 32 bytes. */
    std::vector<std::uint8_t> key;
    /** The IV. */
    std::vector<std::uint8_t> iv;
    /** The additional data. */
    std::vector<std::uint8_t> additional_data;
    /** The plaintext. */
    std::vector<std::uint8_t> message;
    /** The ciphertext. */
    std::vector<std::uint8_t> ciphertext;
    /** The tag. */
    std::vector<std::uint8_t> tag;
    /** Whether Wycheproof's result is valid. */
    bool valid = false;
};

/** Runs one test through `made`, a gcm of the test's key, and counts how it ended. */
template <class Aead>
void check_wycheproof_gcm_test(Aead& made, wycheproof_gcm_test const& t,
                               wycheproof_gcm_counts& counts) {
    auto data = t.ciphertext;
    auto const opened = made.open(t.iv, t.additional_data, data, t.tag);
    if (t.iv.empty() || t.iv.size() > Aead::max_iv_size) {
        BOOST_TEST(opened.error() == crypto::error::invalid_iv_size);
        BOOST_TEST(data == t.ciphertext);
        // Sealed as well (spec section 2.4: the 257-byte IV is refused by seal too), and the
        // data is left as it was.
        auto plaintext = t.message;
        BOOST_TEST(made.seal(t.iv, t.additional_data, plaintext).error() ==
                   crypto::error::invalid_iv_size);
        BOOST_TEST(plaintext == t.message);
        ++(t.iv.empty() ? counts.empty_iv : counts.over_cap);
        return;
    }
    if (!t.valid) {
        BOOST_TEST(opened.error() == crypto::error::authentication_failed);
        BOOST_TEST(all_zero(data));
        ++counts.invalid;
        return;
    }
    BOOST_TEST(opened.has_value());
    BOOST_TEST(data == t.message);
    auto sealed_data = t.message;
    auto const sealed = made.seal(t.iv, t.additional_data, sealed_data);
    BOOST_TEST(sealed_data == t.ciphertext);
    BOOST_TEST(sealed && to_hex(*sealed) == to_hex(t.tag));
    // Sealed incrementally as well, in pieces of every size (I4).
    check_every_piece(made, t.iv, t.additional_data, t.message, to_hex(t.ciphertext),
                      to_hex(t.tag));
    ++counts.valid;
}

/** Wycheproof's AES-GCM tests through Backend, each counted by how it ended. */
template <class Backend>
void check_wycheproof_gcm() {
    auto const document = boost::json::parse(
        read_file(std::string(WEBCPP_TEST_WYCHEPROOF) + "/testvectors_v1/aes_gcm_test.json"));
    wycheproof_gcm_counts counts;
    for (auto const& group : document.at("testGroups").as_array()) {
        for (auto const& test : group.at("tests").as_array()) {
            wycheproof_gcm_test const t{
                .key = wycheproof_bytes(test, "key"),
                .iv = wycheproof_bytes(test, "iv"),
                .additional_data = wycheproof_bytes(test, "aad"),
                .message = wycheproof_bytes(test, "msg"),
                .ciphertext = wycheproof_bytes(test, "ct"),
                .tag = wycheproof_bytes(test, "tag"),
                .valid = test.at("result").as_string() == "valid",
            };
            with_gcm<Backend>(t.key, [&](auto made) {
                if (BOOST_TEST(made.has_value())) {
                    check_wycheproof_gcm_test(*made, t, counts);
                }
            });
        }
    }
    BOOST_TEST_EQ(counts.valid, 226U);
    BOOST_TEST_EQ(counts.invalid, 81U);
    BOOST_TEST_EQ(counts.empty_iv, 6U);
    BOOST_TEST_EQ(counts.over_cap, 3U);
}

}  // namespace webcpp::test

#endif
