// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Wycheproof's tests of an AEAD of ciphers::basic_chacha20_poly1305, read at run time from
// third_party/libs/wycheproof: those with the family's IV size seal and open, the valid
// matching and the invalid failing with authentication_failed and the data zeroed; those with
// another IV size give invalid_nonce_size on seal and open, the data untouched.

#ifndef WEBCPP_TEST_CRYPTO_SUPPORT_WYCHEPROOF_AEAD_HPP
#define WEBCPP_TEST_CRYPTO_SUPPORT_WYCHEPROOF_AEAD_HPP

#include "aead_checks.hpp"
#include "hex.hpp"
#include "test_data.hpp"
#include "wycheproof_gcm.hpp"

#include <boost/json/parse.hpp>
#include <boost/json/value.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace webcpp::test {

/** The counts of an AEAD's Wycheproof tests, by how each ended. */
struct wycheproof_aead_counts {
    /** Valid, opened and sealed. */
    std::size_t valid = 0;
    /** Invalid, refused with authentication_failed and the data zeroed. */
    std::size_t invalid = 0;
    /** An IV of another size than the family's, refused with invalid_nonce_size. */
    std::size_t other_iv = 0;
};

/** Runs one Wycheproof test through `Aead` and counts how it ended. */
template <class Aead>
void check_wycheproof_aead_test(boost::json::value const& test, wycheproof_aead_counts& counts) {
    auto made = Aead::from_key(wycheproof_bytes(test, "key"));
    if (!BOOST_TEST(made.has_value())) {
        return;
    }
    auto const nonce = wycheproof_bytes(test, "iv");
    auto const associated_data = wycheproof_bytes(test, "aad");
    auto const message = wycheproof_bytes(test, "msg");
    auto const ciphertext = wycheproof_bytes(test, "ct");
    auto const tag = wycheproof_bytes(test, "tag");
    auto data = ciphertext;
    auto const opened = made->open(nonce, associated_data, data, tag);
    if (nonce.size() != Aead::nonce_size) {
        BOOST_TEST(opened.error() == crypto::error::invalid_nonce_size);
        BOOST_TEST(data == ciphertext);
        auto plaintext = message;
        BOOST_TEST(made->seal(nonce, associated_data, plaintext).error() ==
                   crypto::error::invalid_nonce_size);
        BOOST_TEST(plaintext == message);
        ++counts.other_iv;
        return;
    }
    if (test.at("result").as_string() != "valid") {
        BOOST_TEST(opened.error() == crypto::error::authentication_failed);
        BOOST_TEST(all_zero(data));
        ++counts.invalid;
        return;
    }
    BOOST_TEST(opened.has_value());
    BOOST_TEST(data == message);
    auto sealed_data = message;
    auto const sealed = made->seal(nonce, associated_data, sealed_data);
    BOOST_TEST(sealed_data == ciphertext);
    BOOST_TEST(sealed && to_hex(*sealed) == to_hex(tag));
    ++counts.valid;
}

/**
 * Every test of one of Wycheproof's files of an AEAD (`testvectors_v1/<file>`) through `Aead`,
 * each counted by how it ended against the counts the file holds.
 */
template <class Aead>
void check_wycheproof_aead(std::string_view file, wycheproof_aead_counts const& expected) {
    auto const document = boost::json::parse(
        read_file(std::string(WEBCPP_TEST_WYCHEPROOF) + "/testvectors_v1/" + std::string(file)));
    wycheproof_aead_counts counts;
    for (auto const& group : document.at("testGroups").as_array()) {
        for (auto const& test : group.at("tests").as_array()) {
            check_wycheproof_aead_test<Aead>(test, counts);
        }
    }
    BOOST_TEST_EQ(counts.valid, expected.valid);
    BOOST_TEST_EQ(counts.invalid, expected.invalid);
    BOOST_TEST_EQ(counts.other_iv, expected.other_iv);
}

}  // namespace webcpp::test

#endif
