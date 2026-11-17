// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// secp256k1 against Wycheproof (spec 8.1): the Bitcoin ECDSA vectors through verify_ecdsa.
// The ECDH vectors are secp256k1_ecdh_test.cpp's.

#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"
#include "support/test_data.hpp"

#include <boost/core/lightweight_test.hpp>
#include <boost/hash2/sha2.hpp>
#include <boost/json.hpp>

#include <secp256k1.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

namespace crypto = webcpp::crypto;
namespace secp = webcpp::crypto::curves::secp256k1;
namespace test = webcpp::test;
namespace json = boost::json;

namespace {

void fail(std::string const& message) {
    BOOST_ERROR(message.c_str());
}

json::value load(std::string const& name) {
    auto const text = test::read_file(WEBCPP_TEST_WYCHEPROOF "/testvectors_v1/" + name + ".json");
    boost::system::error_code ec;
    auto value = json::parse(text, ec);
    BOOST_TEST(!ec);
    return value;
}

std::string str(json::value const& v) {
    return std::string(std::string_view(v.as_string()));
}

void ecdsa_bitcoin() {
    auto const doc = load("ecdsa_secp256k1_sha256_bitcoin_test");
    int total = 0;
    int valid = 0;
    int skipped = 0;
    int invalid = 0;
    for (auto const& group : doc.at("testGroups").as_array()) {
        auto const key = test::from_hex(str(group.at("publicKey").at("uncompressed")));
        for (auto const& t : group.at("tests").as_array()) {
            ++total;
            auto const message = test::from_hex(str(t.at("msg")));
            boost::hash2::sha2_256 hasher;
            hasher.update(message.data(), message.size());
            auto const digest = hasher.result();
            std::array<std::uint8_t, 32> hash{};
            std::ranges::copy(digest, hash.begin());

            auto const der = test::from_hex(str(t.at("sig")));
            secp256k1_ecdsa_signature parsed{};
            std::array<std::uint8_t, 64> compact{};
            // An empty DER has no data pointer to give the parser, which refuses one.
            if (der.empty() ||
                secp256k1_ecdsa_signature_parse_der(secp256k1_context_static, &parsed, der.data(),
                                                    der.size()) == 0) {
                ++skipped;
                continue;
            }
            BOOST_TEST_EQ(secp256k1_ecdsa_signature_serialize_compact(secp256k1_context_static,
                                                                      compact.data(), &parsed),
                          1);
            auto const result = secp::verify_ecdsa(compact, hash, key);
            auto const verdict = str(t.at("result"));
            if (verdict == "valid") {
                ++valid;
                if (!result.has_value()) {
                    fail("tcId " + std::to_string(t.at("tcId").to_number<std::int64_t>()) +
                         ": valid signature refused");
                }
            } else if (verdict == "invalid") {
                ++invalid;
                BOOST_TEST(result.has_error() &&
                           result.error() == crypto::error::invalid_signature);
            } else {
                fail("unexpected result: " + verdict);
            }
        }
    }
    std::cout << "ecdsa bitcoin: tests=" << total << " valid_verified=" << valid
              << " skipped=" << skipped << " invalid_refused=" << invalid << '\n';
    BOOST_TEST_EQ(total, 464);
    BOOST_TEST_EQ(valid, 162);
    BOOST_TEST_EQ(skipped, 190);
    BOOST_TEST_EQ(invalid, 112);
}

}  // namespace

int main() {
    ecdsa_bitcoin();
    return webcpp::test::exit_status(boost::report_errors());
}
