// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// secp256k1 against BIP340's test vectors (bip-0340/test-vectors.csv): each row with a
// secret key gives its public key and its signature, every row verifies as its result says,
// and the refusals are the error the row's reason names.

#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/secp256k1.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"
#include "support/secp256k1_data.hpp"

#include <boost/core/lightweight_test.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <span>
#include <sstream>
#include <string>
#include <vector>

namespace crypto = webcpp::crypto;
namespace secp = webcpp::crypto::secp256k1;
namespace test = webcpp::test;

namespace {

void fail(std::string const& message) {
    BOOST_ERROR(message.c_str());
}

std::vector<std::string> split(std::string const& line) {
    std::vector<std::string> fields;
    std::string field;
    std::istringstream in(line);
    while (std::getline(in, field, ',')) {
        fields.push_back(field);
    }
    if (!line.empty() && line.back() == ',') {
        fields.emplace_back();
    }
    return fields;
}

}  // namespace

int main() {
    auto const text = test::read_text(WEBCPP_TEST_BIPS "/bip-0340/test-vectors.csv");
    std::istringstream in(text);
    std::string line;
    std::getline(in, line);
    if (!line.empty() && line.back() == '\r') {
        line.pop_back();
    }
    BOOST_TEST_EQ(
        line, "index,secret key,public key,aux_rand,message,signature,verification result,comment");

    int rows = 0;
    int signed_rows = 0;
    int accepted = 0;
    int refused_keys = 0;
    int refused_signatures = 0;
    while (std::getline(in, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        if (line.empty()) {
            continue;
        }
        auto const f = split(line);
        if (f.size() != 8) {
            fail("malformed row: " + line);
            continue;
        }
        ++rows;
        auto const index = std::stoi(f[0]);
        auto const pub = test::from_hex(f[2]);
        auto const message = test::from_hex(f[4]);
        auto const signature = test::from_hex(f[5]);
        bool const expected = f[6] == "TRUE";
        BOOST_TEST_EQ(pub.size(), 32u);
        BOOST_TEST_EQ(signature.size(), 64u);
        if (pub.size() != 32 || signature.size() != 64) {
            continue;
        }

        if (!f[1].empty()) {
            ++signed_rows;
            auto const secret = test::from_hex(f[1]);
            auto const aux = test::from_hex(f[3]);
            auto const key = secp::keypair::make(secret);
            BOOST_TEST(key.has_value());
            BOOST_TEST_EQ(aux.size(), 32u);
            if (key.has_value() && aux.size() == 32) {
                auto const xonly = key->xonly_public_key();
                BOOST_TEST(xonly.has_value());
                if (xonly.has_value()) {
                    BOOST_TEST(std::equal(xonly->begin(), xonly->end(), pub.begin()));
                }
                auto const made =
                    key->sign_schnorr(message, std::span<std::uint8_t const, 32>(aux));
                BOOST_TEST(made.has_value());
                if (made.has_value()) {
                    if (!std::equal(made->begin(), made->end(), signature.begin())) {
                        fail("row " + f[0] + ": signature differs: " + test::to_hex(*made));
                    }
                }
            }
        }

        auto const result = secp::verify_schnorr(std::span<std::uint8_t const, 64>(signature),
                                                 message, std::span<std::uint8_t const, 32>(pub));
        if (expected) {
            ++accepted;
            BOOST_TEST(result.has_value());
        } else if (index == 5 || index == 14) {
            ++refused_keys;
            BOOST_TEST(result.has_error() && result.error() == crypto::error::invalid_public_key);
        } else {
            ++refused_signatures;
            BOOST_TEST(result.has_error() && result.error() == crypto::error::invalid_signature);
        }
    }

    std::cout << "bip340: rows=" << rows << " signed=" << signed_rows << " true=" << accepted
              << " refused_keys=" << refused_keys << " refused_signatures=" << refused_signatures
              << '\n';
    BOOST_TEST_EQ(rows, 19);
    BOOST_TEST_EQ(signed_rows, 8);
    BOOST_TEST_EQ(accepted, 9);
    BOOST_TEST_EQ(refused_keys, 2);
    BOOST_TEST_EQ(refused_signatures, 8);
    return webcpp::test::exit_status(boost::report_errors());
}
