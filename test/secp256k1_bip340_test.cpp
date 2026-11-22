// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// secp256k1 against BIP340's test vectors (bip-0340/test-vectors.csv), through
// key.sign(crypto::schnorr, message, aux_rand) and crypto::verify(crypto::schnorr, ...): each row
// with a secret key gives its public key and its signature, every row verifies as its result
// says, and the refusals are the error the row's reason names.

#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/signing.hpp>
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
namespace secp = webcpp::crypto::curves::secp256k1;
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

// What the rows came to.
struct tally {
    int rows = 0;
    int signed_rows = 0;
    int accepted = 0;
    int refused_keys = 0;
    int refused_signatures = 0;
};

// A row with a secret key: its key pair gives the row's public key, and signs the message with
// the row's aux_rand into the row's signature.
void check_signing(std::vector<std::string> const& f, std::vector<std::uint8_t> const& pub,
                   std::vector<std::uint8_t> const& message,
                   std::vector<std::uint8_t> const& signature) {
    auto const secret = test::from_hex(f[1]);
    auto const aux = test::from_hex(f[3]);
    auto const key = secp::keypair::make(secret);
    BOOST_TEST(key.has_value());
    BOOST_TEST_EQ(aux.size(), 32U);
    if (!key.has_value() || aux.size() != 32) {
        return;
    }
    auto const xonly = key->xonly_public_key();
    BOOST_TEST(xonly.has_value() && std::ranges::equal(*xonly, pub));
    auto const made = key->sign(crypto::schnorr, message, std::span<std::uint8_t const, 32>(aux));
    BOOST_TEST(made.has_value());
    if (made.has_value() && !std::ranges::equal(*made, signature)) {
        fail("row " + f[0] + ": signature differs: " + test::to_hex(*made));
    }
}

// One row: signed when it has a secret key, then verified as its result says; rows 5 and 14
// are refused for their public key, the other FALSE rows for their signature.
void check_row(std::vector<std::string> const& f, tally& t) {
    ++t.rows;
    auto const index = std::stoi(f[0]);
    auto const pub = test::from_hex(f[2]);
    auto const message = test::from_hex(f[4]);
    auto const signature = test::from_hex(f[5]);
    BOOST_TEST_EQ(pub.size(), 32U);
    BOOST_TEST_EQ(signature.size(), 64U);
    if (pub.size() != 32 || signature.size() != 64) {
        return;
    }
    if (!f[1].empty()) {
        ++t.signed_rows;
        check_signing(f, pub, message, signature);
    }
    auto const result =
        crypto::verify(crypto::schnorr, std::span<std::uint8_t const, 64>(signature), message,
                       std::span<std::uint8_t const, 32>(pub));
    if (f[6] == "TRUE") {
        ++t.accepted;
        BOOST_TEST(result.has_value());
    } else if (index == 5 || index == 14) {
        ++t.refused_keys;
        BOOST_TEST(result.has_error() && result.error() == crypto::error::invalid_public_key);
    } else {
        ++t.refused_signatures;
        BOOST_TEST(result.has_error() && result.error() == crypto::error::invalid_signature);
    }
}

// A line without the carriage return that ends each of the file's lines.
std::string without_cr(std::string line) {
    if (!line.empty() && line.back() == '\r') {
        line.pop_back();
    }
    return line;
}

}  // namespace

int main() {
    auto const text = test::read_file(WEBCPP_TEST_BIPS "/bip-0340/test-vectors.csv");
    std::istringstream in(text);
    std::string line;
    std::getline(in, line);
    BOOST_TEST_EQ(without_cr(line),
                  "index,secret key,public key,aux_rand,message,signature,verification "
                  "result,comment");
    tally t;
    while (std::getline(in, line)) {
        line = without_cr(line);
        if (line.empty()) {
            continue;
        }
        auto const f = split(line);
        if (f.size() != 8) {
            fail("malformed row: " + line);
            continue;
        }
        check_row(f, t);
    }
    std::cout << "bip340: rows=" << t.rows << " signed=" << t.signed_rows << " true=" << t.accepted
              << " refused_keys=" << t.refused_keys
              << " refused_signatures=" << t.refused_signatures << '\n';
    BOOST_TEST_EQ(t.rows, 19);
    BOOST_TEST_EQ(t.signed_rows, 8);
    BOOST_TEST_EQ(t.accepted, 9);
    BOOST_TEST_EQ(t.refused_keys, 2);
    BOOST_TEST_EQ(t.refused_signatures, 8);
    return webcpp::test::exit_status(boost::report_errors());
}
