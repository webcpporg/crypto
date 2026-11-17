// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// secp256k1's ElligatorSwift against BIP 324's vectors. bip-0324/ellswift_decode_test_vectors.csv:
// each of its 76 encodings decodes to a key whose x is the row's. bip-0324/
// packet_encoding_test_vectors.csv, 7 rows: both encodings decode to keys whose x are
// mid_x_ours and mid_x_theirs, in_priv_ours's key pair has our key, and ellswift_xdh with the two
// encodings in initiator-then-responder order and our party gives mid_shared_secret; the other
// columns (the session's keys, garbage terminators, ciphertexts) are BIP 324's protocol and are
// not read. xswiftec_inv_test_vectors.csv is not read: its inverse map is internal to
// libsecp256k1, whose own ElligatorSwift tests the c-suites lane runs. Over 64 seeded key pairs:
// ellswift_create and ellswift_encode decode to the key pair's key, two encodings of one key with
// different randomness differ, and the initiator's and the responder's ellswift_xdh agree while
// a swapped party does not. A moved-from key pair: invalid_state from ellswift_create and
// ellswift_xdh.

#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/curves/secp256k1/ellswift.hpp>
#include <webcpp/crypto/equal.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/secret.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"
#include "support/secp256k1_checks.hpp"
#include "support/test_data.hpp"

#include <boost/core/lightweight_test.hpp>
#include <boost/system/result.hpp>

#include <secp256k1.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <map>
#include <random>
#include <span>
#include <sstream>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

namespace crypto = webcpp::crypto;
namespace secp = webcpp::crypto::curves::secp256k1;
namespace test = webcpp::test;

namespace {

using encoding = std::array<std::uint8_t, secp::ellswift_size>;
using scalar = std::array<std::uint8_t, 32>;

static_assert(secp::ellswift_size == 64);
static_assert(static_cast<int>(secp::ellswift_party::initiator) == 0);
static_assert(static_cast<int>(secp::ellswift_party::responder) == 1);
static_assert(std::is_same_v<decltype(secp::ellswift_encode(std::declval<secp::public_key const&>(),
                                                            std::declval<scalar const&>())),
                             encoding>);
static_assert(std::is_same_v<decltype(secp::ellswift_decode(std::declval<encoding const&>())),
                             secp::public_key>);
static_assert(std::is_same_v<decltype(secp::ellswift_create(std::declval<secp::keypair const&>(),
                                                            std::declval<scalar const&>())),
                             boost::system::result<encoding>>);
static_assert(
    std::is_same_v<decltype(secp::ellswift_xdh(
                       std::declval<secp::keypair const&>(), std::declval<encoding const&>(),
                       std::declval<encoding const&>(), secp::ellswift_party::initiator)),
                   boost::system::result<crypto::secret<32>>>);
static_assert(noexcept(secp::ellswift_decode(std::declval<encoding const&>())));

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

std::string without_cr(std::string line) {
    if (!line.empty() && line.back() == '\r') {
        line.pop_back();
    }
    return line;
}

// The rows of a CSV file of BIP 324's, each a map from the header's names to the fields.
std::vector<std::map<std::string, std::string>> rows_of(std::string const& path) {
    auto const text = test::read_file(path);
    std::istringstream in(text);
    std::string line;
    std::getline(in, line);
    auto const names = split(without_cr(line));
    std::vector<std::map<std::string, std::string>> rows;
    while (std::getline(in, line)) {
        line = without_cr(line);
        if (line.empty()) {
            continue;
        }
        auto const fields = split(line);
        if (fields.size() != names.size()) {
            BOOST_ERROR(("malformed row: " + line).c_str());
            continue;
        }
        std::map<std::string, std::string> row;
        for (std::size_t i = 0; i < names.size(); ++i) {
            row[names[i]] = fields[i];
        }
        rows.push_back(std::move(row));
    }
    return rows;
}

template <std::size_t N>
std::array<std::uint8_t, N> fixed(std::string const& hex) {
    auto const bytes = test::from_hex(hex);
    std::array<std::uint8_t, N> out{};
    if (!BOOST_TEST_EQ(bytes.size(), N)) {
        return out;
    }
    std::ranges::copy(bytes, out.begin());
    return out;
}

// The x coordinate of a key, in hex: its compressed form without the prefix.
std::string x_of(secp::public_key const& key) {
    auto const compressed = secp::serialize_public_key(key);
    return test::to_hex(std::span<std::uint8_t const>(compressed).subspan(1));
}

secp::keypair keypair_of(std::span<std::uint8_t const, 32> secret_bytes) {
    auto made = secp::keypair::make(secret_bytes);
    if (!BOOST_TEST(made.has_value())) {
        std::exit(boost::report_errors());
    }
    return std::move(*made);
}

secp::public_key public_of(secp::keypair const& key) {
    auto const encoded = key.public_key();
    auto const parsed = secp::parse_public_key(*encoded);
    if (!BOOST_TEST(parsed.has_value())) {
        std::exit(boost::report_errors());
    }
    return *parsed;
}

void decode_vectors() {
    auto const rows = rows_of(WEBCPP_TEST_BIPS "/bip-0324/ellswift_decode_test_vectors.csv");
    int decoded = 0;
    for (auto const& row : rows) {
        auto const key = secp::ellswift_decode(fixed<64>(row.at("ellswift")));
        if (BOOST_TEST_EQ(x_of(key), row.at("x"))) {
            ++decoded;
        } else {
            BOOST_ERROR(row.at("comment").c_str());
        }
    }
    std::cout << "ellswift_decode: rows=" << rows.size() << " decoded=" << decoded << '\n';
    BOOST_TEST_EQ(rows.size(), 76U);
    BOOST_TEST_EQ(decoded, 76);
}

void packet_vectors() {
    auto const rows = rows_of(WEBCPP_TEST_BIPS "/bip-0324/packet_encoding_test_vectors.csv");
    int agreed = 0;
    for (auto const& row : rows) {
        auto const ours = fixed<64>(row.at("in_ellswift_ours"));
        auto const theirs = fixed<64>(row.at("in_ellswift_theirs"));
        bool const initiating = row.at("in_initiating") == "1";
        BOOST_TEST_EQ(x_of(secp::ellswift_decode(ours)), row.at("mid_x_ours"));
        BOOST_TEST_EQ(x_of(secp::ellswift_decode(theirs)), row.at("mid_x_theirs"));
        auto const key = keypair_of(fixed<32>(row.at("in_priv_ours")));
        BOOST_TEST_EQ(x_of(public_of(key)), row.at("mid_x_ours"));
        auto const& initiator = initiating ? ours : theirs;
        auto const& responder = initiating ? theirs : ours;
        auto const shared = secp::ellswift_xdh(
            key, initiator, responder,
            initiating ? secp::ellswift_party::initiator : secp::ellswift_party::responder);
        if (BOOST_TEST(shared.has_value()) &&
            BOOST_TEST_EQ(test::to_hex(shared->bytes()), row.at("mid_shared_secret"))) {
            ++agreed;
        }
    }
    std::cout << "packet_encoding: rows=" << rows.size() << " agreed=" << agreed << '\n';
    BOOST_TEST_EQ(rows.size(), 7U);
    BOOST_TEST_EQ(agreed, 7);
}

scalar draw(std::mt19937_64& generator) {
    for (;;) {
        scalar out{};
        for (auto& octet : out) {
            octet = static_cast<std::uint8_t>(generator());
        }
        if (secp256k1_ec_seckey_verify(secp256k1_context_static, out.data()) == 1) {
            return out;
        }
    }
}

scalar random_bytes(std::mt19937_64& generator) {
    scalar out{};
    for (auto& octet : out) {
        octet = static_cast<std::uint8_t>(generator());
    }
    return out;
}

// One round over two seeded key pairs: the round trips, the encodings' variety, and the
// exchange from both sides.
void seeded_round(std::mt19937_64& generator) {
    auto const initiator_key = keypair_of(draw(generator));
    auto const responder_key = keypair_of(draw(generator));
    auto const initiator_public = public_of(initiator_key);
    auto const first_randomness = random_bytes(generator);
    auto const second_randomness = random_bytes(generator);

    auto const created = secp::ellswift_create(initiator_key, first_randomness);
    auto const created_again = secp::ellswift_create(initiator_key, second_randomness);
    auto const responder_created = secp::ellswift_create(responder_key, first_randomness);
    if (!BOOST_TEST(created && created_again && responder_created)) {
        return;
    }
    BOOST_TEST(secp::ellswift_decode(*created) == initiator_public);
    BOOST_TEST(secp::ellswift_decode(*created_again) == initiator_public);
    BOOST_TEST(*created != *created_again);

    auto const encoded = secp::ellswift_encode(initiator_public, first_randomness);
    auto const encoded_again = secp::ellswift_encode(initiator_public, second_randomness);
    BOOST_TEST(secp::ellswift_decode(encoded) == initiator_public);
    BOOST_TEST(secp::ellswift_decode(encoded_again) == initiator_public);
    BOOST_TEST(encoded != encoded_again);

    auto const initiator_secret = secp::ellswift_xdh(initiator_key, *created, *responder_created,
                                                     secp::ellswift_party::initiator);
    auto const responder_secret = secp::ellswift_xdh(responder_key, *created, *responder_created,
                                                     secp::ellswift_party::responder);
    auto const swapped = secp::ellswift_xdh(initiator_key, *created, *responder_created,
                                            secp::ellswift_party::responder);
    if (!BOOST_TEST(initiator_secret && responder_secret && swapped)) {
        return;
    }
    BOOST_TEST(crypto::equal(initiator_secret->bytes(), responder_secret->bytes()));
    BOOST_TEST(!crypto::equal(initiator_secret->bytes(), swapped->bytes()));
    // Any encoding of the same key gives the same point, but the hash binds the bytes sent.
    auto const other_encoding = secp::ellswift_xdh(
        responder_key, *created_again, *responder_created, secp::ellswift_party::responder);
    BOOST_TEST(other_encoding &&
               !crypto::equal(initiator_secret->bytes(), other_encoding->bytes()));
}

void seeded() {
    std::mt19937_64 generator(0xe115f17ULL);
    for (int round = 0; round < 64; ++round) {
        seeded_round(generator);
    }
}

void moved_from() {
    scalar secret_bytes{};
    secret_bytes.fill(0x11);
    auto source = keypair_of(secret_bytes);
    auto const peer = secp::ellswift_create(source, scalar{});
    auto const target = std::move(source);
    BOOST_TEST(target.public_key().has_value());
    // NOLINTBEGIN(bugprone-use-after-move): the moved-from pair is what is tested
    BOOST_TEST(secp::ellswift_create(source, scalar{}).error() == crypto::error::invalid_state);
    if (BOOST_TEST(peer.has_value())) {
        BOOST_TEST(
            secp::ellswift_xdh(source, *peer, *peer, secp::ellswift_party::initiator).error() ==
            crypto::error::invalid_state);
    }
    test::expect_empty_keypair(source);
    // NOLINTEND(bugprone-use-after-move)
}

}  // namespace

int main() {
    decode_vectors();
    packet_vectors();
    seeded();
    moved_from();
    return webcpp::test::exit_status(boost::report_errors());
}
