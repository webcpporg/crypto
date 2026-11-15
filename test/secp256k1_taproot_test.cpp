// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// secp256k1's BIP341 Taproot tweak against BIP341's wallet-test-vectors.json: every
// scriptPubKey case's output key through taproot_output_key, and every key-path spending
// input's tweaked key pair through tweak_taproot, compared through its public key with the
// vector's tweaked secret key and through its BIP340 signature (all-zero aux) of the sighash
// with the expected witness; then the tweak's refusals.

#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/secp256k1.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"
#include "support/secp256k1_data.hpp"

#include <boost/core/lightweight_test.hpp>
#include <boost/json.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace crypto = webcpp::crypto;
namespace secp = webcpp::crypto::secp256k1;
namespace test = webcpp::test;
namespace json = boost::json;

namespace {

using bytes = std::vector<std::uint8_t>;

std::string str(json::value const& v) {
    return std::string(std::string_view(v.as_string()));
}

// A hex field, or no bytes for a JSON null (a key-path-only output's merkle root).
bytes hex_or_empty(json::value const& v) {
    return v.is_null() ? bytes() : test::from_hex(str(v));
}

template <std::size_t N>
std::array<std::uint8_t, N> fixed(json::value const& v) {
    auto const b = test::from_hex(str(v));
    BOOST_TEST_EQ(b.size(), N);
    std::array<std::uint8_t, N> out{};
    std::ranges::copy(std::span(b).first((std::min)(N, b.size())), out.begin());
    return out;
}

void fail(std::string const& message) {
    BOOST_ERROR(message.c_str());
}

int script_pub_keys(json::value const& doc) {
    int cases = 0;
    for (auto const& c : doc.at("scriptPubKey").as_array()) {
        ++cases;
        auto const internal = fixed<32>(c.at("given").at("internalPubkey"));
        auto const root = hex_or_empty(c.at("intermediary").at("merkleRoot"));
        auto const expected = test::from_hex(str(c.at("intermediary").at("tweakedPubkey")));
        auto const output = secp::taproot_output_key(internal, root);
        BOOST_TEST(output.has_value());
        if (output && !std::ranges::equal(output->key, expected)) {
            fail("scriptPubKey " + std::to_string(cases) + ": output key differs");
        }
        // The scriptPubKey is OP_1, a 32-byte push, and the output key.
        auto const script = test::from_hex(str(c.at("expected").at("scriptPubKey")));
        BOOST_TEST(output && script.size() == 34 &&
                   std::ranges::equal(std::span(script).subspan(2), output->key));
    }
    return cases;
}

// One key-path spending input: its internal key pair tweaked, compared with the vector's
// tweaked secret key, output key and witness.
void check_input(json::value const& input, int index) {
    auto const& given = input.at("given");
    auto const& intermediary = input.at("intermediary");
    auto key = *secp::keypair::make(fixed<32>(given.at("internalPrivkey")));
    BOOST_TEST(*key.xonly_public_key() == fixed<32>(intermediary.at("internalPubkey")));
    auto const root = hex_or_empty(given.at("merkleRoot"));
    BOOST_TEST(key.tweak_taproot(root).has_value());

    // The tweaked pair is the vector's tweaked secret key: the same SEC1 public key, its parity
    // included.
    auto const reference = *secp::keypair::make(fixed<32>(intermediary.at("tweakedPrivkey")));
    BOOST_TEST(*key.public_key() == *reference.public_key());
    auto const output =
        secp::taproot_output_key(fixed<32>(intermediary.at("internalPubkey")), root);
    BOOST_TEST(output.has_value());
    if (!output) {
        return;
    }
    BOOST_TEST(*key.xonly_public_key() == output->key);
    BOOST_TEST_EQ(output->parity, (*key.public_key())[0] == 0x03 ? 1 : 0);

    // Its BIP340 signature of the sighash, with an all-zero aux, is the witness's first 64
    // bytes (a 65th is the hash type, when it is not SIGHASH_DEFAULT).
    std::array<std::uint8_t, 32> const aux{};
    auto const sighash = fixed<32>(intermediary.at("sigHash"));
    auto const signature = key.sign_schnorr(sighash, aux);
    auto const& expected = input.at("expected");
    auto const& witnesses = expected.at("witness").as_array();
    auto const witness = test::from_hex(str(witnesses.at(0)));
    BOOST_TEST(witness.size() == 64 || witness.size() == 65);
    // A 65th byte is the hash type, which SIGHASH_DEFAULT (0) leaves out.
    auto const hash_type = given.at("hashType").to_number<int>();
    if (witness.size() == 65) {
        BOOST_TEST_EQ(int{witness.back()}, hash_type);
    } else {
        BOOST_TEST_EQ(hash_type, 0);
    }
    if (!signature || witness.size() < 64 ||
        !std::ranges::equal(*signature, std::span(witness).first(64))) {
        fail("keyPathSpending input " + std::to_string(index) + ": signature differs");
    }
    BOOST_TEST(signature && secp::verify_schnorr(*signature, sighash, output->key));
}

int key_path_inputs(json::value const& doc) {
    int inputs = 0;
    for (auto const& spending : doc.at("keyPathSpending").as_array()) {
        for (auto const& input : spending.at("inputSpending").as_array()) {
            check_input(input, ++inputs);
        }
    }
    return inputs;
}

void refusals() {
    std::array<std::uint8_t, 32> secret{};
    secret.fill(0x11);
    auto key = *secp::keypair::make(secret);
    auto const before = *key.public_key();
    std::array<std::uint8_t, 31> const short_root{};
    BOOST_TEST(key.tweak_taproot(short_root).error() == crypto::error::invalid_input_size);
    std::array<std::uint8_t, 33> const long_root{};
    BOOST_TEST(key.tweak_taproot(long_root).error() == crypto::error::invalid_input_size);
    // Refused before anything changes.
    BOOST_TEST(*key.public_key() == before);
    auto const internal = *key.xonly_public_key();
    BOOST_TEST(secp::taproot_output_key(internal, short_root).error() ==
               crypto::error::invalid_input_size);
    BOOST_TEST(secp::taproot_output_key(internal, long_root).error() ==
               crypto::error::invalid_input_size);
    std::array<std::uint8_t, 32> const not_a_point{};  // x = 0 has no point
    BOOST_TEST(secp::taproot_output_key(not_a_point, {}).error() ==
               crypto::error::invalid_public_key);

    // NOLINTBEGIN(bugprone-use-after-move): a moved-from pair is what this case tests
    auto moved = std::move(key);
    BOOST_TEST(key.tweak_taproot({}).error() == crypto::error::invalid_state);
    // The root's size is checked first, moved from or not.
    BOOST_TEST(key.tweak_taproot(short_root).error() == crypto::error::invalid_input_size);
    // NOLINTEND(bugprone-use-after-move)
    // The tweaked pair moves as any pair does.
    BOOST_TEST(moved.tweak_taproot({}).has_value());
    auto const output = *secp::taproot_output_key(internal, {});
    auto const again = std::move(moved);
    BOOST_TEST(*again.xonly_public_key() == output.key);
}

}  // namespace

int main() {
    auto const text = test::read_text(WEBCPP_TEST_BIPS "/bip-0341/wallet-test-vectors.json");
    boost::system::error_code ec;
    auto const doc = json::parse(text, ec);
    BOOST_TEST(!ec);
    if (!ec) {
        auto const outputs = script_pub_keys(doc);
        auto const inputs = key_path_inputs(doc);
        std::cout << "bip341: scriptPubKey=" << outputs << " keyPathSpending inputs=" << inputs
                  << '\n';
        BOOST_TEST_EQ(outputs, 7);
        BOOST_TEST_EQ(inputs, 7);
    }
    refusals();
    return webcpp::test::exit_status(boost::report_errors());
}
