// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// secp256k1's three forms of ECDH, each a secret<N>: ecdh (libsecp256k1's SHA-256 of the
// compressed shared point), ecdh_x (the point's raw x coordinate) and ecdh_point (the point,
// SEC1 uncompressed). Two sides agree in every form; a known answer computed apart from
// libsecp256k1; ecdh keeps version 0.1's value; Wycheproof's ECDH vectors, in ASN.1 and JWK
// form, against ecdh_x; the refusals of a moved-from key pair and of every malformed key.

#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/secret.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"
#include "support/secp256k1_data.hpp"

#include <boost/core/lightweight_test.hpp>
#include <boost/hash2/sha2.hpp>
#include <boost/json.hpp>
#include <boost/system/result.hpp>

#include <secp256k1.h>
#include <secp256k1_ecdh.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <random>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace crypto = webcpp::crypto;
namespace secp = webcpp::crypto::curves::secp256k1;
namespace test = webcpp::test;
namespace json = boost::json;

namespace {

using bytes = std::vector<std::uint8_t>;

void fail(std::string const& message) {
    BOOST_ERROR(message.c_str());
}

secp::keypair from_byte(std::uint8_t b) {
    std::array<std::uint8_t, 32> secret{};
    secret.fill(b);
    return *secp::keypair::make(secret);
}

// A key pair from the generator: a secret make refuses (zero, or not below the group order)
// is drawn again.
secp::keypair draw(std::mt19937_64& generator) {
    for (;;) {
        std::array<std::uint8_t, 32> secret{};
        for (auto& octet : secret) {
            octet = static_cast<std::uint8_t>(generator());
        }
        auto made = secp::keypair::make(secret);
        if (made) {
            return std::move(*made);
        }
        BOOST_TEST(made.error() == crypto::error::invalid_secret_key);
    }
}

// The uncompressed SEC1 form, 04 || x || y, of a key pair's public key, through libsecp256k1.
std::array<std::uint8_t, 65> uncompressed(secp::keypair const& key) {
    auto const compressed = *key.public_key();
    secp256k1_pubkey parsed{};
    BOOST_TEST(secp256k1_ec_pubkey_parse(secp256k1_context_static, &parsed, compressed.data(),
                                         compressed.size()) == 1);
    std::array<std::uint8_t, 65> out{};
    std::size_t size = out.size();
    // NOLINTNEXTLINE(bugprone-signed-bitwise): libsecp256k1's macro shifts a signed constant
    unsigned const flags = SECP256K1_EC_UNCOMPRESSED;
    BOOST_TEST(secp256k1_ec_pubkey_serialize(secp256k1_context_static, out.data(), &size, &parsed,
                                             flags) == 1);
    return out;
}

// The SHA-256 of the compressed form of an uncompressed point, which the point must be: what
// libsecp256k1's default ECDH hash computes.
bool hashes_to(std::span<std::uint8_t const, 65> point, std::span<std::uint8_t const, 32> hashed) {
    secp256k1_pubkey parsed{};
    if (secp256k1_ec_pubkey_parse(secp256k1_context_static, &parsed, point.data(), point.size()) !=
        1) {
        return false;
    }
    std::array<std::uint8_t, 33> compressed{};
    std::size_t size = compressed.size();
    // NOLINTNEXTLINE(bugprone-signed-bitwise): libsecp256k1's macro shifts a signed constant
    unsigned const flags = SECP256K1_EC_COMPRESSED;
    secp256k1_ec_pubkey_serialize(secp256k1_context_static, compressed.data(), &size, &parsed,
                                  flags);
    boost::hash2::sha2_256 hasher;
    hasher.update(compressed.data(), compressed.size());
    auto const digest = hasher.result();
    return std::ranges::equal(digest, hashed);
}

void types() {
    auto const key = from_byte(0x11);
    auto const peer = *key.public_key();
    static_assert(std::is_same_v<decltype(key.ecdh(peer)),
                                 boost::system::result<webcpp::crypto::secret<32>>>);
    static_assert(std::is_same_v<decltype(key.ecdh_x(peer)),
                                 boost::system::result<webcpp::crypto::secret<32>>>);
    static_assert(std::is_same_v<decltype(key.ecdh_point(peer)),
                                 boost::system::result<webcpp::crypto::secret<65>>>);
}

// 32 pairs of key pairs from a seeded generator: both sides of each agree in every form, the
// point's x is ecdh_x, the point is on the curve, and ecdh is the SHA-256 of its compressed
// form, as version 0.1's ecdh was.
void agreement() {
    std::mt19937_64 generator(0x5ec9256b1ecdULL);
    for (int round = 0; round < 32; ++round) {
        auto const a = draw(generator);
        auto const b = draw(generator);
        auto const a_public = *a.public_key();
        auto const b_public = *b.public_key();
        auto const x_a = a.ecdh_x(b_public);
        auto const x_b = b.ecdh_x(a_public);
        auto const point_a = a.ecdh_point(b_public);
        auto const point_b = b.ecdh_point(a_public);
        auto const hashed_a = a.ecdh(b_public);
        auto const hashed_b = b.ecdh(a_public);
        if (!BOOST_TEST(x_a && x_b && point_a && point_b && hashed_a && hashed_b)) {
            continue;
        }
        BOOST_TEST(std::ranges::equal(x_a->bytes(), x_b->bytes()));
        BOOST_TEST(std::ranges::equal(point_a->bytes(), point_b->bytes()));
        BOOST_TEST(std::ranges::equal(hashed_a->bytes(), hashed_b->bytes()));
        BOOST_TEST_EQ(point_a->bytes()[0], 0x04U);
        BOOST_TEST(std::ranges::equal(point_a->bytes().subspan<1, 32>(), x_a->bytes()));
        secp256k1_pubkey parsed{};
        BOOST_TEST(secp256k1_ec_pubkey_parse(secp256k1_context_static, &parsed,
                                             point_a->bytes().data(), 65) == 1);
        BOOST_TEST(hashes_to(point_a->bytes(), hashed_a->bytes()));
        // The peer's key, uncompressed, gives the same x.
        auto const x_full = a.ecdh_x(uncompressed(b));
        BOOST_TEST(x_full && std::ranges::equal(x_full->bytes(), x_a->bytes()));
    }
}

// The secrets 0x11 and 0x22 repeated 32 times, whose shared x and first public key were
// computed apart from libsecp256k1, in affine arithmetic over the curve's field.
void known_answer() {
    auto const a = from_byte(0x11);
    auto const b = from_byte(0x22);
    auto const a_public = a.public_key();
    BOOST_TEST(a_public &&
               test::to_hex(*a_public) ==
                   "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa");
    auto const x_a = a.ecdh_x(*b.public_key());
    auto const x_b = b.ecdh_x(*a_public);
    std::string const expected = "77e0510d5042e2f5e9e59c977b81eeed590cf7d20c1c51da451a8eaa9fdc45ff";
    BOOST_TEST(x_a && test::to_hex(x_a->bytes()) == expected);
    BOOST_TEST(x_b && test::to_hex(x_b->bytes()) == expected);
}

// A moved-from key pair answers invalid_state; a key of the wrong size, an x that is no point's
// and X9.62's hybrid prefixes, 06 and 07, are invalid_public_key, in every form.
// NOLINTBEGIN(bugprone-use-after-move)
void guards() {
    auto key = from_byte(0x42);
    secp::keypair moved = std::move(key);
    auto const peer = *moved.public_key();
    BOOST_TEST(key.ecdh(peer).error() == crypto::error::invalid_state);
    BOOST_TEST(key.ecdh_x(peer).error() == crypto::error::invalid_state);
    BOOST_TEST(key.ecdh_point(peer).error() == crypto::error::invalid_state);

    auto const a = from_byte(0x11);
    std::array<std::uint8_t, 33> off_curve{};
    off_curve[0] = 0x02;  // x = 0: no point
    auto first_hybrid = uncompressed(from_byte(0x22));
    auto second_hybrid = first_hybrid;
    first_hybrid[0] = 0x06;
    second_hybrid[0] = 0x07;
    std::vector<bytes> const refused{
        bytes(32),
        bytes(34),
        bytes(66),
        bytes(off_curve.begin(), off_curve.end()),
        bytes(first_hybrid.begin(), first_hybrid.end()),
        bytes(second_hybrid.begin(), second_hybrid.end()),
    };
    for (auto const& peer_key : refused) {
        BOOST_TEST(a.ecdh(peer_key).error() == crypto::error::invalid_public_key);
        BOOST_TEST(a.ecdh_x(peer_key).error() == crypto::error::invalid_public_key);
        BOOST_TEST(a.ecdh_point(peer_key).error() == crypto::error::invalid_public_key);
    }
}

// NOLINTEND(bugprone-use-after-move)

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

struct counts {
    int taken = 0;
    int skipped = 0;
    int valid = 0;
    int invalid = 0;
    int acceptable = 0;
    int acceptable_taken = 0;
    int acceptable_refused = 0;
    int compressed = 0;
    int uncompressed = 0;
    int refused = 0;
    int bad_scalar = 0;
    int agreed_x = 0;
    int agreed_default = 0;
};

// The three forms of a key pair whose secret make accepted, on one taken case: a point
// libsecp256k1 cannot parse is refused in every form; otherwise ecdh_point's x is ecdh_x and
// ecdh equals the C API's default hash.
bool forms(std::string const& label, secp::keypair const& key, bytes const& point,
           std::array<std::uint8_t, 32> const& scalar, bytes const& shared, counts& c) {
    secp256k1_pubkey parsed{};
    bool const parses = secp256k1_ec_pubkey_parse(secp256k1_context_static, &parsed, point.data(),
                                                  point.size()) == 1;
    auto const x = key.ecdh_x(point);
    auto const whole = key.ecdh_point(point);
    auto const hashed = key.ecdh(point);
    if (!x.has_value()) {
        BOOST_TEST(x.error() == crypto::error::invalid_public_key);
        BOOST_TEST(whole.has_error() && whole.error() == crypto::error::invalid_public_key);
        BOOST_TEST(hashed.has_error() && hashed.error() == crypto::error::invalid_public_key);
        return false;
    }
    // A point webcpp took and libsecp256k1's parser refuses is reported here: the C call below
    // would reach libsecp256k1's illegal callback with the unparsed point, and abort.
    if (!BOOST_TEST(parses)) {
        fail(label + ": a point libsecp256k1 refuses was taken");
        return true;
    }
    if (!BOOST_TEST(whole && hashed)) {
        return true;
    }
    BOOST_TEST(std::ranges::equal(whole->bytes().subspan<1, 32>(), x->bytes()));
    std::array<std::uint8_t, 32> reference{};
    if (BOOST_TEST(secp256k1_ecdh(secp256k1_context_static, reference.data(), &parsed,
                                  scalar.data(), nullptr, nullptr) == 1) &&
        std::ranges::equal(hashed->bytes(), reference)) {
        ++c.agreed_default;
    } else {
        fail(label + ": ecdh differs from the C API's default");
    }
    if (std::ranges::equal(x->bytes(), shared)) {
        ++c.agreed_x;
    }
    return true;
}

// One taken case: the point as SEC1 bytes and the private key as 32 bytes. A valid case's
// shared secret is ecdh_x; an invalid one is refused, by make for its scalar or by ecdh_x for
// its point; an acceptable one is counted by what webcpp does.
void ecdh_case(std::string const& label, std::string const& verdict, bytes const& point,
               std::array<std::uint8_t, 32> const& scalar, bytes const& shared, counts& c) {
    ++c.taken;
    auto const key = secp::keypair::make(scalar);
    bool computes = false;
    if (!key.has_value()) {
        // A scalar libsecp256k1 refuses (zero or not below the order) gives no shared secret.
        ++c.bad_scalar;
        BOOST_TEST(key.error() == crypto::error::invalid_secret_key);
    } else {
        int const agreed = c.agreed_x;
        computes = forms(label, *key, point, scalar, shared, c);
        if (verdict == "valid" && c.agreed_x == agreed) {
            fail(label + ": shared secret differs from ecdh_x");
        }
    }
    if (!computes) {
        ++c.refused;
    }
    if (verdict == "valid") {
        ++c.valid;
        BOOST_TEST(computes);
    } else if (verdict == "invalid") {
        ++c.invalid;
        if (computes) {
            fail(label + ": invalid case taken");
        }
    } else {
        ++c.acceptable;
        ++(computes ? c.acceptable_taken : c.acceptable_refused);
    }
}

void print(char const* name, counts const& c) {
    std::cout << name << ": taken=" << c.taken << " skipped=" << c.skipped
              << " uncompressed=" << c.uncompressed << " compressed=" << c.compressed
              << " valid=" << c.valid << " invalid=" << c.invalid << " acceptable=" << c.acceptable
              << " acceptable_taken=" << c.acceptable_taken
              << " acceptable_refused=" << c.acceptable_refused << " refused=" << c.refused
              << " bad_scalar=" << c.bad_scalar << " agreed_with_shared=" << c.agreed_x
              << " agreed_with_default_hash=" << c.agreed_default << '\n';
}

void ecdh_asn() {
    constexpr std::string_view uncompressed_prefix =
        "3056301006072a8648ce3d020106052b8104000a034200";
    constexpr std::string_view compressed_prefix = "3036301006072a8648ce3d020106052b8104000a032200";
    auto const doc = load("ecdh_secp256k1_test");
    counts c;
    int total = 0;
    for (auto const& group : doc.at("testGroups").as_array()) {
        for (auto const& t : group.at("tests").as_array()) {
            ++total;
            auto const label =
                "ecdh asn tcId " + std::to_string(t.at("tcId").to_number<std::int64_t>());
            auto const pub = str(t.at("public"));
            std::string_view tail;
            if (pub.size() == 2 * ((uncompressed_prefix.size() / 2) + 65) &&
                std::string_view(pub).starts_with(uncompressed_prefix)) {
                tail = std::string_view(pub).substr(uncompressed_prefix.size());
                ++c.uncompressed;
            } else if (pub.size() == 2 * ((compressed_prefix.size() / 2) + 33) &&
                       std::string_view(pub).starts_with(compressed_prefix)) {
                tail = std::string_view(pub).substr(compressed_prefix.size());
                ++c.compressed;
            } else {
                ++c.skipped;
                continue;
            }
            auto const priv = test::from_hex(str(t.at("private")));
            ecdh_case(label, str(t.at("result")), test::from_hex(tail), test::scalar32(priv),
                      test::from_hex(str(t.at("shared"))), c);
        }
    }
    print("ecdh asn", c);
    BOOST_TEST_EQ(total, 752);
    BOOST_TEST_EQ(c.taken, 496);
    BOOST_TEST_EQ(c.uncompressed, 492);
    BOOST_TEST_EQ(c.compressed, 4);
    BOOST_TEST_EQ(c.skipped, 256);
    BOOST_TEST_EQ(c.valid, 473);
    BOOST_TEST_EQ(c.invalid, 21);
    BOOST_TEST_EQ(c.acceptable, 2);
    BOOST_TEST_EQ(c.acceptable_taken, 1);
    BOOST_TEST_EQ(c.acceptable_refused, 1);
    BOOST_TEST_EQ(c.agreed_default, c.valid + c.acceptable_taken);
}

void ecdh_jwk() {
    auto const doc = load("ecdh_secp256k1_webcrypto_test");
    counts c;
    int total = 0;
    for (auto const& group : doc.at("testGroups").as_array()) {
        for (auto const& t : group.at("tests").as_array()) {
            ++total;
            auto const label =
                "ecdh jwk tcId " + std::to_string(t.at("tcId").to_number<std::int64_t>());
            auto const& pub = t.at("public").as_object();
            if (str(pub.at("crv")) != "P-256K") {
                ++c.skipped;
                continue;
            }
            bytes point{0x04};
            for (char const* coordinate : {"x", "y"}) {
                auto const part = test::from_base64url(str(pub.at(coordinate)));
                point.insert(point.end(), part.begin(), part.end());
            }
            auto const d = test::from_base64url(str(t.at("private").at("d")));
            ecdh_case(label, str(t.at("result")), point, test::scalar32(d),
                      test::from_hex(str(t.at("shared"))), c);
        }
    }
    print("ecdh jwk", c);
    BOOST_TEST_EQ(total, 496);
    BOOST_TEST_EQ(c.taken, 491);
    BOOST_TEST_EQ(c.valid, 473);
    BOOST_TEST_EQ(c.invalid, 18);
    BOOST_TEST_EQ(c.skipped, 5);
    BOOST_TEST_EQ(c.agreed_default, c.valid);
}

}  // namespace

int main() {
    types();
    agreement();
    known_answer();
    guards();
    ecdh_asn();
    ecdh_jwk();
    return webcpp::test::exit_status(boost::report_errors());
}
