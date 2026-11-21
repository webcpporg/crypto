// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// P-256 ECDH on BearSSL, the shared point's raw x coordinate as WebCrypto's deriveBits gives it:
// two sides agree, 100 times, on key pairs drawn from a printed seed that a define replays;
// fixed points of the algebra, with no table: d * (d * G) is the public point of d * d mod n,
// and d * (2 * G) the public point of 2 * d mod n, those scalars computed in the test by byte
// arithmetic; Wycheproof's ECDH vectors on points (every case: valid ones agree, invalid ones are
// refused, and the compressed points BearSSL does not decode are listed refusals); a moved-from
// key pair; the output's type.

#include <webcpp/crypto/backends/bearssl.hpp>
#include <webcpp/crypto/curves/p256.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/secret.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"
#include "support/p256_data.hpp"
#include "support/test_data.hpp"

#include <boost/core/lightweight_test.hpp>
#include <boost/json.hpp>
#include <boost/system/result.hpp>

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

namespace {

namespace crypto = webcpp::crypto;
namespace p256 = webcpp::crypto::curves::p256;
namespace data = webcpp::test::p256;
namespace test = webcpp::test;
namespace json = boost::json;

using crypto::error;
using p256::keypair;
using p256::public_key;
using scalar = std::array<std::uint8_t, 32>;

// The seed of the drawn key pairs: drawn on each run and printed; a run is replayed by building
// with the printed value, define=WEBCPP_TEST_P256_SEED=<seed> on b2's command line, with -a or a
// build directory of its own, since a define alone does not make b2 build the test again.
std::uint64_t random_seed() {
#ifdef WEBCPP_TEST_P256_SEED
    return WEBCPP_TEST_P256_SEED;
#else
    return std::random_device{}();
#endif
}

// A key pair from the generator: a scalar make refuses (0, or not below n, about once in 2^32)
// is drawn again, 16 times at most; a make that keeps failing fails the test, which goes on with
// RFC 6979's key rather than hang.
keypair draw(std::mt19937_64& generator) {
    for (int attempt = 0; attempt < 16; ++attempt) {
        scalar drawn{};
        std::ranges::generate(drawn,
                              [&generator] { return static_cast<std::uint8_t>(generator()); });
        auto made = keypair::make(drawn);
        if (made) {
            return std::move(*made);
        }
        BOOST_TEST(made.error() == error::invalid_secret_key);
    }
    BOOST_ERROR("draw: keypair::make refused 16 drawn scalars");
    return *keypair::make(data::rfc6979_scalar);
}

// a + b mod n, for a and b below n, big-endian bytes: the sum is below 2n, so one subtraction of
// n at most brings it below n.
scalar add_mod_n(scalar const& a, scalar const& b) {
    scalar sum{};
    unsigned carry = 0;
    for (std::size_t i = sum.size(); i-- > 0;) {
        unsigned const total = unsigned{a[i]} + unsigned{b[i]} + carry;
        sum[i] = static_cast<std::uint8_t>(total);
        carry = total >> 8U;
    }
    // sum - n, and its borrow: n is subtracted when the sum carried out or is not below n.
    scalar reduced{};
    unsigned borrow = 0;
    for (std::size_t i = reduced.size(); i-- > 0;) {
        unsigned const subtrahend = unsigned{data::order[i]} + borrow;
        unsigned const minuend = sum[i];
        reduced[i] = static_cast<std::uint8_t>(minuend - subtrahend);
        borrow = minuend < subtrahend ? 1U : 0U;
    }
    return (carry != 0 || borrow == 0) ? reduced : sum;
}

// a * b mod n, by doubling and adding over b's bits, the most significant first.
scalar mul_mod_n(scalar const& a, scalar const& b) {
    scalar product{};
    for (std::uint8_t const octet : b) {
        for (unsigned bit = 8; bit-- > 0;) {
            product = add_mod_n(product, product);
            if (((unsigned{octet} >> bit) & 1U) != 0) {
                product = add_mod_n(product, a);
            }
        }
    }
    return product;
}

// The x coordinate of a key pair's public point, the bytes 1 to 32 of its uncompressed form.
std::array<std::uint8_t, 32> public_x(keypair const& pair) {
    std::array<std::uint8_t, 32> x{};
    auto const point = pair.public_key();
    if (BOOST_TEST(point.has_value())) {
        auto const bytes = point->uncompressed();
        std::ranges::copy(std::span(bytes).subspan<1, 32>(), x.begin());
    }
    return x;
}

void types() {
    auto const a = keypair::make(data::rfc6979_scalar);
    if (!BOOST_TEST(a.has_value())) {
        return;
    }
    auto const peer = a->public_key();
    if (!BOOST_TEST(peer.has_value())) {
        return;
    }
    // The output is a secret<32>, which wipes itself.
    static_assert(std::is_same_v<decltype(a->ecdh_x(*peer)),
                                 boost::system::result<webcpp::crypto::secret<32>>>);
}

// 100 pairs of key pairs drawn from the seed: each side's x is the other's.
void agreement(std::mt19937_64& generator) {
    for (int round = 0; round < 100; ++round) {
        auto const a = draw(generator);
        auto const b = draw(generator);
        auto const a_public = a.public_key();
        auto const b_public = b.public_key();
        if (!BOOST_TEST(a_public.has_value()) || !BOOST_TEST(b_public.has_value())) {
            return;
        }
        auto const x_a = a.ecdh_x(*b_public);
        auto const x_b = b.ecdh_x(*a_public);
        if (!BOOST_TEST(x_a.has_value()) || !BOOST_TEST(x_b.has_value())) {
            return;
        }
        BOOST_TEST(std::ranges::equal(x_a->bytes(), x_b->bytes()));
    }
}

// The arithmetic itself, on values whose answers are known: (n - 1) + 1 = 0, and
// (n - 1) * (n - 1) = (-1) * (-1) = 1.
void modular_arithmetic() {
    scalar minus_one = data::order;
    minus_one.back() = static_cast<std::uint8_t>(minus_one.back() - 1);
    scalar one{};
    one.back() = 1;
    BOOST_TEST(add_mod_n(minus_one, one) == scalar{});
    BOOST_TEST(mul_mod_n(minus_one, minus_one) == one);
}

// One scalar d: ECDH with its own public key, d * (d * G), is the public point of d * d mod n,
// and with 2 * G, d * (2 * G), the public point of 2 * d mod n; their x coordinates compared.
void fixed_points(scalar const& d, public_key const& two_g) {
    auto const a = keypair::make(d);
    auto const squared = keypair::make(mul_mod_n(d, d));
    auto const doubled = keypair::make(add_mod_n(d, d));
    if (!BOOST_TEST(a.has_value()) || !BOOST_TEST(squared.has_value()) ||
        !BOOST_TEST(doubled.has_value())) {
        return;
    }
    auto const own = a->public_key();
    if (!BOOST_TEST(own.has_value())) {
        return;
    }
    auto const x_own = a->ecdh_x(*own);
    auto const x_doubled = a->ecdh_x(two_g);
    if (!BOOST_TEST(x_own.has_value()) || !BOOST_TEST(x_doubled.has_value())) {
        return;
    }
    BOOST_TEST(std::ranges::equal(x_own->bytes(), public_x(*squared)));
    BOOST_TEST(std::ranges::equal(x_doubled->bytes(), public_x(*doubled)));
}

// Fixed points of the algebra, with no table: RFC 6979's scalar, then 8 drawn from the seed,
// each through fixed_points, the scalars d * d and 2 * d mod n computed by bytes, here.
void own_key(std::mt19937_64& generator) {
    modular_arithmetic();
    scalar two{};
    two.back() = 2;
    auto const doubler = keypair::make(two);
    auto const two_g = doubler ? doubler->public_key() : doubler.error();
    if (!BOOST_TEST(two_g.has_value())) {
        return;
    }
    fixed_points(data::rfc6979_scalar, *two_g);
    for (int i = 0; i < 8; ++i) {
        auto const secret = draw(generator).secret_scalar();
        if (BOOST_TEST(secret.has_value())) {
            scalar d{};
            std::ranges::copy(secret->bytes(), d.begin());
            fixed_points(d, *two_g);
        }
    }
}

// NOLINTBEGIN(bugprone-use-after-move,clang-analyzer-cplusplus.Move): the moved-from state is what
// is tested.
void moved_from() {
    auto made = keypair::make(data::rfc6979_scalar);
    if (!BOOST_TEST(made.has_value())) {
        return;
    }
    keypair const taken = std::move(*made);
    auto const peer = taken.public_key();
    if (!BOOST_TEST(peer.has_value())) {
        return;
    }
    BOOST_TEST(made->ecdh_x(*peer).error() == error::invalid_state);
    BOOST_TEST(taken.ecdh_x(*peer).has_value());
}

// NOLINTEND(bugprone-use-after-move,clang-analyzer-cplusplus.Move)

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

// The counts of the file.
struct counts {
    /** Cases run. */
    int total = 0;
    /** Valid cases whose x agreed. */
    int valid = 0;
    /** Invalid cases refused. */
    int invalid = 0;
    /** Acceptable cases. */
    int acceptable = 0;
    /** Valid or acceptable cases with a compressed point, refused by public_key::make. */
    int compressed_refused = 0;
};

// Whether a case carries a flag.
bool flagged(json::value const& t, std::string_view flag) {
    auto const& flags = t.at("flags").as_array();
    return std::ranges::any_of(flags, [flag](json::value const& f) { return str(f) == flag; });
}

// A case's private key as 32 bytes: Wycheproof writes it as an ASN.1 integer's bytes, which may
// carry a leading 00, or shorter; the leading zero bytes are stripped and the rest left-padded.
// More than 32 significant bytes is no P-256 scalar: nothing is returned.
std::vector<std::uint8_t> scalar_bytes(std::vector<std::uint8_t> const& integer) {
    auto const first = std::ranges::find_if(integer, [](std::uint8_t b) { return b != 0; });
    std::vector<std::uint8_t> const significant(first, integer.end());
    if (significant.size() > 32) {
        return {};
    }
    std::vector<std::uint8_t> padded(32 - significant.size(), 0);
    padded.insert(padded.end(), significant.begin(), significant.end());
    return padded;
}

// The case's own ECDH, or the error of the step that refused it: keypair::make, public_key::make
// or ecdh_x.
boost::system::result<crypto::secret<32>> derive(std::vector<std::uint8_t> const& integer,
                                                 std::vector<std::uint8_t> const& point) {
    auto const padded = scalar_bytes(integer);
    if (padded.empty()) {
        return error::invalid_secret_key;
    }
    auto const pair = keypair::make(padded);
    if (!pair) {
        return pair.error();
    }
    auto const peer = public_key::make(point);
    if (!peer) {
        return peer.error();
    }
    return pair->ecdh_x(*peer);
}

// Reports a case that went wrong, by its number.
void report(json::value const& t, std::string_view what) {
    std::string message = "ecdh_secp256r1_ecpoint_test tcId ";
    message += std::to_string(t.at("tcId").to_number<std::int64_t>());
    message += ": ";
    message += what;
    BOOST_ERROR(message.c_str());
}

// The listed refusal of a valid or acceptable case: a compressed point, which BearSSL does not
// decode.
constexpr std::string_view compressed_reason =
    "BearSSL decodes uncompressed points alone, design D36";

// One case: an invalid one is refused at one of the three steps; a valid or acceptable one agrees
// with its shared x, unless its point is compressed, an expected refusal of public_key::make,
// printed with its reason; any other outcome fails.
void ecpoint_case(json::value const& t, counts& seen) {
    ++seen.total;
    auto const verdict = str(t.at("result"));
    auto const point = test::from_hex(str(t.at("public")));
    auto const derived = derive(test::from_hex(str(t.at("private"))), point);
    if (verdict == "invalid") {
        // Every invalid case of the file is a defect of its point: refused by public_key::make,
        // never by BearSSL's multiplication.
        if (derived.has_value()) {
            report(t, "invalid case derived a shared x");
        } else if (derived.error() != error::invalid_public_key) {
            report(t, "invalid case refused with another error than invalid_public_key");
        } else {
            ++seen.invalid;
        }
        return;
    }
    if (verdict != "valid" && verdict != "acceptable") {
        report(t, verdict + ", not expected");
        return;
    }
    seen.acceptable += verdict == "acceptable" ? 1 : 0;
    bool const compressed =
        point.size() == 33 && (flagged(t, "CompressedPoint") || flagged(t, "CompressedPublic"));
    if (compressed && public_key::make(point).error() == error::invalid_public_key) {
        ++seen.compressed_refused;
        std::cout << "ecdh_secp256r1_ecpoint_test tcId " << t.at("tcId").to_number<std::int64_t>()
                  << " " << verdict << ", refused by public_key::make: " << compressed_reason
                  << '\n';
        return;
    }
    auto const shared = test::from_hex(str(t.at("shared")));
    if (!derived.has_value() || !std::ranges::equal(derived->bytes(), shared)) {
        report(t, verdict + " case refused or disagreed");
        return;
    }
    seen.valid += verdict == "valid" ? 1 : 0;
}

// Wycheproof's ECDH on P-256 with the peer's key as a bare point (SEC 1's encoding), every case
// through ecpoint_case.
void wycheproof_ecpoint() {
    auto const doc = load("ecdh_secp256r1_ecpoint_test");
    counts seen;
    for (auto const& group : doc.at("testGroups").as_array()) {
        for (auto const& t : group.at("tests").as_array()) {
            ecpoint_case(t, seen);
        }
    }
    std::cout << "ecdh_secp256r1_ecpoint_test: tests=" << seen.total
              << " valid_agreed=" << seen.valid << " invalid_refused=" << seen.invalid
              << " acceptable=" << seen.acceptable
              << " compressed_refused=" << seen.compressed_refused << '\n';
    BOOST_TEST_EQ(seen.total, 355);
    BOOST_TEST_EQ(seen.valid, 330);
    BOOST_TEST_EQ(seen.invalid, 24);
    BOOST_TEST_EQ(seen.acceptable, 1);
    BOOST_TEST_EQ(seen.compressed_refused, 1);
}

}  // namespace

int main() {
    std::uint64_t const seed = random_seed();
    std::cout << "p256_ecdh_bearssl: seed " << seed
              << " (replay: define=WEBCPP_TEST_P256_SEED=" << seed << ")\n";
    std::mt19937_64 generator(seed);
    types();
    agreement(generator);
    own_key(generator);
    moved_from();
    wycheproof_ecpoint();
    return webcpp::test::exit_status(boost::report_errors());
}
