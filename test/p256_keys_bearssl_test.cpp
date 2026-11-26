// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// P-256 key pairs and public keys on BearSSL: RFC 6979's key made from its scalar, its public
// point the RFC's and its scalar read back; the scalar's range, 0 < d < n, checked before
// BearSSL (the engine's seam counts its calls); generate; a public key from its point and from
// its coordinates, and every refusal of a point (sizes, prefixes, the compressed form, off the
// curve, a coordinate not below p, the identity's encodings); a moved-from key pair; the key
// pair's storage zero once moved from and once destroyed, read at -O2 with every call inlined
// (the Jamfile's requirements), as ed25519_wipe_sodium_test.cpp reads Ed25519's; the types'
// traits, the key pair contract included; and secret()'s scalar, which makes the same key pair.

#include <cstddef>

namespace {

// The engine's calls: the seam of detail/p_curves.hpp, defined before any crypto header.
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): the seam's counter
std::size_t engine_calls = 0;

}  // namespace

/** Counts a call of the P-curve engine. */
#define WEBCPP_CRYPTO_DETAIL_P_CURVE_ENGINE_ENTERED() (++engine_calls)

#include <webcpp/crypto/backends/bearssl.hpp>
#include <webcpp/crypto/curves/p256.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/keypair.hpp>
#include <webcpp/crypto/signing.hpp>
#include <webcpp/crypto/supports.hpp>
#include <webcpp/secure/secret.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/p256_data.hpp"

#include <boost/core/lightweight_test.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <memory>
#include <span>
#include <type_traits>
#include <utility>

namespace {

namespace crypto = webcpp::crypto;
namespace secure = webcpp::secure;
namespace p256 = webcpp::crypto::curves::p256;
namespace data = webcpp::test::p256;

using crypto::error;
using p256::keypair;
using p256::public_key;

constexpr std::size_t keypair_state =
    sizeof(crypto::detail::p_curve_state<crypto::families::p256, crypto::backends::bearssl>);

static_assert(std::is_standard_layout_v<keypair>);
static_assert(keypair_state == 32 + 65);

// A function the optimiser cannot see into, so that what it is handed is read from memory.
#if defined(_MSC_VER) && !defined(__clang__)
#define WEBCPP_TEST_NOINLINE __declspec(noinline)
#else
#define WEBCPP_TEST_NOINLINE __attribute__((noinline))
#endif

// Whether every byte at `where` is zero, read through a volatile pointer in a function that is
// never inlined. It may be handed the storage of an object that is gone (the destructor's
// check), so it is exempt from the sanitizers that would stop that read.
#if defined(__clang__) || defined(__GNUC__)
__attribute__((no_sanitize("address")))
#endif
WEBCPP_TEST_NOINLINE bool memory_is_zero(void const* where, std::size_t count) {
    auto const volatile* const bytes = static_cast<unsigned char const volatile*>(where);
    for (std::size_t i = 0; i < count; ++i) {
        if (bytes[i] != 0) {
            return false;
        }
    }
    return true;
}

/** `value` with `last` as its last byte. */
std::array<std::uint8_t, 32> with_last_byte(std::array<std::uint8_t, 32> value, std::uint8_t last) {
    value.back() = last;
    return value;
}

void from_secret_of_rfc6979_scalar() {
    auto const made = keypair::from_secret(data::rfc6979_scalar);
    if (!BOOST_TEST(made.has_value())) {
        return;
    }
    auto const point = made->public_key();
    if (BOOST_TEST(point.has_value())) {
        BOOST_TEST(point->uncompressed() == data::rfc6979_public);
    }
    auto const scalar = made->secret();
    if (BOOST_TEST(scalar.has_value())) {
        BOOST_TEST(std::ranges::equal(scalar->bytes(), data::rfc6979_scalar));
    }
}

void scalar_out_of_range() {
    std::array<std::uint8_t, 32> const zero{};
    std::array<std::uint8_t, 32> all_ones{};
    all_ones.fill(0xff);
    BOOST_TEST(keypair::from_secret(zero).error() == error::invalid_secret_key);
    BOOST_TEST(keypair::from_secret(data::order).error() == error::invalid_secret_key);
    BOOST_TEST(keypair::from_secret(with_last_byte(data::order, 0x52)).error() ==
               error::invalid_secret_key);
    BOOST_TEST(keypair::from_secret(all_ones).error() == error::invalid_secret_key);
    BOOST_TEST(keypair::from_secret(with_last_byte(data::order, 0x50)).has_value());
    BOOST_TEST(keypair::from_secret(with_last_byte(zero, 0x01)).has_value());
    std::array<std::uint8_t, 33> const long_scalar{};
    BOOST_TEST(keypair::from_secret(std::span(data::rfc6979_scalar).first(31)).error() ==
               error::invalid_key_size);
    BOOST_TEST(keypair::from_secret(long_scalar).error() == error::invalid_key_size);
}

void scalar_check_reaches_no_backend() {
    // The control: a valid scalar reaches the engine, so the counter can move.
    engine_calls = 0;
    BOOST_TEST(keypair::from_secret(data::rfc6979_scalar).has_value());
    BOOST_TEST_GT(engine_calls, 0U);
    engine_calls = 0;
    BOOST_TEST(keypair::from_secret(data::order).error() == error::invalid_secret_key);
    BOOST_TEST_EQ(engine_calls, 0U);
}

void generate_makes_distinct_valid_keys() {
    auto const first = keypair::generate();
    auto const second = keypair::generate();
    if (!BOOST_TEST(first.has_value()) || !BOOST_TEST(second.has_value())) {
        return;
    }
    auto const first_scalar = first->secret();
    auto const second_scalar = second->secret();
    if (BOOST_TEST(first_scalar.has_value()) && BOOST_TEST(second_scalar.has_value())) {
        BOOST_TEST(!std::ranges::equal(first_scalar->bytes(), second_scalar->bytes()));
    }
    for (auto const* const pair : {&*first, &*second}) {
        auto const point = pair->public_key();
        if (BOOST_TEST(point.has_value())) {
            auto const again = public_key::from_bytes(point->uncompressed());
            if (BOOST_TEST(again.has_value())) {
                BOOST_TEST(again->uncompressed() == point->uncompressed());
            }
        }
    }
}

void public_key_from_point_and_coordinates() {
    std::span<std::uint8_t const, 65> const point(data::rfc6979_public);
    auto const from_point = public_key::from_bytes(point);
    auto const from_coordinates = public_key::from_coordinates(
        point.subspan<1, p256::coordinate_size>(),
        point.subspan<1 + p256::coordinate_size, p256::coordinate_size>());
    if (BOOST_TEST(from_point.has_value()) && BOOST_TEST(from_coordinates.has_value())) {
        BOOST_TEST(from_point->uncompressed() == data::rfc6979_public);
        BOOST_TEST(from_coordinates->uncompressed() == from_point->uncompressed());
    }
}

void public_key_refusals() {
    auto const refused = [](std::span<std::uint8_t const> point) {
        return public_key::from_bytes(point).error() == error::invalid_public_key;
    };
    std::array<std::uint8_t, 66> longer{};
    std::ranges::copy(data::rfc6979_public, longer.begin());
    BOOST_TEST(refused(std::span(data::rfc6979_public).first(64)));
    BOOST_TEST(refused(longer));
    // The compressed form: BearSSL decodes uncompressed points alone (design D36).
    std::array<std::uint8_t, 33> compressed{};
    std::ranges::copy(std::span(data::rfc6979_public).first(33), compressed.begin());
    compressed[0] = 0x02;
    BOOST_TEST(refused(compressed));
    auto other_prefix = data::rfc6979_public;
    other_prefix[0] = 0x05;
    BOOST_TEST(refused(other_prefix));
    // y + 1: off the curve (the last byte of y is 0x99, so no carry).
    auto off_curve = data::rfc6979_public;
    ++off_curve.back();
    BOOST_TEST(refused(off_curve));
    // x = p, with the RFC's y.
    auto x_is_p = data::rfc6979_public;
    std::ranges::copy(data::field_prime, x_is_p.begin() + 1);
    BOOST_TEST(refused(x_is_p));
    // A coordinate not below p of a point on the curve: (0, y0) and (x1, 1) are on it, and
    // accepted; written with x + p and y + p, the same points are refused, the curve's equation
    // alone would not refuse them.
    BOOST_TEST(!refused(data::point_x_zero));
    BOOST_TEST(refused(data::point_x_zero_plus_p));
    BOOST_TEST(!refused(data::point_y_one));
    BOOST_TEST(refused(data::point_y_one_plus_p));
    std::array<std::uint8_t, 65> zeros{};
    BOOST_TEST(refused(zeros));
    // 04 and zeros: (0, 0) is not on the curve, the identity has no affine form.
    zeros[0] = 0x04;
    BOOST_TEST(refused(zeros));
    // from_coordinates refuses as from_bytes does.
    std::span<std::uint8_t const, 65> const off(off_curve);
    BOOST_TEST(public_key::from_coordinates(off.subspan<1, 32>(), off.subspan<33, 32>()).error() ==
               error::invalid_public_key);
}

void backend_choice() {
    // Design D36: natively m62 where BearSSL has it, else m31; on WebAssembly m31 always.
#ifdef WEBCPP_CRYPTO_WEBASSEMBLY
    BOOST_TEST(crypto::detail::bearssl_p256() == &br_ec_p256_m31);
#else
    br_ec_impl const* const wide = br_ec_p256_m62_get();
    BOOST_TEST(crypto::detail::bearssl_p256() == (wide != nullptr ? wide : &br_ec_p256_m31));
#endif
}

void moved_from() {
    auto made = keypair::from_secret(data::rfc6979_scalar);
    if (!BOOST_TEST(made.has_value())) {
        return;
    }
    keypair& a = *made;
    keypair const b = std::move(a);
    // NOLINTBEGIN(bugprone-use-after-move,clang-analyzer-cplusplus.Move): the moved-from state
    // is what is tested.
    BOOST_TEST(a.public_key().error() == error::invalid_state);
    BOOST_TEST(a.secret().error() == error::invalid_state);
    std::array<std::uint8_t, p256::digest_size> const digest{};
    BOOST_TEST(a.sign(crypto::ecdsa_sha256, digest).error() == error::invalid_state);
    BOOST_TEST(a.sign(crypto::ecdsa_sha256, crypto::prehashed{digest}).error() ==
               error::invalid_state);
    auto const peer = b.public_key();
    BOOST_TEST(peer.has_value() && a.agree(*peer).error() == error::invalid_state);
    // NOLINTEND(bugprone-use-after-move,clang-analyzer-cplusplus.Move)
    auto const point = b.public_key();
    if (BOOST_TEST(point.has_value())) {
        BOOST_TEST(point->uncompressed() == data::rfc6979_public);
    }
    auto const scalar = b.secret();
    if (BOOST_TEST(scalar.has_value())) {
        BOOST_TEST(std::ranges::equal(scalar->bytes(), data::rfc6979_scalar));
    }
    // Moved over: the target holds the source's key, and the source is empty.
    auto other = keypair::from_secret(with_last_byte(std::array<std::uint8_t, 32>{}, 0x01));
    if (BOOST_TEST(other.has_value())) {
        a = std::move(*other);
        // NOLINTNEXTLINE(bugprone-use-after-move,clang-analyzer-cplusplus.Move): tested
        BOOST_TEST(other->public_key().error() == error::invalid_state);
        BOOST_TEST(a.public_key().has_value());
    }
}

void wipe() {
    auto made = keypair::from_secret(data::rfc6979_scalar);
    if (!BOOST_TEST(made.has_value())) {
        return;
    }
    // Alive, the state holds the scalar and the point: the checks below can fail.
    BOOST_TEST(!memory_is_zero(&*made, keypair_state));

    keypair taken = std::move(*made);
    BOOST_TEST(memory_is_zero(&*made, keypair_state));

    auto other = keypair::from_secret(data::rfc6979_scalar);
    if (BOOST_TEST(other.has_value())) {
        taken = std::move(*other);
        BOOST_TEST(memory_is_zero(&*other, keypair_state));
    }

    // Destroyed in storage this frame owns: its bytes are read after the destructor.
    alignas(keypair) std::array<std::byte, sizeof(keypair)> storage{};
    keypair* const placed =
        std::construct_at(reinterpret_cast<keypair*>(storage.data()), std::move(taken));
    BOOST_TEST(!memory_is_zero(placed, keypair_state));
    std::destroy_at(placed);
    BOOST_TEST(memory_is_zero(storage.data(), keypair_state));
}

void traits() {
    static_assert(!std::is_copy_constructible_v<keypair>);
    static_assert(!std::is_copy_assignable_v<keypair>);
    static_assert(std::is_nothrow_move_constructible_v<keypair>);
    static_assert(std::is_nothrow_move_assignable_v<keypair>);
    static_assert(!std::is_default_constructible_v<keypair>);
    static_assert(std::is_copy_constructible_v<public_key>);
    static_assert(!std::is_default_constructible_v<public_key>);
    static_assert(crypto::supports_v<keypair, crypto::backends::bearssl>);
    static_assert(!crypto::supports_v<keypair, crypto::backends::sodium>);
    static_assert(crypto::supports_v<public_key, crypto::backends::bearssl>);
    static_assert(std::is_same_v<crypto::default_backend_t<crypto::families::p256>,
                                 crypto::backends::bearssl>);
    static_assert(p256::secret_key_size == 32 && p256::coordinate_size == 32 &&
                  p256::public_key_size == 65 && p256::digest_size == 32 &&
                  p256::signature_size == 64 && p256::max_der_size == 72);
    static_assert(std::is_same_v<decltype(std::declval<keypair const&>().secret()),
                                 boost::system::result<secure::secret<32>>>);
    static_assert(crypto::keypair<keypair>);
    static_assert(std::is_same_v<keypair::public_key_type, public_key>);
    static_assert(keypair::secret_key_size == 32);
}

// secret() gives the scalar back, which makes the same key pair: of the same public point, and
// whose signatures the first one's public key verifies.
void secret_round_trip() {
    auto const first = keypair::generate();
    if (!BOOST_TEST(first.has_value())) {
        return;
    }
    auto const exported = first->secret();
    if (!BOOST_TEST(exported.has_value())) {
        return;
    }
    auto const again = keypair::from_secret(exported->bytes());
    if (!BOOST_TEST(again.has_value())) {
        return;
    }
    auto const first_point = first->public_key();
    auto const again_point = again->public_key();
    BOOST_TEST(first_point && again_point &&
               first_point->uncompressed() == again_point->uncompressed());
    std::array<std::uint8_t, 3> const message{'a', 'b', 'c'};
    auto const signature = again->sign(crypto::ecdsa_sha256, message);
    BOOST_TEST(signature && first_point &&
               crypto::verify(crypto::ecdsa_sha256, *signature, message, *first_point).has_value());
}

}  // namespace

int main() {
    from_secret_of_rfc6979_scalar();
    scalar_out_of_range();
    scalar_check_reaches_no_backend();
    generate_makes_distinct_valid_keys();
    public_key_from_point_and_coordinates();
    public_key_refusals();
    backend_choice();
    moved_from();
    wipe();
    traits();
    secret_round_trip();
    return webcpp::test::exit_status(boost::report_errors());
}
