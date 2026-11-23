// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The five signature types (design D1): each is made from bytes of its own size alone, by its
// from_bytes and by crypto::from_bytes, gives them back unchanged through bytes(), and refuses one
// byte fewer or more with invalid_signature; recoverable_signature gives its last byte as the
// recovery id, which no other type has. Each is a regular value type, and none converts to or is
// made from another of them or bytes. detail::signature_of names each curve's type for its key
// pairs and public keys under each scheme they sign or verify, and void for any other pair.

#include <webcpp/crypto/backends/bearssl.hpp>
#include <webcpp/crypto/backends/sodium.hpp>
#include <webcpp/crypto/curves/ed25519.hpp>
#include <webcpp/crypto/curves/p256.hpp>
#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/detail/signature.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/factories.hpp>
#include <webcpp/crypto/signing.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>

#include <algorithm>
#include <array>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <span>
#include <type_traits>
#include <vector>

namespace {

namespace crypto = webcpp::crypto;
namespace ed25519 = crypto::curves::ed25519;
namespace p256 = crypto::curves::p256;
namespace secp256k1 = crypto::curves::secp256k1;

template <class... Types>
struct type_list {};

using signature_types =
    type_list<ed25519::signature, p256::ecdsa_signature, secp256k1::ecdsa_signature,
              secp256k1::recoverable_signature, secp256k1::schnorr_signature>;

// Neither type converts to the other nor is made from it, either way.
template <class First, class Second>
inline constexpr bool unrelated_v =
    !std::is_convertible_v<First, Second> && !std::is_constructible_v<Second, First> &&
    !std::is_convertible_v<Second, First> && !std::is_constructible_v<First, Second>;

// Signature is unrelated to every type of the list except itself.
template <class Signature, class... Others>
consteval bool unrelated_to_others(type_list<Others...> /*unused*/) {
    return ((std::is_same_v<Signature, Others> || unrelated_v<Signature, Others>) && ...);
}

template <class... Signatures>
consteval bool pairwise_unrelated(type_list<Signatures...> list) {
    return (unrelated_to_others<Signatures>(list) && ...);
}

static_assert(pairwise_unrelated(signature_types{}));

// Written through a concept, so that a type without recovery_id() reads as false instead of
// stopping the build (a requires-expression outside a template is a hard error).
template <class Signature>
concept has_recovery_id = requires(Signature const& signature_value) {
    { signature_value.recovery_id() } -> std::same_as<std::uint8_t>;
};

template <class... Signatures>
consteval bool regular_and_unrelated_to_bytes(type_list<Signatures...> /*unused*/) {
    return ((std::regular<Signatures> && unrelated_v<Signatures, std::span<std::uint8_t const>> &&
             unrelated_v<Signatures, std::array<std::uint8_t, 64>>) &&
            ...);
}

static_assert(regular_and_unrelated_to_bytes(signature_types{}));

static_assert(ed25519::signature::size == 64);
static_assert(p256::ecdsa_signature::size == 64);
static_assert(secp256k1::ecdsa_signature::size == 64);
static_assert(secp256k1::recoverable_signature::size == 65);
static_assert(secp256k1::schnorr_signature::size == 64);

static_assert(has_recovery_id<secp256k1::recoverable_signature>);
static_assert(!has_recovery_id<ed25519::signature>);
static_assert(!has_recovery_id<p256::ecdsa_signature>);
static_assert(!has_recovery_id<secp256k1::ecdsa_signature>);
static_assert(!has_recovery_id<secp256k1::schnorr_signature>);

using crypto::detail::signature_of_t;

static_assert(
    std::is_same_v<signature_of_t<ed25519::keypair, crypto::eddsa_t>, ed25519::signature>);
static_assert(
    std::is_same_v<signature_of_t<ed25519::public_key, crypto::eddsa_t>, ed25519::signature>);
static_assert(
    std::is_same_v<signature_of_t<p256::keypair, crypto::ecdsa_sha256_t>, p256::ecdsa_signature>);
static_assert(std::is_same_v<signature_of_t<p256::public_key, crypto::ecdsa_sha256_t>,
                             p256::ecdsa_signature>);
static_assert(std::is_same_v<signature_of_t<secp256k1::keypair, crypto::ecdsa_sha256_t>,
                             secp256k1::ecdsa_signature>);
static_assert(std::is_same_v<signature_of_t<secp256k1::keypair, crypto::ecdsa_sha256_recoverable_t>,
                             secp256k1::recoverable_signature>);
static_assert(std::is_same_v<signature_of_t<secp256k1::keypair, crypto::schnorr_t>,
                             secp256k1::schnorr_signature>);
static_assert(std::is_same_v<signature_of_t<secp256k1::public_key, crypto::ecdsa_sha256_t>,
                             secp256k1::ecdsa_signature>);
static_assert(std::is_same_v<signature_of_t<secp256k1::public_key, crypto::schnorr_t>,
                             secp256k1::schnorr_signature>);
static_assert(std::is_same_v<signature_of_t<std::array<std::uint8_t, 32>, crypto::schnorr_t>,
                             secp256k1::schnorr_signature>);
static_assert(std::is_same_v<signature_of_t<std::span<std::uint8_t const, 32>, crypto::schnorr_t>,
                             secp256k1::schnorr_signature>);

// A pair that neither signs nor verifies has none.
static_assert(std::is_same_v<signature_of_t<p256::keypair, crypto::schnorr_t>, void>);
static_assert(std::is_same_v<signature_of_t<ed25519::keypair, crypto::ecdsa_sha256_t>, void>);
static_assert(std::is_same_v<signature_of_t<p256::keypair, crypto::eddsa_t>, void>);
static_assert(std::is_same_v<
              signature_of_t<secp256k1::public_key, crypto::ecdsa_sha256_recoverable_t>, void>);
static_assert(std::is_same_v<signature_of_t<std::array<std::uint8_t, 32>, crypto::eddsa_t>, void>);
static_assert(
    std::is_same_v<signature_of_t<std::array<std::uint8_t, 33>, crypto::schnorr_t>, void>);

// Bytes 1, 2, ..., count.
std::vector<std::uint8_t> counting_bytes(std::size_t count) {
    std::vector<std::uint8_t> made_bytes(count);
    for (std::size_t i = 0; i < count; ++i) {
        made_bytes[i] = static_cast<std::uint8_t>(i + 1);
    }
    return made_bytes;
}

// Signature's from_bytes, member and free, keeps bytes of its size and refuses one fewer or more.
template <class Signature>
void round_trips() {
    auto const wire_bytes = counting_bytes(Signature::size);
    auto const made = Signature::from_bytes(wire_bytes);
    if (BOOST_TEST(made.has_value())) {
        BOOST_TEST(std::ranges::equal(made->bytes(), wire_bytes));
        BOOST_TEST(*made != Signature{});
    }
    auto const free_made = crypto::from_bytes<Signature>(wire_bytes);
    if (BOOST_TEST(free_made.has_value())) {
        BOOST_TEST(made.has_value() && *free_made == *made);
    }
    auto const short_bytes = counting_bytes(Signature::size - 1);
    auto const long_bytes = counting_bytes(Signature::size + 1);
    BOOST_TEST(Signature::from_bytes(short_bytes).error() == crypto::error::invalid_signature);
    BOOST_TEST(Signature::from_bytes(long_bytes).error() == crypto::error::invalid_signature);
    BOOST_TEST(Signature::from_bytes({}).error() == crypto::error::invalid_signature);
    BOOST_TEST(crypto::from_bytes<Signature>(short_bytes).error() ==
               crypto::error::invalid_signature);
    // The default value is all zeros.
    Signature const zero_value{};
    BOOST_TEST(
        std::ranges::all_of(zero_value.bytes(), [](std::uint8_t byte) { return byte == 0; }));
}

template <class... Signatures>
void all_round_trip(type_list<Signatures...> /*unused*/) {
    (round_trips<Signatures>(), ...);
}

void signature_from_wire() {
    all_round_trip(signature_types{});

    // The recovery id is the 65th byte, read as it is.
    auto wire_bytes = counting_bytes(secp256k1::recoverable_signature::size);
    wire_bytes.back() = 2;
    auto const recoverable = secp256k1::recoverable_signature::from_bytes(wire_bytes);
    if (BOOST_TEST(recoverable.has_value())) {
        BOOST_TEST_EQ(recoverable->recovery_id(), 2);
        BOOST_TEST_EQ(recoverable->bytes()[64], 2);
    }

    // Two values of the same bytes are equal, and one byte apart are not.
    auto const first = p256::ecdsa_signature::from_bytes(counting_bytes(64));
    auto other_bytes = counting_bytes(64);
    other_bytes[63] = 0;
    auto const second = p256::ecdsa_signature::from_bytes(other_bytes);
    auto const again = p256::ecdsa_signature::from_bytes(counting_bytes(64));
    if (BOOST_TEST(first.has_value() && second.has_value() && again.has_value())) {
        BOOST_TEST(*first == *again);
        BOOST_TEST(*first != *second);
        p256::ecdsa_signature copied = *second;
        copied = *first;
        BOOST_TEST(copied == *first);
    }
}

}  // namespace

int main() {
    signature_from_wire();
    return webcpp::test::exit_status(boost::report_errors());
}
