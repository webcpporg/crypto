// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// signing.hpp's vocabulary, over stand-in key types that this test declares: the tags take no
// `{}`, prehashed deduces its size from a fixed-size digest and converts to and from nothing,
// can_sign and can_verify accept a message or a marker of the scheme's digest size, and refuse
// a marker on a backend that completes by itself; the catch-all verify is a candidate only where
// no curve declares a verifier; sha256_of gives FIPS 180-2's digest.

#include <webcpp/crypto/signing.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"

#include <boost/core/lightweight_test.hpp>
#include <boost/hash2/digest.hpp>
#include <boost/system/result.hpp>

#include <array>
#include <concepts>
#include <cstdint>
#include <span>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

namespace crypto = webcpp::crypto;

namespace {

// A key pair whose backend signs a digest, with ECDSA over SHA-256 alone.
struct stand_in_keypair {};

// The public key that goes with it.
struct stand_in_public_key {};

// A synchronous backend.
struct stand_in_backend {};

// A key pair whose backend completes by itself, as the browser's will.
struct stand_in_async_keypair {};

// A backend that completes by itself.
struct stand_in_async_backend {};

// A public key a curve gives a verifier of its own, so that the catch-all steps aside.
struct stand_in_verified_key {};

// An empty struct without an explicit default constructor, to show the check below can pass.
struct plain_tag {};

}  // namespace

namespace webcpp::crypto::detail {

template <>
inline constexpr bool signs_with_v<stand_in_keypair, ecdsa_sha256_t> = true;

template <>
inline constexpr bool verifies_with_v<stand_in_public_key, ecdsa_sha256_t> = true;

template <>
struct key_backend<stand_in_keypair> {
    using type = stand_in_backend;
};

template <>
inline constexpr bool signs_with_v<stand_in_async_keypair, ecdsa_sha256_t> = true;

template <>
struct key_backend<stand_in_async_keypair> {
    using type = stand_in_async_backend;
};

template <>
inline constexpr bool asynchronous_backend_v<stand_in_async_backend> = true;

template <>
inline constexpr bool has_verifier_v<ecdsa_sha256_t, stand_in_verified_key> = true;

}  // namespace webcpp::crypto::detail

namespace {

using digest32 = std::array<std::uint8_t, 32>;
using message_span = std::span<std::uint8_t const>;

// A function that takes a tag by value, declared only: the concept below asks whether `{}` can
// initialize its parameter, which is copy-list-initialization. A static member, so that no
// compiler reports a function template nothing calls.
template <class Tag>
struct taker {
    static void take(Tag tag);
};

template <class Tag>
concept from_empty_braces = requires { taker<Tag>::take({}); };

// The tags: an explicit default constructor keeps `{}` from standing for a scheme.
static_assert(from_empty_braces<plain_tag>);

template <class... Schemes>
constexpr bool none_from_empty_braces(crypto::detail::scheme_list<Schemes...> /*list*/) noexcept {
    return (!from_empty_braces<Schemes> && ...);
}

static_assert(none_from_empty_braces(crypto::detail::all_schemes{}));
static_assert(!std::is_constructible_v<crypto::ecdsa_sha256_t, int>);
static_assert(std::is_same_v<decltype(crypto::eddsa), crypto::eddsa_t const>);
static_assert(std::is_same_v<decltype(crypto::ecdsa_sha256), crypto::ecdsa_sha256_t const>);
static_assert(std::is_same_v<decltype(crypto::ecdsa_sha256_recoverable),
                             crypto::ecdsa_sha256_recoverable_t const>);
static_assert(std::is_same_v<decltype(crypto::schnorr), crypto::schnorr_t const>);

// The schemes' sizes.
static_assert(crypto::detail::scheme_traits<crypto::eddsa_t>::signature_size == 64);
static_assert(crypto::detail::scheme_traits<crypto::eddsa_t>::digest_size == 0);
static_assert(crypto::detail::scheme_traits<crypto::ecdsa_sha256_t>::signature_size == 64);
static_assert(crypto::detail::scheme_traits<crypto::ecdsa_sha256_t>::digest_size == 32);
static_assert(crypto::detail::scheme_traits<crypto::ecdsa_sha256_recoverable_t>::signature_size ==
              65);
static_assert(crypto::detail::scheme_traits<crypto::ecdsa_sha256_recoverable_t>::digest_size == 32);
static_assert(crypto::detail::scheme_traits<crypto::schnorr_t>::signature_size == 64);
static_assert(crypto::detail::scheme_traits<crypto::schnorr_t>::digest_size == 0);

// The marker deduces its size from a fixed-size digest of each kind.
static_assert(std::is_same_v<decltype(crypto::prehashed{digest32{}}), crypto::prehashed<32>>);
static_assert(
    std::is_same_v<decltype(crypto::prehashed{boost::hash2::digest<32>{}}), crypto::prehashed<32>>);
static_assert(
    std::is_same_v<decltype(crypto::prehashed{std::declval<std::span<std::uint8_t, 48>>()}),
                   crypto::prehashed<48>>);
static_assert(
    std::is_same_v<decltype(crypto::prehashed{std::declval<std::span<std::uint8_t const, 32>>()}),
                   crypto::prehashed<32>>);

// No conversion turns a span or an array into a marker, or a marker into a span.
static_assert(!std::is_convertible_v<std::span<std::uint8_t const, 32>, crypto::prehashed<32>>);
static_assert(!std::is_convertible_v<crypto::prehashed<32>, message_span>);
static_assert(!std::is_convertible_v<digest32, crypto::prehashed<32>>);
static_assert(!std::is_convertible_v<boost::hash2::digest<32>, crypto::prehashed<32>>);

// What is a message and what is a marker.
static_assert(crypto::detail::is_message_v<digest32>);
static_assert(crypto::detail::is_message_v<message_span>);
static_assert(crypto::detail::is_message_v<std::vector<std::uint8_t>>);
static_assert(!crypto::detail::is_message_v<crypto::prehashed<32>>);
static_assert(!crypto::detail::is_message_v<int>);
static_assert(crypto::detail::is_prehashed_v<crypto::prehashed<32>>);
static_assert(!crypto::detail::is_prehashed_v<digest32>);

// A backend signs a digest unless it completes by itself; a byte key has no backend.
static_assert(crypto::detail::signs_prehashed_v<stand_in_backend>);
static_assert(crypto::detail::signs_prehashed_v<void>);
static_assert(!crypto::detail::signs_prehashed_v<stand_in_async_backend>);
static_assert(std::is_void_v<crypto::detail::key_backend<stand_in_public_key>::type>);

// can_sign: a message of any size, or a marker of the scheme's digest size.
static_assert(crypto::can_sign<stand_in_keypair, crypto::ecdsa_sha256_t, digest32>);
static_assert(crypto::can_sign<stand_in_keypair, crypto::ecdsa_sha256_t, digest32 const&>);
static_assert(crypto::can_sign<stand_in_keypair, crypto::ecdsa_sha256_t, message_span>);
static_assert(crypto::can_sign<stand_in_keypair, crypto::ecdsa_sha256_t, crypto::prehashed<32>>);
static_assert(!crypto::can_sign<stand_in_keypair, crypto::ecdsa_sha256_t, crypto::prehashed<48>>);
static_assert(!crypto::can_sign<stand_in_keypair, crypto::ecdsa_sha256_t, int>);
static_assert(!crypto::can_sign<stand_in_keypair, crypto::schnorr_t, message_span>);
static_assert(!crypto::can_sign<stand_in_keypair, crypto::eddsa_t, message_span>);

// On a backend that completes by itself, the message alone.
static_assert(crypto::can_sign<stand_in_async_keypair, crypto::ecdsa_sha256_t, message_span>);
static_assert(
    !crypto::can_sign<stand_in_async_keypair, crypto::ecdsa_sha256_t, crypto::prehashed<32>>);

// can_verify: the same, over the public key.
static_assert(crypto::can_verify<crypto::ecdsa_sha256_t, message_span, stand_in_public_key>);
static_assert(
    crypto::can_verify<crypto::ecdsa_sha256_t, crypto::prehashed<32>, stand_in_public_key const&>);
static_assert(
    !crypto::can_verify<crypto::ecdsa_sha256_t, crypto::prehashed<48>, stand_in_public_key>);
static_assert(!crypto::can_verify<crypto::schnorr_t, message_span, stand_in_public_key>);

// The two traits are apart: a key pair does not verify, a public key does not sign.
static_assert(!crypto::can_sign<stand_in_public_key, crypto::ecdsa_sha256_t, message_span>);
static_assert(!crypto::can_verify<crypto::ecdsa_sha256_t, message_span, stand_in_keypair>);

// The catch-all verify is a candidate where no curve declares a verifier, and steps aside where
// one does; a requires-expression reads its declaration alone, never its refusal.
template <class PublicKey>
concept catch_all_verify = requires(std::array<std::uint8_t, 64> const& signature,
                                    message_span message, PublicKey const& public_key) {
    {
        crypto::verify(crypto::ecdsa_sha256, signature, message, public_key)
    } -> std::same_as<boost::system::result<void>>;
};
static_assert(!crypto::detail::has_verifier_v<crypto::ecdsa_sha256_t, stand_in_public_key>);
static_assert(catch_all_verify<stand_in_public_key>);
static_assert(!catch_all_verify<stand_in_verified_key>);

// A backend named first, as every curve's verify takes it, is no scheme: the catch-all, whose
// first template parameter is the scheme, steps aside for it, and adds no error of its own to a
// call that a curve's verify takes.
template <class Backend, class PublicKey>
concept catch_all_verify_on = requires(std::array<std::uint8_t, 64> const& signature,
                                       message_span message, PublicKey const& public_key) {
    crypto::verify<Backend>(crypto::ecdsa_sha256, signature, message, public_key);
};
static_assert(!catch_all_verify_on<stand_in_backend, stand_in_public_key>);
static_assert(catch_all_verify_on<crypto::ecdsa_sha256_t, stand_in_public_key>);

// The catch-all takes a scheme tag alone: a four-argument verify whose first argument is not a
// scheme, found by argument-dependent lookup through a crypto type, is not captured.
template <class Scheme>
concept catch_all_takes = requires(Scheme scheme, std::array<std::uint8_t, 64> const& signature,
                                   message_span message, stand_in_public_key const& public_key) {
    crypto::verify(scheme, signature, message, public_key);
};

template <class... Schemes>
constexpr bool catch_all_takes_each(crypto::detail::scheme_list<Schemes...> /*list*/) noexcept {
    return (catch_all_takes<Schemes> && ...);
}

static_assert(catch_all_takes_each(crypto::detail::all_schemes{}));
static_assert(!catch_all_takes<int>);
static_assert(!catch_all_takes<crypto::prehashed<32>>);
static_assert(crypto::detail::is_scheme_v<crypto::ecdsa_sha256_recoverable_t>);
static_assert(!crypto::detail::is_scheme_v<crypto::ecdsa_sha256_t const>);

// The library's one list of schemes: is_scheme_v is true of each of its members, each has its
// traits, and the list is the four tags.
template <class... Schemes>
constexpr bool all_are_schemes(crypto::detail::scheme_list<Schemes...> /*list*/) noexcept {
    return (crypto::detail::is_scheme_v<Schemes> && ...) &&
           ((crypto::detail::scheme_traits<Schemes>::signature_size != 0) && ...);
}

static_assert(all_are_schemes(crypto::detail::all_schemes{}));
static_assert(std::is_same_v<
              crypto::detail::all_schemes,
              crypto::detail::scheme_list<crypto::eddsa_t, crypto::ecdsa_sha256_t,
                                          crypto::ecdsa_sha256_recoverable_t, crypto::schnorr_t>>);
static_assert(!crypto::detail::is_scheme_v<crypto::detail::all_schemes>);
static_assert(!crypto::detail::is_scheme_v<crypto::prehashed<32>>);
static_assert(!crypto::detail::in_scheme_list_v<crypto::eddsa_t, int>);
static_assert(!crypto::detail::in_scheme_list_v<crypto::eddsa_t, std::tuple<crypto::eddsa_t>>);

// sha256_of is SHA-256: FIPS 180-2's "abc" and the empty message.
void sha256_of_is_sha256() {
    std::array<std::uint8_t, 3> const abc{'a', 'b', 'c'};
    BOOST_TEST(
        crypto::detail::sha256_of(abc) ==
        webcpp::test::hex<32>("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    BOOST_TEST(
        crypto::detail::sha256_of(message_span{}) ==
        webcpp::test::hex<32>("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
}

// message_bytes views a message's bytes where they are.
void message_bytes_views_the_message() {
    std::vector<std::uint8_t> const message{1, 2, 3};
    auto const bytes = crypto::detail::message_bytes(message);
    BOOST_TEST_EQ(bytes.data(), message.data());
    BOOST_TEST_EQ(bytes.size(), message.size());
    BOOST_TEST(crypto::detail::message_bytes(message_span{}).empty());
}

// The marker views the digest it is given, and the valid inputs pass the checks.
void prehashed_views_the_digest() {
    digest32 const digest = crypto::detail::sha256_of(message_span{});
    crypto::prehashed const marker{digest};
    BOOST_TEST_EQ(marker.digest.data(), digest.data());
    boost::hash2::digest<32> hashed{};
    crypto::prehashed const from_hash2{hashed};
    BOOST_TEST_EQ(from_hash2.digest.data(), hashed.data());
    crypto::detail::check_input<crypto::ecdsa_sha256_t, crypto::prehashed<32>, stand_in_backend>();
    crypto::detail::check_input<crypto::ecdsa_sha256_recoverable_t, crypto::prehashed<32>, void>();
    crypto::detail::check_input<crypto::eddsa_t, digest32, void>();
    crypto::detail::check_input<crypto::schnorr_t, message_span, stand_in_async_backend>();
}

}  // namespace

int main() {
    sha256_of_is_sha256();
    message_bytes_views_the_message();
    prehashed_views_the_digest();
    return webcpp::test::exit_status(boost::report_errors());
}
