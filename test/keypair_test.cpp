// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The key pair contract, crypto::keypair (design D8): Ed25519's, P-256's and secp256k1's key pairs
// meet it, on libsodium, BearSSL and libsecp256k1, each through the contract alone, Ed25519's with
// its two schemes (eddsa_prehashed over a 64-byte digest marker), secp256k1's
// with each of its four schemes (the two recoverable ones over a digest marker, recovered); a
// stand-in that has every member meets it, and stand-ins that
// lack one member each (from_secret, generate, public_key_type, secret), whose from_secret,
// generate, public_key or secret gives another type, or whose curve declares no scheme, or a
// scheme they do not sign, do not; the contract folds over the list of schemes,
// detail::all_schemes, so that a test-only scheme added to a list is asked of a stand-in that
// declares it.

#include <webcpp/crypto/backends/bearssl.hpp>
#include <webcpp/crypto/backends/sodium.hpp>
#include <webcpp/crypto/curves/ed25519.hpp>
#include <webcpp/crypto/curves/p256.hpp>
#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/keypair.hpp>
#include <webcpp/crypto/secret.hpp>
#include <webcpp/crypto/signing.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>
#include <boost/system/result.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <tuple>
#include <type_traits>

namespace crypto = webcpp::crypto;

namespace {

// A public key, for the stand-ins.
struct stand_in_public_key {};

// Every member of the contract, and ECDSA over SHA-256 declared and signed.
struct complete_keypair {
    using public_key_type = stand_in_public_key;
    [[maybe_unused]] static constexpr std::size_t secret_key_size = 32;
    static boost::system::result<complete_keypair> from_secret(
        std::span<std::uint8_t const>) noexcept;
    static boost::system::result<complete_keypair> generate() noexcept;
    [[nodiscard]] boost::system::result<stand_in_public_key> public_key() const noexcept;
    [[nodiscard]] boost::system::result<crypto::secret<32>> secret() const noexcept;
    [[nodiscard]] boost::system::result<std::array<std::uint8_t, 64>> sign(
        crypto::ecdsa_sha256_t, std::span<std::uint8_t const>) const noexcept;
};

// Every member but secret().
struct no_secret_keypair {
    using public_key_type = stand_in_public_key;
    [[maybe_unused]] static constexpr std::size_t secret_key_size = 32;
    static boost::system::result<no_secret_keypair> from_secret(
        std::span<std::uint8_t const>) noexcept;
    static boost::system::result<no_secret_keypair> generate() noexcept;
    [[nodiscard]] boost::system::result<stand_in_public_key> public_key() const noexcept;
    [[nodiscard]] boost::system::result<std::array<std::uint8_t, 64>> sign(
        crypto::ecdsa_sha256_t, std::span<std::uint8_t const>) const noexcept;
};

// A secret() of a size other than secret_key_size.
struct wrong_secret_keypair {
    using public_key_type = stand_in_public_key;
    [[maybe_unused]] static constexpr std::size_t secret_key_size = 32;
    static boost::system::result<wrong_secret_keypair> from_secret(
        std::span<std::uint8_t const>) noexcept;
    static boost::system::result<wrong_secret_keypair> generate() noexcept;
    [[nodiscard]] boost::system::result<stand_in_public_key> public_key() const noexcept;
    [[nodiscard]] boost::system::result<crypto::secret<64>> secret() const noexcept;
    [[nodiscard]] boost::system::result<std::array<std::uint8_t, 64>> sign(
        crypto::ecdsa_sha256_t, std::span<std::uint8_t const>) const noexcept;
};

// A public_key() that gives bytes, not public_key_type.
struct byte_public_keypair {
    using public_key_type = stand_in_public_key;
    [[maybe_unused]] static constexpr std::size_t secret_key_size = 32;
    static boost::system::result<byte_public_keypair> from_secret(
        std::span<std::uint8_t const>) noexcept;
    static boost::system::result<byte_public_keypair> generate() noexcept;
    [[nodiscard]] boost::system::result<std::array<std::uint8_t, 32>> public_key() const noexcept;
    [[nodiscard]] boost::system::result<crypto::secret<32>> secret() const noexcept;
    [[nodiscard]] boost::system::result<std::array<std::uint8_t, 64>> sign(
        crypto::ecdsa_sha256_t, std::span<std::uint8_t const>) const noexcept;
};

// No generate().
struct no_generate_keypair {
    using public_key_type = stand_in_public_key;
    [[maybe_unused]] static constexpr std::size_t secret_key_size = 32;
    static boost::system::result<no_generate_keypair> from_secret(
        std::span<std::uint8_t const>) noexcept;
    [[nodiscard]] boost::system::result<stand_in_public_key> public_key() const noexcept;
    [[nodiscard]] boost::system::result<crypto::secret<32>> secret() const noexcept;
    [[nodiscard]] boost::system::result<std::array<std::uint8_t, 64>> sign(
        crypto::ecdsa_sha256_t, std::span<std::uint8_t const>) const noexcept;
};

// Every member, but its curve declares no scheme for it.
struct no_scheme_keypair {
    using public_key_type = stand_in_public_key;
    [[maybe_unused]] static constexpr std::size_t secret_key_size = 32;
    static boost::system::result<no_scheme_keypair> from_secret(
        std::span<std::uint8_t const>) noexcept;
    static boost::system::result<no_scheme_keypair> generate() noexcept;
    [[nodiscard]] boost::system::result<stand_in_public_key> public_key() const noexcept;
    [[nodiscard]] boost::system::result<crypto::secret<32>> secret() const noexcept;
    [[nodiscard]] boost::system::result<std::array<std::uint8_t, 64>> sign(
        crypto::ecdsa_sha256_t, std::span<std::uint8_t const>) const noexcept;
};

// Its curve declares schnorr too, which it does not sign.
struct unsigned_scheme_keypair {
    using public_key_type = stand_in_public_key;
    [[maybe_unused]] static constexpr std::size_t secret_key_size = 32;
    static boost::system::result<unsigned_scheme_keypair> from_secret(
        std::span<std::uint8_t const>) noexcept;
    static boost::system::result<unsigned_scheme_keypair> generate() noexcept;
    [[nodiscard]] boost::system::result<stand_in_public_key> public_key() const noexcept;
    [[nodiscard]] boost::system::result<crypto::secret<32>> secret() const noexcept;
    [[nodiscard]] boost::system::result<std::array<std::uint8_t, 64>> sign(
        crypto::ecdsa_sha256_t, std::span<std::uint8_t const>) const noexcept;
};

// No from_secret().
struct no_from_secret_keypair {
    using public_key_type = stand_in_public_key;
    [[maybe_unused]] static constexpr std::size_t secret_key_size = 32;
    static boost::system::result<no_from_secret_keypair> generate() noexcept;
    [[nodiscard]] boost::system::result<stand_in_public_key> public_key() const noexcept;
    [[nodiscard]] boost::system::result<crypto::secret<32>> secret() const noexcept;
    [[nodiscard]] boost::system::result<std::array<std::uint8_t, 64>> sign(
        crypto::ecdsa_sha256_t, std::span<std::uint8_t const>) const noexcept;
};

// No public_key_type.
struct no_public_key_type_keypair {
    [[maybe_unused]] static constexpr std::size_t secret_key_size = 32;
    static boost::system::result<no_public_key_type_keypair> from_secret(
        std::span<std::uint8_t const>) noexcept;
    static boost::system::result<no_public_key_type_keypair> generate() noexcept;
    [[nodiscard]] boost::system::result<stand_in_public_key> public_key() const noexcept;
    [[nodiscard]] boost::system::result<crypto::secret<32>> secret() const noexcept;
    [[nodiscard]] boost::system::result<std::array<std::uint8_t, 64>> sign(
        crypto::ecdsa_sha256_t, std::span<std::uint8_t const>) const noexcept;
};

// A generate() that gives something other than result<K>.
struct wrong_generate_keypair {
    using public_key_type = stand_in_public_key;
    [[maybe_unused]] static constexpr std::size_t secret_key_size = 32;
    static boost::system::result<wrong_generate_keypair> from_secret(
        std::span<std::uint8_t const>) noexcept;
    static boost::system::result<int> generate() noexcept;
    [[nodiscard]] boost::system::result<stand_in_public_key> public_key() const noexcept;
    [[nodiscard]] boost::system::result<crypto::secret<32>> secret() const noexcept;
    [[nodiscard]] boost::system::result<std::array<std::uint8_t, 64>> sign(
        crypto::ecdsa_sha256_t, std::span<std::uint8_t const>) const noexcept;
};

// A from_secret() that gives the key pair itself, not result<K>.
struct wrong_from_secret_keypair {
    using public_key_type = stand_in_public_key;
    [[maybe_unused]] static constexpr std::size_t secret_key_size = 32;
    static wrong_from_secret_keypair from_secret(std::span<std::uint8_t const>) noexcept;
    static boost::system::result<wrong_from_secret_keypair> generate() noexcept;
    [[nodiscard]] boost::system::result<stand_in_public_key> public_key() const noexcept;
    [[nodiscard]] boost::system::result<crypto::secret<32>> secret() const noexcept;
    [[nodiscard]] boost::system::result<std::array<std::uint8_t, 64>> sign(
        crypto::ecdsa_sha256_t, std::span<std::uint8_t const>) const noexcept;
};

// A scheme of this test alone, which no curve has.
struct test_scheme_t {
    explicit test_scheme_t() = default;
};

// Every member, and the test scheme declared with ecdsa_sha256, but no sign of the test scheme.
struct unsigned_test_scheme_keypair {
    using public_key_type = stand_in_public_key;
    [[maybe_unused]] static constexpr std::size_t secret_key_size = 32;
    static boost::system::result<unsigned_test_scheme_keypair> from_secret(
        std::span<std::uint8_t const>) noexcept;
    static boost::system::result<unsigned_test_scheme_keypair> generate() noexcept;
    [[nodiscard]] boost::system::result<stand_in_public_key> public_key() const noexcept;
    [[nodiscard]] boost::system::result<crypto::secret<32>> secret() const noexcept;
    [[nodiscard]] boost::system::result<std::array<std::uint8_t, 64>> sign(
        crypto::ecdsa_sha256_t, std::span<std::uint8_t const>) const noexcept;
};

// Every member, and the test scheme declared with ecdsa_sha256 and signed.
struct test_scheme_keypair {
    using public_key_type = stand_in_public_key;
    [[maybe_unused]] static constexpr std::size_t secret_key_size = 32;
    static boost::system::result<test_scheme_keypair> from_secret(
        std::span<std::uint8_t const>) noexcept;
    static boost::system::result<test_scheme_keypair> generate() noexcept;
    [[nodiscard]] boost::system::result<stand_in_public_key> public_key() const noexcept;
    [[nodiscard]] boost::system::result<crypto::secret<32>> secret() const noexcept;
    [[nodiscard]] boost::system::result<std::array<std::uint8_t, 64>> sign(
        crypto::ecdsa_sha256_t, std::span<std::uint8_t const>) const noexcept;
    [[nodiscard]] boost::system::result<std::array<std::uint8_t, 64>> sign(
        test_scheme_t, std::span<std::uint8_t const>) const noexcept;
};

// Every member, and the test scheme alone declared and signed.
struct only_test_scheme_keypair {
    using public_key_type = stand_in_public_key;
    [[maybe_unused]] static constexpr std::size_t secret_key_size = 32;
    static boost::system::result<only_test_scheme_keypair> from_secret(
        std::span<std::uint8_t const>) noexcept;
    static boost::system::result<only_test_scheme_keypair> generate() noexcept;
    [[nodiscard]] boost::system::result<stand_in_public_key> public_key() const noexcept;
    [[nodiscard]] boost::system::result<crypto::secret<32>> secret() const noexcept;
    [[nodiscard]] boost::system::result<std::array<std::uint8_t, 64>> sign(
        test_scheme_t, std::span<std::uint8_t const>) const noexcept;
};

}  // namespace

namespace webcpp::crypto::detail {

template <>
inline constexpr bool signs_with_v<complete_keypair, ecdsa_sha256_t> = true;
template <>
inline constexpr bool signs_with_v<no_secret_keypair, ecdsa_sha256_t> = true;
template <>
inline constexpr bool signs_with_v<wrong_secret_keypair, ecdsa_sha256_t> = true;
template <>
inline constexpr bool signs_with_v<byte_public_keypair, ecdsa_sha256_t> = true;
template <>
inline constexpr bool signs_with_v<no_generate_keypair, ecdsa_sha256_t> = true;
template <>
inline constexpr bool signs_with_v<unsigned_scheme_keypair, ecdsa_sha256_t> = true;
template <>
inline constexpr bool signs_with_v<unsigned_scheme_keypair, schnorr_t> = true;
template <>
inline constexpr bool signs_with_v<no_from_secret_keypair, ecdsa_sha256_t> = true;
template <>
inline constexpr bool signs_with_v<no_public_key_type_keypair, ecdsa_sha256_t> = true;
template <>
inline constexpr bool signs_with_v<wrong_generate_keypair, ecdsa_sha256_t> = true;
template <>
inline constexpr bool signs_with_v<wrong_from_secret_keypair, ecdsa_sha256_t> = true;
template <>
inline constexpr bool signs_with_v<unsigned_test_scheme_keypair, ecdsa_sha256_t> = true;
template <>
inline constexpr bool signs_with_v<unsigned_test_scheme_keypair, test_scheme_t> = true;
template <>
inline constexpr bool signs_with_v<test_scheme_keypair, ecdsa_sha256_t> = true;
template <>
inline constexpr bool signs_with_v<test_scheme_keypair, test_scheme_t> = true;
template <>
inline constexpr bool signs_with_v<only_test_scheme_keypair, test_scheme_t> = true;

}  // namespace webcpp::crypto::detail

// The stand-ins.
static_assert(crypto::keypair<complete_keypair>);
static_assert(!crypto::keypair<no_secret_keypair>);
static_assert(!crypto::keypair<wrong_secret_keypair>);
static_assert(!crypto::keypair<byte_public_keypair>);
static_assert(!crypto::keypair<no_generate_keypair>);
static_assert(!crypto::keypair<no_scheme_keypair>);
static_assert(!crypto::keypair<unsigned_scheme_keypair>);
static_assert(!crypto::keypair<no_from_secret_keypair>);
static_assert(!crypto::keypair<no_public_key_type_keypair>);
static_assert(!crypto::keypair<wrong_generate_keypair>);
static_assert(!crypto::keypair<wrong_from_secret_keypair>);
static_assert(!crypto::keypair<stand_in_public_key>);
static_assert(!crypto::keypair<int>);

// The contract folds over a list of schemes: crypto::keypair is keypair_over all_schemes, and a
// list with the test scheme asks its sign of a key pair that declares it.
// A list with one more scheme at its end.
template <class List, class Scheme>
struct append;

template <class... Schemes, class Scheme>
struct append<crypto::detail::scheme_list<Schemes...>, Scheme> {
    using type = crypto::detail::scheme_list<Schemes..., Scheme>;
};

using with_test_scheme = append<crypto::detail::all_schemes, test_scheme_t>::type;
using test_scheme_alone = crypto::detail::scheme_list<test_scheme_t>;
static_assert(!crypto::detail::keypair_over<unsigned_test_scheme_keypair, with_test_scheme>);
static_assert(crypto::detail::keypair_over<test_scheme_keypair, with_test_scheme>);
static_assert(crypto::detail::keypair_over<complete_keypair, with_test_scheme>);
static_assert(!crypto::detail::keypair_over<unsigned_scheme_keypair, with_test_scheme>);
// Outside the list, the test scheme is not asked, and alone it is not a scheme of the library.
static_assert(crypto::keypair<unsigned_test_scheme_keypair>);
static_assert(crypto::detail::keypair_over<only_test_scheme_keypair, test_scheme_alone>);
static_assert(!crypto::keypair<only_test_scheme_keypair>);
// An empty list has no scheme to sign.
static_assert(!crypto::detail::keypair_over<complete_keypair, crypto::detail::scheme_list<>>);
static_assert(crypto::detail::keypair_over<complete_keypair, crypto::detail::all_schemes>);
// A type that is not a list of schemes asks for a scheme that none is.
static_assert(!crypto::detail::keypair_over<complete_keypair, int>);
static_assert(!crypto::detail::keypair_over<complete_keypair, std::tuple<crypto::ecdsa_sha256_t>>);

// The curves' key pairs, on each backend this test links.
static_assert(crypto::keypair<crypto::curves::ed25519::basic_keypair<crypto::backends::sodium>>);
static_assert(crypto::keypair<crypto::curves::p256::basic_keypair<crypto::backends::bearssl>>);
static_assert(
    crypto::keypair<crypto::curves::secp256k1::basic_keypair<crypto::backends::secp256k1>>);
static_assert(std::is_same_v<crypto::curves::ed25519::keypair::public_key_type,
                             crypto::curves::ed25519::public_key>);
static_assert(std::is_same_v<crypto::curves::p256::keypair::public_key_type,
                             crypto::curves::p256::public_key>);
static_assert(std::is_same_v<crypto::curves::secp256k1::keypair::public_key_type,
                             crypto::curves::secp256k1::public_key>);
static_assert(crypto::curves::ed25519::keypair::secret_key_size == 32);
static_assert(crypto::curves::p256::keypair::secret_key_size == 32);
static_assert(crypto::curves::secp256k1::keypair::secret_key_size == 32);
// A public key is not a key pair.
static_assert(!crypto::keypair<crypto::curves::ed25519::public_key>);
static_assert(!crypto::keypair<crypto::curves::p256::public_key>);
static_assert(!crypto::keypair<crypto::curves::secp256k1::public_key>);

namespace {

// Ed25519's key pair under eddsa_prehashed, through the contract: the key pair made again from
// its secret() signs a 64-byte digest marker, which the first one's public key verifies.
template <crypto::keypair Keypair>
void prehashed_round_trip() {
    auto const key = Keypair::generate();
    BOOST_TEST(key.has_value());
    auto const exported = key->secret();
    BOOST_TEST(exported.has_value());
    auto const again = Keypair::from_secret(exported->bytes());
    BOOST_TEST(again.has_value());
    std::array<std::uint8_t, 64> digest{};
    digest.fill(0x5a);
    auto const signature = again->sign(crypto::eddsa_prehashed, crypto::prehashed{digest});
    BOOST_TEST(signature.has_value());
    BOOST_TEST(crypto::verify(crypto::eddsa_prehashed, *signature, crypto::prehashed{digest},
                              *key->public_key())
                   .has_value());
}

// Each curve's key pair, used through the contract alone: the key pair made again from its
// secret() has the same public key, compared with ==, and signs what the first one's public key
// verifies.
template <crypto::keypair Keypair, class Scheme>
void round_trip(Scheme scheme) {
    auto const key = Keypair::generate();
    BOOST_TEST(key.has_value());
    auto const exported = key->secret();
    BOOST_TEST(exported.has_value());
    auto const again = Keypair::from_secret(exported->bytes());
    BOOST_TEST(again.has_value());
    BOOST_TEST(*again->public_key() == *key->public_key());
    std::array<std::uint8_t, 3> const message{'a', 'b', 'c'};
    auto const signature = again->sign(scheme, message);
    BOOST_TEST(signature.has_value());
    BOOST_TEST(crypto::verify(scheme, *signature, message, *key->public_key()).has_value());
}

// A recoverable scheme of secp256k1's key pair, through the contract: the key pair made again
// from its secret() signs a digest marker, and recover gives the first one's public key.
template <crypto::keypair Keypair, class Scheme>
void recovered_round_trip(Scheme scheme) {
    auto const key = Keypair::generate();
    BOOST_TEST(key.has_value());
    auto const exported = key->secret();
    BOOST_TEST(exported.has_value());
    auto const again = Keypair::from_secret(exported->bytes());
    BOOST_TEST(again.has_value());
    std::array<std::uint8_t, 32> digest{};
    digest.fill(0x3c);
    auto const signature = again->sign(scheme, crypto::prehashed{digest});
    BOOST_TEST(signature.has_value());
    auto const recovered =
        crypto::curves::secp256k1::recover(scheme, *signature, crypto::prehashed{digest});
    BOOST_TEST(recovered.has_value() && *recovered == *key->public_key());
}

}  // namespace

int main() {
    round_trip<crypto::curves::ed25519::basic_keypair<crypto::backends::sodium>>(crypto::eddsa);
    prehashed_round_trip<crypto::curves::ed25519::basic_keypair<crypto::backends::sodium>>();
    round_trip<crypto::curves::p256::basic_keypair<crypto::backends::bearssl>>(
        crypto::ecdsa_sha256);
    using secp256k1_keypair = crypto::curves::secp256k1::basic_keypair<crypto::backends::secp256k1>;
    round_trip<secp256k1_keypair>(crypto::ecdsa_sha256);
    round_trip<secp256k1_keypair>(crypto::schnorr);
    recovered_round_trip<secp256k1_keypair>(crypto::ecdsa_sha256_recoverable);
    recovered_round_trip<secp256k1_keypair>(crypto::ecdsa_keccak256_recoverable);
    return webcpp::test::exit_status(boost::report_errors());
}
