// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The three key pair concepts (design D4): crypto::keypair, what every key pair is (made from
// its secret bytes or drawn, its typed public key, its secret bytes back); crypto::signing_keypair,
// a keypair that signs with every scheme its curve declares for it, at least one, each into the
// scheme's signature type; crypto::agreement_keypair, a keypair whose agree takes its own
// public_key_type and gives a secret<N>. Stand-ins that sign only, agree only, do both, lack one
// member each, or sign or agree into another type give each concept's verdict; the four curves'
// key pairs give D4's table (Ed25519's signs and does not agree, X25519's agrees and does not
// sign, P-256's and secp256k1's do both), on libsodium, BearSSL and libsecp256k1; each is made
// again from its secret() with the same public key, and is used through its concept alone:
// Ed25519's with its two schemes (eddsa_prehashed over a 64-byte digest marker), secp256k1's with
// each of its four (the two recoverable ones over a digest marker, recovered), X25519's, P-256's
// and secp256k1's agreeing with a peer both ways. signing_keypair folds over the list of schemes,
// detail::all_schemes, so that a test-only scheme added to a list is asked of a stand-in that
// declares it.

#include <webcpp/crypto/backends/bearssl.hpp>
#include <webcpp/crypto/backends/sodium.hpp>
#include <webcpp/crypto/constant_time_equal.hpp>
#include <webcpp/crypto/curves/ed25519.hpp>
#include <webcpp/crypto/curves/p256.hpp>
#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/curves/x25519.hpp>
#include <webcpp/crypto/detail/signature.hpp>
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

// A signature, the stand-ins' under every scheme they declare.
struct stand_in_signature {};

// Every member of keypair, and ECDSA over SHA-256 declared and signed: it signs alone.
struct complete_keypair {
    using public_key_type = stand_in_public_key;
    [[maybe_unused]] static constexpr std::size_t secret_key_size = 32;
    static boost::system::result<complete_keypair> from_secret(
        std::span<std::uint8_t const>) noexcept;
    static boost::system::result<complete_keypair> generate() noexcept;
    [[nodiscard]] boost::system::result<stand_in_public_key> public_key() const noexcept;
    [[nodiscard]] boost::system::result<crypto::secret<32>> secret() const noexcept;
    [[nodiscard]] boost::system::result<stand_in_signature> sign(
        crypto::ecdsa_sha256_t, std::span<std::uint8_t const>) const noexcept;
};

// Every member of keypair and an agree with its own public key type: it agrees alone.
struct agreeing_keypair {
    using public_key_type = stand_in_public_key;
    [[maybe_unused]] static constexpr std::size_t secret_key_size = 32;
    static boost::system::result<agreeing_keypair> from_secret(
        std::span<std::uint8_t const>) noexcept;
    static boost::system::result<agreeing_keypair> generate() noexcept;
    [[nodiscard]] boost::system::result<stand_in_public_key> public_key() const noexcept;
    [[nodiscard]] boost::system::result<crypto::secret<32>> secret() const noexcept;
    [[nodiscard]] boost::system::result<crypto::secret<48>> agree(
        stand_in_public_key const&) const noexcept;
};

// Both: ECDSA over SHA-256 declared and signed, and an agree.
struct signing_and_agreeing_keypair {
    using public_key_type = stand_in_public_key;
    [[maybe_unused]] static constexpr std::size_t secret_key_size = 32;
    static boost::system::result<signing_and_agreeing_keypair> from_secret(
        std::span<std::uint8_t const>) noexcept;
    static boost::system::result<signing_and_agreeing_keypair> generate() noexcept;
    [[nodiscard]] boost::system::result<stand_in_public_key> public_key() const noexcept;
    [[nodiscard]] boost::system::result<crypto::secret<32>> secret() const noexcept;
    [[nodiscard]] boost::system::result<stand_in_signature> sign(
        crypto::ecdsa_sha256_t, std::span<std::uint8_t const>) const noexcept;
    [[nodiscard]] boost::system::result<crypto::secret<32>> agree(
        stand_in_public_key const&) const noexcept;
};

// A sign of a declared scheme that gives bytes, not the scheme's signature type.
struct byte_sign_keypair {
    using public_key_type = stand_in_public_key;
    [[maybe_unused]] static constexpr std::size_t secret_key_size = 32;
    static boost::system::result<byte_sign_keypair> from_secret(
        std::span<std::uint8_t const>) noexcept;
    static boost::system::result<byte_sign_keypair> generate() noexcept;
    [[nodiscard]] boost::system::result<stand_in_public_key> public_key() const noexcept;
    [[nodiscard]] boost::system::result<crypto::secret<32>> secret() const noexcept;
    [[nodiscard]] boost::system::result<std::array<std::uint8_t, 64>> sign(
        crypto::ecdsa_sha256_t, std::span<std::uint8_t const>) const noexcept;
};

// An agree that gives bytes, not a secret<N>.
struct byte_agree_keypair {
    using public_key_type = stand_in_public_key;
    [[maybe_unused]] static constexpr std::size_t secret_key_size = 32;
    static boost::system::result<byte_agree_keypair> from_secret(
        std::span<std::uint8_t const>) noexcept;
    static boost::system::result<byte_agree_keypair> generate() noexcept;
    [[nodiscard]] boost::system::result<stand_in_public_key> public_key() const noexcept;
    [[nodiscard]] boost::system::result<crypto::secret<32>> secret() const noexcept;
    [[nodiscard]] boost::system::result<std::array<std::uint8_t, 32>> agree(
        stand_in_public_key const&) const noexcept;
};

// An agree that takes bytes, not its own public key type.
struct byte_peer_keypair {
    using public_key_type = stand_in_public_key;
    [[maybe_unused]] static constexpr std::size_t secret_key_size = 32;
    static boost::system::result<byte_peer_keypair> from_secret(
        std::span<std::uint8_t const>) noexcept;
    static boost::system::result<byte_peer_keypair> generate() noexcept;
    [[nodiscard]] boost::system::result<stand_in_public_key> public_key() const noexcept;
    [[nodiscard]] boost::system::result<crypto::secret<32>> secret() const noexcept;
    [[nodiscard]] boost::system::result<crypto::secret<32>> agree(
        std::span<std::uint8_t const, 32>) const noexcept;
};

// Every member but secret().
struct no_secret_keypair {
    using public_key_type = stand_in_public_key;
    [[maybe_unused]] static constexpr std::size_t secret_key_size = 32;
    static boost::system::result<no_secret_keypair> from_secret(
        std::span<std::uint8_t const>) noexcept;
    static boost::system::result<no_secret_keypair> generate() noexcept;
    [[nodiscard]] boost::system::result<stand_in_public_key> public_key() const noexcept;
    [[nodiscard]] boost::system::result<stand_in_signature> sign(
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
    [[nodiscard]] boost::system::result<stand_in_signature> sign(
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
    [[nodiscard]] boost::system::result<stand_in_signature> sign(
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
    [[nodiscard]] boost::system::result<stand_in_signature> sign(
        crypto::ecdsa_sha256_t, std::span<std::uint8_t const>) const noexcept;
};

// Every member, but its curve declares no scheme for it: a keypair that does nothing.
struct no_scheme_keypair {
    using public_key_type = stand_in_public_key;
    [[maybe_unused]] static constexpr std::size_t secret_key_size = 32;
    static boost::system::result<no_scheme_keypair> from_secret(
        std::span<std::uint8_t const>) noexcept;
    static boost::system::result<no_scheme_keypair> generate() noexcept;
    [[nodiscard]] boost::system::result<stand_in_public_key> public_key() const noexcept;
    [[nodiscard]] boost::system::result<crypto::secret<32>> secret() const noexcept;
    [[nodiscard]] boost::system::result<stand_in_signature> sign(
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
    [[nodiscard]] boost::system::result<stand_in_signature> sign(
        crypto::ecdsa_sha256_t, std::span<std::uint8_t const>) const noexcept;
};

// No from_secret(), though it signs and agrees.
struct no_from_secret_keypair {
    using public_key_type = stand_in_public_key;
    [[maybe_unused]] static constexpr std::size_t secret_key_size = 32;
    static boost::system::result<no_from_secret_keypair> generate() noexcept;
    [[nodiscard]] boost::system::result<stand_in_public_key> public_key() const noexcept;
    [[nodiscard]] boost::system::result<crypto::secret<32>> secret() const noexcept;
    [[nodiscard]] boost::system::result<stand_in_signature> sign(
        crypto::ecdsa_sha256_t, std::span<std::uint8_t const>) const noexcept;
    [[nodiscard]] boost::system::result<crypto::secret<32>> agree(
        stand_in_public_key const&) const noexcept;
};

// No public_key_type.
struct no_public_key_type_keypair {
    [[maybe_unused]] static constexpr std::size_t secret_key_size = 32;
    static boost::system::result<no_public_key_type_keypair> from_secret(
        std::span<std::uint8_t const>) noexcept;
    static boost::system::result<no_public_key_type_keypair> generate() noexcept;
    [[nodiscard]] boost::system::result<stand_in_public_key> public_key() const noexcept;
    [[nodiscard]] boost::system::result<crypto::secret<32>> secret() const noexcept;
    [[nodiscard]] boost::system::result<stand_in_signature> sign(
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
    [[nodiscard]] boost::system::result<stand_in_signature> sign(
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
    [[nodiscard]] boost::system::result<stand_in_signature> sign(
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
    [[nodiscard]] boost::system::result<stand_in_signature> sign(
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
    [[nodiscard]] boost::system::result<stand_in_signature> sign(
        crypto::ecdsa_sha256_t, std::span<std::uint8_t const>) const noexcept;
    [[nodiscard]] boost::system::result<stand_in_signature> sign(
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
    [[nodiscard]] boost::system::result<stand_in_signature> sign(
        test_scheme_t, std::span<std::uint8_t const>) const noexcept;
};

// Whether Type is one of this test's stand-ins, whose schemes all sign into stand_in_signature:
// each named, so that no curve's key pair takes the stand-ins' signature type.
template <class Type>
constexpr bool is_stand_in_v =
    std::is_same_v<Type, complete_keypair> || std::is_same_v<Type, agreeing_keypair> ||
    std::is_same_v<Type, signing_and_agreeing_keypair> || std::is_same_v<Type, byte_sign_keypair> ||
    std::is_same_v<Type, byte_agree_keypair> || std::is_same_v<Type, byte_peer_keypair> ||
    std::is_same_v<Type, no_secret_keypair> || std::is_same_v<Type, wrong_secret_keypair> ||
    std::is_same_v<Type, byte_public_keypair> || std::is_same_v<Type, no_generate_keypair> ||
    std::is_same_v<Type, no_scheme_keypair> || std::is_same_v<Type, unsigned_scheme_keypair> ||
    std::is_same_v<Type, no_from_secret_keypair> ||
    std::is_same_v<Type, no_public_key_type_keypair> ||
    std::is_same_v<Type, wrong_generate_keypair> ||
    std::is_same_v<Type, wrong_from_secret_keypair> ||
    std::is_same_v<Type, unsigned_test_scheme_keypair> ||
    std::is_same_v<Type, test_scheme_keypair> || std::is_same_v<Type, only_test_scheme_keypair>;

}  // namespace

namespace webcpp::crypto::detail {

template <>
inline constexpr bool signs_with_v<complete_keypair, ecdsa_sha256_t> = true;
template <>
inline constexpr bool signs_with_v<signing_and_agreeing_keypair, ecdsa_sha256_t> = true;
template <>
inline constexpr bool signs_with_v<byte_sign_keypair, ecdsa_sha256_t> = true;
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

// Every stand-in signs into the stand-in signature, under every scheme.
template <class Keypair, class Scheme>
    requires is_stand_in_v<Keypair>
struct signature_of<Keypair, Scheme> {
    using type = stand_in_signature;
};

}  // namespace webcpp::crypto::detail

// The curves' key pairs keep their own signature types: the stand-ins' partial specialization
// names none of them.
static_assert(!is_stand_in_v<crypto::curves::ed25519::basic_keypair<crypto::backends::sodium>>);
static_assert(!is_stand_in_v<crypto::curves::p256::basic_keypair<crypto::backends::bearssl>>);
static_assert(
    !is_stand_in_v<crypto::curves::secp256k1::basic_keypair<crypto::backends::secp256k1>>);
static_assert(!is_stand_in_v<crypto::curves::x25519::basic_keypair<crypto::backends::sodium>>);

// The three concepts' verdicts, keypair then signing_keypair then agreement_keypair.
// Signs alone.
static_assert(crypto::keypair<complete_keypair>);
static_assert(crypto::signing_keypair<complete_keypair>);
static_assert(!crypto::agreement_keypair<complete_keypair>);
// Agrees alone.
static_assert(crypto::keypair<agreeing_keypair>);
static_assert(!crypto::signing_keypair<agreeing_keypair>);
static_assert(crypto::agreement_keypair<agreeing_keypair>);
// Both.
static_assert(crypto::keypair<signing_and_agreeing_keypair>);
static_assert(crypto::signing_keypair<signing_and_agreeing_keypair>);
static_assert(crypto::agreement_keypair<signing_and_agreeing_keypair>);
// A sign that gives bytes, an agree that gives bytes or takes them: a keypair that neither signs
// nor agrees by the contract.
static_assert(crypto::keypair<byte_sign_keypair>);
static_assert(!crypto::signing_keypair<byte_sign_keypair>);
static_assert(!crypto::agreement_keypair<byte_sign_keypair>);
static_assert(crypto::keypair<byte_agree_keypair>);
static_assert(!crypto::agreement_keypair<byte_agree_keypair>);
static_assert(crypto::keypair<byte_peer_keypair>);
static_assert(!crypto::agreement_keypair<byte_peer_keypair>);
// No scheme declared, or one declared and not signed: a keypair that does not sign.
static_assert(crypto::keypair<no_scheme_keypair>);
static_assert(!crypto::signing_keypair<no_scheme_keypair>);
static_assert(crypto::keypair<unsigned_scheme_keypair>);
static_assert(!crypto::signing_keypair<unsigned_scheme_keypair>);
// A member of keypair missing or of another type: none of the three, whatever it signs or agrees.
static_assert(!crypto::keypair<no_from_secret_keypair>);
static_assert(!crypto::signing_keypair<no_from_secret_keypair>);
static_assert(!crypto::agreement_keypair<no_from_secret_keypair>);
static_assert(!crypto::keypair<no_secret_keypair>);
static_assert(!crypto::signing_keypair<no_secret_keypair>);
static_assert(!crypto::keypair<wrong_secret_keypair>);
static_assert(!crypto::signing_keypair<wrong_secret_keypair>);
static_assert(!crypto::keypair<byte_public_keypair>);
static_assert(!crypto::keypair<no_generate_keypair>);
static_assert(!crypto::keypair<no_public_key_type_keypair>);
static_assert(!crypto::keypair<wrong_generate_keypair>);
static_assert(!crypto::keypair<wrong_from_secret_keypair>);
static_assert(!crypto::signing_keypair<wrong_from_secret_keypair>);
// Each of them declares ECDSA over SHA-256 and signs it into its signature type: what keeps it
// from signing_keypair is keypair's member alone.
template <class Keypair>
constexpr bool signs_its_schemes_v =
    crypto::detail::signs_some_scheme_v<Keypair, crypto::detail::all_schemes> &&
    crypto::detail::signs_every_declared_v<Keypair, crypto::detail::all_schemes>;
static_assert(signs_its_schemes_v<no_from_secret_keypair>);
static_assert(signs_its_schemes_v<no_secret_keypair>);
static_assert(signs_its_schemes_v<wrong_secret_keypair>);
static_assert(signs_its_schemes_v<byte_public_keypair>);
static_assert(signs_its_schemes_v<no_generate_keypair>);
static_assert(signs_its_schemes_v<no_public_key_type_keypair>);
static_assert(signs_its_schemes_v<wrong_generate_keypair>);
static_assert(signs_its_schemes_v<wrong_from_secret_keypair>);
static_assert(!crypto::keypair<stand_in_public_key>);
static_assert(!crypto::signing_keypair<stand_in_public_key>);
static_assert(!crypto::agreement_keypair<stand_in_public_key>);
static_assert(!crypto::keypair<int>);
static_assert(!crypto::signing_keypair<int>);
static_assert(!crypto::agreement_keypair<int>);
// What a secret result is: result<secret<N>> alone.
static_assert(crypto::detail::is_secret_result_v<boost::system::result<crypto::secret<32>>>);
static_assert(crypto::detail::is_secret_result_v<boost::system::result<crypto::secret<48>>>);
static_assert(!crypto::detail::is_secret_result_v<crypto::secret<32>>);
static_assert(
    !crypto::detail::is_secret_result_v<boost::system::result<std::array<std::uint8_t, 32>>>);
static_assert(!crypto::detail::is_secret_result_v<boost::system::result<void>>);

// signing_keypair folds over a list of schemes: it is signing_keypair_over all_schemes, and a list
// with the test scheme asks its sign of a key pair that declares it.
// A list with one more scheme at its end.
template <class List, class Scheme>
struct append;

template <class... Schemes, class Scheme>
struct append<crypto::detail::scheme_list<Schemes...>, Scheme> {
    using type = crypto::detail::scheme_list<Schemes..., Scheme>;
};

using with_test_scheme = append<crypto::detail::all_schemes, test_scheme_t>::type;
using test_scheme_alone = crypto::detail::scheme_list<test_scheme_t>;
static_assert(
    !crypto::detail::signing_keypair_over<unsigned_test_scheme_keypair, with_test_scheme>);
static_assert(crypto::detail::signing_keypair_over<test_scheme_keypair, with_test_scheme>);
static_assert(crypto::detail::signing_keypair_over<complete_keypair, with_test_scheme>);
static_assert(!crypto::detail::signing_keypair_over<unsigned_scheme_keypair, with_test_scheme>);
// Outside the list, the test scheme is not asked, and alone it is not a scheme of the library.
static_assert(crypto::signing_keypair<unsigned_test_scheme_keypair>);
static_assert(crypto::detail::signing_keypair_over<only_test_scheme_keypair, test_scheme_alone>);
static_assert(!crypto::signing_keypair<only_test_scheme_keypair>);
static_assert(crypto::keypair<only_test_scheme_keypair>);
// An empty list has no scheme to sign.
static_assert(
    !crypto::detail::signing_keypair_over<complete_keypair, crypto::detail::scheme_list<>>);
static_assert(crypto::detail::signing_keypair_over<complete_keypair, crypto::detail::all_schemes>);
// A type that is not a list of schemes asks for a scheme that none is.
static_assert(!crypto::detail::signing_keypair_over<complete_keypair, int>);
static_assert(
    !crypto::detail::signing_keypair_over<complete_keypair, std::tuple<crypto::ecdsa_sha256_t>>);

// The curves' key pairs, on each backend this test links: D4's table.
using ed25519_pair = crypto::curves::ed25519::basic_keypair<crypto::backends::sodium>;
using x25519_pair = crypto::curves::x25519::basic_keypair<crypto::backends::sodium>;
using p256_pair = crypto::curves::p256::basic_keypair<crypto::backends::bearssl>;
using secp256k1_pair = crypto::curves::secp256k1::basic_keypair<crypto::backends::secp256k1>;
static_assert(std::is_same_v<crypto::detail::signature_of_t<ed25519_pair, crypto::eddsa_t>,
                             crypto::curves::ed25519::signature>);
static_assert(std::is_same_v<crypto::detail::signature_of_t<p256_pair, crypto::ecdsa_sha256_t>,
                             crypto::curves::p256::ecdsa_signature>);
static_assert(std::is_same_v<crypto::detail::signature_of_t<secp256k1_pair, crypto::schnorr_t>,
                             crypto::curves::secp256k1::schnorr_signature>);
static_assert(crypto::keypair<ed25519_pair>);
static_assert(crypto::signing_keypair<ed25519_pair>);
static_assert(!crypto::agreement_keypair<ed25519_pair>);
static_assert(crypto::keypair<x25519_pair>);
static_assert(!crypto::signing_keypair<x25519_pair>);
static_assert(crypto::agreement_keypair<x25519_pair>);
static_assert(crypto::keypair<p256_pair>);
static_assert(crypto::signing_keypair<p256_pair>);
static_assert(crypto::agreement_keypair<p256_pair>);
static_assert(crypto::keypair<secp256k1_pair>);
static_assert(crypto::signing_keypair<secp256k1_pair>);
static_assert(crypto::agreement_keypair<secp256k1_pair>);
static_assert(std::is_same_v<crypto::curves::ed25519::keypair::public_key_type,
                             crypto::curves::ed25519::public_key>);
static_assert(std::is_same_v<crypto::curves::x25519::keypair::public_key_type,
                             crypto::curves::x25519::public_key>);
static_assert(std::is_same_v<crypto::curves::p256::keypair::public_key_type,
                             crypto::curves::p256::public_key>);
static_assert(std::is_same_v<crypto::curves::secp256k1::keypair::public_key_type,
                             crypto::curves::secp256k1::public_key>);
static_assert(crypto::curves::ed25519::keypair::secret_key_size == 32);
static_assert(crypto::curves::x25519::keypair::secret_key_size == 32);
static_assert(crypto::curves::p256::keypair::secret_key_size == 32);
static_assert(crypto::curves::secp256k1::keypair::secret_key_size == 32);
// A public key is not a key pair.
static_assert(!crypto::keypair<crypto::curves::ed25519::public_key>);
static_assert(!crypto::keypair<crypto::curves::x25519::public_key>);
static_assert(!crypto::keypair<crypto::curves::p256::public_key>);
static_assert(!crypto::keypair<crypto::curves::secp256k1::public_key>);

namespace {

// A key pair made again from its secret (the spec's from_secret_round_trip), through keypair
// alone: the key pair made from k.secret()->bytes() has k's public key, compared with ==.
template <crypto::keypair Keypair>
void from_secret_round_trip() {
    auto const key = Keypair::generate();
    BOOST_TEST(key.has_value());
    auto const exported = key->secret();
    BOOST_TEST(exported.has_value());
    auto const again = Keypair::from_secret(exported->bytes());
    BOOST_TEST(again.has_value());
    BOOST_TEST(*again->public_key() == *key->public_key());
}

// Ed25519's key pair under eddsa_prehashed, through signing_keypair: the key pair made again from
// its secret() signs a 64-byte digest marker, which the first one's public key verifies.
template <crypto::signing_keypair Keypair>
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

// Each signing curve's key pair, used through signing_keypair alone: the key pair made again from
// its secret() signs what the first one's public key verifies.
template <crypto::signing_keypair Keypair, class Scheme>
void signing_round_trip(Scheme scheme) {
    auto const key = Keypair::generate();
    BOOST_TEST(key.has_value());
    auto const exported = key->secret();
    BOOST_TEST(exported.has_value());
    auto const again = Keypair::from_secret(exported->bytes());
    BOOST_TEST(again.has_value());
    std::array<std::uint8_t, 3> const message{'a', 'b', 'c'};
    auto const signature = crypto::sign(*again, scheme, message);
    BOOST_TEST(signature.has_value());
    BOOST_TEST(crypto::verify(scheme, *signature, message, *key->public_key()).has_value());
}

// A recoverable scheme of secp256k1's key pair, through signing_keypair: the key pair made again
// from its secret() signs a digest marker, and recover gives the first one's public key.
template <crypto::signing_keypair Keypair, class Scheme>
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

// Each agreeing curve's key pair, used through agreement_keypair alone: two key pairs agree with
// each other's public key both ways, the free crypto::agree and the member alike.
template <crypto::agreement_keypair Keypair>
void agreement_round_trip() {
    auto const alice = Keypair::generate();
    auto const bob = Keypair::generate();
    BOOST_TEST(alice.has_value() && bob.has_value());
    auto const alice_shared = crypto::agree(*alice, *bob->public_key());
    auto const bob_shared = bob->agree(*alice->public_key());
    BOOST_TEST(alice_shared.has_value() && bob_shared.has_value());
    BOOST_TEST(crypto::constant_time_equal(alice_shared->bytes(), bob_shared->bytes()));
}

}  // namespace

int main() {
    from_secret_round_trip<ed25519_pair>();
    from_secret_round_trip<x25519_pair>();
    from_secret_round_trip<p256_pair>();
    from_secret_round_trip<secp256k1_pair>();
    signing_round_trip<ed25519_pair>(crypto::eddsa);
    prehashed_round_trip<ed25519_pair>();
    signing_round_trip<p256_pair>(crypto::ecdsa_sha256);
    signing_round_trip<secp256k1_pair>(crypto::ecdsa_sha256);
    signing_round_trip<secp256k1_pair>(crypto::schnorr);
    recovered_round_trip<secp256k1_pair>(crypto::ecdsa_sha256_recoverable);
    recovered_round_trip<secp256k1_pair>(crypto::ecdsa_keccak256_recoverable);
    agreement_round_trip<x25519_pair>();
    agreement_round_trip<p256_pair>();
    agreement_round_trip<secp256k1_pair>();
    return webcpp::test::exit_status(boost::report_errors());
}
