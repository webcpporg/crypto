// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Ethereum's recoverable ECDSA, crypto::ecdsa_keccak256_recoverable (design D8, R18 to R20):
// go-ethereum's recovery vector; web3.js's personal_sign vector, its EIP-191 digest built here
// with webcpp::hash's keccak_256; Keccak-256's original padding, never SHA3-256's; a message
// hashed inside with Keccak-256, of any size, empty and 32 bytes included, signed as its digest
// is and recovered from it; always a low S; a high S recovered as libsecp256k1 and Ethereum's
// ecrecover recover it; the refusals of an id above 3 and of an r of zero; a keccak signature
// recovered under ecdsa_sha256_recoverable, which gives another key; the free crypto::sign; and
// the scheme's traits: its signature type, no crypto::verify of it, a 32-byte digest alone.

#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/signing.hpp>
#include <webcpp/hash/algorithms.hpp>
#include <webcpp/hash/keccak.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"

#include <boost/core/lightweight_test.hpp>
#include <boost/system/result.hpp>

#include <secp256k1.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <random>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace crypto = webcpp::crypto;
namespace secp = webcpp::crypto::curves::secp256k1;

namespace {

using webcpp::test::hex;
using bytes32 = std::array<std::uint8_t, 32>;
using keccak_scheme = crypto::ecdsa_keccak256_recoverable_t;

// The scheme's traits: the recoverable signature type of ecdsa_sha256_recoverable (R20), 65
// bytes over a 32-byte digest, a message or a marker of 32 bytes alone.
static_assert(crypto::detail::is_scheme_v<keccak_scheme>);
static_assert(crypto::detail::scheme_traits<keccak_scheme>::signature_size == 65);
static_assert(crypto::detail::scheme_traits<keccak_scheme>::digest_size == 32);
static_assert(crypto::detail::signs_with_v<secp::keypair, keccak_scheme>);
static_assert(std::is_same_v<crypto::detail::signature_of_t<secp::keypair, keccak_scheme>,
                             secp::recoverable_signature>);
static_assert(crypto::can_sign<secp::keypair, keccak_scheme, std::span<std::uint8_t const>>);
static_assert(crypto::can_sign<secp::keypair, keccak_scheme, crypto::prehashed<32>>);
static_assert(!crypto::can_sign<secp::keypair, keccak_scheme, crypto::prehashed<20>>);
static_assert(std::is_same_v<decltype(std::declval<secp::keypair const&>().sign(
                                 crypto::ecdsa_keccak256_recoverable, std::declval<bytes32>())),
                             boost::system::result<secp::recoverable_signature>>);
static_assert(std::is_same_v<decltype(secp::recover(crypto::ecdsa_keccak256_recoverable,
                                                    std::declval<secp::recoverable_signature>(),
                                                    crypto::prehashed<32>(bytes32{}))),
                             boost::system::result<secp::public_key>>);
// No crypto::verify of the scheme (R18): a public key does not verify it, and the catch-all,
// which stops the build, is the one candidate.
static_assert(!crypto::detail::verifies_with_v<secp::public_key, keccak_scheme>);
static_assert(!crypto::detail::has_verifier_v<keccak_scheme, secp::public_key>);
static_assert(!crypto::can_verify<keccak_scheme, secp::recoverable_signature,
                                  std::span<std::uint8_t const>, secp::public_key>);

// go-ethereum's crypto/signature_test.go, testmsg, testsig and testpubkey, at commit
// e0feab5218041fda40a8de64500a625bac146db6:
// https://github.com/ethereum/go-ethereum/blob/e0feab5218041fda40a8de64500a625bac146db6/crypto/signature_test.go
constexpr auto geth_message =
    hex<32>("ce0677bb30baa8cf067c88db9811f4333d131bf8bcf12fe7065d211dce971008");
constexpr auto geth_signature = hex<65>(
    "90f27b8b488db00b00606796d2987f6a5f59ae62ea05effe84fef5b8b0e54998"
    "4a691139ad57a3f0b906637673aa2f63d1f55cb1a69199d4009eea23ceaddc9301");
constexpr auto geth_public_key = hex<65>(
    "04e32df42865e97135acfb65f3bae71bdc86f4d49150ad6a440b6f15878109880a"
    "0a2b2667f7e725ceea70c673093bf67663e0312623c8e091b13cf2c0f11ef652");

// web3.js 1.x's documentation of web3.eth.accounts.sign('Some data', '0x4c08...2318'), at commit
// 3ebb811b42473efe37c1a9c5f924d3258deefc13 (docs/web3-eth-accounts.rst, "sign"):
// https://github.com/web3/web3.js/blob/3ebb811b42473efe37c1a9c5f924d3258deefc13/docs/web3-eth-accounts.rst
// rendered at https://web3js.readthedocs.io/en/v1.10.0/web3-eth-accounts.html#sign; the address
// is the same page's privateKeyToAccount of the key.
constexpr auto web3_secret =
    hex<32>("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318");
constexpr std::string_view web3_message = "Some data";
constexpr auto web3_message_hash =
    hex<32>("1da44b586eb0729ff70a73c326926f6ed5a25f5b056e7f47fbc6e58d86871655");
constexpr auto web3_r = hex<32>("b91467e570a6466aa9e9876cbcd013baba02900b8979d43fe208a4a4f339f5fd");
constexpr auto web3_s = hex<32>("6007e74cd82e037b800186422fc2da167c747ef045e5d18a5f5d4300f8e1a029");
constexpr std::uint8_t web3_v = 0x1c;
constexpr auto web3_address = hex<20>("2c7536e3605d9c16a7a3d7b1898e529396a65c23");

// The digests of Keccak-256's and SHA3-256's empty message, the second FIPS 202's.
constexpr auto keccak_of_nothing =
    hex<32>("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
constexpr auto sha3_of_nothing =
    hex<32>("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");

// The one helper over a hasher class (update, then result): the digest of bytes.
template <class Hasher>
bytes32 digest_of(std::span<std::uint8_t const> message) {
    Hasher hasher;
    hasher.update(message.data(), message.size());
    auto const hash_result = hasher.result();
    static_assert(std::remove_cvref_t<decltype(hash_result)>{}.size() == 32);
    bytes32 digest{};
    std::copy_n(hash_result.data(), digest.size(), digest.begin());
    return digest;
}

bytes32 keccak_of(std::span<std::uint8_t const> message) {
    return digest_of<webcpp::hash::keccak_256>(message);
}

bytes32 sha3_of(std::span<std::uint8_t const> message) {
    return digest_of<webcpp::hash::sha3_256>(message);
}

std::span<std::uint8_t const> bytes_of(std::string_view text) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): a text's bytes, viewed
    return {reinterpret_cast<std::uint8_t const*>(text.data()), text.size()};
}

// EIP-191's personal_sign digest: Keccak-256 of "\x19Ethereum Signed Message:\n", the message's
// length in decimal, and the message.
bytes32 personal_sign_digest(std::string_view message) {
    std::string prefixed =
        "\x19"
        "Ethereum Signed Message:\n";
    prefixed += std::to_string(message.size());
    prefixed += message;
    return keccak_of(bytes_of(prefixed));
}

secp::keypair key_of(bytes32 const& secret) {
    auto made = secp::keypair::from_secret(secret);
    BOOST_TEST(made.has_value());
    return std::move(*made);
}

secp::public_key public_of(secp::keypair const& key) {
    auto const made = key.public_key();
    BOOST_TEST(made.has_value());
    return *made;
}

secp::recoverable_signature typed(std::span<std::uint8_t const> signature_bytes) {
    auto made = secp::recoverable_signature::from_bytes(signature_bytes);
    BOOST_TEST(made.has_value());
    return made ? *made : secp::recoverable_signature{};
}

// The ECDSA signature of a recoverable one's first 64 bytes, r and s.
secp::ecdsa_signature ecdsa_of(secp::recoverable_signature const& signature) {
    auto made = secp::ecdsa_signature::from_bytes(std::span(signature.bytes()).first<64>());
    BOOST_TEST(made.has_value());
    return made ? *made : secp::ecdsa_signature{};
}

// go-ethereum's digest and signature recover its uncompressed key.
void geth_recover() {
    auto const recovered = secp::recover(crypto::ecdsa_keccak256_recoverable, typed(geth_signature),
                                         crypto::prehashed{geth_message});
    if (BOOST_TEST(recovered.has_value())) {
        BOOST_TEST(recovered->uncompressed() == geth_public_key);
        auto const expected = secp::public_key::from_bytes(geth_public_key);
        BOOST_TEST(expected.has_value() && *recovered == *expected);
    }
}

// web3.js's personal_sign: the EIP-191 digest, its r and s, v = 27 + the recovery id, and the
// address of the key recover gives.
void personal_sign() {
    auto const digest = personal_sign_digest(web3_message);
    BOOST_TEST(digest == web3_message_hash);
    auto const key = key_of(web3_secret);
    auto const signature = key.sign(crypto::ecdsa_keccak256_recoverable, crypto::prehashed{digest});
    if (!BOOST_TEST(signature.has_value())) {
        return;
    }
    auto const& signed_bytes = signature->bytes();
    BOOST_TEST(std::ranges::equal(std::span(signed_bytes).first<32>(), web3_r));
    BOOST_TEST(std::ranges::equal(std::span(signed_bytes).subspan<32, 32>(), web3_s));
    BOOST_TEST_EQ(static_cast<int>(signature->recovery_id()), web3_v - 27);
    auto const recovered =
        secp::recover(crypto::ecdsa_keccak256_recoverable, *signature, crypto::prehashed{digest});
    if (BOOST_TEST(recovered.has_value())) {
        BOOST_TEST(*recovered == public_of(key));
        auto const uncompressed = recovered->uncompressed();
        auto const key_hash = keccak_of(std::span(uncompressed).subspan<1>());
        BOOST_TEST(std::ranges::equal(std::span(key_hash).last<20>(), web3_address));
    }
}

// Keccak-256 is the original padding, not SHA3-256's: the empty message's two digests differ.
void keccak_not_sha3() {
    BOOST_TEST(keccak_of({}) == keccak_of_nothing);
    BOOST_TEST(sha3_of({}) == sha3_of_nothing);
    BOOST_TEST(keccak_of({}) != sha3_of({}));
}

// A message is hashed with Keccak-256 inside: its signature is the one of the marker of its
// Keccak-256 digest, not of its SHA3-256 digest, and recover with the message gives the signer.
void message_is_hashed_one(secp::keypair const& key, std::span<std::uint8_t const> message) {
    auto const of_message = key.sign(crypto::ecdsa_keccak256_recoverable, message);
    auto const keccak_digest = keccak_of(message);
    auto const sha3_digest = sha3_of(message);
    auto const of_keccak =
        key.sign(crypto::ecdsa_keccak256_recoverable, crypto::prehashed{keccak_digest});
    auto const of_sha3 =
        key.sign(crypto::ecdsa_keccak256_recoverable, crypto::prehashed{sha3_digest});
    if (!BOOST_TEST(of_message && of_keccak && of_sha3)) {
        return;
    }
    BOOST_TEST(*of_message == *of_keccak);
    BOOST_TEST(*of_message != *of_sha3);
    auto const recovered = secp::recover(crypto::ecdsa_keccak256_recoverable, *of_message, message);
    BOOST_TEST(recovered.has_value() && *recovered == public_of(key));
    // The free form gives the member's signature.
    auto const free_form = crypto::sign(key, crypto::ecdsa_keccak256_recoverable, message);
    BOOST_TEST(free_form.has_value() && *free_form == *of_message);
}

void message_is_hashed() {
    auto const key = key_of(web3_secret);
    message_is_hashed_one(key, bytes_of(web3_message));
    // 32 bytes, a digest's size, are a message too: hashed, never signed as they are.
    message_is_hashed_one(key, geth_message);
    std::vector<std::uint8_t> const long_message(1000, 0x61);
    message_is_hashed_one(key, long_message);
}

// The empty message is signed as Keccak-256's digest of nothing, and recovered from itself.
void empty_message() {
    auto const key = key_of(web3_secret);
    std::span<std::uint8_t const> const nothing{};
    auto const of_nothing = key.sign(crypto::ecdsa_keccak256_recoverable, nothing);
    auto const of_digest =
        key.sign(crypto::ecdsa_keccak256_recoverable, crypto::prehashed{keccak_of_nothing});
    if (BOOST_TEST(of_nothing && of_digest)) {
        BOOST_TEST(*of_nothing == *of_digest);
        auto const recovered =
            secp::recover(crypto::ecdsa_keccak256_recoverable, *of_nothing, nothing);
        BOOST_TEST(recovered.has_value() && *recovered == public_of(key));
    }
}

// 256 signatures over seeded keys and digests: each S low, as EIP-2 requires, each id 0 to 3,
// each recovered to its signer.
void always_low_s() {
    // NOLINTNEXTLINE(bugprone-random-generator-seed,cert-msc32-c,cert-msc51-cpp): reproducible
    std::mt19937_64 generator(0x6574685f6c6f7753ULL);
    int signed_count = 0;
    while (signed_count < 256) {
        bytes32 secret{};
        bytes32 digest{};
        for (std::size_t index = 0; index < secret.size(); ++index) {
            secret[index] = static_cast<std::uint8_t>(generator());
            digest[index] = static_cast<std::uint8_t>(generator());
        }
        auto made = secp::keypair::from_secret(secret);
        if (!made) {
            continue;
        }
        auto const signature =
            made->sign(crypto::ecdsa_keccak256_recoverable, crypto::prehashed{digest});
        if (!BOOST_TEST(signature.has_value())) {
            return;
        }
        BOOST_TEST(secp::is_low_s(ecdsa_of(*signature)));
        BOOST_TEST(signature->recovery_id() <= 3);
        auto const recovered = secp::recover(crypto::ecdsa_keccak256_recoverable, *signature,
                                             crypto::prehashed{digest});
        BOOST_TEST(recovered.has_value() && *recovered == public_of(*made));
        ++signed_count;
    }
}

// A high S, n - s with the id's parity flipped, recovers the same key: libsecp256k1's recovery
// and Ethereum's ecrecover accept it (only a transaction's signature is refused one, by EIP-2).
void high_s_recovered() {
    auto high_bytes = geth_signature;
    bytes32 s_value{};
    std::copy_n(high_bytes.begin() + 32, 32, s_value.begin());
    BOOST_TEST(secp256k1_ec_seckey_negate(secp256k1_context_static, s_value.data()) == 1);
    std::ranges::copy(s_value, high_bytes.begin() + 32);
    high_bytes[64] ^= 1U;
    auto const high = typed(high_bytes);
    BOOST_TEST(!secp::is_low_s(ecdsa_of(high)));
    auto const recovered =
        secp::recover(crypto::ecdsa_keccak256_recoverable, high, crypto::prehashed{geth_message});
    BOOST_TEST(recovered.has_value() && recovered->uncompressed() == geth_public_key);
}

// The checks of ecdsa_sha256_recoverable's recover: an id above 3, and an r of zero.
void refusals() {
    for (std::uint8_t const id : std::to_array<std::uint8_t>({4, 27, 28, 255})) {
        auto bad_bytes = geth_signature;
        bad_bytes[64] = id;
        auto const refused = secp::recover(crypto::ecdsa_keccak256_recoverable, typed(bad_bytes),
                                           crypto::prehashed{geth_message});
        BOOST_TEST(refused.has_error() && refused.error() == crypto::error::invalid_signature);
    }
    auto zero_r = geth_signature;
    std::fill_n(zero_r.begin(), 32, std::uint8_t{0});
    auto const refused = secp::recover(crypto::ecdsa_keccak256_recoverable, typed(zero_r),
                                       crypto::prehashed{geth_message});
    BOOST_TEST(refused.has_error() && refused.error() == crypto::error::invalid_signature);
}

// A keccak signature of a message recovered under ecdsa_sha256_recoverable, which hashes the
// message with SHA-256, gives another key (R20): a program's comparison of keys refuses it.
void wrong_scheme_key() {
    auto const key = key_of(web3_secret);
    auto const message = bytes_of(web3_message);
    auto const signature = key.sign(crypto::ecdsa_keccak256_recoverable, message);
    if (!BOOST_TEST(signature.has_value())) {
        return;
    }
    auto const other = secp::recover(crypto::ecdsa_sha256_recoverable, *signature, message);
    BOOST_TEST(!other.has_value() || *other != public_of(key));
    auto const same = secp::recover(crypto::ecdsa_keccak256_recoverable, *signature, message);
    BOOST_TEST(same.has_value() && *same == public_of(key));
}

// A key pair moved from refuses to sign with the scheme.
void moved_from() {
    auto source = key_of(web3_secret);
    auto const target = std::move(source);
    static_cast<void>(target);
    // NOLINTNEXTLINE(bugprone-use-after-move): the moved-from key pair is the point
    auto const refused = source.sign(crypto::ecdsa_keccak256_recoverable, bytes_of(web3_message));
    BOOST_TEST(refused.has_error() && refused.error() == crypto::error::invalid_state);
}

}  // namespace

int main() {
    geth_recover();
    personal_sign();
    keccak_not_sha3();
    message_is_hashed();
    empty_message();
    always_low_s();
    high_s_recovered();
    refusals();
    wrong_scheme_key();
    moved_from();
    return webcpp::test::exit_status(boost::report_errors());
}
