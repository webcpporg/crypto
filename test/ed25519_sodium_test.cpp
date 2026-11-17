// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Ed25519 on libsodium: RFC 8032 section 7.1's tests 1, 2, 3 and SHA(abc), each key pair made
// from the RFC's secret key, its public key and signature the RFC's, and verify accepting them;
// the guards (a seed of 31 bytes, a moved-from key pair, a signature changed in one bit, keys and
// signatures of other sizes); generate() under the planted entropy source of the test seam
// WEBCPP_CRYPTO_DETAIL_TEST_ENTROPY, failing and answering; and x25519_secret(), whose public key
// is crypto_sign_ed25519_pk_to_curve25519's of the Ed25519 public key.

#include <webcpp/crypto/curves/ed25519.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"

#include <boost/core/lightweight_test.hpp>

#include <sodium/crypto_scalarmult_curve25519.h>
#include <sodium/crypto_sign_ed25519.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace crypto = webcpp::crypto;
namespace ed25519 = webcpp::crypto::curves::ed25519;
namespace test = webcpp::test;

namespace {

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): the planted source's script
bool entropy_fails = false;

}  // namespace

// The planted source: 0x42 in every byte, or -1 with EIO, as getentropy fails.
extern "C" int webcpp_test_entropy(void* output_bytes, std::size_t byte_count) {
    if (entropy_fails) {
        errno = EIO;
        return -1;
    }
    std::memset(output_bytes, 0x42, byte_count);
    return 0;
}

namespace {

/** One test of RFC 8032 section 7.1, as the RFC writes it. */
struct rfc8032_case {
    std::string_view name;
    std::string_view secret_key;
    std::string_view public_key;
    std::string_view message;
    std::string_view signature;
};

// clang-format off
constexpr auto rfc8032_cases = std::to_array<rfc8032_case>({
    {.name = "TEST 1",
     .secret_key = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     .public_key = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
     .message = "",
     .signature = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    },
    {.name = "TEST 2",
     .secret_key = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     .public_key = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
     .message = "72",
     .signature = "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    },
    {.name = "TEST 3",
     .secret_key = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
     .public_key = "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
     .message = "af82",
     .signature = "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    },
    {.name = "TEST SHA(abc)",
     .secret_key = "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
     .public_key = "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
     .message = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
     .signature = "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
    },
});
// clang-format on

void rfc8032() {
    for (auto const& tested : rfc8032_cases) {
        auto const seed = test::from_hex(tested.secret_key);
        auto const expected_public_key = test::from_hex(tested.public_key);
        auto const message = test::from_hex(tested.message);
        auto const expected_signature = test::from_hex(tested.signature);

        auto const key = ed25519::keypair::make(seed);
        BOOST_TEST(key.has_value());
        if (!key) {
            continue;
        }
        auto const public_key = key->public_key();
        BOOST_TEST(public_key && std::ranges::equal(*public_key, expected_public_key));
        auto const signature = key->sign(message);
        BOOST_TEST(signature && std::ranges::equal(*signature, expected_signature));
        if (!signature || !public_key) {
            continue;
        }
        // The default policy, and strict named, on the default backend and on libsodium named.
        BOOST_TEST(ed25519::verify(*public_key, message, *signature).has_value());
        BOOST_TEST((ed25519::verify<ed25519::strict, crypto::backends::sodium>(*public_key, message,
                                                                               *signature)
                        .has_value()));
        BOOST_TEST(ed25519::verify(expected_public_key, message, expected_signature).has_value());
    }
}

void guards() {
    auto const seed = test::from_hex(rfc8032_cases[1].secret_key);
    auto const message = test::from_hex(rfc8032_cases[1].message);

    // A seed of 31 or 33 bytes is not a seed.
    auto const short_seed = ed25519::keypair::make(std::span(seed).first(31));
    BOOST_TEST(short_seed.has_error() && short_seed.error() == crypto::error::invalid_key_size);
    std::vector<std::uint8_t> long_seed(seed);
    long_seed.push_back(0);
    auto const long_made = ed25519::keypair::make(long_seed);
    BOOST_TEST(long_made.has_error() && long_made.error() == crypto::error::invalid_key_size);

    // A moved-from key pair is empty: every member says invalid_state; the target works.
    auto made = ed25519::keypair::make(seed);
    BOOST_TEST(made.has_value());
    if (!made) {
        return;
    }
    ed25519::keypair source = std::move(*made);
    ed25519::keypair target = std::move(source);
    // NOLINTBEGIN(bugprone-use-after-move,clang-analyzer-cplusplus.Move): the moved-from state
    // is what is tested
    BOOST_TEST(source.public_key().error() == crypto::error::invalid_state);
    BOOST_TEST(source.sign(message).error() == crypto::error::invalid_state);
    BOOST_TEST(source.x25519_secret().error() == crypto::error::invalid_state);
    // NOLINTEND(bugprone-use-after-move,clang-analyzer-cplusplus.Move)
    auto const signature = target.sign(message);
    BOOST_TEST(signature &&
               std::ranges::equal(*signature, test::from_hex(rfc8032_cases[1].signature)));

    // Moved over: the target takes the key, the source is empty.
    auto other = ed25519::keypair::make(test::from_hex(rfc8032_cases[0].secret_key));
    BOOST_TEST(other.has_value());
    if (other) {
        target = std::move(*other);
        auto const first = target.public_key();
        BOOST_TEST(first &&
                   std::ranges::equal(*first, test::from_hex(rfc8032_cases[0].public_key)));
        // NOLINTNEXTLINE(bugprone-use-after-move,clang-analyzer-cplusplus.Move): tested
        BOOST_TEST(other->public_key().error() == crypto::error::invalid_state);
    }
}

void refusals() {
    auto const message = test::from_hex(rfc8032_cases[1].message);
    // A signature changed in one bit, of R or of S, and a message changed in one bit.
    auto const public_key = test::from_hex(rfc8032_cases[1].public_key);
    auto const good = test::from_hex(rfc8032_cases[1].signature);
    for (std::size_t const index :
         {std::size_t{0}, std::size_t{31}, std::size_t{32}, std::size_t{63}}) {
        auto changed = good;
        changed[index] ^= 0x01U;
        auto const refused = ed25519::verify(public_key, message, changed);
        BOOST_TEST(refused.has_error() && refused.error() == crypto::error::invalid_signature);
    }
    auto changed_message = message;
    changed_message[0] ^= 0x01U;
    BOOST_TEST(ed25519::verify(public_key, changed_message, good).error() ==
               crypto::error::invalid_signature);

    // A public key or a signature of another size.
    BOOST_TEST(ed25519::verify(std::span(public_key).first(31), message, good).error() ==
               crypto::error::invalid_public_key);
    BOOST_TEST(ed25519::verify(public_key, message, std::span(good).first(63)).error() ==
               crypto::error::invalid_signature);
    std::vector<std::uint8_t> long_signature(good);
    long_signature.push_back(0);
    BOOST_TEST(ed25519::verify(public_key, message, long_signature).error() ==
               crypto::error::invalid_signature);
}

void generated() {
    // The source fails: no key pair, entropy_unavailable.
    entropy_fails = true;
    auto const refused = ed25519::keypair::generate();
    BOOST_TEST(refused.has_error() && refused.error() == crypto::error::entropy_unavailable);

    // The source answers: the key pair of the seed it gave, 32 bytes of 0x42.
    entropy_fails = false;
    auto const drawn = ed25519::keypair::generate();
    std::array<std::uint8_t, 32> seed{};
    seed.fill(0x42);
    auto const made = ed25519::keypair::make(seed);
    BOOST_TEST(drawn.has_value() && made.has_value());
    if (drawn && made) {
        auto const drawn_key = drawn->public_key();
        auto const made_key = made->public_key();
        BOOST_TEST(drawn_key && made_key && *drawn_key == *made_key);
    }
}

void conversion() {
    for (auto const& tested : rfc8032_cases) {
        auto const key = ed25519::keypair::make(test::from_hex(tested.secret_key));
        BOOST_TEST(key.has_value());
        if (!key) {
            continue;
        }
        auto const x25519_secret = key->x25519_secret();
        BOOST_TEST(x25519_secret.has_value());
        if (!x25519_secret) {
            continue;
        }
        static_assert(
            std::is_same_v<std::remove_cvref_t<decltype(*x25519_secret)>, crypto::secret<32>>);
        // The X25519 public key of the converted secret is libsodium's conversion of the
        // Ed25519 public key.
        std::array<std::uint8_t, 32> from_secret{};
        BOOST_TEST_EQ(
            crypto_scalarmult_curve25519_base(from_secret.data(), x25519_secret->bytes().data()),
            0);
        std::array<std::uint8_t, 32> from_public{};
        auto const public_key = test::from_hex(tested.public_key);
        BOOST_TEST_EQ(crypto_sign_ed25519_pk_to_curve25519(from_public.data(), public_key.data()),
                      0);
        BOOST_TEST(from_secret == from_public);
    }
}

}  // namespace

int main() {
    static_assert(
        std::is_same_v<ed25519::keypair, ed25519::basic_keypair<crypto::backends::sodium>>);
    static_assert(std::is_same_v<ed25519::keypair::family_type, crypto::families::ed25519>);
    static_assert(std::is_same_v<ed25519::keypair::name_type, crypto::families::ed25519>);
    static_assert(ed25519::keypair::seed_size == 32 && ed25519::keypair::public_key_size == 32 &&
                  ed25519::keypair::signature_size == 64);
    static_assert(!std::is_copy_constructible_v<ed25519::keypair> &&
                  !std::is_copy_assignable_v<ed25519::keypair>);
    static_assert(std::is_nothrow_move_constructible_v<ed25519::keypair> &&
                  std::is_nothrow_move_assignable_v<ed25519::keypair>);
    rfc8032();
    guards();
    refusals();
    generated();
    conversion();
    return test::exit_status(boost::report_errors());
}
