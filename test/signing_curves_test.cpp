// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Every curve's crypto::verify in one program: a 32-byte array is BIP340's x-only key under
// crypto::schnorr and no key under crypto::eddsa, which takes curves::ed25519::public_key (design
// R17), each call resolved to its curve's overload with no ambiguity and no catch-all, and each
// signature verifying under its own scheme alone: its type is its curve's and scheme's (design
// R1), so a signature of another curve or scheme is refused by can_verify and by the build, and
// its bytes made into the other type are refused at run time; ECDSA takes each curve's key object
// and no bytes. The backend, named, comes first on every curve and picks its own curve's overload
// alone; Ed25519's policy is the fifth argument. Every signing key pair (crypto::signing_keypair:
// Ed25519's, P-256's and secp256k1's, not X25519's) signs through crypto::sign, used through the
// concept alone, a signature its public key verifies with crypto::verify under each scheme that
// verifies.

#include <webcpp/crypto/backends/bearssl.hpp>
#include <webcpp/crypto/backends/sodium.hpp>
#include <webcpp/crypto/curves/ed25519.hpp>
#include <webcpp/crypto/curves/p256.hpp>
#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/curves/x25519.hpp>
#include <webcpp/crypto/detail/signature.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/keypair.hpp>
#include <webcpp/crypto/signing.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>

#include <array>
#include <cstdint>
#include <span>
#include <type_traits>
#include <utility>

namespace crypto = webcpp::crypto;

namespace {

using key_bytes = std::array<std::uint8_t, 32>;
using message_bytes = std::span<std::uint8_t const>;
using ed25519_signature = crypto::curves::ed25519::signature;
using crypto::curves::secp256k1::schnorr_signature;
using secp256k1_ecdsa_signature = crypto::curves::secp256k1::ecdsa_signature;
using p256_ecdsa_signature = crypto::curves::p256::ecdsa_signature;
using p256_bearssl_key = crypto::curves::p256::basic_public_key<crypto::backends::bearssl>;

// A 32-byte array is a key of schnorr alone; eddsa's key is Ed25519's object.
static_assert(!crypto::detail::has_verifier_v<crypto::eddsa_t, key_bytes>);
static_assert(crypto::detail::has_verifier_v<crypto::schnorr_t, key_bytes>);
static_assert(!crypto::detail::has_verifier_v<crypto::ecdsa_sha256_t, key_bytes>);
static_assert(!crypto::can_verify<crypto::eddsa_t, ed25519_signature, message_bytes, key_bytes>);
static_assert(crypto::can_verify<crypto::schnorr_t, schnorr_signature, message_bytes, key_bytes>);
static_assert(!crypto::can_verify<crypto::ecdsa_sha256_t, secp256k1_ecdsa_signature, message_bytes,
                                  key_bytes>);
static_assert(crypto::can_verify<crypto::eddsa_t, ed25519_signature, message_bytes,
                                 crypto::curves::ed25519::public_key>);
static_assert(!crypto::can_verify<crypto::schnorr_t, schnorr_signature, message_bytes,
                                  crypto::curves::ed25519::public_key>);
// A span of a size known only at run time is no key.
static_assert(!crypto::can_verify<crypto::eddsa_t, ed25519_signature, message_bytes,
                                  std::span<std::uint8_t const>>);
static_assert(!crypto::can_verify<crypto::schnorr_t, schnorr_signature, message_bytes,
                                  std::span<std::uint8_t const>>);
// ECDSA's key is each curve's object, and its signature each curve's type.
static_assert(crypto::can_verify<crypto::ecdsa_sha256_t, secp256k1_ecdsa_signature, message_bytes,
                                 crypto::curves::secp256k1::public_key>);
static_assert(crypto::can_verify<crypto::ecdsa_sha256_t, p256_ecdsa_signature, message_bytes,
                                 p256_bearssl_key>);
// The wrong curve (the spec's scenario): a secp256k1 signature is no P-256 signature, and the
// other way round, though both are 64 bytes, r then s.
static_assert(!crypto::can_verify<crypto::ecdsa_sha256_t, secp256k1_ecdsa_signature, message_bytes,
                                  p256_bearssl_key>);
static_assert(!crypto::can_verify<crypto::ecdsa_sha256_t, p256_ecdsa_signature, message_bytes,
                                  crypto::curves::secp256k1::public_key>);
// The wrong scheme: Ed25519's and BIP340's signatures, both 64 bytes, are not each other's.
static_assert(!crypto::can_verify<crypto::eddsa_t, schnorr_signature, message_bytes,
                                  crypto::curves::ed25519::public_key>);
static_assert(!crypto::can_verify<crypto::schnorr_t, ed25519_signature, message_bytes, key_bytes>);

// Whether crypto::verify<Backend>(crypto::ecdsa_sha256, ...) is callable with `Key` and its
// signature type: a P-256 key takes its own backend alone, which is deduced and which an explicit
// other one contradicts.
template <class Backend, class Key>
concept verifies_ecdsa_on =
    requires(crypto::detail::signature_of_t<Key, crypto::ecdsa_sha256_t> const& signature,
             message_bytes message, Key const& key) {
        crypto::verify<Backend>(crypto::ecdsa_sha256, signature, message, key);
    };
static_assert(verifies_ecdsa_on<crypto::backends::bearssl, p256_bearssl_key>);
static_assert(!verifies_ecdsa_on<crypto::backends::openssl, p256_bearssl_key>);
static_assert(
    verifies_ecdsa_on<crypto::backends::secp256k1, crypto::curves::secp256k1::public_key>);

// Ed25519 and BIP340 signatures, each against its key, Ed25519's typed and BIP340's x-only key
// held in a 32-byte array: each verifies under its own scheme; its bytes, made into the other
// scheme's type as bytes from the wire would be, are refused under the other.
void byte_keys() {
    key_bytes seed{};
    seed.fill(0x42);
    std::array<std::uint8_t, 5> const message{'h', 'e', 'l', 'l', 'o'};
    auto const ed25519 = crypto::curves::ed25519::keypair::from_secret(seed);
    auto const secp256k1 = crypto::curves::secp256k1::keypair::from_secret(seed);
    if (!BOOST_TEST(ed25519.has_value()) || !BOOST_TEST(secp256k1.has_value())) {
        return;
    }
    auto const ed25519_key = *ed25519->public_key();
    key_bytes const xonly_key = secp256k1->public_key()->xonly();
    auto const eddsa_signature = ed25519->sign(crypto::eddsa, message);
    auto const schnorr_signature = secp256k1->sign(crypto::schnorr, message);
    if (!BOOST_TEST(eddsa_signature.has_value()) || !BOOST_TEST(schnorr_signature.has_value())) {
        return;
    }
    BOOST_TEST(crypto::verify(crypto::eddsa, *eddsa_signature, message, ed25519_key).has_value());
    BOOST_TEST(crypto::verify(crypto::schnorr, *schnorr_signature, message, xonly_key).has_value());
    auto const schnorr_as_eddsa = ed25519_signature::from_bytes(schnorr_signature->bytes());
    auto const eddsa_as_schnorr =
        crypto::curves::secp256k1::schnorr_signature::from_bytes(eddsa_signature->bytes());
    if (!BOOST_TEST(schnorr_as_eddsa.has_value()) || !BOOST_TEST(eddsa_as_schnorr.has_value())) {
        return;
    }
    BOOST_TEST(crypto::verify(crypto::eddsa, *schnorr_as_eddsa, message, ed25519_key).error() ==
               crypto::error::invalid_signature);
    BOOST_TEST(crypto::verify(crypto::schnorr, *eddsa_as_schnorr, message, xonly_key).has_error());
}

using hello = std::array<std::uint8_t, 5>;

constexpr hello hello_message{'h', 'e', 'l', 'l', 'o'};

// Ed25519 with its backend named first, libsodium, with and without its policy named as the
// fifth argument: the named backend picks Ed25519's verify alone, the catch-all included.
void backend_first_ed25519() {
    key_bytes seed{};
    seed.fill(0x24);
    auto const ed25519 =
        crypto::curves::ed25519::basic_keypair<crypto::backends::sodium>::from_secret(seed);
    if (!BOOST_TEST(ed25519.has_value())) {
        return;
    }
    auto const ed25519_key = *ed25519->public_key();
    auto const signature = ed25519->sign(crypto::eddsa, hello_message);
    if (!BOOST_TEST(signature.has_value())) {
        return;
    }
    BOOST_TEST(crypto::verify<crypto::backends::sodium>(crypto::eddsa, *signature, hello_message,
                                                        ed25519_key)
                   .has_value());
    BOOST_TEST(crypto::verify<crypto::backends::sodium>(crypto::eddsa, *signature, hello_message,
                                                        ed25519_key,
                                                        crypto::curves::ed25519::strict)
                   .has_value());
    BOOST_TEST(crypto::verify(crypto::eddsa, *signature, hello_message, ed25519_key,
                              crypto::curves::ed25519::strict)
                   .has_value());
    auto altered_bytes = signature->bytes();
    altered_bytes[0] ^= 0x01U;
    auto const altered = ed25519_signature::from_bytes(altered_bytes).value();
    BOOST_TEST(crypto::verify<crypto::backends::sodium>(crypto::eddsa, altered, hello_message,
                                                        ed25519_key,
                                                        crypto::curves::ed25519::strict)
                   .error() == crypto::error::invalid_signature);
}

// secp256k1 with its own backend named first, on Schnorr, ECDSA and recovery; P-256 with
// BearSSL, its key's, named first.
void backend_first_ecdsa() {
    key_bytes seed{};
    seed.fill(0x24);
    auto const secp256k1 = crypto::curves::secp256k1::keypair::from_secret(seed);
    auto const p256 =
        crypto::curves::p256::basic_keypair<crypto::backends::bearssl>::from_secret(seed);
    if (!BOOST_TEST(secp256k1.has_value()) || !BOOST_TEST(p256.has_value())) {
        return;
    }
    auto const secp256k1_key = secp256k1->public_key();
    auto const p256_key = p256->public_key();
    if (!BOOST_TEST(secp256k1_key.has_value()) || !BOOST_TEST(p256_key.has_value())) {
        return;
    }
    auto const xonly_key = secp256k1_key->xonly();
    auto const schnorr_signature = secp256k1->sign(crypto::schnorr, hello_message);
    auto const ecdsa_signature = secp256k1->sign(crypto::ecdsa_sha256, hello_message);
    auto const recoverable_signature =
        secp256k1->sign(crypto::ecdsa_sha256_recoverable, hello_message);
    auto const p256_signature = p256->sign(crypto::ecdsa_sha256, hello_message);
    if (!BOOST_TEST(schnorr_signature.has_value()) || !BOOST_TEST(ecdsa_signature.has_value()) ||
        !BOOST_TEST(recoverable_signature.has_value()) || !BOOST_TEST(p256_signature.has_value())) {
        return;
    }
    BOOST_TEST(crypto::verify<crypto::backends::secp256k1>(crypto::schnorr, *schnorr_signature,
                                                           hello_message, xonly_key)
                   .has_value());
    BOOST_TEST(crypto::verify<crypto::backends::secp256k1>(crypto::schnorr, *schnorr_signature,
                                                           hello_message, *secp256k1_key)
                   .has_value());
    BOOST_TEST(crypto::verify<crypto::backends::secp256k1>(crypto::ecdsa_sha256, *ecdsa_signature,
                                                           hello_message, *secp256k1_key)
                   .has_value());
    auto const recovered = crypto::curves::secp256k1::recover<crypto::backends::secp256k1>(
        crypto::ecdsa_sha256_recoverable, *recoverable_signature, hello_message);
    BOOST_TEST((recovered.has_value() && *recovered == *secp256k1_key));
    BOOST_TEST(crypto::verify<crypto::backends::bearssl>(crypto::ecdsa_sha256, *p256_signature,
                                                         hello_message, *p256_key)
                   .has_value());
}

// A signing key pair, through crypto::signing_keypair alone: crypto::sign gives the scheme's
// signature type for its curve, which its public key verifies, and refuses with a changed message.
template <crypto::signing_keypair Keypair, class Scheme>
void signs_what_its_public_key_verifies(Scheme scheme) {
    static_assert(std::is_same_v<std::remove_cvref_t<decltype(*crypto::sign(
                                     std::declval<Keypair const&>(), scheme, hello_message))>,
                                 crypto::detail::signature_of_t<Keypair, Scheme>>);
    auto const key = Keypair::generate();
    if (!BOOST_TEST(key.has_value())) {
        return;
    }
    auto const public_key = key->public_key();
    auto const signature = crypto::sign(*key, scheme, hello_message);
    if (!BOOST_TEST(public_key.has_value()) || !BOOST_TEST(signature.has_value())) {
        return;
    }
    BOOST_TEST(crypto::verify(scheme, *signature, hello_message, *public_key).has_value());
    hello const changed{'h', 'e', 'l', 'l', 'p'};
    BOOST_TEST(crypto::verify(scheme, *signature, changed, *public_key) ==
               crypto::error::invalid_signature);
}

// D4's signing column: the three signing curves' key pairs, not X25519's.
static_assert(
    crypto::signing_keypair<crypto::curves::ed25519::basic_keypair<crypto::backends::sodium>>);
static_assert(
    crypto::signing_keypair<crypto::curves::p256::basic_keypair<crypto::backends::bearssl>>);
static_assert(
    crypto::signing_keypair<crypto::curves::secp256k1::basic_keypair<crypto::backends::secp256k1>>);
static_assert(
    !crypto::signing_keypair<crypto::curves::x25519::basic_keypair<crypto::backends::sodium>>);

}  // namespace

int main() {
    byte_keys();
    backend_first_ed25519();
    backend_first_ecdsa();
    signs_what_its_public_key_verifies<
        crypto::curves::ed25519::basic_keypair<crypto::backends::sodium>>(crypto::eddsa);
    signs_what_its_public_key_verifies<
        crypto::curves::p256::basic_keypair<crypto::backends::bearssl>>(crypto::ecdsa_sha256);
    signs_what_its_public_key_verifies<
        crypto::curves::secp256k1::basic_keypair<crypto::backends::secp256k1>>(
        crypto::ecdsa_sha256);
    signs_what_its_public_key_verifies<
        crypto::curves::secp256k1::basic_keypair<crypto::backends::secp256k1>>(crypto::schnorr);
    return webcpp::test::exit_status(boost::report_errors());
}
