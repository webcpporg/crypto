// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Every public function that runs BearSSL's code enters its own detail::timing_guard and leaves
// the thread's DIT as it found it, on every target, also where DIT does not apply, each with valid
// input and with input refused before the backend (support/timing_coverage.hpp).
// A check fails, naming itself, when its call enters no guard or when the first guard it enters is
// not the one of the function it names (support/timing_seam.hpp), so that a function that forgot
// its own guard fails although it calls another guarded function.
//
// What it covers, by family; a family BearSSL gains adds its line and its checks:
// - AES-GCM, gcm<aes128>, gcm<aes192> and gcm<aes256>: from_key, the move constructor and move
//   assignment (ruling R3), seal, open, begin_seal, update, result, and the asynchronous
//   async_from_key, async_seal and async_open, free (secret_key_encryption::aead's) and member;
//   the free crypto::from_key, secret_key_encryption::aead::seal and
//   secret_key_encryption::aead::open.
// - ChaCha20-Poly1305, aead: from_key, seal, open; the free crypto::from_key,
//   secret_key_encryption::aead::seal and secret_key_encryption::aead::open; the asynchronous
//   async_from_key, async_seal and async_open, member and free.
// - P-256, curves::p256: basic_keypair::from_secret, generate, sign (ecdsa_sha256, of a message and
//   of a digest), agree; basic_public_key::from_bytes, from_coordinates, verify (ecdsa_sha256, of a
//   message and of a digest); crypto::verify (ecdsa_sha256, of a message and of a digest), to_der,
//   from_der; decode_spki, decode_pkcs8; the free synchronous forms of the members,
//   crypto::from_secret, crypto::generate, crypto::sign and crypto::agree, which enter their own
//   guard before the member's, and crypto::from_bytes, which holds none (the member's is its
//   first); not guarded (no BearSSL call): public_key, secret, uncompressed, encode_spki,
//   encode_pkcs8, basic_keypair's move constructor and move assignment, and normalize_low_s and
//   is_low_s, which test/timing_test.cpp calls without a backend, and ecdsa_signature's
//   from_bytes, member and free, and bytes; and the asynchronous
//   async_from_secret, async_generate, async_sign and async_verify (ecdsa_sha256, of a message and
//   of a digest) and async_agree, all but async_generate (which takes no input) also refused once
//   before BearSSL, both free and as the members basic_keypair::async_from_secret, async_generate,
//   async_sign, async_agree and basic_public_key::async_verify, which the free ones call.

#include "support/timing_seam.hpp"

#include <webcpp/crypto/async.hpp>
#include <webcpp/crypto/backends/bearssl.hpp>
#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/crypto/ciphers/chacha20_poly1305.hpp>
#include <webcpp/crypto/ciphers/gcm.hpp>
#include <webcpp/crypto/curves/p256.hpp>
#include <webcpp/crypto/curves/p256/formats.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/keypair.hpp>
#include <webcpp/crypto/signing.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/p256_data.hpp"
#include "support/timing_coverage.hpp"

#include <webcpp/asio/io_context.hpp>

#include <boost/core/lightweight_test.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <span>
#include <utility>

namespace {

namespace crypto = webcpp::crypto;
using crypto::backends::bearssl;

// The ciphers: AES-GCM and ChaCha20-Poly1305.
void cover_ciphers() {
    webcpp::test::cover_gcm<crypto::ciphers::gcm<crypto::ciphers::aes128<bearssl>>>("aes128_gcm",
                                                                                    "bearssl");
    webcpp::test::cover_async_gcm<crypto::ciphers::gcm<crypto::ciphers::aes128<bearssl>>>(
        "aes128_gcm", "bearssl");
    webcpp::test::cover_gcm<crypto::ciphers::gcm<crypto::ciphers::aes192<bearssl>>>("aes192_gcm",
                                                                                    "bearssl");
    webcpp::test::cover_async_gcm<crypto::ciphers::gcm<crypto::ciphers::aes192<bearssl>>>(
        "aes192_gcm", "bearssl");
    webcpp::test::cover_gcm<crypto::ciphers::gcm<crypto::ciphers::aes256<bearssl>>>("aes256_gcm",
                                                                                    "bearssl");
    webcpp::test::cover_async_gcm<crypto::ciphers::gcm<crypto::ciphers::aes256<bearssl>>>(
        "aes256_gcm", "bearssl");
    webcpp::test::cover_aead<crypto::ciphers::chacha20_poly1305<bearssl>>("chacha20_poly1305",
                                                                          "bearssl");
}

// P-256: the key pair's from_secret and generate, the public key's from_bytes and
// from_coordinates, each refused once before
// BearSSL; the functions that copy what the key pair holds enter no guard.
void cover_p256_keys() {
    namespace p256 = crypto::curves::p256;
    namespace data = webcpp::test::p256;
    using keypair = p256::basic_keypair<bearssl>;
    using public_key = p256::basic_public_key<bearssl>;
    webcpp::test::covered("p256::basic_keypair::from_secret on bearssl", [] {
        BOOST_TEST(keypair::from_secret(data::rfc6979_scalar).has_value());
    });
    webcpp::test::covered("p256::basic_keypair::from_secret of the order on bearssl", [] {
        BOOST_TEST(keypair::from_secret(data::order).error() == crypto::error::invalid_secret_key);
    });
    webcpp::test::covered("p256::basic_keypair::generate on bearssl",
                          [] { BOOST_TEST(keypair::generate().has_value()); });
    std::span<std::uint8_t const, 65> const point(data::rfc6979_public);
    webcpp::test::covered("p256::basic_public_key::from_bytes of a point on bearssl",
                          "basic_public_key::from_bytes",
                          [point] { BOOST_TEST(public_key::from_bytes(point).has_value()); });
    webcpp::test::covered(
        "p256::basic_public_key::from_coordinates on bearssl", "basic_public_key::from_coordinates",
        [point] {
            BOOST_TEST(public_key::from_coordinates(point.subspan<1, 32>(), point.subspan<33, 32>())
                           .has_value());
        });
    webcpp::test::covered("p256::basic_public_key::from_bytes of 64 bytes on bearssl",
                          "basic_public_key::from_bytes", [point] {
                              BOOST_TEST(public_key::from_bytes(point.first(64)).error() ==
                                         crypto::error::invalid_public_key);
                          });
    auto const made = keypair::from_secret(data::rfc6979_scalar);
    if (!BOOST_TEST(made.has_value())) {
        return;
    }
    webcpp::test::uncovered("p256::basic_keypair::public_key on bearssl",
                            [&made] { BOOST_TEST(made->public_key().has_value()); });
    webcpp::test::uncovered("p256::basic_keypair::secret on bearssl",
                            [&made] { BOOST_TEST(made->secret().has_value()); });
    auto const key = made->public_key();
    if (!BOOST_TEST(key.has_value())) {
        return;
    }
    webcpp::test::uncovered("p256::basic_public_key::uncompressed on bearssl",
                            [&key] { BOOST_TEST(key->uncompressed() == data::rfc6979_public); });
}

// P-256: the key pair's move constructor and move assignment only wipe the source: they enter
// no guard.
void cover_p256_keypair_moves() {
    namespace p256 = crypto::curves::p256;
    namespace data = webcpp::test::p256;
    using keypair = p256::basic_keypair<bearssl>;
    auto mover = keypair::from_secret(data::rfc6979_scalar);
    if (BOOST_TEST(mover.has_value())) {
        webcpp::test::uncovered("p256::basic_keypair move constructor on bearssl", [&mover] {
            keypair const taken = std::move(*mover);
            BOOST_TEST(taken.public_key().has_value());
        });
    }
    auto target = keypair::from_secret(data::rfc6979_scalar);
    auto source = keypair::from_secret(data::rfc6979_scalar);
    if (BOOST_TEST(target.has_value()) && BOOST_TEST(source.has_value())) {
        webcpp::test::uncovered("p256::basic_keypair move assignment on bearssl",
                                [&target, &source] {
                                    *target = std::move(*source);
                                    BOOST_TEST(target->public_key().has_value());
                                });
    }
}

// P-256's sign on a moved-from key pair: refused with invalid_state before BearSSL, inside its own
// guard.
void cover_p256_sign_moved_from(std::array<std::uint8_t, 32> const& digest) {
    namespace p256 = crypto::curves::p256;
    namespace data = webcpp::test::p256;
    using keypair = p256::basic_keypair<bearssl>;
    auto source = keypair::from_secret(data::rfc6979_scalar);
    if (BOOST_TEST(source.has_value())) {
        keypair const taken = std::move(*source);
        webcpp::test::covered(
            "p256::basic_keypair::sign moved from on bearssl", [&source, &digest] {
                // NOLINTNEXTLINE(bugprone-use-after-move,clang-analyzer-cplusplus.Move): tested
                BOOST_TEST(source->sign(crypto::ecdsa_sha256, crypto::prehashed{digest}).error() ==
                           crypto::error::invalid_state);
            });
    }
}

// SHA-256 of "test" (RFC 6979, section A.2.5), whose signature is data::rfc6979_test.
constexpr std::array<std::uint8_t, 32> p256_test_digest{
    0x9f, 0x86, 0xd0, 0x81, 0x88, 0x4c, 0x7d, 0x65, 0x9a, 0x2f, 0xea, 0xa0, 0xc5, 0x5a, 0xd0, 0x15,
    0xa3, 0xbf, 0x4f, 0x1b, 0x2b, 0x0b, 0x82, 0x2c, 0xd1, 0x5d, 0x6c, 0x15, 0xb0, 0xf0, 0x0a, 0x08,
};
// The message "test" itself.
constexpr std::array<std::uint8_t, 4> p256_test_message{'t', 'e', 's', 't'};

// P-256's crypto::verify of ECDSA over SHA-256, of the message and of its digest, and refused
// once before BearSSL (an r of 0).
void cover_p256_verify() {
    namespace p256 = crypto::curves::p256;
    namespace data = webcpp::test::p256;
    auto const key = p256::basic_public_key<bearssl>::from_bytes(data::rfc6979_public);
    auto const test = p256::ecdsa_signature::from_bytes(data::rfc6979_test);
    auto zero_r_bytes = data::rfc6979_test;
    std::fill_n(zero_r_bytes.begin(), 32, std::uint8_t{0});
    auto const zero_r = p256::ecdsa_signature::from_bytes(zero_r_bytes);
    if (!BOOST_TEST(key.has_value()) || !BOOST_TEST(test.has_value()) ||
        !BOOST_TEST(zero_r.has_value())) {
        return;
    }
    webcpp::test::covered(
        "p256 crypto::verify of a message on bearssl", "crypto::verify", [&key, &test] {
            BOOST_TEST(
                crypto::verify(crypto::ecdsa_sha256, *test, p256_test_message, *key).has_value());
        });
    webcpp::test::covered("p256 crypto::verify of a digest on bearssl", "crypto::verify",
                          [&key, &test] {
                              BOOST_TEST(crypto::verify(crypto::ecdsa_sha256, *test,
                                                        crypto::prehashed{p256_test_digest}, *key)
                                             .has_value());
                          });
    webcpp::test::covered("p256 crypto::verify of r = 0 on bearssl", "crypto::verify",
                          [&key, &zero_r] {
                              BOOST_TEST(crypto::verify(crypto::ecdsa_sha256, *zero_r,
                                                        crypto::prehashed{p256_test_digest}, *key)
                                             .error() == crypto::error::invalid_signature);
                          });
}

// P-256's basic_public_key::verify of ECDSA over SHA-256, of the message and of its digest, and
// refused once before BearSSL (an r of 0).
void cover_p256_public_key_verify() {
    namespace p256 = crypto::curves::p256;
    namespace data = webcpp::test::p256;
    auto const key = p256::basic_public_key<bearssl>::from_bytes(data::rfc6979_public);
    auto const test = p256::ecdsa_signature::from_bytes(data::rfc6979_test);
    auto zero_r_bytes = data::rfc6979_test;
    std::fill_n(zero_r_bytes.begin(), 32, std::uint8_t{0});
    auto const zero_r = p256::ecdsa_signature::from_bytes(zero_r_bytes);
    if (!BOOST_TEST(key.has_value()) || !BOOST_TEST(test.has_value()) ||
        !BOOST_TEST(zero_r.has_value())) {
        return;
    }
    webcpp::test::covered("p256::basic_public_key::verify of a message on bearssl", [&key, &test] {
        BOOST_TEST(key->verify(crypto::ecdsa_sha256, *test, p256_test_message).has_value());
    });
    webcpp::test::covered("p256::basic_public_key::verify of a digest on bearssl", [&key, &test] {
        BOOST_TEST(key->verify(crypto::ecdsa_sha256, *test, crypto::prehashed{p256_test_digest})
                       .has_value());
    });
    webcpp::test::covered("p256::basic_public_key::verify of r = 0 on bearssl", [&key, &zero_r] {
        BOOST_TEST(key->verify(crypto::ecdsa_sha256, *zero_r, crypto::prehashed{p256_test_digest})
                       .error() == crypto::error::invalid_signature);
    });
}

// P-256's free synchronous forms, crypto::from_secret, crypto::generate, crypto::sign and
// crypto::agree, each entering its own guard before the member's, and refused once before
// BearSSL (the group order, a moved-from key pair); crypto::from_bytes holds none, so the first
// guard it enters is the member's.
void cover_p256_free_forms() {
    namespace p256 = crypto::curves::p256;
    namespace data = webcpp::test::p256;
    using keypair = p256::basic_keypair<bearssl>;
    webcpp::test::covered("p256 crypto::from_secret on bearssl", "crypto::from_secret", [] {
        BOOST_TEST(crypto::from_secret<keypair>(data::rfc6979_scalar).has_value());
    });
    webcpp::test::covered("p256 crypto::from_secret of the order on bearssl", "crypto::from_secret",
                          [] {
                              BOOST_TEST(crypto::from_secret<keypair>(data::order).error() ==
                                         crypto::error::invalid_secret_key);
                          });
    using public_key = p256::basic_public_key<bearssl>;
    std::span<std::uint8_t const, 65> const point(data::rfc6979_public);
    webcpp::test::covered(
        "p256 crypto::from_bytes of a public key on bearssl", "basic_public_key::from_bytes",
        [point] { BOOST_TEST(crypto::from_bytes<public_key>(point).has_value()); });
    webcpp::test::covered("p256 crypto::from_bytes of a public key of 64 bytes on bearssl",
                          "basic_public_key::from_bytes", [point] {
                              BOOST_TEST(crypto::from_bytes<public_key>(point.first(64)).error() ==
                                         crypto::error::invalid_public_key);
                          });
    webcpp::test::covered("p256 crypto::generate on bearssl", "crypto::generate",
                          [] { BOOST_TEST(crypto::generate<keypair>().has_value()); });
    auto made = keypair::from_secret(data::rfc6979_scalar);
    auto const peer = public_key::from_bytes(data::rfc6979_public);
    if (!BOOST_TEST(made.has_value()) || !BOOST_TEST(peer.has_value())) {
        return;
    }
    webcpp::test::covered("p256 crypto::sign on bearssl", "crypto::sign", [&made] {
        auto const signature = crypto::sign(*made, crypto::ecdsa_sha256, p256_test_message);
        BOOST_TEST(signature.has_value() && signature->bytes() == data::rfc6979_test);
    });
    webcpp::test::covered("p256 crypto::agree on bearssl", "crypto::agree",
                          [&made, &peer] { BOOST_TEST(crypto::agree(*made, *peer).has_value()); });
    keypair const taken = std::move(*made);
    webcpp::test::covered("p256 crypto::sign moved from on bearssl", "crypto::sign", [&made] {
        // NOLINTNEXTLINE(bugprone-use-after-move,clang-analyzer-cplusplus.Move): tested
        BOOST_TEST(crypto::sign(*made, crypto::ecdsa_sha256, p256_test_message).error() ==
                   crypto::error::invalid_state);
    });
    webcpp::test::covered(
        "p256 crypto::agree moved from on bearssl", "crypto::agree", [&made, &peer] {
            // NOLINTNEXTLINE(bugprone-use-after-move,clang-analyzer-cplusplus.Move): tested
            BOOST_TEST(crypto::agree(*made, *peer).error() == crypto::error::invalid_state);
        });
}

// P-256's DER both ways, each refused once before BearSSL (a short buffer, an empty DER).
void cover_p256_der() {
    namespace p256 = crypto::curves::p256;
    namespace data = webcpp::test::p256;
    std::array<std::uint8_t, p256::max_der_size> der{};
    auto const test = p256::ecdsa_signature::from_bytes(data::rfc6979_test);
    if (!BOOST_TEST(test.has_value())) {
        return;
    }
    webcpp::test::covered("p256::to_der on bearssl", [&der, &test] {
        BOOST_TEST(p256::to_der<bearssl>(*test, der).has_value());
    });
    webcpp::test::covered("p256::to_der into 71 bytes on bearssl", [&der, &test] {
        BOOST_TEST(p256::to_der<bearssl>(*test, std::span(der).first(71)).error() ==
                   crypto::error::invalid_input_size);
    });
    auto const encoded = p256::to_der<bearssl>(*test, der);
    if (!BOOST_TEST(encoded.has_value())) {
        return;
    }
    webcpp::test::covered("p256::from_der on bearssl", [&der, &encoded, &test] {
        auto const decoded = p256::from_der<bearssl>(std::span(der).first(*encoded));
        BOOST_TEST(decoded.has_value() && *decoded == *test);
    });
    webcpp::test::covered("p256::from_der of nothing on bearssl", [] {
        BOOST_TEST(p256::from_der<bearssl>({}).error() == crypto::error::invalid_signature);
    });
}

// P-256's ECDSA: the signature, of the message and of its digest, refused once before BearSSL (a
// moved-from key pair); its verification; and DER both ways.
void cover_p256_ecdsa() {
    namespace p256 = crypto::curves::p256;
    namespace data = webcpp::test::p256;
    auto const made = p256::basic_keypair<bearssl>::from_secret(data::rfc6979_scalar);
    if (!BOOST_TEST(made.has_value())) {
        return;
    }
    webcpp::test::covered(
        "p256::basic_keypair::sign of a message on bearssl", "p256::basic_keypair::sign", [&made] {
            auto const signature = made->sign(crypto::ecdsa_sha256, p256_test_message);
            BOOST_TEST(signature.has_value() && signature->bytes() == data::rfc6979_test);
        });
    webcpp::test::covered(
        "p256::basic_keypair::sign of a digest on bearssl", "p256::basic_keypair::sign", [&made] {
            auto const signature =
                made->sign(crypto::ecdsa_sha256, crypto::prehashed{p256_test_digest});
            BOOST_TEST(signature.has_value() && signature->bytes() == data::rfc6979_test);
        });
    cover_p256_sign_moved_from(p256_test_digest);
    cover_p256_verify();
    cover_p256_public_key_verify();
    cover_p256_free_forms();
    cover_p256_der();
    webcpp::test::cover_signature<p256::ecdsa_signature>("p256::ecdsa_signature", "bearssl");
}

// P-256's ECDH: the shared x of RFC 6979's key with its own public key, and the same call on a
// moved-from key pair, refused with invalid_state before BearSSL, inside its own guard.
void cover_p256_ecdh() {
    namespace p256 = crypto::curves::p256;
    namespace data = webcpp::test::p256;
    using keypair = p256::basic_keypair<bearssl>;
    using public_key = p256::basic_public_key<bearssl>;
    auto made = keypair::from_secret(data::rfc6979_scalar);
    auto const peer = public_key::from_bytes(data::rfc6979_public);
    if (!BOOST_TEST(made.has_value()) || !BOOST_TEST(peer.has_value())) {
        return;
    }
    webcpp::test::covered("p256::basic_keypair::agree on bearssl",
                          [&made, &peer] { BOOST_TEST(made->agree(*peer).has_value()); });
    keypair const taken = std::move(*made);
    webcpp::test::covered("p256::basic_keypair::agree moved from on bearssl", [&made, &peer] {
        // NOLINTNEXTLINE(bugprone-use-after-move,clang-analyzer-cplusplus.Move): tested
        BOOST_TEST(made->agree(*peer).error() == crypto::error::invalid_state);
    });
}

// P-256's formats: the decoders, with an encoding each and one refused before BearSSL, inside
// their own guards (from_secret's and from_bytes', which they call, are entered after theirs); the
// encoders copy what the key and the key pair hold and enter no guard.
void cover_p256_formats() {
    namespace p256 = crypto::curves::p256;
    namespace data = webcpp::test::p256;
    using keypair = p256::basic_keypair<bearssl>;
    auto const made = keypair::from_secret(data::rfc6979_scalar);
    if (!BOOST_TEST(made.has_value())) {
        return;
    }
    auto const key = made->public_key();
    if (!BOOST_TEST(key.has_value())) {
        return;
    }
    std::array<std::uint8_t, p256::max_spki_size> spki{};
    std::array<std::uint8_t, p256::max_pkcs8_size> pkcs8{};
    webcpp::test::uncovered("p256::encode_spki on bearssl",
                            [&] { BOOST_TEST(p256::encode_spki(*key, spki).has_value()); });
    webcpp::test::uncovered("p256::encode_pkcs8 on bearssl",
                            [&] { BOOST_TEST(p256::encode_pkcs8(*made, pkcs8).has_value()); });
    webcpp::test::covered("p256::decode_spki on bearssl",
                          [&] { BOOST_TEST(p256::decode_spki<bearssl>(spki).has_value()); });
    webcpp::test::covered("p256::decode_spki of a short encoding on bearssl", [&] {
        BOOST_TEST(p256::decode_spki<bearssl>(std::span(spki).first(1)).error() ==
                   crypto::error::invalid_encoding);
    });
    webcpp::test::covered("p256::decode_pkcs8 on bearssl",
                          [&] { BOOST_TEST(p256::decode_pkcs8<bearssl>(pkcs8).has_value()); });
    webcpp::test::covered("p256::decode_pkcs8 of a short encoding on bearssl", [&] {
        BOOST_TEST(p256::decode_pkcs8<bearssl>(std::span(pkcs8).first(1)).error() ==
                   crypto::error::invalid_encoding);
    });
}

// P-256's asynchronous functions, each with valid input and with input refused before BearSSL (a
// scalar of 31 bytes, a signature whose r is 0, a moved-from key pair), an io_context run after
// each call so that its completion is delivered. The first guard each enters is its own (the
// synchronous call it makes holds others, which run after).
void cover_async_p256() {
    namespace p256 = crypto::curves::p256;
    namespace data = webcpp::test::p256;
    using keypair = p256::basic_keypair<bearssl>;
    using public_key = p256::basic_public_key<bearssl>;
    using signature_type = p256::ecdsa_signature;
    webcpp::asio::io_context context;
    auto const executor = context.get_executor();
    std::array<std::uint8_t, 3> const message{1, 2, 3};
    int completions = 0;
    signature_type kept{};
    webcpp::test::async_completion_counter<signature_type> const counted{
        .completions = &completions,
    };
    webcpp::test::async_completion_counter<signature_type> const keeping{
        .completions = &completions,
        .tag = &kept,
    };
    // Each call's completion is delivered before the next call.
    auto const deliver = [&context] {
        context.restart();
        context.run();  // lint-run: the test's event loop
    };
    webcpp::test::covered(
        "p256 crypto::async_from_secret on bearssl", "crypto::async_from_secret", [&] {
            crypto::async_from_secret<keypair>(executor, data::rfc6979_scalar, counted);
            deliver();
        });
    webcpp::test::covered("p256 crypto::async_from_secret with a short scalar on bearssl",
                          "crypto::async_from_secret", [&] {
                              crypto::async_from_secret<keypair>(
                                  executor, std::span(data::rfc6979_scalar).first(31), counted);
                              deliver();
                          });
    webcpp::test::covered("p256::async_generate on bearssl", "crypto::async_generate", [&] {
        crypto::async_generate<keypair>(executor, counted);
        deliver();
    });
    webcpp::test::covered("p256::basic_keypair::async_from_secret on bearssl", [&] {
        keypair::async_from_secret(executor, data::rfc6979_scalar, counted);
        deliver();
    });
    webcpp::test::covered("p256::basic_keypair::async_from_secret with a short scalar on bearssl",
                          [&] {
                              keypair::async_from_secret(
                                  executor, std::span(data::rfc6979_scalar).first(31), counted);
                              deliver();
                          });
    webcpp::test::covered("p256::basic_keypair::async_generate on bearssl", [&] {
        keypair::async_generate(executor, counted);
        deliver();
    });
    auto made = keypair::from_secret(data::rfc6979_scalar);
    auto const key = public_key::from_bytes(data::rfc6979_public);
    auto const rfc_test = signature_type::from_bytes(data::rfc6979_test);
    auto zero_r_bytes = data::rfc6979_test;
    std::fill_n(zero_r_bytes.begin(), 32, std::uint8_t{0});
    auto const zero_r = signature_type::from_bytes(zero_r_bytes);
    if (!BOOST_TEST(made.has_value()) || !BOOST_TEST(key.has_value()) ||
        !BOOST_TEST(rfc_test.has_value()) || !BOOST_TEST(zero_r.has_value())) {
        return;
    }
    webcpp::test::covered("p256::async_sign on bearssl", "crypto::async_sign", [&] {
        crypto::async_sign(executor, *made, crypto::ecdsa_sha256, message, keeping);
        deliver();
    });
    webcpp::test::covered("p256::async_sign of a digest on bearssl", "crypto::async_sign", [&] {
        crypto::async_sign(executor, *made, crypto::ecdsa_sha256,
                           crypto::prehashed{p256_test_digest}, counted);
        deliver();
    });
    webcpp::test::covered("p256::async_verify on bearssl", "crypto::async_verify", [&] {
        crypto::async_verify(executor, crypto::ecdsa_sha256, kept, message, *key, counted);
        deliver();
    });
    webcpp::test::covered("p256::async_verify of a digest on bearssl", "crypto::async_verify", [&] {
        crypto::async_verify(executor, crypto::ecdsa_sha256, *rfc_test,
                             crypto::prehashed{p256_test_digest}, *key, counted);
        deliver();
    });
    webcpp::test::covered("p256::async_verify of r = 0 on bearssl", "crypto::async_verify", [&] {
        crypto::async_verify(executor, crypto::ecdsa_sha256, *zero_r, message, *key, counted);
        deliver();
    });
    webcpp::test::covered("p256::async_agree on bearssl", "crypto::async_agree", [&] {
        crypto::async_agree(executor, *made, *key, counted);
        deliver();
    });
    webcpp::test::covered("p256::basic_keypair::async_sign on bearssl", [&] {
        made->async_sign(executor, crypto::ecdsa_sha256, message, counted);
        deliver();
    });
    webcpp::test::covered("p256::basic_keypair::async_sign of a digest on bearssl", [&] {
        made->async_sign(executor, crypto::ecdsa_sha256, crypto::prehashed{p256_test_digest},
                         counted);
        deliver();
    });
    webcpp::test::covered("p256::basic_public_key::async_verify on bearssl", [&] {
        key->async_verify(executor, crypto::ecdsa_sha256, kept, message, counted);
        deliver();
    });
    webcpp::test::covered("p256::basic_public_key::async_verify of a digest on bearssl", [&] {
        key->async_verify(executor, crypto::ecdsa_sha256, *rfc_test,
                          crypto::prehashed{p256_test_digest}, counted);
        deliver();
    });
    webcpp::test::covered("p256::basic_public_key::async_verify of r = 0 on bearssl", [&] {
        key->async_verify(executor, crypto::ecdsa_sha256, *zero_r, message, counted);
        deliver();
    });
    webcpp::test::covered("p256::basic_keypair::async_agree on bearssl", [&] {
        made->async_agree(executor, *key, counted);
        deliver();
    });
    [[maybe_unused]] keypair const taken(std::move(*made));
    webcpp::test::covered("p256::async_sign moved from on bearssl", "crypto::async_sign", [&] {
        // NOLINTNEXTLINE(bugprone-use-after-move,clang-analyzer-cplusplus.Move): tested
        crypto::async_sign(executor, *made, crypto::ecdsa_sha256, message, counted);
        deliver();
    });
    webcpp::test::covered("p256::async_agree moved from on bearssl", "crypto::async_agree", [&] {
        // NOLINTNEXTLINE(bugprone-use-after-move,clang-analyzer-cplusplus.Move): tested
        crypto::async_agree(executor, *made, *key, counted);
        deliver();
    });
    webcpp::test::covered("p256::basic_keypair::async_sign moved from on bearssl", [&] {
        // NOLINTNEXTLINE(bugprone-use-after-move,clang-analyzer-cplusplus.Move): tested
        made->async_sign(executor, crypto::ecdsa_sha256, message, counted);
        deliver();
    });
    webcpp::test::covered("p256::basic_keypair::async_agree moved from on bearssl", [&] {
        // NOLINTNEXTLINE(bugprone-use-after-move,clang-analyzer-cplusplus.Move): tested
        made->async_agree(executor, *key, counted);
        deliver();
    });
    BOOST_TEST_EQ(completions, 22);
}

}  // namespace

int main() {
    cover_ciphers();
    cover_p256_keys();
    cover_p256_keypair_moves();
    cover_p256_ecdsa();
    cover_p256_ecdh();
    cover_p256_formats();
    cover_async_p256();
    return webcpp::test::exit_status(boost::report_errors());
}
