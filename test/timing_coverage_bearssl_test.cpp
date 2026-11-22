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
// - AES-GCM, gcm<aes128>, gcm<aes192> and gcm<aes256>: make, the move constructor and move
//   assignment (ruling R3), seal, open, begin_seal, update, result, and the asynchronous
//   async_make, async_seal and async_open.
// - ChaCha20-Poly1305, aead: make, seal, open.
// - P-256, curves::p256: basic_keypair::make, generate, sign_ecdsa, ecdh_x;
//   basic_public_key::make (both); verify_ecdsa, to_der, from_der; decode_spki, decode_pkcs8; not
//   guarded (no BearSSL call): public_key, secret_scalar, uncompressed, encode_spki, encode_pkcs8,
//   basic_keypair's move constructor and move assignment, and normalize_ecdsa and check_low_s,
//   which test/timing_test.cpp calls without a backend; and the asynchronous async_make,
//   async_generate, async_sign, async_verify and async_agree, all but async_generate (which takes
//   no input) also refused once before BearSSL.

#include "support/timing_seam.hpp"

#include <webcpp/crypto/async.hpp>
#include <webcpp/crypto/backends/bearssl.hpp>
#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/crypto/ciphers/chacha20_poly1305.hpp>
#include <webcpp/crypto/ciphers/gcm.hpp>
#include <webcpp/crypto/curves/p256.hpp>
#include <webcpp/crypto/curves/p256/formats.hpp>
#include <webcpp/crypto/error.hpp>
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

// P-256: the key pair's make and generate, the public key's two make, each refused once before
// BearSSL; the functions that copy what the key pair holds enter no guard.
void cover_p256_keys() {
    namespace p256 = crypto::curves::p256;
    namespace data = webcpp::test::p256;
    using keypair = p256::basic_keypair<bearssl>;
    using public_key = p256::basic_public_key<bearssl>;
    webcpp::test::covered("p256::basic_keypair::make on bearssl",
                          [] { BOOST_TEST(keypair::make(data::rfc6979_scalar).has_value()); });
    webcpp::test::covered("p256::basic_keypair::make of the order on bearssl", [] {
        BOOST_TEST(keypair::make(data::order).error() == crypto::error::invalid_secret_key);
    });
    webcpp::test::covered("p256::basic_keypair::generate on bearssl",
                          [] { BOOST_TEST(keypair::generate().has_value()); });
    std::span<std::uint8_t const, 65> const point(data::rfc6979_public);
    webcpp::test::covered("p256::basic_public_key::make of a point on bearssl",
                          "basic_public_key::make",
                          [point] { BOOST_TEST(public_key::make(point).has_value()); });
    webcpp::test::covered(
        "p256::basic_public_key::make of coordinates on bearssl", "basic_public_key::make",
        [point] {
            BOOST_TEST(
                public_key::make(point.subspan<1, 32>(), point.subspan<33, 32>()).has_value());
        });
    webcpp::test::covered("p256::basic_public_key::make of 64 bytes on bearssl",
                          "basic_public_key::make", [point] {
                              BOOST_TEST(public_key::make(point.first(64)).error() ==
                                         crypto::error::invalid_public_key);
                          });
    auto const made = keypair::make(data::rfc6979_scalar);
    if (!BOOST_TEST(made.has_value())) {
        return;
    }
    webcpp::test::uncovered("p256::basic_keypair::public_key on bearssl",
                            [&made] { BOOST_TEST(made->public_key().has_value()); });
    webcpp::test::uncovered("p256::basic_keypair::secret_scalar on bearssl",
                            [&made] { BOOST_TEST(made->secret_scalar().has_value()); });
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
    auto mover = keypair::make(data::rfc6979_scalar);
    if (BOOST_TEST(mover.has_value())) {
        webcpp::test::uncovered("p256::basic_keypair move constructor on bearssl", [&mover] {
            keypair const taken = std::move(*mover);
            BOOST_TEST(taken.public_key().has_value());
        });
    }
    auto target = keypair::make(data::rfc6979_scalar);
    auto source = keypair::make(data::rfc6979_scalar);
    if (BOOST_TEST(target.has_value()) && BOOST_TEST(source.has_value())) {
        webcpp::test::uncovered("p256::basic_keypair move assignment on bearssl",
                                [&target, &source] {
                                    *target = std::move(*source);
                                    BOOST_TEST(target->public_key().has_value());
                                });
    }
}

// P-256's sign_ecdsa on a moved-from key pair: refused with invalid_state before BearSSL, inside
// its own guard.
void cover_p256_sign_moved_from(std::span<std::uint8_t const, 32> digest) {
    namespace p256 = crypto::curves::p256;
    namespace data = webcpp::test::p256;
    using keypair = p256::basic_keypair<bearssl>;
    auto source = keypair::make(data::rfc6979_scalar);
    if (BOOST_TEST(source.has_value())) {
        keypair const taken = std::move(*source);
        webcpp::test::covered(
            "p256::basic_keypair::sign_ecdsa moved from on bearssl", [&source, &digest] {
                // NOLINTNEXTLINE(bugprone-use-after-move,clang-analyzer-cplusplus.Move): tested
                BOOST_TEST(source->sign_ecdsa(digest).error() == crypto::error::invalid_state);
            });
    }
}

// P-256's ECDSA: the signature, its verification, and DER both ways, each refused once before
// BearSSL (a moved-from key pair, an r of 0, a short buffer, an empty DER).
void cover_p256_ecdsa() {
    namespace p256 = crypto::curves::p256;
    namespace data = webcpp::test::p256;
    using keypair = p256::basic_keypair<bearssl>;
    using public_key = p256::basic_public_key<bearssl>;
    auto const made = keypair::make(data::rfc6979_scalar);
    auto const key = public_key::make(data::rfc6979_public);
    if (!BOOST_TEST(made.has_value()) || !BOOST_TEST(key.has_value())) {
        return;
    }
    // SHA-256 of "test" (RFC 6979, section A.2.5), whose signature is data::rfc6979_test.
    std::array<std::uint8_t, 32> const digest{
        0x9f, 0x86, 0xd0, 0x81, 0x88, 0x4c, 0x7d, 0x65, 0x9a, 0x2f, 0xea,
        0xa0, 0xc5, 0x5a, 0xd0, 0x15, 0xa3, 0xbf, 0x4f, 0x1b, 0x2b, 0x0b,
        0x82, 0x2c, 0xd1, 0x5d, 0x6c, 0x15, 0xb0, 0xf0, 0x0a, 0x08,
    };
    webcpp::test::covered("p256::basic_keypair::sign_ecdsa on bearssl", [&made, &digest] {
        auto const signature = made->sign_ecdsa(digest);
        BOOST_TEST(signature.has_value() && *signature == data::rfc6979_test);
    });
    cover_p256_sign_moved_from(digest);
    webcpp::test::covered("p256::verify_ecdsa on bearssl", [&key, &digest] {
        BOOST_TEST(p256::verify_ecdsa(data::rfc6979_test, digest, *key).has_value());
    });
    auto zero_r = data::rfc6979_test;
    std::fill_n(zero_r.begin(), 32, std::uint8_t{0});
    webcpp::test::covered("p256::verify_ecdsa of r = 0 on bearssl", [&key, &digest, &zero_r] {
        BOOST_TEST(p256::verify_ecdsa(zero_r, digest, *key).error() ==
                   crypto::error::invalid_signature);
    });
    std::array<std::uint8_t, p256::max_der_size> der{};
    webcpp::test::covered("p256::to_der on bearssl", [&der] {
        BOOST_TEST(p256::to_der<bearssl>(data::rfc6979_test, der).has_value());
    });
    webcpp::test::covered("p256::to_der into 71 bytes on bearssl", [&der] {
        BOOST_TEST(p256::to_der<bearssl>(data::rfc6979_test, std::span(der).first(71)).error() ==
                   crypto::error::invalid_input_size);
    });
    auto const encoded = p256::to_der<bearssl>(data::rfc6979_test, der);
    if (!BOOST_TEST(encoded.has_value())) {
        return;
    }
    webcpp::test::covered("p256::from_der on bearssl", [&der, &encoded] {
        auto const decoded = p256::from_der<bearssl>(std::span(der).first(*encoded));
        BOOST_TEST(decoded.has_value() && *decoded == data::rfc6979_test);
    });
    webcpp::test::covered("p256::from_der of nothing on bearssl", [] {
        BOOST_TEST(p256::from_der<bearssl>({}).error() == crypto::error::invalid_signature);
    });
}

// P-256's ECDH: the shared x of RFC 6979's key with its own public key, and the same call on a
// moved-from key pair, refused with invalid_state before BearSSL, inside its own guard.
void cover_p256_ecdh() {
    namespace p256 = crypto::curves::p256;
    namespace data = webcpp::test::p256;
    using keypair = p256::basic_keypair<bearssl>;
    using public_key = p256::basic_public_key<bearssl>;
    auto made = keypair::make(data::rfc6979_scalar);
    auto const peer = public_key::make(data::rfc6979_public);
    if (!BOOST_TEST(made.has_value()) || !BOOST_TEST(peer.has_value())) {
        return;
    }
    webcpp::test::covered("p256::basic_keypair::ecdh_x on bearssl",
                          [&made, &peer] { BOOST_TEST(made->ecdh_x(*peer).has_value()); });
    keypair const taken = std::move(*made);
    webcpp::test::covered("p256::basic_keypair::ecdh_x moved from on bearssl", [&made, &peer] {
        // NOLINTNEXTLINE(bugprone-use-after-move,clang-analyzer-cplusplus.Move): tested
        BOOST_TEST(made->ecdh_x(*peer).error() == crypto::error::invalid_state);
    });
}

// P-256's formats: the decoders, with an encoding each and one refused before BearSSL, inside
// their own guards (make's, which they call, is entered after theirs); the encoders copy what the
// key and the key pair hold and enter no guard.
void cover_p256_formats() {
    namespace p256 = crypto::curves::p256;
    namespace data = webcpp::test::p256;
    using keypair = p256::basic_keypair<bearssl>;
    auto const made = keypair::make(data::rfc6979_scalar);
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
// scalar of 31 bytes, a signature of 63 bytes, a moved-from key pair), an io_context run after
// each call so that its completion is delivered. The first guard each enters is its own (the
// synchronous call it makes holds others, which run after).
void cover_async_p256() {
    namespace p256 = crypto::curves::p256;
    namespace data = webcpp::test::p256;
    using keypair = p256::basic_keypair<bearssl>;
    using public_key = p256::basic_public_key<bearssl>;
    using signature_type = std::array<std::uint8_t, p256::signature_size>;
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
    webcpp::test::covered("p256::async_make on bearssl", "crypto::async_make", [&] {
        crypto::async_make<keypair>(executor, data::rfc6979_scalar, counted);
        deliver();
    });
    webcpp::test::covered("p256::async_make with a short scalar on bearssl", "crypto::async_make",
                          [&] {
                              crypto::async_make<keypair>(
                                  executor, std::span(data::rfc6979_scalar).first(31), counted);
                              deliver();
                          });
    webcpp::test::covered("p256::async_generate on bearssl", "crypto::async_generate", [&] {
        crypto::async_generate<keypair>(executor, counted);
        deliver();
    });
    auto made = keypair::make(data::rfc6979_scalar);
    auto const key = public_key::make(data::rfc6979_public);
    if (!BOOST_TEST(made.has_value()) || !BOOST_TEST(key.has_value())) {
        return;
    }
    webcpp::test::covered("p256::async_sign on bearssl", "crypto::async_sign", [&] {
        crypto::async_sign(executor, *made, message, keeping);
        deliver();
    });
    webcpp::test::covered("p256::async_verify on bearssl", "crypto::async_verify", [&] {
        crypto::async_verify(executor, *key, message, kept, counted);
        deliver();
    });
    webcpp::test::covered("p256::async_verify of 63 bytes on bearssl", "crypto::async_verify", [&] {
        crypto::async_verify(executor, *key, message, std::span(kept).first(63), counted);
        deliver();
    });
    webcpp::test::covered("p256::async_agree on bearssl", "crypto::async_agree", [&] {
        crypto::async_agree(executor, *made, *key, counted);
        deliver();
    });
    [[maybe_unused]] keypair const taken(std::move(*made));
    webcpp::test::covered("p256::async_sign moved from on bearssl", "crypto::async_sign", [&] {
        // NOLINTNEXTLINE(bugprone-use-after-move,clang-analyzer-cplusplus.Move): tested
        crypto::async_sign(executor, *made, message, counted);
        deliver();
    });
    webcpp::test::covered("p256::async_agree moved from on bearssl", "crypto::async_agree", [&] {
        // NOLINTNEXTLINE(bugprone-use-after-move,clang-analyzer-cplusplus.Move): tested
        crypto::async_agree(executor, *made, *key, counted);
        deliver();
    });
    BOOST_TEST_EQ(completions, 9);
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
