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
//   assignment (ruling R3), seal, open, begin_seal, update, result.
// - ChaCha20-Poly1305, aead: make, seal, open.
// - P-256, curves::p256: basic_keypair::make, generate, sign_ecdsa; basic_public_key::make
//   (both); verify_ecdsa, to_der, from_der; not guarded (no BearSSL call): public_key,
//   secret_scalar, uncompressed, and normalize_ecdsa and check_low_s, which test/timing_test.cpp
//   calls without a backend.

#include "support/timing_seam.hpp"

#include <webcpp/crypto/backends/bearssl.hpp>
#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/crypto/ciphers/chacha20_poly1305.hpp>
#include <webcpp/crypto/ciphers/gcm.hpp>
#include <webcpp/crypto/curves/p256.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/p256_data.hpp"
#include "support/timing_coverage.hpp"

#include <boost/core/lightweight_test.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <span>

namespace {

namespace crypto = webcpp::crypto;
using crypto::backends::bearssl;

// The ciphers: AES-GCM and ChaCha20-Poly1305.
void cover_ciphers() {
    webcpp::test::cover_gcm<crypto::ciphers::gcm<crypto::ciphers::aes128<bearssl>>>("aes128_gcm",
                                                                                    "bearssl");
    webcpp::test::cover_gcm<crypto::ciphers::gcm<crypto::ciphers::aes192<bearssl>>>("aes192_gcm",
                                                                                    "bearssl");
    webcpp::test::cover_gcm<crypto::ciphers::gcm<crypto::ciphers::aes256<bearssl>>>("aes256_gcm",
                                                                                    "bearssl");
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

// P-256's ECDSA: the signature, its verification, and DER both ways, each refused once before
// BearSSL (an r of 0, a short buffer, an empty DER).
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

}  // namespace

int main() {
    cover_ciphers();
    cover_p256_keys();
    cover_p256_ecdsa();
    return webcpp::test::exit_status(boost::report_errors());
}
