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
// - P-256, curves::p256: basic_keypair::make, generate; basic_public_key::make (both); not
//   guarded (no BearSSL call): public_key, secret_scalar, uncompressed.

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

}  // namespace

int main() {
    cover_ciphers();
    cover_p256_keys();
    return webcpp::test::exit_status(boost::report_errors());
}
