// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The convenience header with no backend linked compiles, links and runs (spec section 2.1): this
// program includes <webcpp/crypto.hpp> alone, names no backend, links none, and calls equal and
// erase_secret. The headers whose families name a default backend it does not link are there all
// the same: P-256's key pair names BearSSL. The convenience header leaves the asynchronous family
// out: <webcpp/crypto/async.hpp> needs webcpp::asio, which the program would then link.

#include <webcpp/crypto.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>
#include <boost/hash2/digest.hpp>

#include <array>
#include <cstdint>
#include <type_traits>

#if defined(WEBCPP_CRYPTO_HAS_BEARSSL) || defined(WEBCPP_CRYPTO_HAS_OPENSSL) || \
    defined(WEBCPP_CRYPTO_HAS_CTAES) || defined(WEBCPP_CRYPTO_HAS_SECP256K1) || \
    defined(WEBCPP_CRYPTO_HAS_SODIUM)
#error "this program links no backend: its project must not name one"
#endif

#ifdef WEBCPP_CRYPTO_ASYNC_HPP
#error "<webcpp/crypto.hpp> must not include <webcpp/crypto/async.hpp>, which needs webcpp::asio"
#endif

// curves/p256.hpp is included, and its key pair names its default, BearSSL, which is not linked.
static_assert(std::is_same_v<webcpp::crypto::curves::p256::keypair::backend_type,
                             webcpp::crypto::backends::bearssl>);
static_assert(webcpp::crypto::supports_v<webcpp::crypto::curves::p256::keypair,
                                         webcpp::crypto::backends::bearssl>);
// curves/p256/formats.hpp is included with it.
static_assert(webcpp::crypto::curves::p256::max_pkcs8_size == 138);
// signing.hpp is included: the scheme tags and the concepts.
static_assert(
    std::is_same_v<decltype(webcpp::crypto::ecdsa_sha256), webcpp::crypto::ecdsa_sha256_t const>);

int main() {
    std::array<std::uint8_t, 16> const zero{};
    std::array<std::uint8_t, 16> other{};
    other.back() = 1;
    BOOST_TEST(webcpp::crypto::equal(zero, zero));
    BOOST_TEST(!webcpp::crypto::equal(zero, other));
    boost::hash2::digest<16> const digest{};
    BOOST_TEST(webcpp::crypto::equal(digest, digest));
    webcpp::crypto::erase_secret(other);
    BOOST_TEST(webcpp::crypto::equal(zero, other));
    return webcpp::test::exit_status(boost::report_errors());
}
