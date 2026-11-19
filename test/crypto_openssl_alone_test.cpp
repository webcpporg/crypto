// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// <webcpp/crypto.hpp> in a program that links OpenSSL alone: the header compiles on every
// target that builds OpenSSL, aes256_gcm.hpp included, whose default on WASI, BearSSL, is not
// linked and refuses only where it is called, and the program seals with the type that names
// OpenSSL.

#include <webcpp/crypto.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>

#include <array>
#include <cstdint>

#if !defined(WEBCPP_CRYPTO_HAS_OPENSSL) || defined(WEBCPP_CRYPTO_HAS_BEARSSL)
#error "the test links /webcpp/crypto//openssl alone"
#endif

int main() {
    namespace crypto = webcpp::crypto;
    using aead = crypto::ciphers::gcm<crypto::ciphers::aes256<crypto::backends::openssl>>;
    std::array<std::uint8_t, 32> const key{};
    std::array<std::uint8_t, 12> const iv{};
    std::array<std::uint8_t, 16> data{};
    auto made = aead::make(key);
    BOOST_TEST(made && made->seal(iv, {}, data).has_value());
    return webcpp::test::exit_status(boost::report_errors());
}
