// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// <webcpp/crypto.hpp> in a program that links OpenSSL alone while BearSSL is the default (here
// selected by WEBCPP_CRYPTO_DEFAULT_BACKEND_BEARSSL, as WebAssembly's default is): the header
// leaves out aes256_gcm.hpp, whose default backend is not linked, and the program seals with
// the type that names OpenSSL.

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
