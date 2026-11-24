// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// What a program that still calls crypto::async_seal and crypto::async_open as it did sees (design
// D11): each call stops the build, although async.hpp, which brings
// secret_key_encryption::aead::async_seal and async_open, is included. clang offers the box forms,
// secret_key_encryption::async_seal and async_open, whose arity is one less, and the corrected call
// adds its own error: those four errors alone. The object is a parameter: the calls are compiled,
// never run.

#include <webcpp/crypto/async.hpp>
#include <webcpp/crypto/ciphers/aes256_gcm.hpp>

#include <webcpp/asio/io_context.hpp>

#include <boost/hash2/digest.hpp>
#include <boost/system/error_code.hpp>

#include <array>
#include <cstdint>

namespace {

/** Seals and opens asynchronously through the removed free forms. */
void sealed_and_opened(webcpp::crypto::ciphers::aes256_gcm& cipher) {
    std::array<std::uint8_t, 12> const nonce{};
    std::array<std::uint8_t, 3> const associated_data{1, 2, 3};
    std::array<std::uint8_t, 5> data{'h', 'e', 'l', 'l', 'o'};
    std::array<std::uint8_t, 16> const tag{};
    webcpp::asio::io_context context;
    auto const executor = context.get_executor();
    // clang-format off
    // expected-error@+3 {{no member named 'async_seal' in namespace 'webcpp::crypto'; did you mean 'webcpp::crypto::secret_key_encryption::async_seal'?}}
    // expected-error@+2 {{no matching function for call to 'async_seal'}} (knock-on)
    // clang-format on
    webcpp::crypto::async_seal(executor, cipher, nonce, associated_data, data,
                               [](boost::system::error_code, boost::hash2::digest<16>) {});
    // clang-format off
    // expected-error@+3 {{no member named 'async_open' in namespace 'webcpp::crypto'; did you mean 'webcpp::crypto::secret_key_encryption::async_open'?}}
    // expected-error@+2 {{no matching function for call to 'async_open'}} (knock-on)
    // clang-format on
    webcpp::crypto::async_open(executor, cipher, nonce, associated_data, data, tag,
                               [](boost::system::error_code) {});
}

}  // namespace

// The function is compiled, which is the test; it is never run.
int main() {
    static_cast<void>(&sealed_and_opened);
    return 0;
}
