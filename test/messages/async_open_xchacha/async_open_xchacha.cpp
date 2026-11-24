// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// secret_key_encryption::aead::async_open of an AEAD WebCrypto lacks, XChaCha20-Poly1305, on a
// backend that completes by itself (a stand-in whose detail::asynchronous_backend_v is true), stops
// with the refusal that sends it to a native backend (design D6), and with that error alone: it
// fires before any member of the AEAD is named (ruling P12). The object is a parameter, since
// making one would run the stand-in's engine.

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so each
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/crypto/detail/asynchronous.hpp:* {{webcpp::crypto: WebCrypto has no ChaCha20-Poly1305, XChaCha20-Poly1305, secret box or crypto_box: no form of them, synchronous or asynchronous, runs on the browser's backend; name a native backend for them. On the browser's backend only AES-GCM seals and opens.}}
// clang-format on
#include <webcpp/crypto/async.hpp>
#include <webcpp/crypto/ciphers/chacha20_poly1305.hpp>

#include <webcpp/asio/io_context.hpp>

#include <boost/system/error_code.hpp>

#include <array>
#include <cstdint>

namespace {

/** A backend that completes by itself, as part B's browser backend will. */
struct stand_in_browser {};

}  // namespace

template <>
inline constexpr bool webcpp::crypto::detail::asynchronous_backend_v<stand_in_browser> = true;

/** XChaCha20-Poly1305 on the stand-in. */
using stand_in_xchacha = webcpp::crypto::ciphers::xchacha20_poly1305<stand_in_browser>;

namespace {

/** Opens asynchronously with an object of the stand-in's. */
void opened(stand_in_xchacha& cipher) {
    std::array<std::uint8_t, 24> const nonce{};
    std::array<std::uint8_t, 5> data{'h', 'e', 'l', 'l', 'o'};
    std::array<std::uint8_t, 16> const tag{};
    webcpp::asio::io_context context;
    webcpp::crypto::secret_key_encryption::aead::async_open(
        context.get_executor(), cipher, nonce, {}, data, tag, [](boost::system::error_code) {});
}

}  // namespace

// The function is compiled, which is the test; it is never run.
int main() {
    static_cast<void>(&opened);
    return 0;
}
