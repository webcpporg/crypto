// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// crypto::async_from_key of an AEAD WebCrypto lacks, XChaCha20-Poly1305, on a backend that
// completes by itself (a stand-in whose detail::asynchronous_backend_v is true), stops where it is
// called (design D6): on MSVC the compile fails. The text is checked on clang, in
// test/messages/async_from_key_xchacha.
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

/** Makes an object of the stand-in's asynchronously. */
void made() {
    std::array<std::uint8_t, 32> const key{};
    webcpp::asio::io_context context;
    webcpp::crypto::async_from_key<stand_in_xchacha>(
        context.get_executor(), key, [](boost::system::error_code, stand_in_xchacha) {});
}

}  // namespace

// The function is compiled, which is the test; it is never run.
int main() {
    static_cast<void>(&made);
    return 0;
}
