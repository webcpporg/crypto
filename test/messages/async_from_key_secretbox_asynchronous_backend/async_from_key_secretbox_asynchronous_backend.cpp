// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// crypto::async_from_key of a secret box, which WebCrypto lacks, on a backend that completes by
// itself (a stand-in whose detail::asynchronous_backend_v is true) stops with the refusal that
// sends it to a native backend (design D6), and with that error alone: it fires before any member
// of the box is named (ruling P12).

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so each
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/crypto/detail/asynchronous.hpp:* {{webcpp::crypto: WebCrypto has no ChaCha20-Poly1305, XChaCha20-Poly1305, secret box or crypto_box: their async_seal, async_open and async_from_key run on a native backend; on the browser's backend only AES-GCM is asynchronous.}}
// clang-format on
#include <webcpp/crypto/async.hpp>
#include <webcpp/crypto/secret_key_encryption/secretbox.hpp>

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

/** A secret box on the stand-in. */
using stand_in_secretbox = webcpp::crypto::secret_key_encryption::secretbox<stand_in_browser>;

namespace {

/** Makes a secret box of the stand-in's asynchronously. */
void made() {
    std::array<std::uint8_t, 32> const key{};
    webcpp::asio::io_context context;
    webcpp::crypto::async_from_key<stand_in_secretbox>(
        context.get_executor(), key, [](boost::system::error_code, stand_in_secretbox) {});
}

}  // namespace

// The function is compiled, which is the test; it is never run.
int main() {
    static_cast<void>(&made);
    return 0;
}
