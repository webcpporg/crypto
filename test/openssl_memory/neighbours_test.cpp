// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The option beside its neighbours in the process (spec section 8.5): Boost.Asio's TLS, as
// webcpp::beast's tls uses it, and libdatachannel, as webcpp::webrtc uses it, are linked into
// the program, and the install, main's first statement, succeeds: neither used OpenSSL during
// static initialisation. One symbol of each is kept in a volatile pointer, so that the linker
// keeps their objects and static initialisers; neither is called. Asio's context is never
// constructed, but the function that would construct one is kept too, so that Asio's
// openssl_init instance, which every program that makes a context has, is initialised before
// main. Then one gcm is made and sealed, so that blocks exist, and after main OpenSSL's
// cleanup gives every block back (support.hpp's exit).
// rtcInitLogger alone brings in libdatachannel's static initialisers: its object, the C
// API's, names the rest of the library, so the linker takes 37 objects of libdatachannel.a,
// among them 21 of the 28 that have static initialisers, every one that names an OpenSSL
// function (certificate, dtlstransport, dtlssrtptransport) included; the 7 left out
// (the RTP depacketizers, the pacing handler, and the TLS and WebSocket transports, empty
// without WebSocket) name none. libjuice and usrsctp have none. Measured with the linker's
// map on macOS and on Linux (libdatachannel 0.24.6, 2026-11-17), so R15's fallback,
// rtc::InitLogger's address, is not needed.

#include "support.hpp"

#include <webcpp/asio/ssl.hpp>
#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/crypto/ciphers/gcm.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>

#include <rtc/rtc.h>

#include <array>
#include <cstdint>

namespace {

namespace ssl = webcpp::asio::ssl;

// Makes the context Beast's TLS would make; never called, only kept.
SSL_CTX* make_context() {
    ssl::context context(ssl::context::tls_client);
    return context.native_handle();
}

// The kept symbols: the linker keeps what they name, and nothing calls them.
// NOLINTBEGIN(cppcoreguidelines-avoid-non-const-global-variables): kept for the linker
auto volatile asio_symbol = &ssl::context::native_handle;
auto volatile asio_constructor = &make_context;
auto volatile libdatachannel_symbol = &rtcInitLogger;
// NOLINTEND(cppcoreguidelines-avoid-non-const-global-variables)

}  // namespace

int main() {
    namespace crypto = webcpp::crypto;
    if (!BOOST_TEST(crypto::backends::openssl::install_memory_functions().has_value())) {
        return webcpp::test::exit_status(boost::report_errors());
    }
    BOOST_TEST(asio_symbol != nullptr);
    BOOST_TEST(asio_constructor != nullptr);
    BOOST_TEST(libdatachannel_symbol != nullptr);
    {
        using aead = crypto::ciphers::gcm<crypto::ciphers::aes256<crypto::backends::openssl>>;
        std::array<std::uint8_t, 32> const key{};
        auto made = aead::from_key(key);
        BOOST_TEST(made.has_value());
        if (made.has_value()) {
            std::array<std::uint8_t, 12> const iv{};
            std::array<std::uint8_t, 64> data{};
            BOOST_TEST(made->seal(iv, {}, data).has_value());
        }
    }
    BOOST_TEST_NE(webcpp::test::the_counting_resource().allocations(), 0U);
    BOOST_TEST(!webcpp::test::the_counting_resource().foreign_free());
    if (int const errors = boost::report_errors(); errors != 0) {
        return webcpp::test::exit_status(errors);
    }
    webcpp::test::the_counting_resource().main_returned();
    return 3;  // the resource ends the process with 0 once OpenSSL has freed everything
}
