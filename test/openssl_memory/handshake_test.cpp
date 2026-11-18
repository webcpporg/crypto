// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A TLS 1.3 handshake through libssl under the option (spec section 8.5): installed first, the
// configuration file not read, libssl and the C library's gmtime started; a server whose P-256 key
// and self-signed certificate are made at run time and a client that does not verify, in one
// process over a pair of memory BIOs, which stand for the spec's loopback socket (libssl allocates
// the same, and no socket is needed); both stepped with SSL_do_handshake until both finish, one
// application record each way, then everything freed. From the key to the last free the C library's
// allocator is never called (the interposer); no foreign block is freed through the adapter; and
// after main OpenSSL's cleanup gives every block back (support.hpp's exit).

#include "support.hpp"

#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <array>
#include <ctime>
#include <memory>
#include <string_view>
#include <utility>

namespace {

// OpenSSL's objects, each freed by its own function.
struct free_key {
    void operator()(EVP_PKEY* key) const noexcept { EVP_PKEY_free(key); }
};

struct free_certificate {
    void operator()(X509* certificate) const noexcept { X509_free(certificate); }
};

struct free_context {
    void operator()(SSL_CTX* context) const noexcept { SSL_CTX_free(context); }
};

struct free_connection {
    void operator()(SSL* connection) const noexcept { SSL_free(connection); }
};

using key_ptr = std::unique_ptr<EVP_PKEY, free_key>;
using certificate_ptr = std::unique_ptr<X509, free_certificate>;
using context_ptr = std::unique_ptr<SSL_CTX, free_context>;
using connection_ptr = std::unique_ptr<SSL, free_connection>;

// A P-256 key, made at run time.
key_ptr make_key() {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg): the curve's name is a variadic argument.
    return key_ptr(EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-256"));
}

// A certificate for key, signed by key itself, valid for an hour from now.
certificate_ptr make_certificate(EVP_PKEY* key) {
    certificate_ptr certificate(X509_new());
    if (!certificate) {
        return certificate;
    }
    X509* const raw = certificate.get();
    X509_NAME* const name = X509_get_subject_name(raw);
    constexpr std::array<unsigned char, 9> common_name{'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't'};
    // NOLINTNEXTLINE(bugprone-signed-bitwise): OpenSSL's macro ORs signed flags
    constexpr int ascii = MBSTRING_ASC;
    bool const made =
        X509_set_version(raw, X509_VERSION_3) == 1 &&
        ASN1_INTEGER_set(X509_get_serialNumber(raw), 1) == 1 &&
        X509_gmtime_adj(X509_getm_notBefore(raw), 0) != nullptr &&
        X509_gmtime_adj(X509_getm_notAfter(raw), 3600) != nullptr &&
        X509_NAME_add_entry_by_txt(name, "CN", ascii, common_name.data(),
                                   static_cast<int>(common_name.size()), -1, 0) == 1 &&
        X509_set_issuer_name(raw, name) == 1 && X509_set_pubkey(raw, key) == 1 &&
        X509_sign(raw, key, EVP_sha256()) > 0;
    if (!made) {
        certificate.reset();
    }
    return certificate;
}

// A TLS 1.3-only context: the server's with key and certificate, the client's not verifying.
context_ptr make_context(bool is_server, EVP_PKEY* key, X509* certificate) {
    context_ptr context(SSL_CTX_new(is_server ? TLS_server_method() : TLS_client_method()));
    if (!context) {
        return context;
    }
    bool made = SSL_CTX_set_min_proto_version(context.get(), TLS1_3_VERSION) == 1;
    if (is_server) {
        made = made && SSL_CTX_use_certificate(context.get(), certificate) == 1 &&
               SSL_CTX_use_PrivateKey(context.get(), key) == 1;
    } else {
        SSL_CTX_set_verify(context.get(), SSL_VERIFY_NONE, nullptr);
    }
    if (!made) {
        context.reset();
    }
    return context;
}

// Whether a step of connection may go on: it finished, or it waits for the other side.
bool goes_on(SSL const* connection, int result) {
    if (result == 1) {
        return true;
    }
    int const reason = SSL_get_error(connection, result);
    return reason == SSL_ERROR_WANT_READ || reason == SSL_ERROR_WANT_WRITE;
}

// Steps both sides until both finished; false when either fails or neither finishes.
bool handshake(SSL* client, SSL* server) {
    constexpr int most_steps = 16;
    for (int step = 0; step != most_steps; ++step) {
        int const by_client = SSL_do_handshake(client);
        if (!goes_on(client, by_client)) {
            return false;
        }
        int const by_server = SSL_do_handshake(server);
        if (!goes_on(server, by_server)) {
            return false;
        }
        if (by_client == 1 && by_server == 1) {
            return true;
        }
    }
    return false;
}

// Sends one application record from one side and reads it on the other.
bool record(SSL* from, SSL* to, std::string_view text) {
    if (!std::cmp_equal(SSL_write(from, text.data(), static_cast<int>(text.size())), text.size())) {
        return false;
    }
    std::array<char, 16> received{};
    int const read = SSL_read(to, received.data(), static_cast<int>(received.size()));
    return std::cmp_equal(read, text.size()) &&
           std::string_view(received.data(), text.size()) == text;
}

// The whole exchange: key, certificate, contexts, connections over a pair of memory BIOs, the
// handshake and a record each way; everything is freed on return.
void exchange() {
    key_ptr const key = make_key();
    if (!BOOST_TEST(key != nullptr)) {
        return;
    }
    certificate_ptr const certificate = make_certificate(key.get());
    context_ptr const server_context = make_context(true, key.get(), certificate.get());
    context_ptr const client_context = make_context(false, nullptr, nullptr);
    if (!BOOST_TEST(certificate != nullptr) || !BOOST_TEST(server_context != nullptr) ||
        !BOOST_TEST(client_context != nullptr)) {
        return;
    }
    connection_ptr const server(SSL_new(server_context.get()));
    connection_ptr const client(SSL_new(client_context.get()));
    if (!BOOST_TEST(server != nullptr) || !BOOST_TEST(client != nullptr)) {
        return;
    }
    BIO* client_end = nullptr;
    BIO* server_end = nullptr;
    if (!BOOST_TEST_EQ(BIO_new_bio_pair(&client_end, 0, &server_end, 0), 1)) {
        return;
    }
    // Each connection owns its end of the pair from here on, and frees it.
    SSL_set_bio(client.get(), client_end, client_end);
    SSL_set_bio(server.get(), server_end, server_end);
    SSL_set_connect_state(client.get());
    SSL_set_accept_state(server.get());
    if (!BOOST_TEST(handshake(client.get(), server.get()))) {
        return;
    }
    BOOST_TEST_EQ(SSL_version(client.get()), TLS1_3_VERSION);
    BOOST_TEST_EQ(SSL_version(server.get()), TLS1_3_VERSION);
    BOOST_TEST(record(client.get(), server.get(), "from the client"));
    BOOST_TEST(record(server.get(), client.get(), "from the server"));
}

}  // namespace

int main() {
    if (!BOOST_TEST(webcpp::crypto::backends::openssl::install_memory_functions().has_value())) {
        return webcpp::test::exit_status(boost::report_errors());
    }
    webcpp::test::say_whether_c_is_counted();
    // Three things make the C library allocate once per process, outside every hook of
    // OpenSSL's, so they are done here, before counting. The configuration file: its FILE and
    // buffer (spec section 3.7); it is not read.
    BOOST_TEST_EQ(OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, nullptr), 1);
    // libssl's start-up, which sorts its cipher table with the C library's qsort; glibc's takes
    // its scratch block from malloc (measured on Debian 13: one malloc and one free).
    BOOST_TEST_EQ(OPENSSL_init_ssl(OPENSSL_INIT_NO_LOAD_CONFIG, nullptr), 1);
    // The C library's gmtime, which OpenSSL calls for a certificate's dates: its first call
    // loads the time zone data, and on macOS its thread's buffer (measured on macOS: 80 calls
    // of the C library's allocator).
    std::time_t const now = std::time(nullptr);
    std::tm calendar{};
    BOOST_TEST(OPENSSL_gmtime(&now, &calendar) != nullptr);
    webcpp_test_count_c_allocations(1);
    exchange();
    webcpp_test_count_c_allocations(0);
    BOOST_TEST_EQ(webcpp_test_c_allocations(), 0U);
    BOOST_TEST_NE(webcpp::test::the_counting_resource().allocations(), 0U);
    BOOST_TEST(!webcpp::test::the_counting_resource().foreign_free());
    if (int const errors = boost::report_errors(); errors != 0) {
        return webcpp::test::exit_status(errors);
    }
    webcpp::test::the_counting_resource().main_returned();
    return 3;  // the resource ends the process with 0 once OpenSSL has freed everything
}
