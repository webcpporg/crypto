// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Makes RFC 6979's P-256 key pair (a published scalar, never a real key), signs "sample" with
// crypto::ecdsa_sha256 and verifies the signature, each operation in its four forms: the member,
// its free form, and the asynchronous member and its free form, which complete through an event
// loop. RFC 6979's nonce makes the four signatures the same bytes, and the four verifications
// agree.
// tag::program[]
#include <webcpp/crypto/async.hpp>
#include <webcpp/crypto/curves/p256.hpp>
#include <webcpp/crypto/make.hpp>
#include <webcpp/crypto/signing.hpp>

#include <webcpp/asio/io_context.hpp>

#include <boost/system/error_code.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <span>
#include <string_view>

namespace asio = webcpp::asio;
namespace crypto = webcpp::crypto;
namespace p256 = webcpp::crypto::curves::p256;

namespace {

// Prints bytes in hex after a name, 32 bytes (64 digits) to a line, the lines after the first
// indented under the first.
void print(char const* name, std::span<std::uint8_t const> bytes) {
    int const indent = std::printf("%s ", name);
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        if (i != 0 && i % 32 == 0) {
            std::printf("\n%*s", indent, "");
        }
        std::printf("%02x", bytes[i]);
    }
    std::printf("\n");
}

// A text's bytes, the message.
std::span<std::uint8_t const> bytes_of(std::string_view text) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): a text's bytes
    return {reinterpret_cast<std::uint8_t const*>(text.data()), text.size()};
}

// Prints a form's verdict: whether its signature is the member's, or whether it verified.
void report(char const* form, bool ok) {
    std::printf("%-22s %s\n", form, ok ? "yes" : "no");
}

}  // namespace

int main() {
    // RFC 6979 section A.2.5's key: a published scalar, never a real key.
    std::array<std::uint8_t, 32> const scalar{
        0xc9, 0xaf, 0xa9, 0xd8, 0x45, 0xba, 0x75, 0x16, 0x6b, 0x5c, 0x21,
        0x57, 0x67, 0xb1, 0xd6, 0x93, 0x4e, 0x50, 0xc3, 0xdb, 0x36, 0xe8,
        0x9b, 0x12, 0x7b, 0x8a, 0x62, 0x2b, 0x12, 0x0f, 0x67, 0x21,
    };
    auto const message = bytes_of("sample");

    // tag::make[]
    // The member and its free form make the same key pair from the same scalar.
    auto const key = p256::keypair::make(scalar);
    auto const same_key = crypto::make<p256::keypair>(scalar);
    // end::make[]
    auto const public_key = key ? key->public_key() : key.error();
    auto const same_public_key = same_key ? same_key->public_key() : same_key.error();
    if (!public_key || !same_public_key) {
        std::printf("failed\n");
        return 1;
    }
    report("make: free = member", public_key->uncompressed() == same_public_key->uncompressed());

    // tag::sign[]
    // Synchronous: the member, and its free form, which calls it.
    auto const signature = key->sign(crypto::ecdsa_sha256, message);
    auto const free_signature = crypto::sign(*key, crypto::ecdsa_sha256, message);

    // Asynchronous: the member, and its free form, which calls it. Each runs the synchronous
    // member when it is initiated and completes through the loop, never inside the call.
    asio::io_context loop;
    auto const executor = loop.get_executor();
    std::array<std::uint8_t, 64> async_signature{};
    std::array<std::uint8_t, 64> free_async_signature{};
    key->async_sign(executor, crypto::ecdsa_sha256, message,
                    [&](boost::system::error_code code, std::array<std::uint8_t, 64> made) {
                        if (!code) {
                            async_signature = made;
                        }
                    });
    crypto::async_sign(executor, *key, crypto::ecdsa_sha256, message,
                       [&](boost::system::error_code code, std::array<std::uint8_t, 64> made) {
                           if (!code) {
                               free_async_signature = made;
                           }
                       });
    loop.run();  // lint-run: the program's event loop
    // end::sign[]
    if (!signature || !free_signature) {
        std::printf("failed\n");
        return 1;
    }
    print("signature", *signature);
    report("sign: free", *free_signature == *signature);
    report("sign: async member", async_signature == *signature);
    report("sign: async free", free_async_signature == *signature);

    // tag::verify[]
    // Synchronous: the public key's member, and its free form, crypto::verify.
    bool const verified = public_key->verify(crypto::ecdsa_sha256, *signature, message).has_value();
    bool const free_verified =
        crypto::verify(crypto::ecdsa_sha256, *signature, message, *public_key).has_value();

    // Asynchronous: the member and its free form complete with the error code alone.
    bool async_verified = false;
    bool free_async_verified = false;
    public_key->async_verify(executor, crypto::ecdsa_sha256, *signature, message,
                             [&](boost::system::error_code code) { async_verified = !code; });
    crypto::async_verify(executor, crypto::ecdsa_sha256, *signature, message, *public_key,
                         [&](boost::system::error_code code) { free_async_verified = !code; });
    loop.restart();
    loop.run();  // lint-run: the program's event loop
    // end::verify[]
    report("verify: member", verified);
    report("verify: free", free_verified);
    report("verify: async member", async_verified);
    report("verify: async free", free_async_verified);

    bool const ok = *free_signature == *signature && async_signature == *signature &&
                    free_async_signature == *signature && verified && free_verified &&
                    async_verified && free_async_verified;
    std::printf(ok ? "the four forms agree\n" : "failed\n");
    return ok ? 0 : 1;
}

// end::program[]
