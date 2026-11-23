// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A coroutine on an event loop makes an Ed25519 key pair from RFC 8032's second test seed (a
// published seed, never a real key), signs the test's message with crypto::eddsa, and verifies
// the signature with the public key alone, each step a co_await of an asynchronous function with
// use_awaitable. The coroutine ends, and the loop with it, when the last completion has run:
// nothing waits for a time.
// tag::program[]
#include <webcpp/crypto/async.hpp>
#include <webcpp/crypto/curves/ed25519.hpp>

#include <webcpp/asio/as_tuple.hpp>
#include <webcpp/asio/awaitable.hpp>
#include <webcpp/asio/co_spawn.hpp>
#include <webcpp/asio/io_context.hpp>
#include <webcpp/asio/this_coro.hpp>
#include <webcpp/asio/use_awaitable.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <span>

namespace asio = webcpp::asio;
namespace crypto = webcpp::crypto;
namespace ed25519 = webcpp::crypto::curves::ed25519;

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

// Each co_await completes through the loop; the key pair and the message are the coroutine's own,
// alive until it ends, as the functions ask.
asio::awaitable<bool> sign_and_verify() {
    // RFC 8032 section 7.1, TEST 2: a published seed, never a real key.
    std::array<std::uint8_t, 32> const seed{
        0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3,
        0x46, 0xec, 0x11, 0x4e, 0x0f, 0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab,
        0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb,
    };
    std::array<std::uint8_t, 1> const message{0x72};
    auto const executor = co_await asio::this_coro::executor;
    auto const use = asio::as_tuple(asio::use_awaitable);

    auto made_result = co_await crypto::async_from_secret<ed25519::keypair>(executor, seed, use);

    auto& [made, key] = made_result;
    if (made) {
        std::printf("from_secret: %s\n", made.message().c_str());
        co_return false;
    }
    auto const public_key = key.public_key();
    if (!public_key) {
        auto const public_key_error = public_key.error();
        std::printf("public key: %s\n", public_key_error.message().c_str());
        co_return false;
    }
    auto [signed_code, signature] =
        co_await crypto::async_sign(executor, key, crypto::eddsa, message, use);
    if (signed_code) {
        std::printf("sign: %s\n", signed_code.message().c_str());
        co_return false;
    }
    print("public key", public_key->bytes());
    print("signature ", signature);
    // The verifier holds the public key, the message and the signature; nothing secret.
    auto [verified] = co_await crypto::async_verify(executor, crypto::eddsa, signature, message,
                                                    *public_key, use);
    if (verified) {
        std::printf("verify: %s\n", verified.message().c_str());
        co_return false;
    }
    co_return true;
}

}  // namespace

int main() {
    asio::io_context loop;
    bool ok = false;
    asio::co_spawn(loop, sign_and_verify(), [&](std::exception_ptr const& failure, bool result) {
        ok = !failure && result;
    });
    loop.run();  // lint-run: the program's event loop
    std::printf(ok ? "verified\n" : "failed\n");
    return ok ? 0 : 1;
}

// end::program[]
