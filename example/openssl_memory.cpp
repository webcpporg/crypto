// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Sends every allocation of OpenSSL's to the program's own memory resource, natively, then seals
// and opens one block with AES-256-GCM on OpenSSL, on a worker thread as an audio engine's or a
// server's would. Built with WEBCPP_CRYPTO_OPENSSL_MEMORY_RESOURCE, /webcpp/crypto//openssl and
// threads (example/Jamfile).
// tag::program[]
#include <webcpp/crypto/backends/openssl.hpp>
#include <webcpp/crypto/ciphers/aes256_gcm.hpp>

#include <openssl/crypto.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <memory_resource>
#include <string>
#include <thread>

namespace crypto = webcpp::crypto;

// tag::resource[]
// Declared by crypto under WEBCPP_CRYPTO_OPENSSL_MEMORY_RESOURCE, defined once by the program.
// Never destroyed: OpenSSL frees through it after main returns. The synchronized pool serves
// OpenSSL on any thread.
std::pmr::memory_resource& webcpp::crypto::openssl_memory_resource() noexcept {
    // Never deleted, on purpose; a new that fails this early ends the program, which has no
    // resource for OpenSSL.
    // NOLINTNEXTLINE(cppcoreguidelines-owning-memory,bugprone-unhandled-exception-at-new)
    static auto* const resource = new std::pmr::synchronized_pool_resource;
    return *resource;
}

// end::resource[]
int main() {
    // tag::install[]
    // The first statement of main: before any thread starts and before anything uses OpenSSL.
    auto const installed = crypto::backends::openssl::install_memory_functions();
    if (!installed) {
        std::string const message = installed.error().message();
        std::printf("install: %s\n", message.c_str());
        return 1;
    }
    // end::install[]

    bool ok = false;
    std::thread worker([&ok] {
        // A zero key and IV keep the output stable: a real program draws its key from
        // random_device and never reuses an IV under it.
        std::array<std::uint8_t, 32> const key{};
        std::array<std::uint8_t, 12> const iv{};
        std::array<std::uint8_t, 16> data{};
        {
            auto aead = crypto::ciphers::aes256_gcm::from_key(key);
            if (aead) {
                auto const tag = aead->seal(iv, {}, data);
                ok =
                    tag && aead->open(iv, {}, data, *tag) && data == std::array<std::uint8_t, 16>{};
            } else {
                std::string const message = aead.error().message();
                std::printf("from_key: %s\n", message.c_str());
            }
        }
        // tag::thread[]
        // The thread's last call into OpenSSL, on every path: it gives the thread's own blocks back
        // to the resource now. On Windows, whose static libcrypto is never told that a thread ends,
        // they would otherwise stay in the resource until the process ends.
        OPENSSL_thread_stop();
        // end::thread[]
    });
    worker.join();
    auto const name = crypto::ciphers::aes256_gcm::backend_type::name;
    std::printf("aes256_gcm %s backend=%.*s\n", ok ? "ok" : "FAILED", static_cast<int>(name.size()),
                name.data());
    return ok ? 0 : 1;
}

// end::program[]
