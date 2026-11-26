// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Seeds BearSSL's own HMAC-DRBG from webcpp::crypto::random_device and draws bytes from it.
// A generator is only as good as its seed: the seed must come from the system's entropy, never
// from the clock or a counter.
// tag::program[]
#include <webcpp/crypto/random_device.hpp>
#include <webcpp/secure/erase_secret.hpp>

#include <bearssl.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <span>

int main() {
    std::array<std::uint8_t, 32> seed{};
    webcpp::crypto::random_device device;
    if (!device.fill(seed)) {
        return 1;
    }

    br_hmac_drbg_context drbg;
    br_hmac_drbg_init(&drbg, &br_sha256_vtable, seed.data(), seed.size());
    // The generator holds what it needs: the seed goes now.
    webcpp::secure::erase_secret(seed);

    std::array<std::uint8_t, 16> bytes{};
    br_hmac_drbg_generate(&drbg, bytes.data(), bytes.size());
    // The bytes are random, so the program never prints them.
    // The generator's state predicts its next outputs: wipe it, and what it gave, after use.
    webcpp::secure::erase_secret(std::span(&drbg, 1));
    webcpp::secure::erase_secret(bytes);
    std::printf("seeded\n");
    return 0;
}

// end::program[]
