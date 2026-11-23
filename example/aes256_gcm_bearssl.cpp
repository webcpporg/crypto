// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Seals one zero block with AES-256-GCM on BearSSL, names the backend in the type, checks the
// result against test case 14 of the GCM specification, and opens it again. Naming the backend
// pins the implementation, so the same bytes and the same code run on every target.
// tag::program[]
#include <webcpp/crypto/backends/bearssl.hpp>
#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/crypto/ciphers/gcm.hpp>
#include <webcpp/crypto/constant_time_equal.hpp>

#include <array>
#include <cstdint>
#include <cstdio>

namespace crypto = webcpp::crypto;

// The backend is part of the type: no default, no surprise.
using aead_type = crypto::ciphers::gcm<crypto::ciphers::aes256<crypto::backends::bearssl>>;

int main() {
    // The test vector's zero key and IV: a real program draws its key from random_device and
    // never reuses an IV under it.
    std::array<std::uint8_t, 32> const key{};
    std::array<std::uint8_t, 12> const iv{};
    std::array<std::uint8_t, 16> data{};
    std::array<std::uint8_t, 16> const expected_cipher{
        0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e,
        0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3, 0x9d, 0x18,
    };
    std::array<std::uint8_t, 16> const expected_tag{
        0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0,
        0x26, 0x5b, 0x98, 0xb5, 0xd4, 0x8a, 0xb9, 0x19,
    };

    auto aead = aead_type::from_key(key);
    if (!aead) {
        return 1;
    }
    // Seal encrypts in place and returns the tag.
    auto const tag = aead->seal(iv, {}, data);
    if (!tag || data != expected_cipher || !crypto::constant_time_equal(*tag, expected_tag)) {
        return 1;
    }
    // Open decrypts in place and checks the tag; on a mismatch it zeroes data and returns
    // authentication_failed.
    if (!aead->open(iv, {}, data, expected_tag) || data != std::array<std::uint8_t, 16>{}) {
        return 1;
    }
    auto const name = aead_type::backend_type::name;
    std::printf("aes256_gcm ok backend=%.*s\n", static_cast<int>(name.size()), name.data());
    return 0;
}

// end::program[]
