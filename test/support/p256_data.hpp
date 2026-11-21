// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The P-256 constants the P-256 tests share, each with its source: RFC 6979's key, the group
// order n and (n - 1) / 2, and the field prime p.

#ifndef WEBCPP_TEST_CRYPTO_SUPPORT_P256_DATA_HPP
#define WEBCPP_TEST_CRYPTO_SUPPORT_P256_DATA_HPP

#include "hex.hpp"

#include <array>
#include <cstdint>

namespace webcpp::test::p256 {

// RFC 6979, section A.2.5: the P-256 key.
inline constexpr auto rfc6979_scalar =
    hex<32>("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
// RFC 6979, section A.2.5: its public key, d * G, as SEC 1's uncompressed point 04 || Ux || Uy.
inline constexpr auto rfc6979_public = hex<65>(
    "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
    "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299");
// FIPS 186-5 / SEC 2: the group order n, and (n - 1) / 2, the largest low S.
inline constexpr auto order =
    hex<32>("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
inline constexpr auto half_order =
    hex<32>("7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8");
// FIPS 186-5 / SEC 2: the field prime p, which no coordinate reaches.
inline constexpr auto field_prime =
    hex<32>("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");

}  // namespace webcpp::test::p256

#endif  // WEBCPP_TEST_CRYPTO_SUPPORT_P256_DATA_HPP
