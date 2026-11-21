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
// Points on the curve, computed on 2026-11-21 from FIPS 186-5's b with p = 3 mod 4: (0, y0),
// y0 = b^((p + 1) / 4), and (x1, 1), x1 a root of x^3 - 3x + b - 1; each checked against the
// curve's equation. Then the same points with x + p and with y + p, which fit in 32 bytes.
inline constexpr auto point_x_zero = hex<65>(
    "040000000000000000000000000000000000000000000000000000000000000000"
    "66485c780e2f83d72433bd5d84a06bb6541c2af31dae871728bf856a174f93f4");
inline constexpr auto point_x_zero_plus_p = hex<65>(
    "04ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"
    "66485c780e2f83d72433bd5d84a06bb6541c2af31dae871728bf856a174f93f4");
inline constexpr auto point_y_one = hex<65>(
    "048d0177ebab9c6e9e10db6dd095dbac0d6375e8a97b70f611875d877f0069d2c7"
    "0000000000000000000000000000000000000000000000000000000000000001");
inline constexpr auto point_y_one_plus_p = hex<65>(
    "048d0177ebab9c6e9e10db6dd095dbac0d6375e8a97b70f611875d877f0069d2c7"
    "ffffffff00000001000000000000000000000001000000000000000000000000");

}  // namespace webcpp::test::p256

#endif  // WEBCPP_TEST_CRYPTO_SUPPORT_P256_DATA_HPP
