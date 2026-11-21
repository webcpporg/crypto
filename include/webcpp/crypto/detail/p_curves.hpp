// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

#ifndef WEBCPP_CRYPTO_DETAIL_P_CURVES_HPP
#define WEBCPP_CRYPTO_DETAIL_P_CURVES_HPP

#include <webcpp/crypto/config.hpp>

#include <webcpp/crypto/detail/capabilities.hpp>
#include <webcpp/crypto/detail/declassify.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

/*
 * WEBCPP_CRYPTO_DETAIL_P_CURVE_ENGINE_ENTERED() runs first in each function of a backend's P-curve
 * engine that calls the backend's code. Nothing in a program's build; a test defines it before its
 * first include to count those calls, so that it sees a refusal that the family's header makes
 * before the backend (test/p256_keys_bearssl_test.cpp).
 */
#ifndef WEBCPP_CRYPTO_DETAIL_P_CURVE_ENGINE_ENTERED
/** Marks a call of a P-curve engine's backend code: nothing in a program's build. */
#define WEBCPP_CRYPTO_DETAIL_P_CURVE_ENGINE_ENTERED() static_cast<void>(0)
#endif

namespace webcpp::crypto::detail {

/** A P-curve's constants: its sizes, the group order and its half, big-endian. */
template <class Curve>
struct p_curve_traits;

/** P-256's constants (FIPS 186-5; SEC 2). */
template <>
struct p_curve_traits<families::p256> {
    /** The size of a scalar, and of a coordinate. */
    static constexpr std::size_t scalar_size = 32;
    /** The size of the digest ECDSA signs, SHA-256's. */
    static constexpr std::size_t digest_size = 32;
    /** The longest strict DER encoding of an ECDSA signature. */
    static constexpr std::size_t max_der_size = 72;
    /** n, the group order (FIPS 186-5; SEC 2). */
    static constexpr std::array<std::uint8_t, 32> order{
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17,
        0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
    };
    /** (n - 1) / 2, the largest S of a low-S signature. */
    static constexpr std::array<std::uint8_t, 32> half_order{
        0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b,
        0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8,
    };
};

/**
 * Whether 0 < value < bound, both big-endian of N bytes, in time independent of `value`: the
 * borrow of value - bound and the OR of value's bytes over every byte, as BearSSL's br_ec_keygen
 * computes them. The verdict alone is declassified: whether a key is valid is public.
 *
 * @param value The secret scalar.
 * @param bound The group order.
 * @return Whether the scalar is in range.
 */
template <std::size_t N>
[[nodiscard]] bool p_curve_scalar_valid(std::span<std::uint8_t const, N> value,
                                        std::array<std::uint8_t, N> const& bound) noexcept {
    unsigned borrow = 0;
    unsigned nonzero = 0;
    for (std::size_t i = N; i-- > 0;) {
        borrow = ((static_cast<unsigned>(value[i]) - bound[i] - borrow) >> 8U) & 1U;
        nonzero |= value[i];
    }
    // Not const: the comparison below must read the variable again after the declassifying
    // client request, whose memory clobber reaches a mutable object only.
    // NOLINTNEXTLINE(misc-const-correctness): see above
    unsigned verdict = borrow & ((nonzero + 0xffU) >> 8U);
    WEBCPP_CRYPTO_DETAIL_DECLASSIFY(&verdict, sizeof verdict);
    return verdict != 0;
}

/**
 * What a P-curve key pair stores on a backend whose header does not specialise it: nothing, since
 * its engine refuses the backend where the family is called.
 */
template <class Curve, class Backend>
struct p_curve_state {};

/**
 * The work of a P-curve on a backend: a backend's header specialises it per curve, and each
 * curve's header defines the refusal for the others (`curves/p256.hpp`).
 */
template <class Curve, class Backend>
struct p_curve_engine;

/**
 * The one door into a P-curve's opaque types (a public key, whose default constructor is
 * private): the family's functions make one through it and write its point before they return
 * it. It hands out nothing a caller of crypto could not already do.
 */
struct p_curve_access {
    /**
     * An object of an opaque type, not yet written: the function that returns it writes it
     * first.
     *
     * @tparam Opaque The type, whose default constructor is private.
     * @return The unwritten object.
     */
    template <class Opaque>
    [[nodiscard]] static Opaque blank() noexcept {
        return Opaque();
    }

    /**
     * A public key's point, to be written by the function that makes the key.
     *
     * @tparam PublicKey The public key's type.
     * @param key The public key.
     * @return Its encoded point.
     */
    template <class PublicKey>
    [[nodiscard]] static auto& point(PublicKey& key) noexcept {
        return key.point_;
    }
};

}  // namespace webcpp::crypto::detail

#endif  // WEBCPP_CRYPTO_DETAIL_P_CURVES_HPP
