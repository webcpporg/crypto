// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

#ifndef WEBCPP_CRYPTO_DETAIL_P_CURVES_HPP
#define WEBCPP_CRYPTO_DETAIL_P_CURVES_HPP

#include <webcpp/crypto/config.hpp>

#include <webcpp/crypto/detail/capabilities.hpp>
#include <webcpp/secure/declassify.hpp>

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
 * Whether 0 < `scalar_bytes` < `bound_bytes`, both big-endian of N bytes, in time independent of
 * `scalar_bytes`: the borrow of the difference and the OR of the scalar's bytes over every byte, as
 * BearSSL's br_ec_keygen computes them. The verdict alone is declassified: whether a key is valid
 * is public.
 *
 * @param scalar_bytes The secret scalar.
 * @param bound_bytes The group order.
 * @return Whether the scalar is in range.
 */
template <std::size_t N>
[[nodiscard]] bool p_curve_scalar_valid(std::span<std::uint8_t const, N> scalar_bytes,
                                        std::array<std::uint8_t, N> const& bound_bytes) noexcept {
    unsigned borrow_bit = 0;
    unsigned nonzero_bits = 0;
    for (std::size_t limb_index = N; limb_index-- > 0;) {
        borrow_bit = ((static_cast<unsigned>(scalar_bytes[limb_index]) - bound_bytes[limb_index] -
                       borrow_bit) >>
                      8U) &
                     1U;
        nonzero_bits |= scalar_bytes[limb_index];
    }
    // Not const: the comparison below must read the variable again after the declassifying
    // client request, whose memory clobber reaches a mutable object only.
    // NOLINTNEXTLINE(misc-const-correctness): see above
    unsigned scalar_verdict = borrow_bit & ((nonzero_bits + 0xffU) >> 8U);
    secure::declassify(scalar_verdict);
    return scalar_verdict != 0;
}

/**
 * Whether an ECDSA signature r || s has 0 < r < n and 0 < s < n, each checked by
 * `p_curve_scalar_valid`: a signature is public, the same check serves.
 *
 * @tparam Curve The curve's family tag.
 * @param signature_bytes r then s, big-endian, each of the curve's scalar size.
 * @return Whether both are in range.
 */
template <class Curve>
[[nodiscard]] bool p_curve_signature_in_range(
    std::span<std::uint8_t const, 2 * p_curve_traits<Curve>::scalar_size>
        signature_bytes) noexcept {
    constexpr std::size_t byte_count = p_curve_traits<Curve>::scalar_size;
    bool const r_valid = p_curve_scalar_valid(signature_bytes.template first<byte_count>(),
                                              p_curve_traits<Curve>::order);
    bool const s_valid = p_curve_scalar_valid(signature_bytes.template last<byte_count>(),
                                              p_curve_traits<Curve>::order);
    return r_valid && s_valid;
}

/**
 * Whether an ECDSA signature's s, already checked 0 < s < n, is low: s <= (n - 1) / 2, the borrow
 * of (n - 1) / 2 - s over every byte, the same arithmetic as `p_curve_scalar_valid`'s. The
 * verdict alone is declassified: a signature is public once it is made, but a constant-time
 * checker (memcheck, MemorySanitizer) still holds secret one computed from the secret scalar where
 * `normalize_low_s` or `is_low_s` branches on this verdict; `sign` itself normalizes without a
 * branch, with `p_curve_high_s_mask`.
 *
 * @tparam Curve The curve's family tag.
 * @param s_bytes The signature's s, big-endian.
 * @return Whether s is at most half the group order.
 */
template <class Curve>
[[nodiscard]] bool p_curve_low_s(
    std::span<std::uint8_t const, p_curve_traits<Curve>::scalar_size> s_bytes) noexcept {
    constexpr auto const& half_order = p_curve_traits<Curve>::half_order;
    unsigned borrow_bit = 0;
    for (std::size_t limb_index = s_bytes.size(); limb_index-- > 0;) {
        borrow_bit =
            ((static_cast<unsigned>(half_order[limb_index]) - s_bytes[limb_index] - borrow_bit) >>
             8U) &
            1U;
    }
    // Not const: the comparison below must read the variable again after the declassifying
    // client request, whose memory clobber reaches a mutable object only.
    // NOLINTNEXTLINE(misc-const-correctness): see above
    unsigned high_borrow = borrow_bit;
    secure::declassify(high_borrow);
    return high_borrow == 0;
}

/**
 * Whether an ECDSA signature's s, already checked 0 < s < n, is high, s > (n - 1) / 2, as a mask:
 * 0xff when high, 0x00 when low, from the borrow of (n - 1) / 2 - s over every byte, with no branch
 * and nothing declassified, so that signing can normalize a signature it has just made, still
 * secret to a constant-time checker, in constant time (libsecp256k1's
 * `secp256k1_scalar_cond_negate` does the same).
 *
 * @tparam Curve The curve's family tag.
 * @param s_bytes The signature's s, big-endian.
 * @return 0xff when s is above half the group order, 0x00 otherwise.
 */
template <class Curve>
[[nodiscard]] std::uint8_t p_curve_high_s_mask(
    std::span<std::uint8_t const, p_curve_traits<Curve>::scalar_size> s_bytes) noexcept {
    constexpr auto const& half_order = p_curve_traits<Curve>::half_order;
    unsigned borrow_bit = 0;
    for (std::size_t limb_index = s_bytes.size(); limb_index-- > 0;) {
        borrow_bit =
            ((static_cast<unsigned>(half_order[limb_index]) - s_bytes[limb_index] - borrow_bit) >>
             8U) &
            1U;
    }
    return static_cast<std::uint8_t>(0U - borrow_bit);
}

/**
 * n - s, the other s of the same signature, for an s already checked 0 < s < n, so that the
 * result is in that range too: the borrow arithmetic of `p_curve_scalar_valid`, over every byte.
 *
 * @tparam Curve The curve's family tag.
 * @param s_bytes The signature's s, big-endian.
 * @param output_bytes n - s, big-endian; it may not overlap `s_bytes`.
 */
template <class Curve>
void p_curve_negate_scalar(
    std::span<std::uint8_t const, p_curve_traits<Curve>::scalar_size> s_bytes,
    std::span<std::uint8_t, p_curve_traits<Curve>::scalar_size> output_bytes) noexcept {
    constexpr auto const& curve_order = p_curve_traits<Curve>::order;
    unsigned borrow_bit = 0;
    for (std::size_t limb_index = s_bytes.size(); limb_index-- > 0;) {
        unsigned const limb_difference =
            static_cast<unsigned>(curve_order[limb_index]) - s_bytes[limb_index] - borrow_bit;
        output_bytes[limb_index] = static_cast<std::uint8_t>(limb_difference);
        borrow_bit = (limb_difference >> 8U) & 1U;
    }
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
 * private), for the family's own functions alone: they make one through it and write its point
 * before they return it. A key made through it is not validated: only a point a key pair
 * computed or the backend checked may be written into it.
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
     * @param key_object The public key.
     * @return Its encoded point.
     */
    template <class PublicKey>
    [[nodiscard]] static auto& point(PublicKey& key_object) noexcept {
        return key_object.point_;
    }
};

}  // namespace webcpp::crypto::detail

#endif  // WEBCPP_CRYPTO_DETAIL_P_CURVES_HPP
