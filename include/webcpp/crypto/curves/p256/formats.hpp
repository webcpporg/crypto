// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 P-256's keys in the standard formats, by fixed layouts: a public key's SPKI (RFC 5480, the
 secp256r1 OID, the uncompressed point), 91 bytes, and a key pair's PKCS#8 (RFC 5208 around RFC
 5915's ECPrivateKey with its public key and no parameters), 138 bytes, each decoded only when it
 is exactly what the encoder writes. `pem::armour` and `pem::unarmour` (`<webcpp/crypto/pem.hpp>`,
 on libsodium) turn either into PEM text.

 @see "Keys in files: SPKI, PKCS#8 and PEM", in the guide's P-256 chapter.
*/
#ifndef WEBCPP_CRYPTO_CURVES_P256_FORMATS_HPP
#define WEBCPP_CRYPTO_CURVES_P256_FORMATS_HPP

#include <webcpp/crypto/config.hpp>

#include <webcpp/crypto/curves/p256.hpp>
#include <webcpp/crypto/detail/capabilities.hpp>
#include <webcpp/crypto/detail/declassify.hpp>
#include <webcpp/crypto/detail/defaults.hpp>
#include <webcpp/crypto/detail/timing.hpp>
#include <webcpp/crypto/equal.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/secret.hpp>

#include <boost/system/result.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace webcpp::crypto::detail {

/**
 * RFC 5480's SPKI before a P-256 point: the SEQUENCE, the AlgorithmIdentifier (id-ecPublicKey
 * 1.2.840.10045.2.1, secp256r1 1.2.840.10045.3.1.7), then a BIT STRING of 66 bytes whose first,
 * the unused bits, is 0.
 */
inline constexpr std::array<std::uint8_t, 26> p256_spki_prefix{
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
};

/**
 * PKCS#8 before the scalar: version 0, the AlgorithmIdentifier as the SPKI's, and an OCTET STRING
 * holding RFC 5915's ECPrivateKey (version 1, then its 32-byte OCTET STRING), with no [0]
 * parameters.
 */
inline constexpr std::array<std::uint8_t, 36> p256_pkcs8_prefix{
    0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
    0x03, 0x01, 0x07, 0x04, 0x6d, 0x30, 0x6b, 0x02, 0x01, 0x01, 0x04, 0x20,
};

/** PKCS#8 between the scalar and the uncompressed public point: ECPrivateKey's [1] BIT STRING. */
inline constexpr std::array<std::uint8_t, 5> p256_pkcs8_infix{0xa1, 0x44, 0x03, 0x42, 0x00};

}  // namespace webcpp::crypto::detail

namespace webcpp::crypto::curves::p256 {

/** The size of an SPKI, 91 bytes: the prefix and the uncompressed point. */
inline constexpr std::size_t max_spki_size = 91;

/** The size of a PKCS#8, 138 bytes: the prefix, the scalar, the infix and the public point. */
inline constexpr std::size_t max_pkcs8_size = 138;

static_assert(detail::p256_spki_prefix.size() + public_key_size == max_spki_size);
static_assert(detail::p256_pkcs8_prefix.size() + secret_key_size + detail::p256_pkcs8_infix.size() +
                  public_key_size ==
              max_pkcs8_size);

/**
 * Writes a public key's SPKI (RFC 5480, the secp256r1 OID, the uncompressed point) into
 * `output_bytes`: the bytes WebCrypto's `exportKey("spki")` and OpenSSL's `i2d_PUBKEY` write.
 *
 * A copy of the key's bytes, with no backend call.
 *
 * @tparam Backend The key's backend.
 * @param key The key.
 * @param output_bytes At least `max_spki_size` bytes; nothing is written on an error.
 * @return The number of bytes written, `max_spki_size`; `invalid_input_size` when
 * `output_bytes` is shorter than `max_spki_size`.
 */
template <class Backend>
[[nodiscard]] boost::system::result<std::size_t> encode_spki(
    basic_public_key<Backend> const& key, std::span<std::uint8_t> output_bytes) noexcept {
    if (output_bytes.size() < max_spki_size) {
        return error::invalid_input_size;
    }
    auto const cursor = std::ranges::copy(detail::p256_spki_prefix, output_bytes.begin()).out;
    std::ranges::copy(key.uncompressed(), cursor);
    return max_spki_size;
}

/**
 * The public key of an SPKI that is exactly what `encode_spki` writes, its point checked as
 * `basic_public_key::make` checks it.
 *
 * @tparam Backend The backend that checks the point; by default the family's.
 * @param spki_bytes The SPKI, exactly: nothing may follow it.
 * @return The key; `invalid_encoding` for any other bytes: another curve, a compressed point,
 * explicit curve parameters, a long form where DER has the short one, a point off the curve or a
 * coordinate not below p.
 */
template <class Backend = default_backend_t<families::p256>>
[[nodiscard]] boost::system::result<basic_public_key<Backend>> decode_spki(
    std::span<std::uint8_t const> spki_bytes) noexcept {
    detail::timing_guard const timing;
    constexpr std::size_t prefix_size = detail::p256_spki_prefix.size();
    if (spki_bytes.size() != max_spki_size ||
        !equal(spki_bytes.first(prefix_size), detail::p256_spki_prefix)) {
        return error::invalid_encoding;
    }
    auto decoded = basic_public_key<Backend>::make(spki_bytes.subspan(prefix_size));
    if (!decoded) {
        if (decoded.error() == error::invalid_public_key) {
            return error::invalid_encoding;
        }
        return decoded.error();
    }
    return decoded;
}

/**
 * Writes a key pair's PKCS#8 into `output_bytes`: version 0, and RFC 5915's ECPrivateKey of
 * version 1 with the uncompressed public key and no parameters inside, the form OpenSSL's and
 * BearSSL's encoders write.
 *
 * A copy of what the key pair holds, with no backend call.
 *
 * @tparam Backend The key pair's backend.
 * @param key_pair The key pair.
 * @param output_bytes At least `max_pkcs8_size` bytes; nothing is written on an error. They hold
 * the secret scalar after the call: a `secret<max_pkcs8_size>`'s keeps them wiped.
 * @return The number of bytes written, `max_pkcs8_size`; `invalid_state` moved from;
 * `invalid_input_size` when `output_bytes` is shorter than `max_pkcs8_size`.
 */
template <class Backend>
[[nodiscard]] boost::system::result<std::size_t> encode_pkcs8(
    basic_keypair<Backend> const& key_pair, std::span<std::uint8_t> output_bytes) noexcept {
    auto const public_point = key_pair.public_key();
    if (!public_point) {
        return public_point.error();
    }
    if (output_bytes.size() < max_pkcs8_size) {
        return error::invalid_input_size;
    }
    auto const scalar = key_pair.secret();
    if (!scalar) {
        return scalar.error();
    }
    auto cursor = std::ranges::copy(detail::p256_pkcs8_prefix, output_bytes.begin()).out;
    cursor = std::ranges::copy(scalar.unsafe_value().bytes(), cursor).out;
    cursor = std::ranges::copy(detail::p256_pkcs8_infix, cursor).out;
    std::ranges::copy(public_point.unsafe_value().uncompressed(), cursor);
    return max_pkcs8_size;
}

/**
 * The key pair of a PKCS#8 that is exactly what `encode_pkcs8` writes for its scalar, made as
 * `basic_keypair::make` makes it.
 *
 * @tparam Backend The backend; by default the family's.
 * @param pkcs8_bytes The PKCS#8, exactly: nothing may follow it.
 * @return The key pair; `invalid_encoding` for any other bytes: another version, another curve,
 * no public key, [0] parameters inside the ECPrivateKey, a scalar 0 or not below n, a public key
 * that is not the scalar's; `backend_failure` as `make` reports it.
 */
template <class Backend = default_backend_t<families::p256>>
[[nodiscard]] boost::system::result<basic_keypair<Backend>> decode_pkcs8(
    std::span<std::uint8_t const> pkcs8_bytes) noexcept {
    detail::timing_guard const timing;
    constexpr std::size_t prefix_size = detail::p256_pkcs8_prefix.size();
    constexpr std::size_t infix_at = prefix_size + secret_key_size;
    constexpr std::size_t point_at = infix_at + detail::p256_pkcs8_infix.size();
    if (pkcs8_bytes.size() != max_pkcs8_size ||
        !equal(pkcs8_bytes.first(prefix_size), detail::p256_pkcs8_prefix) ||
        !equal(pkcs8_bytes.subspan(infix_at, detail::p256_pkcs8_infix.size()),
               detail::p256_pkcs8_infix)) {
        return error::invalid_encoding;
    }
    // The scalar's copy is a secret, wiped when it goes, on every path.
    secret<secret_key_size> scalar;
    std::ranges::copy(pkcs8_bytes.subspan(prefix_size, secret_key_size), scalar.writable().begin());
    auto made_pair = basic_keypair<Backend>::make(scalar.bytes());
    if (!made_pair) {
        if (made_pair.error() == error::invalid_secret_key) {
            return error::invalid_encoding;
        }
        return made_pair.error();
    }
    auto const public_point = made_pair.unsafe_value().public_key();
    if (!public_point) {
        return public_point.error();
    }
    // The point is d * G, computed from the secret; whether the input's is the same is public.
    // Not const: the branch reads it again after the mark (detail/declassify.hpp's tip).
    // NOLINTNEXTLINE(misc-const-correctness): see above
    bool is_same = equal(public_point.unsafe_value().uncompressed(), pkcs8_bytes.subspan(point_at));
    WEBCPP_CRYPTO_DETAIL_DECLASSIFY(&is_same, sizeof is_same);
    if (!is_same) {
        return error::invalid_encoding;
    }
    return made_pair;
}

}  // namespace webcpp::crypto::curves::p256

#endif  // WEBCPP_CRYPTO_CURVES_P256_FORMATS_HPP
