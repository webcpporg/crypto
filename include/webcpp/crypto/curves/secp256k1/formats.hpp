// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 secp256k1's keys in the standard formats on libsecp256k1: a public key's SPKI (RFC 5480, the
 secp256k1 OID, either point form) and a key pair's PKCS#8 (RFC 5208 around RFC 5915's
 ECPrivateKey), each decoded only when it is exactly what the encoder writes. `pem::armour` and
 `pem::unarmour` (`<webcpp/crypto/pem.hpp>`, on libsodium) turn either into PEM text.

 @see "Keys in files: SPKI, PKCS#8 and PEM", in the guide's secp256k1 chapter.
*/
#ifndef WEBCPP_CRYPTO_CURVES_SECP256K1_FORMATS_HPP
#define WEBCPP_CRYPTO_CURVES_SECP256K1_FORMATS_HPP

#include <webcpp/crypto/config.hpp>

#include <webcpp/crypto/backends/secp256k1.hpp>
#include <webcpp/crypto/constant_time_equal.hpp>
#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/detail/capabilities.hpp>
#include <webcpp/crypto/detail/declassify.hpp>
#include <webcpp/crypto/detail/defaults.hpp>
#include <webcpp/crypto/detail/timing.hpp>
#include <webcpp/crypto/detail/wipe.hpp>
#include <webcpp/crypto/error.hpp>

#include <boost/system/result.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory_resource>
#include <span>

namespace webcpp::crypto::detail {

/**
 * RFC 5480's SPKI before an uncompressed secp256k1 point: the SEQUENCE, the AlgorithmIdentifier
 * (id-ecPublicKey, secp256k1), then a BIT STRING of 66 bytes.
 */
inline constexpr std::array<std::uint8_t, 23> secp256k1_spki_uncompressed_prefix{
    0x30, 0x56, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
    0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a, 0x03, 0x42, 0x00,
};

/** RFC 5480's SPKI before a compressed secp256k1 point, whose BIT STRING has 34 bytes. */
inline constexpr std::array<std::uint8_t, 23> secp256k1_spki_compressed_prefix{
    0x30, 0x36, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
    0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a, 0x03, 0x22, 0x00,
};

/**
 * PKCS#8 before the secret, in OpenSSL's form: version 0, the AlgorithmIdentifier, and an
 * OCTET STRING holding RFC 5915's ECPrivateKey (version 1, then its 32-byte OCTET STRING), with
 * no [0] parameters.
 */
inline constexpr std::array<std::uint8_t, 33> secp256k1_pkcs8_prefix{
    0x30, 0x81, 0x84, 0x02, 0x01, 0x00, 0x30, 0x10, 0x06, 0x07, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04,
    0x00, 0x0a, 0x04, 0x6d, 0x30, 0x6b, 0x02, 0x01, 0x01, 0x04, 0x20,
};

/** PKCS#8 between the secret and the uncompressed public point: ECPrivateKey's [1] BIT STRING. */
inline constexpr std::array<std::uint8_t, 5> secp256k1_pkcs8_infix{0xa1, 0x44, 0x03, 0x42, 0x00};

}  // namespace webcpp::crypto::detail

namespace webcpp::crypto::curves::secp256k1 {

/** The size of an SPKI with a compressed point, 56 bytes. */
inline constexpr std::size_t spki_compressed_size = 56;

/** The size of an SPKI with an uncompressed point, 88 bytes. */
inline constexpr std::size_t spki_uncompressed_size = 88;

/** The size of the longest SPKI, 88 bytes. */
inline constexpr std::size_t max_spki_size = spki_uncompressed_size;

/** The size of a PKCS#8, 135 bytes: the secret and the uncompressed public point. */
inline constexpr std::size_t max_pkcs8_size = 135;

/**
 * Writes a public key's SPKI (RFC 5480, the secp256k1 OID) into `output_bytes`.
 *
 * @tparam Backend The backend, `backends::secp256k1`.
 * @param parsed_key The key.
 * @param output_bytes At least `max_spki_size` bytes, whatever the form; nothing is written on
 * an error.
 * @param encoded_form The point's SEC1 form, `compressed` by default.
 * @return The number of bytes written, `spki_compressed_size` or `spki_uncompressed_size`;
 * `invalid_input_size` when `output_bytes` is shorter than `max_spki_size`.
 */
template <class Backend = default_backend_t<families::secp256k1>>
[[nodiscard]] boost::system::result<std::size_t> encode_spki(
    public_key const& parsed_key, std::span<std::uint8_t> output_bytes,
    point_form encoded_form = point_form::compressed) noexcept {
    detail::timing_guard const timing_scope;
    static_assert(webcpp::crypto::detail::secp256k1_refuses_others<families::secp256k1, Backend>);
    webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
    if (output_bytes.size() < max_spki_size) {
        return error::invalid_input_size;
    }
    secp256k1_selftest();
    bool const is_compressed = encoded_form == point_form::compressed;
    std::array<std::uint8_t, 65> point_bytes{};
    std::size_t point_length = is_compressed ? 33 : 65;
    secp256k1_ec_pubkey_serialize(secp256k1_context_static, point_bytes.data(), &point_length,
                                  &webcpp::crypto::detail::secp256k1_access::point(parsed_key),
                                  is_compressed ? webcpp::crypto::detail::secp256k1_compressed
                                                : webcpp::crypto::detail::secp256k1_uncompressed);
    auto const write_cursor =
        std::ranges::copy(is_compressed
                              ? webcpp::crypto::detail::secp256k1_spki_compressed_prefix
                              : webcpp::crypto::detail::secp256k1_spki_uncompressed_prefix,
                          output_bytes.begin())
            .out;
    std::ranges::copy(std::span<std::uint8_t const>(point_bytes).first(point_length), write_cursor);
    return is_compressed ? spki_compressed_size : spki_uncompressed_size;
}

/**
 * The public key of an SPKI in exactly one of the two forms `encode_spki` writes.
 *
 * @tparam Backend The backend, `backends::secp256k1`.
 * @param spki_bytes The SPKI, exactly: nothing may follow it.
 * @return The key; `invalid_encoding` for any other bytes, a point off the curve and X9.62's
 * hybrid form included.
 */
template <class Backend = default_backend_t<families::secp256k1>>
[[nodiscard]] boost::system::result<public_key> decode_spki(
    std::span<std::uint8_t const> spki_bytes) noexcept {
    detail::timing_guard const timing_scope;
    static_assert(webcpp::crypto::detail::secp256k1_refuses_others<families::secp256k1, Backend>);
    webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
    secp256k1_selftest();
    std::span<std::uint8_t const> const expected_prefix =
        spki_bytes.size() == spki_compressed_size
            ? std::span<std::uint8_t const>(
                  webcpp::crypto::detail::secp256k1_spki_compressed_prefix)
            : std::span<std::uint8_t const>(
                  webcpp::crypto::detail::secp256k1_spki_uncompressed_prefix);
    if ((spki_bytes.size() != spki_compressed_size &&
         spki_bytes.size() != spki_uncompressed_size) ||
        !constant_time_equal(spki_bytes.first(expected_prefix.size()), expected_prefix)) {
        return error::invalid_encoding;
    }
    using access = webcpp::crypto::detail::secp256k1_access;
    public_key decoded_key = access::make_public_key();
    // 33 bytes parse only with the prefix 02 or 03, and 65 only with 04.
    if (!webcpp::crypto::detail::secp256k1_parse_public_key(
            spki_bytes.subspan(expected_prefix.size()), access::point(decoded_key))) {
        return error::invalid_encoding;
    }
    return decoded_key;
}

/**
 * Writes a key pair's PKCS#8 into `output_bytes`, in OpenSSL's form: version 0, and RFC 5915's
 * ECPrivateKey of version 1 with the uncompressed public key and no parameters inside.
 *
 * @tparam Backend The backend, `backends::secp256k1`.
 * @param key_pair The key pair.
 * @param output_bytes At least `max_pkcs8_size` bytes; nothing is written on an error.
 * @return The number of bytes written, `max_pkcs8_size`; `invalid_state` moved from;
 * `invalid_input_size` when `output_bytes` is shorter than `max_pkcs8_size`.
 */
template <class Backend = default_backend_t<families::secp256k1>>
[[nodiscard]] boost::system::result<std::size_t> encode_pkcs8(
    basic_keypair<Backend> const& key_pair, std::span<std::uint8_t> output_bytes) noexcept {
    detail::timing_guard const timing_scope;
    static_assert(webcpp::crypto::detail::secp256k1_refuses_others<families::secp256k1, Backend>);
    webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
    using access = webcpp::crypto::detail::secp256k1_access;
    if (!access::keyed(key_pair)) {
        return error::invalid_state;
    }
    if (output_bytes.size() < max_pkcs8_size) {
        return error::invalid_input_size;
    }
    secp256k1_selftest();
    webcpp::crypto::detail::secp256k1_secret secret_bytes;
    secp256k1_keypair_sec(secp256k1_context_static, secret_bytes.bytes.data(),
                          &access::pair(key_pair));
    secp256k1_pubkey const public_point = webcpp::crypto::detail::secp256k1_public_point(
        secp256k1_context_static, access::pair(key_pair));
    std::array<std::uint8_t, 65> point_bytes{};
    std::size_t point_length = point_bytes.size();
    secp256k1_ec_pubkey_serialize(secp256k1_context_static, point_bytes.data(), &point_length,
                                  &public_point, webcpp::crypto::detail::secp256k1_uncompressed);
    auto write_cursor =
        std::ranges::copy(webcpp::crypto::detail::secp256k1_pkcs8_prefix, output_bytes.begin()).out;
    write_cursor = std::ranges::copy(secret_bytes.bytes, write_cursor).out;
    write_cursor =
        std::ranges::copy(webcpp::crypto::detail::secp256k1_pkcs8_infix, write_cursor).out;
    std::ranges::copy(point_bytes, write_cursor);
    return max_pkcs8_size;
}

/**
 * The key pair of a PKCS#8 that is exactly what `encode_pkcs8` writes for its secret, made as
 * `basic_keypair::from_secret` makes it.
 *
 * @tparam Backend The backend, `backends::secp256k1`.
 * @param pkcs8_bytes The PKCS#8, exactly: nothing may follow it.
 * @param memory_resource The resource of the key pair's signing context, as `from_secret` takes it.
 * @return The key pair; `invalid_encoding` for any other bytes, a secret zero or not below the
 * group order and a public key not the secret's included; `entropy_unavailable` and
 * `backend_failure` as `from_secret` reports them.
 */
template <class Backend = default_backend_t<families::secp256k1>>
[[nodiscard]] boost::system::result<basic_keypair<Backend>> decode_pkcs8(
    std::span<std::uint8_t const> pkcs8_bytes,
    std::pmr::memory_resource* memory_resource = std::pmr::get_default_resource()) {
    detail::timing_guard const timing_scope;
    static_assert(webcpp::crypto::detail::secp256k1_refuses_others<families::secp256k1, Backend>);
    webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
    secp256k1_selftest();
    constexpr std::size_t prefix_size = webcpp::crypto::detail::secp256k1_pkcs8_prefix.size();
    if (pkcs8_bytes.size() != max_pkcs8_size ||
        !constant_time_equal(pkcs8_bytes.first(prefix_size),
                             webcpp::crypto::detail::secp256k1_pkcs8_prefix)) {
        return error::invalid_encoding;
    }
    webcpp::crypto::detail::secp256k1_secret secret_bytes;
    std::ranges::copy(pkcs8_bytes.subspan(prefix_size, secret_bytes.bytes.size()),
                      secret_bytes.bytes.begin());
    auto made_pair = basic_keypair<Backend>::from_secret(secret_bytes.bytes, memory_resource);
    if (!made_pair) {
        if (made_pair.error() == error::invalid_secret_key) {
            return error::invalid_encoding;
        }
        return made_pair.error();
    }
    // The rest, the public key above all, is checked by encoding the key pair again: a PKCS#8
    // whose public key is not its secret's is refused.
    std::array<std::uint8_t, max_pkcs8_size> encoded_again{};
    // Not const: the branch reads it again after the mark (detail/declassify.hpp's tip); the
    // comparison runs on the secret's bytes, and its verdict is public.
    // NOLINTNEXTLINE(misc-const-correctness): see above
    bool is_same = encode_pkcs8(*made_pair, encoded_again).has_value() &&
                   constant_time_equal(encoded_again, pkcs8_bytes);
    WEBCPP_CRYPTO_DETAIL_DECLASSIFY(&is_same, sizeof is_same);
    webcpp::crypto::detail::wipe(encoded_again.data(), encoded_again.size());
    if (!is_same) {
        return error::invalid_encoding;
    }
    return made_pair;
}

}  // namespace webcpp::crypto::curves::secp256k1

#endif  // WEBCPP_CRYPTO_CURVES_SECP256K1_FORMATS_HPP
