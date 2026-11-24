// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 X25519's standard key formats (RFC 8410): a public key's SPKI, the 44 bytes OpenSSL's
 `i2d_PUBKEY` and WebCrypto's `exportKey("spki")` give, and a secret key's PKCS#8 version 1, the
 48 bytes of the secret key alone that OpenSSL's `i2d_PrivateKey` and WebCrypto's
 `exportKey("pkcs8")` give; decoded strictly, as the one encoding that encoding the key again
 gives (design D30). `pem::armour` and `pem::unarmour` turn either into text.

 The operations of the family X25519, on its default backend, libsodium on every target.

 @see "Key formats: SPKI, PKCS#8 and PEM", in the guide.
*/
#ifndef WEBCPP_CRYPTO_CURVES_X25519_FORMATS_HPP
#define WEBCPP_CRYPTO_CURVES_X25519_FORMATS_HPP

#include <webcpp/crypto/config.hpp>

#include <webcpp/crypto/curves/x25519.hpp>
#include <webcpp/crypto/detail/capabilities.hpp>
#include <webcpp/crypto/detail/defaults.hpp>
#include <webcpp/crypto/detail/timing.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/secret.hpp>

#include <boost/system/result.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace webcpp::crypto::detail {

/**
 * RFC 8410's SPKI before an X25519 public key: SEQUENCE, AlgorithmIdentifier 1.3.101.110,
 * BIT STRING.
 */
inline constexpr std::array<std::uint8_t, 12> x25519_spki_prefix{
    0x30, 0x2a,                                // SEQUENCE, 42 bytes
    0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e,  // AlgorithmIdentifier, OID 1.3.101.110
    0x03, 0x21, 0x00,                          // BIT STRING, 33 bytes, no unused bits
};
/**
 * RFC 8410's PKCS#8 (version 1) before an X25519 secret key: OneAsymmetricKey, OCTET STRING of an
 * OCTET STRING.
 */
inline constexpr std::array<std::uint8_t, 16> x25519_pkcs8_prefix{
    0x30, 0x2e,                                // SEQUENCE, 46 bytes
    0x02, 0x01, 0x00,                          // INTEGER 0, version 1
    0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e,  // AlgorithmIdentifier, OID 1.3.101.110
    0x04, 0x22, 0x04, 0x20,                    // OCTET STRING, 34 bytes: an OCTET STRING, 32
};

/**
 * X25519's key formats on a backend; the primary refuses (defined at the end of this header). A
 * backend's specialisation provides `encode_spki(public_key, out)`,
 * `decode_spki(spki, public_key)`, `encode_pkcs8(secret_key, out)` and
 * `decode_pkcs8(pkcs8, secret_key)`, over spans of the formats' fixed sizes, the decoders
 * returning `invalid_encoding` for any other bytes than the one encoding.
 */
template <class Name, class Backend>
struct x25519_formats_engine;

}  // namespace webcpp::crypto::detail

namespace webcpp::crypto::curves::x25519 {

/** The SPKI's size, 44 bytes: the one size RFC 8410 gives an X25519 public key's. */
inline constexpr std::size_t max_spki_size = 44;
/** The PKCS#8's size, 48 bytes: version 1, with the secret key alone. */
inline constexpr std::size_t max_pkcs8_size = 48;

/**
 * Writes a public key's SPKI (RFC 8410) into `output_bytes`.
 *
 * @tparam Backend The backend; by default the family's.
 * @param public_key 32 bytes.
 * @param output_bytes At least `max_spki_size` bytes.
 * @return The bytes written, 44; `invalid_public_key` for a key of another size;
 * `invalid_input_size` for an `output_bytes` too small. Nothing is written on a refusal.
 */
template <class Backend = default_backend_t<families::x25519>>
[[nodiscard]] boost::system::result<std::size_t> encode_spki(
    std::span<std::uint8_t const> public_key, std::span<std::uint8_t> output_bytes) noexcept {
    if (public_key.size() != 32) {
        return error::invalid_public_key;
    }
    if (output_bytes.size() < max_spki_size) {
        return error::invalid_input_size;
    }
    detail::x25519_formats_engine<families::x25519, Backend>::encode_spki(
        public_key.first<32>(), output_bytes.first<max_spki_size>());
    return max_spki_size;
}

/**
 * The public key of an SPKI, refused unless it is exactly RFC 8410's form: the 12 bytes of
 * X25519's prefix, then the key, and nothing after.
 *
 * A key of low order is not refused here: `agree` refuses it with `weak_public_key`.
 *
 * @tparam Backend The backend; by default the family's.
 * @param spki_bytes The DER.
 * @return 32 bytes; `invalid_encoding`.
 */
template <class Backend = default_backend_t<families::x25519>>
[[nodiscard]] boost::system::result<std::array<std::uint8_t, 32>> decode_spki(
    std::span<std::uint8_t const> spki_bytes) noexcept {
    detail::timing_guard const timing_scope;
    if (spki_bytes.size() != max_spki_size) {
        return error::invalid_encoding;
    }
    std::array<std::uint8_t, 32> public_key{};
    auto const decoded_key = detail::x25519_formats_engine<families::x25519, Backend>::decode_spki(
        spki_bytes.first<max_spki_size>(), public_key);
    if (!decoded_key) {
        return decoded_key.error();
    }
    return public_key;
}

/**
 * Writes a secret key's PKCS#8 (RFC 8410, version 1: the secret key, without the public key)
 * into `output_bytes`, which then holds the secret key: a program wipes it, or seals it, when it is
 * done.
 *
 * @tparam Backend The backend; by default the family's.
 * @param secret_key 32 bytes, as `public_key` and `agree` take it.
 * @param output_bytes At least `max_pkcs8_size` bytes.
 * @return The bytes written, 48; `invalid_key_size` for a key of another size;
 * `invalid_input_size` for an `output_bytes` too small. Nothing is written on a refusal.
 */
template <class Backend = default_backend_t<families::x25519>>
[[nodiscard]] boost::system::result<std::size_t> encode_pkcs8(
    std::span<std::uint8_t const> secret_key, std::span<std::uint8_t> output_bytes) noexcept {
    if (secret_key.size() != 32) {
        return error::invalid_key_size;
    }
    if (output_bytes.size() < max_pkcs8_size) {
        return error::invalid_input_size;
    }
    detail::x25519_formats_engine<families::x25519, Backend>::encode_pkcs8(
        secret_key.first<32>(), output_bytes.first<max_pkcs8_size>());
    return max_pkcs8_size;
}

/**
 * The secret key of a PKCS#8, refused unless it is exactly RFC 8410's version 1 form: the 16
 * bytes of X25519's prefix, then the secret key, and nothing after.
 *
 * Version 2, which carries the public key as well, is refused, as are attributes and BER's other
 * lengths.
 *
 * @tparam Backend The backend; by default the family's.
 * @param pkcs8_bytes The DER.
 * @return 32 secret bytes, which wipe themselves; `invalid_encoding`.
 */
template <class Backend = default_backend_t<families::x25519>>
[[nodiscard]] boost::system::result<secret<32>> decode_pkcs8(
    std::span<std::uint8_t const> pkcs8_bytes) noexcept {
    detail::timing_guard const timing_scope;
    if (pkcs8_bytes.size() != max_pkcs8_size) {
        return error::invalid_encoding;
    }
    secret<32> secret_key;
    auto const decoded_key = detail::x25519_formats_engine<families::x25519, Backend>::decode_pkcs8(
        pkcs8_bytes.first<max_pkcs8_size>(), secret_key.writable());
    if (!decoded_key) {
        return decoded_key.error();
    }
    return secret_key;
}

}  // namespace webcpp::crypto::curves::x25519

namespace webcpp::crypto::detail {

/**
 * X25519's key formats on a backend whose header does not specialise them: the family's
 * refusal, which names what the program needs (`detail/capabilities.hpp`). Its functions are
 * never called: the refusal stops the build where the class is instantiated, and they keep the
 * compiler from adding errors of their own after it; those that return report
 * `backend_failure`, so that a path the refusal missed fails closed.
 */
template <class Name, class Backend>
struct x25519_formats_engine {
    WEBCPP_CRYPTO_DETAIL_REFUSE_X25519(Backend);

    /** Never called. */
    template <class... Arguments>
    static void encode_spki(Arguments&&... /*arguments*/) noexcept {}

    /** Never called; fails closed. */
    template <class... Arguments>
    [[nodiscard]] static boost::system::result<void> decode_spki(
        Arguments&&... /*arguments*/) noexcept {
        return error::backend_failure;
    }

    /** Never called. */
    template <class... Arguments>
    static void encode_pkcs8(Arguments&&... /*arguments*/) noexcept {}

    /** Never called; fails closed. */
    template <class... Arguments>
    [[nodiscard]] static boost::system::result<void> decode_pkcs8(
        Arguments&&... /*arguments*/) noexcept {
        return error::backend_failure;
    }
};

}  // namespace webcpp::crypto::detail

/** Defined once this header's declarations are, which libsodium's engine specialises. */
#define WEBCPP_CRYPTO_DETAIL_X25519_FORMATS_DECLARED 1

// The default backend's engine, when the program links it (design D32): libsodium on every
// target. Its header specialises it for this header, wherever it was first included.
#if defined(WEBCPP_CRYPTO_DETAIL_DEFAULT_X25519_SODIUM) && defined(WEBCPP_CRYPTO_HAS_SODIUM)
#include <webcpp/crypto/backends/sodium.hpp>
#endif

#endif  // WEBCPP_CRYPTO_CURVES_X25519_FORMATS_HPP
