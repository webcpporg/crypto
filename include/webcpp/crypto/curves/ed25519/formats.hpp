// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 Ed25519's standard key formats (RFC 8410): a public key's SPKI, the 44 bytes OpenSSL's
 `i2d_PUBKEY` and WebCrypto's `exportKey("spki")` give, and a key pair's PKCS#8 version 1, the 48
 bytes of its seed alone that OpenSSL's `i2d_PrivateKey` and WebCrypto's `exportKey("pkcs8")`
 give; decoded strictly, as the one encoding that encoding the key again gives (design D30).
 `pem::armour` and `pem::unarmour` turn either into text.

 The operations of the family Ed25519, on its default backend, libsodium on every target.

 @see "Key formats: SPKI, PKCS#8 and PEM", in the guide.
*/
#ifndef WEBCPP_CRYPTO_CURVES_ED25519_FORMATS_HPP
#define WEBCPP_CRYPTO_CURVES_ED25519_FORMATS_HPP

#include <webcpp/crypto/config.hpp>

#include <webcpp/crypto/curves/ed25519.hpp>
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
 * RFC 8410's SPKI before an Ed25519 public key: SEQUENCE, AlgorithmIdentifier 1.3.101.112,
 * BIT STRING.
 */
inline constexpr std::array<std::uint8_t, 12> ed25519_spki_prefix{
    0x30, 0x2a,                                // SEQUENCE, 42 bytes
    0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,  // AlgorithmIdentifier, OID 1.3.101.112
    0x03, 0x21, 0x00,                          // BIT STRING, 33 bytes, no unused bits
};
/**
 * RFC 8410's PKCS#8 (version 1) before an Ed25519 seed: OneAsymmetricKey, OCTET STRING of an
 * OCTET STRING.
 */
inline constexpr std::array<std::uint8_t, 16> ed25519_pkcs8_prefix{
    0x30, 0x2e,                                // SEQUENCE, 46 bytes
    0x02, 0x01, 0x00,                          // INTEGER 0, version 1
    0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,  // AlgorithmIdentifier, OID 1.3.101.112
    0x04, 0x22, 0x04, 0x20,                    // OCTET STRING, 34 bytes: an OCTET STRING, 32
};

/**
 * Ed25519's key formats on a backend; the primary refuses (defined at the end of this header). A
 * backend's specialisation provides `encode_spki(public_key, out)`,
 * `decode_spki(spki, public_key)`, `encode_pkcs8(state, out)` and `decode_pkcs8(pkcs8, seed)`,
 * over spans of the formats' fixed sizes, the decoders returning `invalid_encoding` for any
 * other bytes than the one encoding.
 */
template <class Name, class Backend>
struct ed25519_formats_engine;

/** Reads a key pair's state for its PKCS#8, as `basic_keypair` lets it. */
template <class Backend>
struct ed25519_keypair_access {
    /**
     * Writes the key pair's PKCS#8.
     *
     * @param key The key pair.
     * @param out 48 bytes.
     * @return Nothing; `invalid_state` moved from.
     */
    [[nodiscard]] static boost::system::result<void> encode_pkcs8(
        curves::ed25519::basic_keypair<Backend> const& key,
        std::span<std::uint8_t, 48> out) noexcept {
        if (!key.keyed_) {
            return error::invalid_state;
        }
        ed25519_formats_engine<families::ed25519, Backend>::encode_pkcs8(key.state_, out);
        return {};
    }
};

}  // namespace webcpp::crypto::detail

namespace webcpp::crypto::curves::ed25519 {

/** The SPKI's size, 44 bytes: the one size RFC 8410 gives an Ed25519 public key's. */
inline constexpr std::size_t max_spki_size = 44;
/** The PKCS#8's size, 48 bytes: version 1, with the seed alone. */
inline constexpr std::size_t max_pkcs8_size = 48;

/**
 * Writes a public key's SPKI (RFC 8410) into `out`.
 *
 * @tparam Backend The backend; by default the family's.
 * @param key The public key.
 * @param out At least `max_spki_size` bytes.
 * @return The bytes written, 44; `invalid_input_size` for an `out` too small. Nothing is written
 * on a refusal.
 */
template <class Backend = default_backend_t<families::ed25519>>
[[nodiscard]] boost::system::result<std::size_t> encode_spki(public_key const& key,
                                                             std::span<std::uint8_t> out) noexcept {
    if (out.size() < max_spki_size) {
        return error::invalid_input_size;
    }
    auto const key_bytes = key.bytes();
    detail::ed25519_formats_engine<families::ed25519, Backend>::encode_spki(
        std::span<std::uint8_t const, public_key::size>(key_bytes), out.first<max_spki_size>());
    return max_spki_size;
}

/**
 * The public key of an SPKI, refused unless it is exactly RFC 8410's form: the 12 bytes of
 * Ed25519's prefix, then the key, and nothing after.
 *
 * The key's point is not checked here, as `public_key::make` does not check it: `crypto::verify`
 * refuses a key that is not one.
 *
 * @tparam Backend The backend; by default the family's.
 * @param spki The DER.
 * @return The public key; `invalid_encoding`.
 */
template <class Backend = default_backend_t<families::ed25519>>
[[nodiscard]] boost::system::result<public_key> decode_spki(
    std::span<std::uint8_t const> spki) noexcept {
    detail::timing_guard const timing;
    if (spki.size() != max_spki_size) {
        return error::invalid_encoding;
    }
    std::array<std::uint8_t, public_key::size> key_bytes{};
    auto const decoded = detail::ed25519_formats_engine<families::ed25519, Backend>::decode_spki(
        spki.first<max_spki_size>(), key_bytes);
    if (!decoded) {
        return decoded.error();
    }
    return public_key::make(key_bytes);
}

/**
 * Writes a key pair's PKCS#8 (RFC 8410, version 1: the seed, without the public key) into `out`,
 * which then holds the secret key: a program wipes it, or seals it, when it is done.
 *
 * @tparam Backend The key pair's backend.
 * @param key The key pair.
 * @param out At least `max_pkcs8_size` bytes.
 * @return The bytes written, 48; `invalid_state` for a key pair moved from; `invalid_input_size`
 * for an `out` too small. Nothing is written on a refusal.
 */
template <class Backend = default_backend_t<families::ed25519>>
[[nodiscard]] boost::system::result<std::size_t> encode_pkcs8(
    basic_keypair<Backend> const& key, std::span<std::uint8_t> out) noexcept {
    if (out.size() < max_pkcs8_size) {
        return error::invalid_input_size;
    }
    auto const written =
        detail::ed25519_keypair_access<Backend>::encode_pkcs8(key, out.first<max_pkcs8_size>());
    if (!written) {
        return written.error();
    }
    return max_pkcs8_size;
}

/**
 * The key pair of a PKCS#8, refused unless it is exactly RFC 8410's version 1 form: the 16 bytes
 * of Ed25519's prefix, then the seed, and nothing after.
 *
 * Version 2, which carries the public key as well, is refused, as are attributes and BER's other
 * lengths.
 *
 * @tparam Backend The backend; by default the family's.
 * @param pkcs8 The DER.
 * @return The key pair, made from the seed at once; `invalid_encoding`; `backend_failure`.
 */
template <class Backend = default_backend_t<families::ed25519>>
[[nodiscard]] boost::system::result<basic_keypair<Backend>> decode_pkcs8(
    std::span<std::uint8_t const> pkcs8) noexcept {
    detail::timing_guard const timing;
    if (pkcs8.size() != max_pkcs8_size) {
        return error::invalid_encoding;
    }
    secret<32> seed;
    auto const decoded = detail::ed25519_formats_engine<families::ed25519, Backend>::decode_pkcs8(
        pkcs8.first<max_pkcs8_size>(), seed.writable());
    if (!decoded) {
        return decoded.error();
    }
    return basic_keypair<Backend>::make(seed.bytes());
}

}  // namespace webcpp::crypto::curves::ed25519

namespace webcpp::crypto::detail {

/**
 * Ed25519's key formats on a backend whose header does not specialise them: the family's
 * refusal, which names what the program needs (`detail/capabilities.hpp`). Its functions are
 * never called: the refusal stops the build where the class is instantiated, and they keep the
 * compiler from adding errors of their own after it; those that return report
 * `backend_failure`, so that a path the refusal missed fails closed.
 */
template <class Name, class Backend>
struct ed25519_formats_engine {
    WEBCPP_CRYPTO_DETAIL_REFUSE_ED25519(Backend);

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
#define WEBCPP_CRYPTO_DETAIL_ED25519_FORMATS_DECLARED 1

// The default backend's engine, when the program links it (design D32): libsodium on every
// target. Its header specialises it for this header, wherever it was first included.
#if defined(WEBCPP_CRYPTO_DETAIL_DEFAULT_ED25519_SODIUM) && defined(WEBCPP_CRYPTO_HAS_SODIUM)
#include <webcpp/crypto/backends/sodium.hpp>
#endif

#endif  // WEBCPP_CRYPTO_CURVES_ED25519_FORMATS_HPP
