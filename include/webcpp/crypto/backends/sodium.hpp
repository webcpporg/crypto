// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 The backend libsodium: libsodium 1.0.22's own C code, built from its sources by
 `/third_party//sodium`, the one copy webcpp::hash and webcpp::crypto share.

 @see "The backends", in the guide.
*/
#ifndef WEBCPP_CRYPTO_BACKENDS_SODIUM_HPP
#define WEBCPP_CRYPTO_BACKENDS_SODIUM_HPP

#include <webcpp/crypto/config.hpp>

#ifndef WEBCPP_CRYPTO_HAS_SODIUM
// clang-format off
#error "webcpp::crypto: the backend libsodium is used and not linked. In the program's Jamfile, add /third_party//sodium beside /webcpp/crypto//crypto, as in: exe app : app.cpp /webcpp/crypto//crypto /third_party//sodium ; (without b2: define WEBCPP_CRYPTO_HAS_SODIUM=1 and link libsodium built with webcpp's src/canary_sodium.c)"
// clang-format on
#else

#include <webcpp/crypto/detail/canary.h>
#include <webcpp/crypto/detail/capabilities.hpp>
#include <webcpp/crypto/detail/declassify.hpp>
#include <webcpp/crypto/detail/engines.hpp>
#include <webcpp/crypto/detail/wipe.hpp>
#include <webcpp/crypto/error.hpp>

#include <sodium/core.h>  // through /third_party//sodium, as webcpp::hash's header does
#include <sodium/crypto_aead_chacha20poly1305.h>
#include <sodium/crypto_aead_xchacha20poly1305.h>
#include <sodium/crypto_secretbox.h>
#include <sodium/crypto_secretbox_xchacha20poly1305.h>
#include <boost/hash2/digest.hpp>
#include <boost/system/result.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <span>
#include <string_view>

/** The canary's name, which every libsodium function of webcpp::crypto reads. */
#define WEBCPP_CRYPTO_DETAIL_SODIUM_CANARY \
    WEBCPP_CRYPTO_DETAIL_CANARY(sodium, WEBCPP_CRYPTO_SODIUM_COMMIT, portable)

#ifdef _MSC_VER
#pragma detect_mismatch(            \
    "webcpp_crypto_backend_sodium", \
    WEBCPP_CRYPTO_DETAIL_MISMATCH_VALUE(sodium, WEBCPP_CRYPTO_SODIUM_COMMIT, portable))
#endif

// src/canary_sodium.c defines the canary with a constant, so its initialisation is static, never
// dynamic; constinit, on this declaration, states it.
extern "C" constinit const char WEBCPP_CRYPTO_DETAIL_SODIUM_CANARY;

namespace webcpp::crypto::backends {

/** The backend libsodium (design D7). */
struct sodium {
    /** The backend's name, which the examples print. */
    static constexpr std::string_view name = "sodium";
};

}  // namespace webcpp::crypto::backends

namespace webcpp::crypto::detail {

/**
 Reads libsodium's canary and initialises libsodium, which every engine calls first.
 `sodium_init` is idempotent and takes libsodium's own lock; its state is libsodium's.

 @return Nothing; `backend_failure` when `sodium_init` returns -1.
*/
[[nodiscard]] inline boost::system::result<void> sodium_ready() noexcept {
    read_canary(WEBCPP_CRYPTO_DETAIL_SODIUM_CANARY);
    if (sodium_init() < 0) {
        return error::backend_failure;
    }
    return {};
}

/**
 Whether a libsodium function that checks a secret refused: its verdict, a tag that does not
 match or an all-zero shared secret, which webcpp reports and so branches on, here, where it is
 marked public for the constant-time checks (`WEBCPP_CRYPTO_DETAIL_DECLASSIFY`).

 @param returned_code What the function returned: 0, or -1 when it refused.
 @return Whether it refused.
*/
[[nodiscard]] inline bool sodium_refused(int returned_code) noexcept {
    // Not const: the comparison reads it again after the mark (detail/declassify.hpp's tip).
    // NOLINTNEXTLINE(misc-const-correctness): see above
    int call_verdict = returned_code;
    WEBCPP_CRYPTO_DETAIL_DECLASSIFY(&verdict, sizeof verdict);
    return call_verdict != 0;
}

/** libsodium's detached functions of an AEAD family, which differ only by name. */
template <class Family>
struct sodium_aead_calls;

/** RFC 8439's ChaCha20-Poly1305: libsodium's `_ietf` functions. */
template <>
struct sodium_aead_calls<families::chacha20_poly1305> {
    /** Encrypts and computes the tag apart. */
    static constexpr auto encrypt_call = &crypto_aead_chacha20poly1305_ietf_encrypt_detached;
    /** Checks the tag apart, then decrypts. */
    static constexpr auto decrypt_call = &crypto_aead_chacha20poly1305_ietf_decrypt_detached;
};

/** The original ChaCha20-Poly1305: libsodium's functions without a suffix. */
template <>
struct sodium_aead_calls<families::chacha20_poly1305_original> {
    /** Encrypts and computes the tag apart. */
    static constexpr auto encrypt_call = &crypto_aead_chacha20poly1305_encrypt_detached;
    /** Checks the tag apart, then decrypts. */
    static constexpr auto decrypt_call = &crypto_aead_chacha20poly1305_decrypt_detached;
};

/** XChaCha20-Poly1305: libsodium's `xchacha20poly1305_ietf` functions. */
template <>
struct sodium_aead_calls<families::xchacha20_poly1305> {
    /** Encrypts and computes the tag apart. */
    static constexpr auto encrypt_call = &crypto_aead_xchacha20poly1305_ietf_encrypt_detached;
    /** Checks the tag apart, then decrypts. */
    static constexpr auto decrypt_call = &crypto_aead_xchacha20poly1305_ietf_decrypt_detached;
};

/** An AEAD's state on libsodium: the key, in the object, since libsodium takes it per call. */
template <class Family>
    requires requires { sodium_aead_calls<Family>::encrypt_call; }
struct aead_state<Family, backends::sodium> {
    /** The key. */
    std::array<unsigned char, 32> key{};
};

/**
 * An AEAD on libsodium, one template for the three ChaCha20-Poly1305 families. libsodium's
 * detached decryption checks the tag before it writes a byte, and zeroes the data when it
 * does not match; `aead` zeroes it too.
 */
template <class Family>
    requires requires { sodium_aead_calls<Family>::encrypt_call; }
struct aead_engine<Family, backends::sodium> {
    /** The state. */
    using state = aead_state<Family, backends::sodium>;
    /** libsodium's functions of the family. */
    using calls = sodium_aead_calls<Family>;

    /**
     * Initialises libsodium and keeps the key.
     *
     * @param engine_state The state.
     * @param key_bytes The key, 32 bytes (`aead` has checked its size).
     * @return Nothing; `backend_failure` when libsodium cannot start.
     */
    [[nodiscard]] static boost::system::result<void> init(
        state& engine_state, std::span<std::uint8_t const> key_bytes) noexcept {
        auto const library_ready = sodium_ready();
        if (!library_ready) {
            return library_ready;
        }
        std::ranges::copy(key_bytes, engine_state.key.begin());
        return {};
    }

    /**
     * Encrypts `data_bytes` in place and writes the tag; libsodium reads the nonce and the
     * additional data before it writes a byte of the ciphertext.
     *
     * @return Nothing; `backend_failure` when libsodium fails.
     */
    [[nodiscard]] static boost::system::result<void> seal(
        state& engine_state, std::span<std::uint8_t const> iv_bytes,
        std::span<std::uint8_t const> additional_data, std::span<std::uint8_t> data_bytes,
        boost::hash2::digest<16>& tag_bytes) noexcept {
        read_canary(WEBCPP_CRYPTO_DETAIL_SODIUM_CANARY);
        unsigned long long tag_length = 0;
        // libsodium encrypts in place when the output is the input (its documented contract);
        // an empty span's null data() is never read or written, since every stream of
        // ChaCha20 returns at once on no byte.
        if (calls::encrypt_call(data_bytes.data(), tag_bytes.data(), &tag_length, data_bytes.data(),
                                data_bytes.size(), additional_data.data(), additional_data.size(),
                                nullptr, iv_bytes.data(), engine_state.key.data()) != 0) {
            return error::backend_failure;
        }
        return {};
    }

    /**
     * Checks the tag, then decrypts `data_bytes` in place.
     *
     * @return Nothing; `authentication_failed` when the tag does not match.
     */
    [[nodiscard]] static boost::system::result<void> open(
        state& engine_state, std::span<std::uint8_t const> iv_bytes,
        std::span<std::uint8_t const> additional_data, std::span<std::uint8_t> data_bytes,
        std::array<std::uint8_t, 16> const& tag_bytes) noexcept {
        read_canary(WEBCPP_CRYPTO_DETAIL_SODIUM_CANARY);
        // An empty span's null data() makes libsodium check the tag alone: its detached
        // decryptions return the verdict when the output is null, before clearing or decrypting
        // it.
        if (sodium_refused(calls::decrypt_call(data_bytes.data(), nullptr, data_bytes.data(),
                                               data_bytes.size(), tag_bytes.data(),
                                               additional_data.data(), additional_data.size(),
                                               iv_bytes.data(), engine_state.key.data()))) {
            return error::authentication_failed;
        }
        return {};
    }

    /** Moves the key; the source is wiped. */
    static void move(state& target_state, state& source_state) noexcept {
        target_state.key = source_state.key;
        wipe_object(source_state.key);
    }

    /** Wipes the key. */
    static void reset(state& engine_state) noexcept { wipe_object(engine_state.key); }
};

/** libsodium's detached functions of a secret box family, which differ only by name. */
template <class Family>
struct sodium_secretbox_calls;

/** `crypto_secretbox`, XSalsa20-Poly1305. */
template <>
struct sodium_secretbox_calls<families::secretbox_xsalsa20poly1305> {
    /** Encrypts and computes the tag apart. */
    static constexpr auto encrypt_call = &crypto_secretbox_detached;
    /** Checks the tag apart, then decrypts. */
    static constexpr auto decrypt_call = &crypto_secretbox_open_detached;
};

/** `crypto_secretbox_xchacha20poly1305`. */
template <>
struct sodium_secretbox_calls<families::secretbox_xchacha20poly1305> {
    /** Encrypts and computes the tag apart. */
    static constexpr auto encrypt_call = &crypto_secretbox_xchacha20poly1305_detached;
    /** Checks the tag apart, then decrypts. */
    static constexpr auto decrypt_call = &crypto_secretbox_xchacha20poly1305_open_detached;
};

/**
 * Seals `data_bytes` in place with a secret box's detached function under a 32-byte key. libsodium
 * reads the nonce again after it writes the first bytes of the ciphertext, so a nonce that
 * lies in `data_bytes` is copied first; an empty span's null data() is never read or written.
 *
 * @return Nothing; `backend_failure` when libsodium fails.
 */
template <class Encrypt>
[[nodiscard]] boost::system::result<void> sodium_secretbox_seal(
    Encrypt encrypt_call, std::span<unsigned char const, 32> key_bytes,
    std::span<std::uint8_t const, 24> iv_bytes, std::span<std::uint8_t> data_bytes,
    boost::hash2::digest<16>& tag_bytes) noexcept {
    std::array<unsigned char, 24> nonce_bytes{};
    std::ranges::copy(iv_bytes, nonce_bytes.begin());
    if (encrypt_call(data_bytes.data(), tag_bytes.data(), data_bytes.data(), data_bytes.size(),
                     nonce_bytes.data(), key_bytes.data()) != 0) {
        return error::backend_failure;
    }
    return {};
}

/**
 * Checks the tag, then decrypts `data_bytes` in place, with a secret box's detached function; the
 * nonce is copied first, as `sodium_secretbox_seal` says. An empty span's null data() makes
 * libsodium check the tag alone.
 *
 * @return Nothing; `authentication_failed` when the tag does not match.
 */
template <class Decrypt>
[[nodiscard]] boost::system::result<void> sodium_secretbox_open(
    Decrypt decrypt_call, std::span<unsigned char const, 32> key_bytes,
    std::span<std::uint8_t const, 24> iv_bytes, std::span<std::uint8_t> data_bytes,
    std::array<std::uint8_t, 16> const& tag_bytes) noexcept {
    std::array<unsigned char, 24> nonce_bytes{};
    std::ranges::copy(iv_bytes, nonce_bytes.begin());
    if (sodium_refused(decrypt_call(data_bytes.data(), data_bytes.data(), tag_bytes.data(),
                                    data_bytes.size(), nonce_bytes.data(), key_bytes.data()))) {
        return error::authentication_failed;
    }
    return {};
}

/** A secret box's state on libsodium: the key, in the object, since libsodium takes it per call. */
template <class Family>
    requires requires { sodium_secretbox_calls<Family>::encrypt_call; }
struct aead_state<Family, backends::sodium> {
    /** The key. */
    std::array<unsigned char, 32> key{};
};

/**
 * A secret box on libsodium, `crypto_secretbox` and its XChaCha20 twin, as an `aead` without
 * additional data (`aead` has refused a non-empty one). libsodium's detached decryption checks
 * the tag before it writes a byte; `aead` zeroes the data when it does not match.
 */
template <class Family>
    requires requires { sodium_secretbox_calls<Family>::encrypt_call; }
struct aead_engine<Family, backends::sodium> {
    /** The state. */
    using state = aead_state<Family, backends::sodium>;
    /** libsodium's functions of the family. */
    using calls = sodium_secretbox_calls<Family>;

    /**
     * Initialises libsodium and keeps the key.
     *
     * @return Nothing; `backend_failure` when libsodium cannot start.
     */
    [[nodiscard]] static boost::system::result<void> init(
        state& engine_state, std::span<std::uint8_t const> key_bytes) noexcept {
        auto const library_ready = sodium_ready();
        if (!library_ready) {
            return library_ready;
        }
        std::ranges::copy(key_bytes, engine_state.key.begin());
        return {};
    }

    /**
     * Encrypts `data_bytes` in place and writes the tag.
     *
     * @return Nothing; `backend_failure` when libsodium fails.
     */
    [[nodiscard]] static boost::system::result<void> seal(
        state& engine_state, std::span<std::uint8_t const> iv_bytes,
        std::span<std::uint8_t const> /*additional_data*/, std::span<std::uint8_t> data_bytes,
        boost::hash2::digest<16>& tag_bytes) noexcept {
        read_canary(WEBCPP_CRYPTO_DETAIL_SODIUM_CANARY);
        return sodium_secretbox_seal(calls::encrypt_call,
                                     std::span<unsigned char const, 32>(engine_state.key),
                                     iv_bytes.first<24>(), data_bytes, tag_bytes);
    }

    /**
     * Checks the tag, then decrypts `data_bytes` in place.
     *
     * @return Nothing; `authentication_failed` when the tag does not match.
     */
    [[nodiscard]] static boost::system::result<void> open(
        state& engine_state, std::span<std::uint8_t const> iv_bytes,
        std::span<std::uint8_t const> /*additional_data*/, std::span<std::uint8_t> data_bytes,
        std::array<std::uint8_t, 16> const& tag_bytes) noexcept {
        read_canary(WEBCPP_CRYPTO_DETAIL_SODIUM_CANARY);
        return sodium_secretbox_open(calls::decrypt_call,
                                     std::span<unsigned char const, 32>(engine_state.key),
                                     iv_bytes.first<24>(), data_bytes, tag_bytes);
    }

    /** Moves the key; the source is wiped. */
    static void move(state& target_state, state& source_state) noexcept {
        target_state.key = source_state.key;
        wipe_object(source_state.key);
    }

    /** Wipes the key. */
    static void reset(state& engine_state) noexcept { wipe_object(engine_state.key); }
};

}  // namespace webcpp::crypto::detail

#endif  // WEBCPP_CRYPTO_HAS_SODIUM
#endif  // WEBCPP_CRYPTO_BACKENDS_SODIUM_HPP

// Ed25519 and Ed25519ph on libsodium, for a program that includes curves/ed25519.hpp, before
// this header or after it: outside the guard above, so that curves/ed25519.hpp, which includes
// this header last, gets them either way; a program that does not include it pays nothing.
#if defined(WEBCPP_CRYPTO_CURVES_ED25519_HPP) && defined(WEBCPP_CRYPTO_HAS_SODIUM) && \
    !defined(WEBCPP_CRYPTO_BACKENDS_SODIUM_ED25519)
/** Defined once libsodium's Ed25519 engines are. */
#define WEBCPP_CRYPTO_BACKENDS_SODIUM_ED25519

#include <webcpp/crypto/detail/wipe.hpp>

#include <sodium/crypto_sign_ed25519.h>

#include <array>
#include <cstdint>
#include <span>

namespace webcpp::crypto::detail {

/** What an Ed25519 key pair stores on libsodium. */
template <>
struct ed25519_state<families::ed25519, backends::sodium> {
    /** libsodium's secret key: the seed, then the public key. */
    std::array<unsigned char, crypto_sign_ed25519_SECRETKEYBYTES> secret_key{};
};

/** Ed25519 on libsodium: strict verification, `crypto_sign_ed25519_verify_detached`. */
template <>
struct ed25519_engine<families::ed25519, backends::sodium> {
    /** The key pair's state. */
    using state = ed25519_state<families::ed25519, backends::sodium>;

    /**
     * Makes the secret key of a seed, `crypto_sign_ed25519_seed_keypair`.
     *
     * @return Nothing; `backend_failure`.
     */
    [[nodiscard]] static boost::system::result<void> seed_keypair(
        state& keyed_state, std::span<std::uint8_t const, 32> seed_bytes) noexcept {
        auto const library_ready = sodium_ready();
        if (!library_ready) {
            return library_ready;
        }
        std::array<unsigned char, crypto_sign_ed25519_PUBLICKEYBYTES> public_key{};
        if (crypto_sign_ed25519_seed_keypair(public_key.data(), keyed_state.secret_key.data(),
                                             seed_bytes.data()) != 0) {
            return error::backend_failure;
        }
        return {};
    }

    /** The public key, the secret key's second half. */
    static void public_key(state const& keyed_state,
                           std::span<std::uint8_t, 32> output_bytes) noexcept {
        read_canary(WEBCPP_CRYPTO_DETAIL_SODIUM_CANARY);
        static_cast<void>(
            crypto_sign_ed25519_sk_to_pk(output_bytes.data(), keyed_state.secret_key.data()));
    }

    /** The seed, the secret key's first half, `crypto_sign_ed25519_sk_to_seed`. */
    static void seed(state const& keyed_state, std::span<std::uint8_t, 32> output_bytes) noexcept {
        read_canary(WEBCPP_CRYPTO_DETAIL_SODIUM_CANARY);
        static_cast<void>(
            crypto_sign_ed25519_sk_to_seed(output_bytes.data(), keyed_state.secret_key.data()));
    }

    /**
     * Signs a message, `crypto_sign_ed25519_detached`.
     *
     * @return Nothing; `backend_failure`.
     */
    [[nodiscard]] static boost::system::result<void> sign(
        state const& keyed_state, std::span<std::uint8_t const> message_bytes,
        std::span<std::uint8_t, 64> output_bytes) noexcept {
        read_canary(WEBCPP_CRYPTO_DETAIL_SODIUM_CANARY);
        if (crypto_sign_ed25519_detached(output_bytes.data(), nullptr, message_bytes.data(),
                                         message_bytes.size(),
                                         keyed_state.secret_key.data()) != 0) {
            return error::backend_failure;
        }
        return {};
    }

    /**
     * Verifies a signature, `crypto_sign_ed25519_verify_detached`: the policy `strict`.
     *
     * @return Nothing; `invalid_signature`; `backend_failure`.
     */
    [[nodiscard]] static boost::system::result<void> verify(
        std::span<std::uint8_t const, 32> public_key, std::span<std::uint8_t const> message_bytes,
        std::span<std::uint8_t const, 64> signature_bytes) noexcept {
        auto const library_ready = sodium_ready();
        if (!library_ready) {
            return library_ready;
        }
        if (crypto_sign_ed25519_verify_detached(signature_bytes.data(), message_bytes.data(),
                                                message_bytes.size(), public_key.data()) != 0) {
            return error::invalid_signature;
        }
        return {};
    }

    /**
     * The X25519 secret key, `crypto_sign_ed25519_sk_to_curve25519`.
     *
     * @return Nothing; `backend_failure`.
     */
    [[nodiscard]] static boost::system::result<void> x25519_secret(
        state const& keyed_state, std::span<std::uint8_t, 32> output_bytes) noexcept {
        read_canary(WEBCPP_CRYPTO_DETAIL_SODIUM_CANARY);
        if (crypto_sign_ed25519_sk_to_curve25519(output_bytes.data(),
                                                 keyed_state.secret_key.data()) != 0) {
            return error::backend_failure;
        }
        return {};
    }

    /**
     * The X25519 public key of an Ed25519 public key, `crypto_sign_ed25519_pk_to_curve25519`,
     * which refuses a key of small order, not on the curve or outside the main subgroup.
     *
     * @return Nothing; `invalid_public_key`; `backend_failure`.
     */
    [[nodiscard]] static boost::system::result<void> to_x25519_public(
        std::span<std::uint8_t const, 32> public_key,
        std::span<std::uint8_t, 32> output_bytes) noexcept {
        auto const library_ready = sodium_ready();
        if (!library_ready) {
            return library_ready;
        }
        if (crypto_sign_ed25519_pk_to_curve25519(output_bytes.data(), public_key.data()) != 0) {
            return error::invalid_public_key;
        }
        return {};
    }

    /** Wipes the secret key. */
    static void reset(state& keyed_state) noexcept { wipe_object(keyed_state.secret_key); }
};

/** What an Ed25519ph signer stores on libsodium: the message's SHA-512 state. */
template <>
struct ed25519ph_state<tags::ed25519ph, backends::sodium> {
    /** libsodium's state. */
    crypto_sign_ed25519ph_state hashing{};
};

/** Ed25519ph on libsodium, `crypto_sign_ed25519ph_*`. */
template <>
struct ed25519ph_engine<tags::ed25519ph, backends::sodium> {
    /** The signer's state. */
    using state = ed25519ph_state<tags::ed25519ph, backends::sodium>;

    /**
     * Begins a message, `crypto_sign_ed25519ph_init`.
     *
     * @return Nothing; `backend_failure`.
     */
    [[nodiscard]] static boost::system::result<void> begin(state& begun_state) noexcept {
        auto const library_ready = sodium_ready();
        if (!library_ready) {
            return library_ready;
        }
        if (crypto_sign_ed25519ph_init(&begun_state.hashing) != 0) {
            return error::backend_failure;
        }
        return {};
    }

    /** Adds a piece, `crypto_sign_ed25519ph_update`, which cannot fail. */
    static void update(state& begun_state, std::span<std::uint8_t const> piece_bytes) noexcept {
        read_canary(WEBCPP_CRYPTO_DETAIL_SODIUM_CANARY);
        static_cast<void>(crypto_sign_ed25519ph_update(&begun_state.hashing, piece_bytes.data(),
                                                       piece_bytes.size()));
    }

    /**
     * Signs the message, `crypto_sign_ed25519ph_final_create`.
     *
     * @return Nothing; `backend_failure`.
     */
    [[nodiscard]] static boost::system::result<void> sign(
        state& begun_state, ed25519_state<families::ed25519, backends::sodium> const& keyed_state,
        std::span<std::uint8_t, 64> output_bytes) noexcept {
        read_canary(WEBCPP_CRYPTO_DETAIL_SODIUM_CANARY);
        if (crypto_sign_ed25519ph_final_create(&begun_state.hashing, output_bytes.data(), nullptr,
                                               keyed_state.secret_key.data()) != 0) {
            return error::backend_failure;
        }
        return {};
    }

    /**
     * Verifies a signature of the message, `crypto_sign_ed25519ph_final_verify`, strict.
     *
     * @return Nothing; `invalid_signature`.
     */
    [[nodiscard]] static boost::system::result<void> verify(
        state& begun_state, std::span<std::uint8_t const, 32> public_key,
        std::span<std::uint8_t const, 64> signature_bytes) noexcept {
        read_canary(WEBCPP_CRYPTO_DETAIL_SODIUM_CANARY);
        if (crypto_sign_ed25519ph_final_verify(&begun_state.hashing, signature_bytes.data(),
                                               public_key.data()) != 0) {
            return error::invalid_signature;
        }
        return {};
    }

    /** Wipes the message's state. */
    static void reset(state& begun_state) noexcept { wipe_object(begun_state.hashing); }
};

}  // namespace webcpp::crypto::detail

#endif  // Ed25519 on libsodium

// X25519 on libsodium, for a program that includes curves/x25519.hpp, before this header or
// after it, as Ed25519's above.
#if defined(WEBCPP_CRYPTO_CURVES_X25519_HPP) && defined(WEBCPP_CRYPTO_HAS_SODIUM) && \
    !defined(WEBCPP_CRYPTO_BACKENDS_SODIUM_X25519)
/** Defined once libsodium's X25519 engine is. */
#define WEBCPP_CRYPTO_BACKENDS_SODIUM_X25519

#include <sodium/crypto_scalarmult_curve25519.h>

#include <cstdint>
#include <span>

namespace webcpp::crypto::detail {

/** X25519 on libsodium, `crypto_scalarmult_curve25519`. */
template <>
struct x25519_engine<families::x25519, backends::sodium> {
    /**
     * The public key of a secret key, `crypto_scalarmult_curve25519_base`.
     *
     * @return Nothing; `backend_failure`.
     */
    [[nodiscard]] static boost::system::result<void> base(
        std::span<std::uint8_t const, 32> secret_key,
        std::span<std::uint8_t, 32> output_bytes) noexcept {
        auto const library_ready = sodium_ready();
        if (!library_ready) {
            return library_ready;
        }
        if (crypto_scalarmult_curve25519_base(output_bytes.data(), secret_key.data()) != 0) {
            return error::backend_failure;
        }
        return {};
    }

    /**
     * The shared secret, `crypto_scalarmult_curve25519`, which returns -1 for an all-zero
     * result.
     *
     * @return Nothing; `weak_public_key`; `backend_failure`.
     */
    [[nodiscard]] static boost::system::result<void> agree(
        std::span<std::uint8_t const, 32> secret_key,
        std::span<std::uint8_t const, 32> peer_public_key,
        std::span<std::uint8_t, 32> output_bytes) noexcept {
        auto const library_ready = sodium_ready();
        if (!library_ready) {
            return library_ready;
        }
        if (sodium_refused(crypto_scalarmult_curve25519(output_bytes.data(), secret_key.data(),
                                                        peer_public_key.data()))) {
            return error::weak_public_key;
        }
        return {};
    }
};

}  // namespace webcpp::crypto::detail

#endif  // X25519 on libsodium

// The boxes on libsodium, for a program that includes public_key_encryption/box.hpp, before this
// header or after it, as Ed25519's above.
#if defined(WEBCPP_CRYPTO_PUBLIC_KEY_ENCRYPTION_BOX_HPP) && defined(WEBCPP_CRYPTO_HAS_SODIUM) && \
    !defined(WEBCPP_CRYPTO_BACKENDS_SODIUM_BOX)
/** Defined once libsodium's box engines are. */
#define WEBCPP_CRYPTO_BACKENDS_SODIUM_BOX

#include <webcpp/crypto/detail/wipe.hpp>

#include <sodium/crypto_box.h>
#include <sodium/crypto_box_curve25519xchacha20poly1305.h>

#include <array>
#include <cstdint>
#include <span>

namespace webcpp::crypto::detail {

/** libsodium's functions of a box family, which differ only by name. */
template <class Family>
struct sodium_box_calls;

/** `crypto_box`, X25519-XSalsa20-Poly1305. */
template <>
struct sodium_box_calls<families::box_xsalsa20poly1305> {
    /** Agrees the key. */
    static constexpr auto beforenm_call = &crypto_box_beforenm;
    /** Encrypts and computes the tag apart. */
    static constexpr auto encrypt_call = &crypto_box_detached_afternm;
    /** Checks the tag apart, then decrypts. */
    static constexpr auto decrypt_call = &crypto_box_open_detached_afternm;
};

/** `crypto_box_curve25519xchacha20poly1305`, X25519-XChaCha20-Poly1305. */
template <>
struct sodium_box_calls<families::box_xchacha20poly1305> {
    /** Agrees the key. */
    static constexpr auto beforenm_call = &crypto_box_curve25519xchacha20poly1305_beforenm;
    /** Encrypts and computes the tag apart. */
    static constexpr auto encrypt_call = &crypto_box_curve25519xchacha20poly1305_detached_afternm;
    /** Checks the tag apart, then decrypts. */
    static constexpr auto decrypt_call =
        &crypto_box_curve25519xchacha20poly1305_open_detached_afternm;
};

/** What a box stores on libsodium: the key `beforenm` agreed. */
template <class Family>
    requires requires { sodium_box_calls<Family>::beforenm_call; }
struct box_state<Family, backends::sodium> {
    /** The agreed key. */
    std::array<unsigned char, 32> key{};
};

/** A box on libsodium: `beforenm` once, then the `afternm` functions per message. */
template <class Family>
    requires requires { sodium_box_calls<Family>::beforenm_call; }
struct box_engine<Family, backends::sodium> {
    /** The state. */
    using state = box_state<Family, backends::sodium>;
    /** libsodium's functions of the family. */
    using calls = sodium_box_calls<Family>;

    /**
     * Agrees the key: X25519 of the secret key and the peer's public key, which libsodium
     * refuses for a peer key of small order, then the family's key derivation.
     *
     * @return Nothing; `weak_public_key`; `backend_failure` when libsodium cannot start.
     */
    [[nodiscard]] static boost::system::result<void> init(
        state& engine_state, std::span<std::uint8_t const, 32> secret_key,
        std::span<std::uint8_t const, 32> peer_public_key) noexcept {
        auto const library_ready = sodium_ready();
        if (!library_ready) {
            return library_ready;
        }
        if (sodium_refused(calls::beforenm_call(engine_state.key.data(), peer_public_key.data(),
                                                secret_key.data()))) {
            wipe_object(engine_state.key);
            return error::weak_public_key;
        }
        return {};
    }

    /**
     * Encrypts `data_bytes` in place and writes the tag.
     *
     * @return Nothing; `backend_failure` when libsodium fails.
     */
    [[nodiscard]] static boost::system::result<void> seal(
        state& engine_state, std::span<std::uint8_t const, 24> iv_bytes,
        std::span<std::uint8_t> data_bytes, boost::hash2::digest<16>& tag_bytes) noexcept {
        read_canary(WEBCPP_CRYPTO_DETAIL_SODIUM_CANARY);
        return sodium_secretbox_seal(calls::encrypt_call,
                                     std::span<unsigned char const, 32>(engine_state.key), iv_bytes,
                                     data_bytes, tag_bytes);
    }

    /**
     * Checks the tag, then decrypts `data_bytes` in place.
     *
     * @return Nothing; `authentication_failed` when the tag does not match.
     */
    [[nodiscard]] static boost::system::result<void> open(
        state& engine_state, std::span<std::uint8_t const, 24> iv_bytes,
        std::span<std::uint8_t> data_bytes,
        std::array<std::uint8_t, 16> const& tag_bytes) noexcept {
        read_canary(WEBCPP_CRYPTO_DETAIL_SODIUM_CANARY);
        return sodium_secretbox_open(calls::decrypt_call,
                                     std::span<unsigned char const, 32>(engine_state.key), iv_bytes,
                                     data_bytes, tag_bytes);
    }

    /** Moves the key; the source is wiped. */
    static void move(state& target_state, state& source_state) noexcept {
        target_state.key = source_state.key;
        wipe_object(source_state.key);
    }

    /** Wipes the key. */
    static void reset(state& engine_state) noexcept { wipe_object(engine_state.key); }
};

}  // namespace webcpp::crypto::detail

#endif  // the boxes on libsodium

// Sealed boxes on libsodium, for a program that includes public_key_encryption/sealed_box.hpp,
// before this header or after it, as Ed25519's above.
#if defined(WEBCPP_CRYPTO_PUBLIC_KEY_ENCRYPTION_SEALED_BOX_HPP) && \
    defined(WEBCPP_CRYPTO_HAS_SODIUM) && !defined(WEBCPP_CRYPTO_BACKENDS_SODIUM_SEALED_BOX)
/** Defined once libsodium's sealed box engine is. */
#define WEBCPP_CRYPTO_BACKENDS_SODIUM_SEALED_BOX

#include <sodium/crypto_box.h>

#include <cstdint>
#include <span>

namespace webcpp::crypto::detail {

/** Sealed boxes on libsodium, `crypto_box_seal` and `crypto_box_seal_open`. */
template <>
struct sealed_box_engine<families::sealed_box, backends::sodium> {
    /**
     * Seals `message_bytes` into `output_bytes` (`basic_sealed_box` has checked the sizes):
     * libsodium draws the key pair from its own generator and wipes its secret key.
     *
     * @return Nothing; `weak_public_key` for a recipient key of small order, which libsodium's
     * box refuses; `backend_failure` when libsodium cannot start.
     */
    [[nodiscard]] static boost::system::result<void> seal(
        std::span<std::uint8_t const, 32> recipient_public_key,
        std::span<std::uint8_t const> message_bytes,
        std::span<std::uint8_t> output_bytes) noexcept {
        auto const library_ready = sodium_ready();
        if (!library_ready) {
            return library_ready;
        }
        if (crypto_box_seal(output_bytes.data(), message_bytes.data(), message_bytes.size(),
                            recipient_public_key.data()) != 0) {
            return error::weak_public_key;
        }
        return {};
    }

    /**
     * Opens `sealed_bytes` into `output_bytes` (`basic_sealed_box` has checked the sizes).
     *
     * @return Nothing; `authentication_failed`; `backend_failure` when libsodium cannot start.
     */
    [[nodiscard]] static boost::system::result<void> open(
        std::span<std::uint8_t const, 32> recipient_public_key,
        std::span<std::uint8_t const, 32> recipient_secret_key,
        std::span<std::uint8_t const> sealed_bytes, std::span<std::uint8_t> output_bytes) noexcept {
        auto const library_ready = sodium_ready();
        if (!library_ready) {
            return library_ready;
        }
        if (sodium_refused(crypto_box_seal_open(output_bytes.data(), sealed_bytes.data(),
                                                sealed_bytes.size(), recipient_public_key.data(),
                                                recipient_secret_key.data()))) {
            return error::authentication_failed;
        }
        return {};
    }
};

}  // namespace webcpp::crypto::detail

#endif  // sealed boxes on libsodium
// RFC 8410's key formats on libsodium, for a program that includes curves/ed25519/formats.hpp or
// curves/x25519/formats.hpp, before this header or after it, as Ed25519's above: each defines
// its macro ..._FORMATS_DECLARED once its declarations are, then includes this header. RFC 8410
// fixes the layout around the 32 key bytes, so libsodium's engine writes and compares its
// prefixes, constants rather than cryptography (design D30).
#if (defined(WEBCPP_CRYPTO_DETAIL_ED25519_FORMATS_DECLARED) || \
     defined(WEBCPP_CRYPTO_DETAIL_X25519_FORMATS_DECLARED)) && \
    defined(WEBCPP_CRYPTO_HAS_SODIUM) && !defined(WEBCPP_CRYPTO_BACKENDS_SODIUM_RFC8410)
/** Defined once libsodium's RFC 8410 layouts are. */
#define WEBCPP_CRYPTO_BACKENDS_SODIUM_RFC8410

#include <webcpp/crypto/constant_time_equal.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace webcpp::crypto::detail {

/**
 * RFC 8410's fixed layouts on libsodium: a prefix, then 32 key bytes. A decoding is accepted
 * only where its prefix is the one encoding the key gives, compared with `constant_time_equal`, and
 * its size the one size (the callers check it), which is design D30's re-encoding test for a fixed
 * layout.
 */
struct sodium_rfc8410 {
    /**
     * Writes the prefix, then the key.
     *
     * @param prefix_bytes The format's prefix.
     * @param key_bytes 32 bytes.
     * @param output_bytes The prefix's size and 32 bytes.
     */
    template <std::size_t PrefixSize>
    static void encode(std::array<std::uint8_t, PrefixSize> const& prefix_bytes,
                       std::span<std::uint8_t const, 32> key_bytes,
                       std::span<std::uint8_t, PrefixSize + 32> output_bytes) noexcept {
        read_canary(WEBCPP_CRYPTO_DETAIL_SODIUM_CANARY);
        std::ranges::copy(key_bytes, std::ranges::copy(prefix_bytes, output_bytes.begin()).out);
    }

    /**
     * Copies the key out of an encoding whose prefix is the format's.
     *
     * @param prefix_bytes The format's prefix.
     * @param der_bytes The prefix's size and 32 bytes.
     * @param key_bytes 32 bytes, written only when the prefix is the format's.
     * @return Nothing; `invalid_encoding`.
     */
    template <std::size_t PrefixSize>
    [[nodiscard]] static boost::system::result<void> decode(
        std::array<std::uint8_t, PrefixSize> const& prefix_bytes,
        std::span<std::uint8_t const, PrefixSize + 32> der_bytes,
        std::span<std::uint8_t, 32> key_bytes) noexcept {
        read_canary(WEBCPP_CRYPTO_DETAIL_SODIUM_CANARY);
        if (!constant_time_equal(der_bytes.template first<PrefixSize>(), prefix_bytes)) {
            return error::invalid_encoding;
        }
        std::ranges::copy(der_bytes.template last<32>(), key_bytes.begin());
        return {};
    }
};

}  // namespace webcpp::crypto::detail

#endif  // RFC 8410 on libsodium

#if defined(WEBCPP_CRYPTO_DETAIL_ED25519_FORMATS_DECLARED) && defined(WEBCPP_CRYPTO_HAS_SODIUM) && \
    !defined(WEBCPP_CRYPTO_BACKENDS_SODIUM_ED25519_FORMATS)
/** Defined once libsodium's Ed25519 formats engine is. */
#define WEBCPP_CRYPTO_BACKENDS_SODIUM_ED25519_FORMATS

namespace webcpp::crypto::detail {

/** Ed25519's SPKI and PKCS#8 on libsodium: RFC 8410's prefixes around the key bytes. */
template <>
struct ed25519_formats_engine<families::ed25519, backends::sodium> {
    /** Writes the SPKI. */
    static void encode_spki(std::span<std::uint8_t const, 32> public_key,
                            std::span<std::uint8_t, 44> output_bytes) noexcept {
        sodium_rfc8410::encode(ed25519_spki_prefix, public_key, output_bytes);
    }

    /**
     * Reads the public key of an SPKI.
     *
     * @return Nothing; `invalid_encoding`.
     */
    [[nodiscard]] static boost::system::result<void> decode_spki(
        std::span<std::uint8_t const, 44> spki_bytes,
        std::span<std::uint8_t, 32> public_key) noexcept {
        return sodium_rfc8410::decode(ed25519_spki_prefix, spki_bytes, public_key);
    }

    /** Writes the PKCS#8 of the seed, the first half of libsodium's secret key. */
    static void encode_pkcs8(ed25519_state<families::ed25519, backends::sodium> const& keyed_state,
                             std::span<std::uint8_t, 48> output_bytes) noexcept {
        sodium_rfc8410::encode(ed25519_pkcs8_prefix,
                               std::span<std::uint8_t const>(keyed_state.secret_key).first<32>(),
                               output_bytes);
    }

    /**
     * Reads the seed of a PKCS#8.
     *
     * @return Nothing; `invalid_encoding`.
     */
    [[nodiscard]] static boost::system::result<void> decode_pkcs8(
        std::span<std::uint8_t const, 48> pkcs8_bytes,
        std::span<std::uint8_t, 32> seed_bytes) noexcept {
        return sodium_rfc8410::decode(ed25519_pkcs8_prefix, pkcs8_bytes, seed_bytes);
    }
};

}  // namespace webcpp::crypto::detail

#endif  // Ed25519's formats on libsodium

#if defined(WEBCPP_CRYPTO_DETAIL_X25519_FORMATS_DECLARED) && defined(WEBCPP_CRYPTO_HAS_SODIUM) && \
    !defined(WEBCPP_CRYPTO_BACKENDS_SODIUM_X25519_FORMATS)
/** Defined once libsodium's X25519 formats engine is. */
#define WEBCPP_CRYPTO_BACKENDS_SODIUM_X25519_FORMATS

namespace webcpp::crypto::detail {

/** X25519's SPKI and PKCS#8 on libsodium: RFC 8410's prefixes around the key bytes. */
template <>
struct x25519_formats_engine<families::x25519, backends::sodium> {
    /** Writes the SPKI. */
    static void encode_spki(std::span<std::uint8_t const, 32> public_key,
                            std::span<std::uint8_t, 44> output_bytes) noexcept {
        sodium_rfc8410::encode(x25519_spki_prefix, public_key, output_bytes);
    }

    /**
     * Reads the public key of an SPKI.
     *
     * @return Nothing; `invalid_encoding`.
     */
    [[nodiscard]] static boost::system::result<void> decode_spki(
        std::span<std::uint8_t const, 44> spki_bytes,
        std::span<std::uint8_t, 32> public_key) noexcept {
        return sodium_rfc8410::decode(x25519_spki_prefix, spki_bytes, public_key);
    }

    /** Writes the PKCS#8 of a secret key. */
    static void encode_pkcs8(std::span<std::uint8_t const, 32> secret_key,
                             std::span<std::uint8_t, 48> output_bytes) noexcept {
        sodium_rfc8410::encode(x25519_pkcs8_prefix, secret_key, output_bytes);
    }

    /**
     * Reads the secret key of a PKCS#8.
     *
     * @return Nothing; `invalid_encoding`.
     */
    [[nodiscard]] static boost::system::result<void> decode_pkcs8(
        std::span<std::uint8_t const, 48> pkcs8_bytes,
        std::span<std::uint8_t, 32> secret_key) noexcept {
        return sodium_rfc8410::decode(x25519_pkcs8_prefix, pkcs8_bytes, secret_key);
    }
};

}  // namespace webcpp::crypto::detail

#endif  // X25519's formats on libsodium

// PEM's base64 on libsodium, for a program that includes pem.hpp, before this header or after
// it, as Ed25519's above.
#if defined(WEBCPP_CRYPTO_PEM_HPP) && defined(WEBCPP_CRYPTO_HAS_SODIUM) && \
    !defined(WEBCPP_CRYPTO_BACKENDS_SODIUM_PEM)
/** Defined once libsodium's PEM engine is. */
#define WEBCPP_CRYPTO_BACKENDS_SODIUM_PEM

#include <webcpp/crypto/detail/wipe.hpp>

#include <sodium/utils.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace webcpp::crypto::detail {

/**
 * PEM's base64 on libsodium: `sodium_bin2base64` and `sodium_base642bin` with the original
 * alphabet and padding (`sodium_base64_VARIANT_ORIGINAL`), whose time does not depend on the
 * bytes, a private key's in a PKCS#8.
 */
template <>
struct pem_engine<families::pem, backends::sodium> {
    /**
     * Initialises libsodium.
     *
     * @return Nothing; `backend_failure`.
     */
    [[nodiscard]] static boost::system::result<void> ready() noexcept { return sodium_ready(); }

    /**
     * The base64 of at most 48 bytes, with padding.
     *
     * @param input_bytes 1 to 48 bytes.
     * @param output_characters Exactly the base64's characters, four per three bytes begun.
     */
    static void encode(std::span<std::uint8_t const> input_bytes,
                       std::span<char> output_characters) noexcept {
        read_canary(WEBCPP_CRYPTO_DETAIL_SODIUM_CANARY);
        // libsodium ends the text with a NUL, which `output_characters` does not hold.
        // NOLINTNEXTLINE(readability-math-missing-parentheses,bugprone-signed-bitwise): its macro
        std::array<char, sodium_base64_ENCODED_LEN(48, sodium_base64_VARIANT_ORIGINAL)>
            base64_text{};
        static_cast<void>(sodium_bin2base64(base64_text.data(), base64_text.size(),
                                            input_bytes.data(), input_bytes.size(),
                                            sodium_base64_VARIANT_ORIGINAL));
        std::ranges::copy(std::span<char const>(base64_text).first(output_characters.size()),
                          output_characters.begin());
        wipe_object(base64_text);
    }

    /**
     * The bytes of at most 64 characters of base64 with padding.
     *
     * @param base64_text 1 to 64 characters.
     * @param output_bytes 48 bytes, of which the decoded are written.
     * @return The bytes' count; `invalid_encoding` for a character outside the alphabet, padding
     * missing or misplaced, or characters left over.
     */
    [[nodiscard]] static boost::system::result<std::size_t> decode(
        std::string_view base64_text, std::span<std::uint8_t, 48> output_bytes) noexcept {
        read_canary(WEBCPP_CRYPTO_DETAIL_SODIUM_CANARY);
        std::size_t written_count = 0;
        char const* parse_end = nullptr;
        if (sodium_base642bin(output_bytes.data(), output_bytes.size(), base64_text.data(),
                              base64_text.size(), nullptr, &written_count, &parse_end,
                              sodium_base64_VARIANT_ORIGINAL) != 0 ||
            parse_end != base64_text.data() + base64_text.size()) {
            return error::invalid_encoding;
        }
        return written_count;
    }
};

}  // namespace webcpp::crypto::detail

#endif  // PEM on libsodium
// crypto_kx on libsodium, for a program that includes key_exchange/kx.hpp, before this header or
// after it, as Ed25519's above.
#if defined(WEBCPP_CRYPTO_KEY_EXCHANGE_KX_HPP) && defined(WEBCPP_CRYPTO_HAS_SODIUM) && \
    !defined(WEBCPP_CRYPTO_BACKENDS_SODIUM_KX)
/** Defined once libsodium's crypto_kx engine is. */
#define WEBCPP_CRYPTO_BACKENDS_SODIUM_KX

#include <webcpp/crypto/detail/wipe.hpp>

#include <sodium/crypto_kx.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <span>

namespace webcpp::crypto::detail {

/** What a crypto_kx key pair stores on libsodium. */
template <>
struct kx_state<families::kx, backends::sodium> {
    /** libsodium's secret key, first, where the wipe test reads it. */
    std::array<unsigned char, crypto_kx_SECRETKEYBYTES> secret_key{};
    /** The public key. */
    std::array<unsigned char, crypto_kx_PUBLICKEYBYTES> public_key{};
};

/** crypto_kx on libsodium, `crypto_kx_*`. */
template <>
struct kx_engine<families::kx, backends::sodium> {
    /** The key pair's state. */
    using state = kx_state<families::kx, backends::sodium>;

    /**
     * Makes the key pair of a seed, `crypto_kx_seed_keypair`.
     *
     * @return Nothing; `backend_failure`.
     */
    [[nodiscard]] static boost::system::result<void> seed_keypair(
        state& keyed_state,
        std::span<std::uint8_t const, crypto_kx_SEEDBYTES> seed_bytes) noexcept {
        auto const library_ready = sodium_ready();
        if (!library_ready) {
            return library_ready;
        }
        if (crypto_kx_seed_keypair(keyed_state.public_key.data(), keyed_state.secret_key.data(),
                                   seed_bytes.data()) != 0) {
            return error::backend_failure;
        }
        return {};
    }

    /** The public key. */
    static void public_key(
        state const& keyed_state,
        std::span<std::uint8_t, crypto_kx_PUBLICKEYBYTES> output_bytes) noexcept {
        std::ranges::copy(keyed_state.public_key, output_bytes.begin());
    }

    /**
     * The client's session keys, `crypto_kx_client_session_keys`, which returns -1 for a server
     * key whose X25519 shared secret is all zero.
     *
     * @return Nothing; `weak_public_key`.
     */
    [[nodiscard]] static boost::system::result<void> client(
        state const& keyed_state,
        std::span<std::uint8_t const, crypto_kx_PUBLICKEYBYTES> server_key,
        std::span<std::uint8_t, crypto_kx_SESSIONKEYBYTES> receive_key,
        std::span<std::uint8_t, crypto_kx_SESSIONKEYBYTES> transmit_key) noexcept {
        read_canary(WEBCPP_CRYPTO_DETAIL_SODIUM_CANARY);
        if (sodium_refused(crypto_kx_client_session_keys(
                receive_key.data(), transmit_key.data(), keyed_state.public_key.data(),
                keyed_state.secret_key.data(), server_key.data()))) {
            return error::weak_public_key;
        }
        return {};
    }

    /**
     * The server's session keys, `crypto_kx_server_session_keys`, which returns -1 for a client
     * key whose X25519 shared secret is all zero.
     *
     * @return Nothing; `weak_public_key`.
     */
    [[nodiscard]] static boost::system::result<void> server(
        state const& keyed_state,
        std::span<std::uint8_t const, crypto_kx_PUBLICKEYBYTES> client_key,
        std::span<std::uint8_t, crypto_kx_SESSIONKEYBYTES> receive_key,
        std::span<std::uint8_t, crypto_kx_SESSIONKEYBYTES> transmit_key) noexcept {
        read_canary(WEBCPP_CRYPTO_DETAIL_SODIUM_CANARY);
        if (sodium_refused(crypto_kx_server_session_keys(
                receive_key.data(), transmit_key.data(), keyed_state.public_key.data(),
                keyed_state.secret_key.data(), client_key.data()))) {
            return error::weak_public_key;
        }
        return {};
    }

    /** Wipes the key pair. */
    static void reset(state& keyed_state) noexcept { wipe_object(keyed_state); }
};

}  // namespace webcpp::crypto::detail

#endif  // crypto_kx on libsodium
