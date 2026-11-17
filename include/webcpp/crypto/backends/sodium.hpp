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
#include <webcpp/crypto/detail/engines.hpp>
#include <webcpp/crypto/detail/wipe.hpp>
#include <webcpp/crypto/error.hpp>

#include <sodium/core.h>  // through /third_party//sodium, as webcpp::hash's header does
#include <sodium/crypto_aead_chacha20poly1305.h>
#include <sodium/crypto_aead_xchacha20poly1305.h>
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

extern "C" const char WEBCPP_CRYPTO_DETAIL_SODIUM_CANARY;

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

/** libsodium's detached functions of an AEAD family, which differ only by name. */
template <class Family>
struct sodium_aead_calls;

/** RFC 8439's ChaCha20-Poly1305: libsodium's `_ietf` functions. */
template <>
struct sodium_aead_calls<families::chacha20_poly1305> {
    /** Encrypts and computes the tag apart. */
    static constexpr auto encrypt = &crypto_aead_chacha20poly1305_ietf_encrypt_detached;
    /** Checks the tag apart, then decrypts. */
    static constexpr auto decrypt = &crypto_aead_chacha20poly1305_ietf_decrypt_detached;
};

/** The original ChaCha20-Poly1305: libsodium's functions without a suffix. */
template <>
struct sodium_aead_calls<families::chacha20_poly1305_original> {
    /** Encrypts and computes the tag apart. */
    static constexpr auto encrypt = &crypto_aead_chacha20poly1305_encrypt_detached;
    /** Checks the tag apart, then decrypts. */
    static constexpr auto decrypt = &crypto_aead_chacha20poly1305_decrypt_detached;
};

/** XChaCha20-Poly1305: libsodium's `xchacha20poly1305_ietf` functions. */
template <>
struct sodium_aead_calls<families::xchacha20_poly1305> {
    /** Encrypts and computes the tag apart. */
    static constexpr auto encrypt = &crypto_aead_xchacha20poly1305_ietf_encrypt_detached;
    /** Checks the tag apart, then decrypts. */
    static constexpr auto decrypt = &crypto_aead_xchacha20poly1305_ietf_decrypt_detached;
};

/** An AEAD's state on libsodium: the key, in the object, since libsodium takes it per call. */
template <class Family>
    requires requires { sodium_aead_calls<Family>::encrypt; }
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
    requires requires { sodium_aead_calls<Family>::encrypt; }
struct aead_engine<Family, backends::sodium> {
    /** The state. */
    using state = aead_state<Family, backends::sodium>;
    /** libsodium's functions of the family. */
    using calls = sodium_aead_calls<Family>;

    /**
     * Initialises libsodium and keeps the key.
     *
     * @param s The state.
     * @param key The key, 32 bytes (`aead` has checked its size).
     * @return Nothing; `backend_failure` when libsodium cannot start.
     */
    [[nodiscard]] static boost::system::result<void> init(
        state& s, std::span<std::uint8_t const> key) noexcept {
        auto const ready = sodium_ready();
        if (!ready) {
            return ready;
        }
        std::ranges::copy(key, s.key.begin());
        return {};
    }

    /**
     * Encrypts `data` in place and writes the tag; libsodium reads the nonce and the
     * additional data before it writes a byte of the ciphertext.
     *
     * @return Nothing; `backend_failure` when libsodium fails.
     */
    [[nodiscard]] static boost::system::result<void> seal(
        state& s, std::span<std::uint8_t const> iv, std::span<std::uint8_t const> additional_data,
        std::span<std::uint8_t> data, boost::hash2::digest<16>& tag) noexcept {
        read_canary(WEBCPP_CRYPTO_DETAIL_SODIUM_CANARY);
        unsigned long long tag_length = 0;
        auto* const bytes = writable(data);
        // libsodium encrypts in place when the output is the input (its documented contract).
        if (calls::encrypt(bytes, tag.data(), &tag_length, bytes, data.size(),
                           additional_data.data(), additional_data.size(), nullptr, iv.data(),
                           s.key.data()) != 0) {
            return error::backend_failure;
        }
        return {};
    }

    /**
     * Checks the tag, then decrypts `data` in place.
     *
     * @return Nothing; `authentication_failed` when the tag does not match.
     */
    [[nodiscard]] static boost::system::result<void> open(
        state& s, std::span<std::uint8_t const> iv, std::span<std::uint8_t const> additional_data,
        std::span<std::uint8_t> data, std::array<std::uint8_t, 16> const& tag) noexcept {
        read_canary(WEBCPP_CRYPTO_DETAIL_SODIUM_CANARY);
        auto* const bytes = writable(data);
        if (calls::decrypt(bytes, nullptr, bytes, data.size(), tag.data(), additional_data.data(),
                           additional_data.size(), iv.data(), s.key.data()) != 0) {
            return error::authentication_failed;
        }
        return {};
    }

    /** Moves the key; the source is wiped. */
    static void move(state& to, state& from) noexcept {
        to.key = from.key;
        wipe_object(from.key);
    }

    /** Wipes the key. */
    static void reset(state& s) noexcept { wipe_object(s.key); }

private:
    // The data's first byte, or one of the engine's own for an empty span, whose data() may be
    // null: libsodium clears the output of a failed open with memset, which takes no null
    // pointer, even for no byte.
    static std::uint8_t* writable(std::span<std::uint8_t> data) noexcept {
        static std::uint8_t none = 0;
        return data.empty() ? &none : data.data();
    }
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
    [[nodiscard]] static boost::system::result<void> make(
        state& keyed, std::span<std::uint8_t const, 32> seed) noexcept {
        auto const ready = sodium_ready();
        if (!ready) {
            return ready;
        }
        std::array<unsigned char, crypto_sign_ed25519_PUBLICKEYBYTES> public_key{};
        if (crypto_sign_ed25519_seed_keypair(public_key.data(), keyed.secret_key.data(),
                                             seed.data()) != 0) {
            return error::backend_failure;
        }
        return {};
    }

    /** The public key, the secret key's second half. */
    static void public_key(state const& keyed, std::span<std::uint8_t, 32> out) noexcept {
        read_canary(WEBCPP_CRYPTO_DETAIL_SODIUM_CANARY);
        static_cast<void>(crypto_sign_ed25519_sk_to_pk(out.data(), keyed.secret_key.data()));
    }

    /**
     * Signs a message, `crypto_sign_ed25519_detached`.
     *
     * @return Nothing; `backend_failure`.
     */
    [[nodiscard]] static boost::system::result<void> sign(
        state const& keyed, std::span<std::uint8_t const> message,
        std::span<std::uint8_t, 64> out) noexcept {
        read_canary(WEBCPP_CRYPTO_DETAIL_SODIUM_CANARY);
        if (crypto_sign_ed25519_detached(out.data(), nullptr, message.data(), message.size(),
                                         keyed.secret_key.data()) != 0) {
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
        std::span<std::uint8_t const, 32> public_key, std::span<std::uint8_t const> message,
        std::span<std::uint8_t const, 64> signature) noexcept {
        auto const ready = sodium_ready();
        if (!ready) {
            return ready;
        }
        if (crypto_sign_ed25519_verify_detached(signature.data(), message.data(), message.size(),
                                                public_key.data()) != 0) {
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
        state const& keyed, std::span<std::uint8_t, 32> out) noexcept {
        read_canary(WEBCPP_CRYPTO_DETAIL_SODIUM_CANARY);
        if (crypto_sign_ed25519_sk_to_curve25519(out.data(), keyed.secret_key.data()) != 0) {
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
        std::span<std::uint8_t const, 32> public_key, std::span<std::uint8_t, 32> out) noexcept {
        auto const ready = sodium_ready();
        if (!ready) {
            return ready;
        }
        if (crypto_sign_ed25519_pk_to_curve25519(out.data(), public_key.data()) != 0) {
            return error::invalid_public_key;
        }
        return {};
    }

    /** Wipes the secret key. */
    static void reset(state& keyed) noexcept { wipe_object(keyed.secret_key); }
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
    [[nodiscard]] static boost::system::result<void> begin(state& begun) noexcept {
        auto const ready = sodium_ready();
        if (!ready) {
            return ready;
        }
        if (crypto_sign_ed25519ph_init(&begun.hashing) != 0) {
            return error::backend_failure;
        }
        return {};
    }

    /** Adds a piece, `crypto_sign_ed25519ph_update`, which cannot fail. */
    static void update(state& begun, std::span<std::uint8_t const> piece) noexcept {
        read_canary(WEBCPP_CRYPTO_DETAIL_SODIUM_CANARY);
        static_cast<void>(crypto_sign_ed25519ph_update(&begun.hashing, piece.data(), piece.size()));
    }

    /**
     * Signs the message, `crypto_sign_ed25519ph_final_create`.
     *
     * @return Nothing; `backend_failure`.
     */
    [[nodiscard]] static boost::system::result<void> sign(
        state& begun, ed25519_state<families::ed25519, backends::sodium> const& keyed,
        std::span<std::uint8_t, 64> out) noexcept {
        read_canary(WEBCPP_CRYPTO_DETAIL_SODIUM_CANARY);
        if (crypto_sign_ed25519ph_final_create(&begun.hashing, out.data(), nullptr,
                                               keyed.secret_key.data()) != 0) {
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
        state& begun, std::span<std::uint8_t const, 32> public_key,
        std::span<std::uint8_t const, 64> signature) noexcept {
        read_canary(WEBCPP_CRYPTO_DETAIL_SODIUM_CANARY);
        if (crypto_sign_ed25519ph_final_verify(&begun.hashing, signature.data(),
                                               public_key.data()) != 0) {
            return error::invalid_signature;
        }
        return {};
    }

    /** Wipes the message's state. */
    static void reset(state& begun) noexcept { wipe_object(begun.hashing); }
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
        std::span<std::uint8_t const, 32> secret_key, std::span<std::uint8_t, 32> out) noexcept {
        auto const ready = sodium_ready();
        if (!ready) {
            return ready;
        }
        if (crypto_scalarmult_curve25519_base(out.data(), secret_key.data()) != 0) {
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
        std::span<std::uint8_t, 32> out) noexcept {
        auto const ready = sodium_ready();
        if (!ready) {
            return ready;
        }
        if (crypto_scalarmult_curve25519(out.data(), secret_key.data(), peer_public_key.data()) !=
            0) {
            return error::weak_public_key;
        }
        return {};
    }
};

}  // namespace webcpp::crypto::detail

#endif  // X25519 on libsodium
