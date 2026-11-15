// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 secp256k1 on libsecp256k1: BIP340 Schnorr and ECDSA signatures, their verification, and
 ECDH; ECDSA's DER and low-S forms, and the tweak of an x-only key.

 @see "secp256k1", in the guide.
*/
#ifndef WEBCPP_CRYPTO_CURVES_SECP256K1_HPP
#define WEBCPP_CRYPTO_CURVES_SECP256K1_HPP

#include <webcpp/crypto/config.hpp>

#include <webcpp/crypto/backends/secp256k1.hpp>
#include <webcpp/crypto/detail/wipe.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/random_device.hpp>  // lint-world: the context's randomisation, its purpose

#include <boost/system/result.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory_resource>
#include <span>
#include <type_traits>
#include <utility>

// clang-format off
/** The refusal of a backend other than libsecp256k1 by `curves::secp256k1`. */
#define WEBCPP_CRYPTO_DETAIL_SECP256K1_ONLY "webcpp::crypto: curves::secp256k1 runs on libsecp256k1 alone. Name backends::secp256k1, or leave the backend out, as in curves::secp256k1::keypair."
// clang-format on

namespace webcpp::crypto::detail {

// NOLINTBEGIN(bugprone-signed-bitwise): libsecp256k1's macros shift a signed constant
/** The flags of a context that signs and verifies: none. */
inline constexpr unsigned secp256k1_context_flags = SECP256K1_CONTEXT_NONE;

/** The flag of the SEC1 compressed form. */
inline constexpr unsigned secp256k1_compressed = SECP256K1_EC_COMPRESSED;
// NOLINTEND(bugprone-signed-bitwise)

/**
 * The error of a key pair whose context could not be randomised: every failure of the
 * generator is `entropy_unavailable`, the library's one word for it.
 *
 * Tip: the system's generator answers `errc::not_supported` where there is none (an
 * Emscripten audio worklet); a key pair's caller handles one error for both.
 */
inline boost::system::error_code secp256k1_seed_error(
    boost::system::error_code /*generator*/) noexcept {
    return error::entropy_unavailable;
}

/**
 * Secret bytes out of a key pair, its secret key or its context's seed, wiped when the scope
 * ends on every path, a failure's or an exception's included.
 */
struct secp256k1_secret {
    /** The secret bytes. */
    std::array<unsigned char, 32> bytes{};

    /** Wipes the bytes. */
    ~secp256k1_secret() { wipe(bytes.data(), bytes.size()); }
};

/**
 * Parses a public key of 33 bytes, compressed, or 65, uncompressed. libsecp256k1 also
 * accepts X9.62's hybrid forms, prefix 06 or 07, of 65 bytes; they are refused here, as every
 * prefix other than 02, 03 and 04 is.
 *
 * @param key The key, SEC1.
 * @param parsed Where the parsed key goes.
 * @return Whether it is a key: false in every way it can be wrong, `invalid_public_key` to the
 * caller.
 */
[[nodiscard]] inline bool secp256k1_parse_public_key(std::span<std::uint8_t const> key,
                                                     secp256k1_pubkey& parsed) noexcept {
    bool const sized = key.size() == 33 || (key.size() == 65 && key[0] == 0x04);
    return sized && secp256k1_ec_pubkey_parse(secp256k1_context_static, &parsed, key.data(),
                                              key.size()) != 0;
}

/**
 * Whether 32 bytes of a compact signature, its r or its s, are not zero.
 *
 * @param half The 32 bytes.
 * @return Whether one byte is not zero.
 */
[[nodiscard]] inline bool secp256k1_nonzero(std::span<std::uint8_t const, 32> half) noexcept {
    return std::ranges::any_of(half, [](std::uint8_t b) { return b != 0; });
}

/**
 * Parses a compact ECDSA signature, r then s, each below the group order and not zero.
 *
 * @param compact The 64 bytes.
 * @param parsed Where the parsed signature goes.
 * @return Whether it is a signature: false in every way it can be wrong, `invalid_signature` to
 * the caller.
 */
[[nodiscard]] inline bool secp256k1_parse_compact(std::span<std::uint8_t const, 64> compact,
                                                  secp256k1_ecdsa_signature& parsed) noexcept {
    return secp256k1_ecdsa_signature_parse_compact(secp256k1_context_static, &parsed,
                                                   compact.data()) != 0 &&
           secp256k1_nonzero(compact.first<32>()) && secp256k1_nonzero(compact.last<32>());
}

/**
 * The compact form of a signature a DER parser read, refused when its r or its s is zero,
 * which is how libsecp256k1's parsers give a number not below the group order.
 *
 * @param parsed The signature.
 * @param out Where the 64 bytes go.
 * @return Whether r and s are both in range.
 */
[[nodiscard]] inline bool secp256k1_compact_of(secp256k1_ecdsa_signature const& parsed,
                                               std::array<std::uint8_t, 64>& out) noexcept {
    secp256k1_ecdsa_signature_serialize_compact(secp256k1_context_static, out.data(), &parsed);
    return secp256k1_nonzero(std::span<std::uint8_t const, 64>(out).first<32>()) &&
           secp256k1_nonzero(std::span<std::uint8_t const, 64>(out).last<32>());
}

/**
 * Whether `Backend` is libsecp256k1, the one backend of `curves::secp256k1`.
 *
 * @tparam Backend The backend a function or the key pair names.
 */
template <class Backend>
inline constexpr bool secp256k1_backend = std::is_same_v<Backend, backends::secp256k1>;

}  // namespace webcpp::crypto::detail

namespace webcpp::crypto::curves::secp256k1 {

/** The longest strict DER encoding of a secp256k1 ECDSA signature, in bytes. */
inline constexpr std::size_t max_der_size = 72;

/** A tweaked x-only key: the key and the parity of its point's y. */
struct tweaked_xonly_key {
    /** The 32-byte x-only key. */
    std::array<std::uint8_t, 32> key;
    /** 0 when the tweaked point's y is even, 1 when it is odd. */
    int parity;
};

/**
 * A secp256k1 key pair on libsecp256k1, with a signing context of its own in the resource it
 * is given, randomised from the random device as libsecp256k1 recommends.
 *
 * @tparam Backend `backends::secp256k1`, its only backend.
 */
template <class Backend = backends::secp256k1>
class basic_keypair {
    static_assert(webcpp::crypto::detail::secp256k1_backend<Backend>,
                  WEBCPP_CRYPTO_DETAIL_SECP256K1_ONLY);

public:
    /** The backend. */
    using backend_type = Backend;

    /**
     * Makes a key pair from a secret key.
     *
     * @param secret 32 bytes, not zero and below the group order.
     * @param memory The resource of the signing context, the one allocation; it must outlive
     * the key pair.
     * @return The key pair; `invalid_key_size`; `invalid_secret_key`;
     * `entropy_unavailable`, also where there is no generator at all (an Emscripten audio
     * worklet), whatever the generator's own error; `backend_failure`, should libsecp256k1 refuse
     * the context's randomisation or the key pair after the secret's check, which v0.8.0 does not
     * (its `secp256k1_context_randomize` fails only on the static context, and
     * `secp256k1_keypair_create` only on a secret `secp256k1_ec_seckey_verify` refuses). A
     * failed allocation is the resource's to report; the seed is wiped then too.
     */
    [[nodiscard]] static boost::system::result<basic_keypair> make(
        std::span<std::uint8_t const> secret,
        std::pmr::memory_resource* memory = std::pmr::get_default_resource()) {
        if (secret.size() != 32) {
            return error::invalid_key_size;
        }
        webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
        secp256k1_selftest();
        if (secp256k1_ec_seckey_verify(secp256k1_context_static, secret.data()) == 0) {
            return error::invalid_secret_key;
        }
        webcpp::crypto::detail::secp256k1_secret seed;
        auto const seeded = random_device().fill(seed.bytes);  // lint-world: the context's seed
        if (!seeded) {
            return webcpp::crypto::detail::secp256k1_seed_error(seeded.error());
        }
        basic_keypair made;
        made.memory_ = memory;
        made.context_ = secp256k1_context_preallocated_create(
            memory->allocate(context_size(), alignof(std::max_align_t)),
            webcpp::crypto::detail::secp256k1_context_flags);
        int const randomised = secp256k1_context_randomize(made.context_, seed.bytes.data());
        if (randomised == 0 ||
            secp256k1_keypair_create(made.context_, &made.keypair_, secret.data()) == 0) {
            return error::backend_failure;
        }
        made.keyed_ = true;
        return made;
    }

    /**
     * Moves the key pair and its context; the source is wiped and empty.
     *
     * @param other The source, empty afterwards.
     */
    basic_keypair(basic_keypair&& other) noexcept
        : context_(std::exchange(other.context_, nullptr)),
          memory_(other.memory_),
          keypair_(other.keypair_),
          keyed_(std::exchange(other.keyed_, false)) {
        webcpp::crypto::detail::wipe_object(other.keypair_);
    }

    /**
     * Moves over this key pair, which is wiped and gives its context back first.
     *
     * @param other The source, empty afterwards.
     * @return This key pair.
     */
    basic_keypair& operator=(basic_keypair&& other) noexcept {
        if (this != &other) {
            release();
            context_ = std::exchange(other.context_, nullptr);
            memory_ = other.memory_;
            keypair_ = other.keypair_;
            keyed_ = std::exchange(other.keyed_, false);
            webcpp::crypto::detail::wipe_object(other.keypair_);
        }
        return *this;
    }

    /** Not copyable: a key pair's secret and context have one owner. */
    basic_keypair(basic_keypair const&) = delete;
    /** Not copyable: a key pair's secret and context have one owner. */
    basic_keypair& operator=(basic_keypair const&) = delete;

    /** Wipes the key pair and gives the context back to its resource. */
    ~basic_keypair() { release(); }

    /**
     * The BIP340 x-only public key.
     *
     * @return 32 bytes; `invalid_state` moved from.
     */
    [[nodiscard]] boost::system::result<std::array<std::uint8_t, 32>> xonly_public_key()
        const noexcept {
        if (!keyed_) {
            return error::invalid_state;
        }
        webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
        secp256k1_xonly_pubkey xonly{};
        std::array<std::uint8_t, 32> out{};
        secp256k1_keypair_xonly_pub(context_, &xonly, nullptr, &keypair_);
        secp256k1_xonly_pubkey_serialize(context_, out.data(), &xonly);
        return out;
    }

    /**
     * The public key, SEC1 compressed.
     *
     * @return 33 bytes; `invalid_state` moved from.
     */
    [[nodiscard]] boost::system::result<std::array<std::uint8_t, 33>> public_key() const noexcept {
        if (!keyed_) {
            return error::invalid_state;
        }
        webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
        secp256k1_pubkey key{};
        std::array<std::uint8_t, 33> out{};
        std::size_t size = out.size();
        secp256k1_keypair_pub(context_, &key, &keypair_);
        secp256k1_ec_pubkey_serialize(context_, out.data(), &size, &key,
                                      webcpp::crypto::detail::secp256k1_compressed);
        return out;
    }

    /**
     * A BIP340 signature of a message of any length.
     *
     * @param message The message.
     * @param aux 32 bytes of fresh randomness, the caller's.
     * @return 64 bytes; `invalid_state` moved from; `backend_failure`.
     */
    [[nodiscard]] boost::system::result<std::array<std::uint8_t, 64>> sign_schnorr(
        std::span<std::uint8_t const> message,
        std::span<std::uint8_t const, 32> aux) const noexcept {
        if (!keyed_) {
            return error::invalid_state;
        }
        webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
        webcpp::crypto::detail::secp256k1_secret randomness;
        std::ranges::copy(aux, randomness.bytes.begin());
        secp256k1_schnorrsig_extraparams extra = SECP256K1_SCHNORRSIG_EXTRAPARAMS_INIT;
        extra.ndata = randomness.bytes.data();
        std::array<std::uint8_t, 64> out{};
        if (secp256k1_schnorrsig_sign_custom(context_, out.data(), message.data(), message.size(),
                                             &keypair_, &extra) == 0) {
            return error::backend_failure;
        }
        return out;
    }

    /**
     * An ECDSA signature of a 32-byte hash: RFC 6979's nonce, low-S, compact form.
     *
     * @param hash The hash.
     * @return 64 bytes, r then s; `invalid_state` moved from; `backend_failure`.
     */
    [[nodiscard]] boost::system::result<std::array<std::uint8_t, 64>> sign_ecdsa(
        std::span<std::uint8_t const, 32> hash) const noexcept {
        if (!keyed_) {
            return error::invalid_state;
        }
        webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
        webcpp::crypto::detail::secp256k1_secret secret;
        secp256k1_keypair_sec(context_, secret.bytes.data(), &keypair_);
        secp256k1_ecdsa_signature signature{};
        std::array<std::uint8_t, 64> out{};
        if (secp256k1_ecdsa_sign(context_, &signature, hash.data(), secret.bytes.data(), nullptr,
                                 nullptr) == 0) {
            return error::backend_failure;
        }
        secp256k1_ecdsa_signature_serialize_compact(context_, out.data(), &signature);
        return out;
    }

    /**
     * The SHA-256 of the compressed shared point with a peer's public key, libsecp256k1's
     * default.
     *
     * @param public_key The peer's key, SEC1: 33 bytes, prefix 02 or 03, or 65, prefix 04.
     * @return 32 bytes; `invalid_state`; `invalid_public_key`; `backend_failure`.
     */
    [[nodiscard]] boost::system::result<std::array<std::uint8_t, 32>> ecdh(
        std::span<std::uint8_t const> public_key) const noexcept {
        if (!keyed_) {
            return error::invalid_state;
        }
        secp256k1_pubkey parsed{};
        if (!webcpp::crypto::detail::secp256k1_parse_public_key(public_key, parsed)) {
            return error::invalid_public_key;
        }
        webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
        webcpp::crypto::detail::secp256k1_secret secret;
        secp256k1_keypair_sec(context_, secret.bytes.data(), &keypair_);
        std::array<std::uint8_t, 32> out{};
        if (secp256k1_ecdh(context_, out.data(), &parsed, secret.bytes.data(), nullptr, nullptr) ==
            0) {
            return error::backend_failure;
        }
        return out;
    }

    /**
     * Tweaks this key pair in place by a 32-byte tweak t: its x-only public key P becomes
     * P + t*G, and its secret key follows (`secp256k1_keypair_xonly_tweak_add`).
     *
     * The caller computes the tweak, as a protocol defines it.
     *
     * Allocates nothing; the pair keeps its context, its wiping and its behaviour when moved
     * from.
     *
     * @param tweak The 32-byte tweak, a big-endian scalar.
     * @return Nothing; `invalid_state` moved from; `invalid_secret_key` for a tweak not below
     * the group order, or one that gives no valid key (negligible, but checked), after which
     * the pair is wiped and empty, as moved from.
     */
    [[nodiscard]] boost::system::result<void> tweak_xonly(
        std::span<std::uint8_t const, 32> tweak) noexcept {
        if (!keyed_) {
            return error::invalid_state;
        }
        webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
        if (secp256k1_keypair_xonly_tweak_add(context_, &keypair_, tweak.data()) == 0) {
            release();
            return error::invalid_secret_key;
        }
        return {};
    }

private:
    basic_keypair() noexcept = default;

    static std::size_t context_size() noexcept {
        return secp256k1_context_preallocated_size(webcpp::crypto::detail::secp256k1_context_flags);
    }

    void release() noexcept {
        webcpp::crypto::detail::wipe_object(keypair_);
        keyed_ = false;
        if (context_ != nullptr) {
            secp256k1_context_preallocated_destroy(context_);
            memory_->deallocate(context_, context_size(), alignof(std::max_align_t));
            context_ = nullptr;
        }
    }

    secp256k1_context* context_ = nullptr;
    std::pmr::memory_resource* memory_ = nullptr;
    secp256k1_keypair keypair_{};
    bool keyed_ = false;
};

/** A key pair on libsecp256k1. */
using keypair = basic_keypair<>;

/**
 * Verifies a BIP340 signature with libsecp256k1's static context, which allocates nothing,
 * after its self-test (`include/secp256k1.h:235-247`).
 *
 * @tparam Backend The backend, `backends::secp256k1`.
 * @param signature 64 bytes.
 * @param message The message, of any length.
 * @param xonly_public_key 32 bytes.
 * @return Nothing; `invalid_public_key`; `invalid_signature`.
 */
template <class Backend = backends::secp256k1>
[[nodiscard]] boost::system::result<void> verify_schnorr(
    std::span<std::uint8_t const, 64> signature, std::span<std::uint8_t const> message,
    std::span<std::uint8_t const, 32> xonly_public_key) noexcept {
    static_assert(webcpp::crypto::detail::secp256k1_backend<Backend>,
                  WEBCPP_CRYPTO_DETAIL_SECP256K1_ONLY);
    webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
    secp256k1_selftest();
    secp256k1_xonly_pubkey key{};
    if (secp256k1_xonly_pubkey_parse(secp256k1_context_static, &key, xonly_public_key.data()) ==
        0) {
        return error::invalid_public_key;
    }
    if (secp256k1_schnorrsig_verify(secp256k1_context_static, signature.data(), message.data(),
                                    message.size(), &key) == 0) {
        return error::invalid_signature;
    }
    return {};
}

/**
 * Verifies an ECDSA signature in compact form with the static context, after its self-test;
 * a high-S signature is refused, as libsecp256k1 refuses it.
 *
 * @tparam Backend The backend, `backends::secp256k1`.
 * @param signature 64 bytes, r then s.
 * @param hash The 32-byte hash signed.
 * @param public_key SEC1: 33 bytes, prefix 02 or 03, or 65, prefix 04.
 * @return Nothing; `invalid_public_key`; `invalid_signature`.
 */
template <class Backend = backends::secp256k1>
[[nodiscard]] boost::system::result<void> verify_ecdsa(
    std::span<std::uint8_t const, 64> signature, std::span<std::uint8_t const, 32> hash,
    std::span<std::uint8_t const> public_key) noexcept {
    static_assert(webcpp::crypto::detail::secp256k1_backend<Backend>,
                  WEBCPP_CRYPTO_DETAIL_SECP256K1_ONLY);
    webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
    secp256k1_selftest();
    secp256k1_pubkey key{};
    if (!webcpp::crypto::detail::secp256k1_parse_public_key(public_key, key)) {
        return error::invalid_public_key;
    }
    secp256k1_ecdsa_signature parsed{};
    if (secp256k1_ecdsa_signature_parse_compact(secp256k1_context_static, &parsed,
                                                signature.data()) == 0 ||
        secp256k1_ecdsa_verify(secp256k1_context_static, &parsed, hash.data(), &key) == 0) {
        return error::invalid_signature;
    }
    return {};
}

/**
 * Encodes a compact ECDSA signature as strict DER (BIP66), with libsecp256k1's own encoder.
 *
 * @tparam Backend The backend, `backends::secp256k1`.
 * @param compact 64 bytes, r then s.
 * @param out At least `max_der_size` bytes, whatever this signature's length; nothing is
 * written on an error.
 * @return The number of bytes written, at most `max_der_size`; `invalid_input_size` when `out`
 * is shorter than `max_der_size`; `invalid_signature` when r or s is zero or not below the
 * group order.
 */
template <class Backend = backends::secp256k1>
[[nodiscard]] boost::system::result<std::size_t> to_der(std::span<std::uint8_t const, 64> compact,
                                                        std::span<std::uint8_t> out) noexcept {
    static_assert(webcpp::crypto::detail::secp256k1_backend<Backend>,
                  WEBCPP_CRYPTO_DETAIL_SECP256K1_ONLY);
    if (out.size() < max_der_size) {
        return error::invalid_input_size;
    }
    webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
    secp256k1_selftest();
    secp256k1_ecdsa_signature parsed{};
    if (!webcpp::crypto::detail::secp256k1_parse_compact(compact, parsed)) {
        return error::invalid_signature;
    }
    std::array<std::uint8_t, max_der_size> der{};
    std::size_t size = der.size();
    secp256k1_ecdsa_signature_serialize_der(secp256k1_context_static, der.data(), &size, &parsed);
    std::ranges::copy(std::span<std::uint8_t const>(der).first(size), out.begin());
    return size;
}

/**
 * Decodes a strict DER ECDSA signature (BIP66, `secp256k1_ecdsa_signature_parse_der`) to its
 * compact form.
 *
 * @tparam Backend The backend, `backends::secp256k1`.
 * @param der The encoding, exactly: nothing may follow it.
 * @return 64 bytes, r then s; `invalid_signature` for anything that is not strict DER, and for
 * an r or an s that is zero or not below the group order.
 */
template <class Backend = backends::secp256k1>
[[nodiscard]] boost::system::result<std::array<std::uint8_t, 64>> from_der(
    std::span<std::uint8_t const> der) noexcept {
    static_assert(webcpp::crypto::detail::secp256k1_backend<Backend>,
                  WEBCPP_CRYPTO_DETAIL_SECP256K1_ONLY);
    if (der.empty()) {
        return error::invalid_signature;
    }
    webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
    secp256k1_selftest();
    secp256k1_ecdsa_signature parsed{};
    std::array<std::uint8_t, 64> out{};
    if (secp256k1_ecdsa_signature_parse_der(secp256k1_context_static, &parsed, der.data(),
                                            der.size()) == 0 ||
        !webcpp::crypto::detail::secp256k1_compact_of(parsed, out)) {
        return error::invalid_signature;
    }
    return out;
}

/**
 * The low-S form of a compact ECDSA signature (`secp256k1_ecdsa_signature_normalize`), the
 * only form `verify_ecdsa` accepts; a low-S signature is returned unchanged.
 *
 * Tip: normalizing makes a signature malleable on purpose; only for signatures from a signer
 * that does not enforce low-S.
 *
 * @tparam Backend The backend, `backends::secp256k1`.
 * @param compact 64 bytes, r then s.
 * @return 64 bytes, r then n - s when s was above half the group order;
 * `invalid_signature` when r or s is zero or not below the group order.
 */
template <class Backend = backends::secp256k1>
[[nodiscard]] boost::system::result<std::array<std::uint8_t, 64>> normalize_ecdsa(
    std::span<std::uint8_t const, 64> compact) noexcept {
    static_assert(webcpp::crypto::detail::secp256k1_backend<Backend>,
                  WEBCPP_CRYPTO_DETAIL_SECP256K1_ONLY);
    webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
    secp256k1_selftest();
    secp256k1_ecdsa_signature parsed{};
    if (!webcpp::crypto::detail::secp256k1_parse_compact(compact, parsed)) {
        return error::invalid_signature;
    }
    secp256k1_ecdsa_signature_normalize(secp256k1_context_static, &parsed, &parsed);
    std::array<std::uint8_t, 64> out{};
    secp256k1_ecdsa_signature_serialize_compact(secp256k1_context_static, out.data(), &parsed);
    return out;
}

/**
 * Tweaks an x-only public key by a 32-byte tweak t: P + t*G, with libsecp256k1's static
 * context, which allocates nothing (`secp256k1_xonly_pubkey_tweak_add`).
 *
 * The caller computes the tweak, as a protocol defines it.
 *
 * @tparam Backend The backend, `backends::secp256k1`.
 * @param xonly_public_key The 32-byte x-only key P.
 * @param tweak The 32-byte tweak, a big-endian scalar.
 * @return The tweaked x-only key and its parity; `invalid_public_key` for a key that is not a
 * point's x; `invalid_secret_key` for a tweak not below the group order, or one that gives
 * no valid key (negligible, but checked).
 */
template <class Backend = backends::secp256k1>
[[nodiscard]] boost::system::result<tweaked_xonly_key> tweak_xonly(
    std::span<std::uint8_t const, 32> xonly_public_key,
    std::span<std::uint8_t const, 32> tweak) noexcept {
    static_assert(webcpp::crypto::detail::secp256k1_backend<Backend>,
                  WEBCPP_CRYPTO_DETAIL_SECP256K1_ONLY);
    webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
    secp256k1_selftest();
    secp256k1_xonly_pubkey key{};
    if (secp256k1_xonly_pubkey_parse(secp256k1_context_static, &key, xonly_public_key.data()) ==
        0) {
        return error::invalid_public_key;
    }
    secp256k1_pubkey tweaked{};
    if (secp256k1_xonly_pubkey_tweak_add(secp256k1_context_static, &tweaked, &key, tweak.data()) ==
        0) {
        return error::invalid_secret_key;
    }
    secp256k1_xonly_pubkey output{};
    tweaked_xonly_key out{};
    secp256k1_xonly_pubkey_from_pubkey(secp256k1_context_static, &output, &out.parity, &tweaked);
    secp256k1_xonly_pubkey_serialize(secp256k1_context_static, out.key.data(), &output);
    return out;
}

}  // namespace webcpp::crypto::curves::secp256k1

#endif  // WEBCPP_CRYPTO_CURVES_SECP256K1_HPP
