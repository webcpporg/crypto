// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 secp256k1 on libsecp256k1: BIP340 Schnorr and ECDSA signatures, their verification, and
 ECDH.

 @see "secp256k1", in the guide.
*/
#ifndef WEBCPP_CRYPTO_SECP256K1_HPP
#define WEBCPP_CRYPTO_SECP256K1_HPP

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
#include <utility>

namespace webcpp::crypto::secp256k1 {

namespace detail {

// A context that signs and verifies needs no flag.
// NOLINTNEXTLINE(bugprone-signed-bitwise): libsecp256k1's macro shifts a signed constant
inline constexpr unsigned context_flags = SECP256K1_CONTEXT_NONE;

// The SEC1 compressed form's flag.
// NOLINTNEXTLINE(bugprone-signed-bitwise): libsecp256k1's macro shifts a signed constant
inline constexpr unsigned compressed = SECP256K1_EC_COMPRESSED;

/**
 * The error of a key pair whose context could not be randomised: every failure of the
 * generator is `entropy_unavailable`, spec 2.8's one word for it.
 *
 * Tip: the system's generator answers `errc::not_supported` where there is none (an
 * Emscripten audio worklet); a key pair's caller handles one error for both.
 */
inline boost::system::error_code seed_error(boost::system::error_code /*generator*/) noexcept {
    return error::entropy_unavailable;
}

/**
 * Secret bytes out of a key pair, its secret key or its context's seed, wiped when the scope
 * ends on every path, a failure's or an exception's included.
 */
struct secret {
    std::array<unsigned char, 32> bytes{};

    ~secret() { webcpp::crypto::detail::wipe(bytes.data(), bytes.size()); }
};

/**
 * Parses a public key of 33 or 65 bytes.
 *
 * @param key The key, SEC1.
 * @param parsed Where the parsed key goes.
 * @return Whether it is a key: false in every way it can be wrong, `invalid_public_key` to the
 * caller.
 */
[[nodiscard]] inline bool parse(std::span<std::uint8_t const> key,
                                secp256k1_pubkey& parsed) noexcept {
    return (key.size() == 33 || key.size() == 65) &&
           secp256k1_ec_pubkey_parse(secp256k1_context_static, &parsed, key.data(), key.size()) !=
               0;
}

}  // namespace detail

/**
 * A secp256k1 key pair on libsecp256k1, with a signing context of its own in the resource it
 * is given, randomised from the random device as libsecp256k1 recommends.
 *
 * @tparam Backend `backends::secp256k1`, its only backend.
 */
template <class Backend = backends::secp256k1>
class basic_keypair {
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
     * `entropy_unavailable`, also where there is no generator at all (an audio worklet,
     * `detail::seed_error`); `backend_failure`, should libsecp256k1 refuse the context's
     * randomisation or the key pair after the secret's check, which v0.8.0 does not (its
     * `secp256k1_context_randomize` fails only on the static context, and
     * `secp256k1_keypair_create` only on a secret `secp256k1_ec_seckey_verify` refuses). A
     * failed allocation is the resource's to report; the seed is wiped then too.
     */
    static boost::system::result<basic_keypair> make(
        std::span<std::uint8_t const> secret,
        std::pmr::memory_resource* memory = std::pmr::get_default_resource()) {
        if (secret.size() != 32) {
            return error::invalid_key_size;
        }
        webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
        if (secp256k1_ec_seckey_verify(secp256k1_context_static, secret.data()) == 0) {
            return error::invalid_secret_key;
        }
        detail::secret seed;
        auto const seeded = random_device().fill(seed.bytes);  // lint-world: the context's seed
        if (!seeded) {
            return detail::seed_error(seeded.error());
        }
        basic_keypair made;
        made.memory_ = memory;
        made.context_ = secp256k1_context_preallocated_create(
            memory->allocate(context_size(), alignof(std::max_align_t)), detail::context_flags);
        int const randomised = secp256k1_context_randomize(made.context_, seed.bytes.data());
        if (randomised == 0 ||
            secp256k1_keypair_create(made.context_, &made.keypair_, secret.data()) == 0) {
            return error::backend_failure;
        }
        made.keyed_ = true;
        return made;
    }

    /** Moves the key pair and its context; the source is wiped and empty. */
    basic_keypair(basic_keypair&& other) noexcept
        : context_(std::exchange(other.context_, nullptr)),
          memory_(other.memory_),
          keypair_(other.keypair_),
          keyed_(std::exchange(other.keyed_, false)) {
        webcpp::crypto::detail::wipe_object(other.keypair_);
    }

    /** Moves over this key pair, which is wiped and gives its context back first. */
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
        secp256k1_ec_pubkey_serialize(context_, out.data(), &size, &key, detail::compressed);
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
        std::array<std::uint8_t, 32> randomness{};
        std::ranges::copy(aux, randomness.begin());
        secp256k1_schnorrsig_extraparams extra = SECP256K1_SCHNORRSIG_EXTRAPARAMS_INIT;
        extra.ndata = randomness.data();
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
        detail::secret secret;
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
     * @param public_key The peer's key, 33 or 65 bytes.
     * @return 32 bytes; `invalid_state`; `invalid_public_key`; `backend_failure`.
     */
    [[nodiscard]] boost::system::result<std::array<std::uint8_t, 32>> ecdh(
        std::span<std::uint8_t const> public_key) const noexcept {
        if (!keyed_) {
            return error::invalid_state;
        }
        secp256k1_pubkey parsed{};
        if (!detail::parse(public_key, parsed)) {
            return error::invalid_public_key;
        }
        webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
        detail::secret secret;
        secp256k1_keypair_sec(context_, secret.bytes.data(), &keypair_);
        std::array<std::uint8_t, 32> out{};
        if (secp256k1_ecdh(context_, out.data(), &parsed, secret.bytes.data(), nullptr, nullptr) ==
            0) {
            return error::backend_failure;
        }
        return out;
    }

private:
    basic_keypair() noexcept = default;

    static std::size_t context_size() noexcept {
        return secp256k1_context_preallocated_size(detail::context_flags);
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
 * @param signature 64 bytes.
 * @param message The message, of any length.
 * @param xonly_public_key 32 bytes.
 * @return Nothing; `invalid_public_key`; `invalid_signature`.
 */
template <class Backend = backends::secp256k1>
boost::system::result<void> verify_schnorr(
    std::span<std::uint8_t const, 64> signature, std::span<std::uint8_t const> message,
    std::span<std::uint8_t const, 32> xonly_public_key) noexcept {
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
 * @param signature 64 bytes, r then s.
 * @param hash The 32-byte hash signed.
 * @param public_key 33 or 65 bytes, SEC1.
 * @return Nothing; `invalid_public_key`; `invalid_signature`.
 */
template <class Backend = backends::secp256k1>
boost::system::result<void> verify_ecdsa(std::span<std::uint8_t const, 64> signature,
                                         std::span<std::uint8_t const, 32> hash,
                                         std::span<std::uint8_t const> public_key) noexcept {
    webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
    secp256k1_selftest();
    secp256k1_pubkey key{};
    if (!detail::parse(public_key, key)) {
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

}  // namespace webcpp::crypto::secp256k1

#endif  // WEBCPP_CRYPTO_SECP256K1_HPP
