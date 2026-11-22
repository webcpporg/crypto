// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 `basic_sealed_box`, libsodium's sealed boxes (`crypto_box_seal`): anonymous encryption to a
 public key. `sealed_box` names it on its default backend, libsodium on every target, whose
 header this one includes when the program links it; a program that uses it without linking it
 stops where it calls it, with the Jamfile line that links it.

 @see "Sealed boxes", in the guide.
*/
#ifndef WEBCPP_CRYPTO_HYBRID_SEALED_BOX_HPP
#define WEBCPP_CRYPTO_HYBRID_SEALED_BOX_HPP

#include <webcpp/crypto/config.hpp>

#include <webcpp/crypto/detail/capabilities.hpp>
#include <webcpp/crypto/detail/defaults.hpp>
#include <webcpp/crypto/detail/engines.hpp>
#include <webcpp/crypto/detail/timing.hpp>
#include <webcpp/crypto/detail/wipe.hpp>
#include <webcpp/crypto/error.hpp>

#include <boost/system/result.hpp>

#include <cstddef>
#include <cstdint>
#include <span>

namespace webcpp::crypto::detail {

/**
 * The work of sealed boxes on a backend, whose specialisation provides
 * `seal(recipient_public_key, message, out)` and
 * `open(recipient_public_key, recipient_secret_key, sealed, out)`; the
 * primary refuses (defined at the end of this header).
 */
template <class Family, class Backend>
struct sealed_box_engine;

}  // namespace webcpp::crypto::detail

namespace webcpp::crypto::hybrid {

/**
 * Sealed boxes: anonymous encryption to a public key.
 *
 * `seal` draws a key pair for the message
 * (libsodium draws it from its own generator), seals the message in a box from that key pair
 * to the recipient's public key, under a nonce derived from the two public keys, and writes
 * the drawn public key, the tag and the ciphertext; the drawn secret key is wiped. Only the
 * recipient's key pair opens it. The recipient cannot tell who sealed it, and the sender
 * cannot open it afterwards: a sealed box proves nothing about who wrote it.
 *
 * @tparam Backend The backend; by default the family's.
 */
template <class Backend = default_backend_t<families::sealed_box>>
struct basic_sealed_box {
    /** The backend. */
    using backend_type = Backend;
    /** The family of the capability table, which `supports_v` reads. */
    using family_type = families::sealed_box;
    /** The algorithm of the capability table: the family's own tag, its one algorithm. */
    using name_type = families::sealed_box;
    /** The size of a public key and of a secret key. */
    static constexpr std::size_t key_size = 32;
    /** How much longer a sealed box is than its message: the drawn public key and the tag. */
    static constexpr std::size_t overhead = 48;

    /**
     * Seals `message` into `out`, of `message.size() + overhead` bytes: the drawn public key,
     * the tag, then the ciphertext.
     *
     * The message may be the first `message.size()` bytes of
     * `out`, sealed in place; it overlaps `out` in no other way, and the key does not.
     *
     * The sizes are checked first; a refusal of theirs or of the key's leaves `out` untouched.
     * A failure of the work zeroes it.
     *
     * @param recipient_public_key The recipient's X25519 public key, `key_size` bytes.
     * @param message The message.
     * @param out `message.size() + overhead` bytes.
     * @return Nothing; `invalid_input_size` for an `out` of another size; `invalid_public_key`
     * for a key of another size; `weak_public_key` for a key of small order; `backend_failure`.
     */
    [[nodiscard]] static boost::system::result<void> seal(
        std::span<std::uint8_t const> recipient_public_key, std::span<std::uint8_t const> message,
        std::span<std::uint8_t> out) noexcept {
        detail::timing_guard const timing;
        if (out.size() < overhead || out.size() - overhead != message.size()) {
            return error::invalid_input_size;
        }
        if (recipient_public_key.size() != key_size) {
            return error::invalid_public_key;
        }
        auto const sealed = engine::seal(recipient_public_key.first<key_size>(), message, out);
        if (!sealed) {
            detail::wipe(out.data(), out.size());
            return sealed.error();
        }
        return {};
    }

    /**
     * Opens `sealed` into `out`, of `sealed.size() - overhead` bytes, with the recipient's
     * keys.
     *
     * `out` overlaps neither `sealed` nor the keys.
     *
     * The sizes are checked first; a refusal of theirs or of the keys' leaves `out` untouched.
     * When the box does not open, or the backend fails, `out` is zeroed.
     *
     * @param recipient_public_key The recipient's X25519 public key, `key_size` bytes.
     * @param recipient_secret_key The recipient's X25519 secret key, `key_size` bytes.
     * @param sealed A sealed box, at least `overhead` bytes.
     * @param out `sealed.size() - overhead` bytes.
     * @return Nothing; `invalid_input_size` for a `sealed` shorter than `overhead` or an `out`
     * of another size; `invalid_public_key`; `invalid_key_size`; `authentication_failed` when
     * the box was not sealed to this key pair, or was changed; `backend_failure`.
     */
    [[nodiscard]] static boost::system::result<void> open(
        std::span<std::uint8_t const> recipient_public_key,
        std::span<std::uint8_t const> recipient_secret_key, std::span<std::uint8_t const> sealed,
        std::span<std::uint8_t> out) noexcept {
        detail::timing_guard const timing;
        if (sealed.size() < overhead || out.size() != sealed.size() - overhead) {
            return error::invalid_input_size;
        }
        if (recipient_public_key.size() != key_size) {
            return error::invalid_public_key;
        }
        if (recipient_secret_key.size() != key_size) {
            return error::invalid_key_size;
        }
        auto const opened = engine::open(recipient_public_key.first<key_size>(),
                                         recipient_secret_key.first<key_size>(), sealed, out);
        if (!opened) {
            detail::wipe(out.data(), out.size());
            return opened.error();
        }
        return {};
    }

private:
    using engine = detail::sealed_box_engine<families::sealed_box, Backend>;
};

/** Sealed boxes on their default backend. */
using sealed_box = basic_sealed_box<>;

}  // namespace webcpp::crypto::hybrid

namespace webcpp::crypto::detail {

/**
 * The sealed boxes' engine on a backend whose header does not specialise it: the family's
 * refusal (`detail/capabilities.hpp`). Its functions are never called: the refusal stops the
 * build where the class is instantiated, and they keep the compiler from adding errors of their
 * own after it; they report `backend_failure`, so that a path the refusal missed fails closed.
 */
template <class Family, class Backend>
struct sealed_box_engine {
    WEBCPP_CRYPTO_DETAIL_REFUSE_SEALED_BOX(Backend);

    /** Never called; fails closed. */
    template <class... Arguments>
    [[nodiscard]] static boost::system::result<void> seal(Arguments&&... /*arguments*/) noexcept {
        return error::backend_failure;
    }

    /** Never called; fails closed. */
    template <class... Arguments>
    [[nodiscard]] static boost::system::result<void> open(Arguments&&... /*arguments*/) noexcept {
        return error::backend_failure;
    }
};

}  // namespace webcpp::crypto::detail

// The default backend's engine, when the program links it (design D32): libsodium on every
// target. Its header specialises it for this header, wherever it was first included.
#if defined(WEBCPP_CRYPTO_DETAIL_DEFAULT_SEALED_BOX_SODIUM) && defined(WEBCPP_CRYPTO_HAS_SODIUM)
#include <webcpp/crypto/backends/sodium.hpp>
#endif

#endif  // WEBCPP_CRYPTO_HYBRID_SEALED_BOX_HPP
