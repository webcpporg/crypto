// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 `basic_sealed_box`, libsodium's sealed boxes (`crypto_box_seal`): anonymous encryption to an
 X25519 public key, opened with the recipient's X25519 key pair. `sealed_box` names it on its
 default backend, libsodium on every target, whose header this one includes when the program links
 it; a program that uses it without linking it stops where it calls it, with the Jamfile line that
 links it.

 It lives in `public_key_encryption` beside `box`, named by what it does, encryption to a public
 key: `crypto::hybrid` is left free for the post-quantum hybrids (X25519MLKEM768, X-Wing), which
 the word now names, and a later HPKE (RFC 9180) joins the boxes here.

 @see "Sealed boxes", in the guide.
*/
#ifndef WEBCPP_CRYPTO_PUBLIC_KEY_ENCRYPTION_SEALED_BOX_HPP
#define WEBCPP_CRYPTO_PUBLIC_KEY_ENCRYPTION_SEALED_BOX_HPP

#include <webcpp/crypto/config.hpp>

#include <webcpp/crypto/curves/x25519.hpp>
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
 * `open(recipient_public_key, recipient_secret_key, sealed, out)`; the primary refuses (defined at
 * the end of this header).
 */
template <class Family, class Backend>
struct sealed_box_engine;

}  // namespace webcpp::crypto::detail

namespace webcpp::crypto::public_key_encryption {

/**
 * Sealed boxes: anonymous encryption to a public key.
 *
 * `seal` draws a key pair for the message (libsodium draws it from its own generator), seals the
 * message in a box from that key pair to the recipient's public key, under a nonce derived from the
 * two public keys, and writes the drawn public key, the tag and the ciphertext; the drawn secret
 * key is wiped. Only the recipient's key pair opens it. The recipient cannot tell who sealed it,
 * and the sender cannot open it afterwards: a sealed box proves nothing about who wrote it.
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
    /** The recipient's key pair's type, of the sealed box's backend. */
    using keypair_type = curves::x25519::basic_keypair<Backend>;
    /** The recipient's public key's type. */
    using public_key_type = curves::x25519::public_key;

    // A backend that has the sealed box but no X25519 cannot make the key pair it takes: refused
    // where the class is named. A backend without the sealed box is refused by its engine alone.
    static_assert(
        !detail::supported<families::sealed_box, families::sealed_box, Backend> ||
            detail::supported<families::x25519, families::x25519, Backend>,
        "webcpp::crypto: public_key_encryption::basic_sealed_box takes an X25519 key pair "
        "of its own backend, which has no X25519.");
    /** The size of a public key and of a secret key. */
    static constexpr std::size_t key_size = 32;
    /** How much longer a sealed box is than its message: the drawn public key and the tag. */
    static constexpr std::size_t overhead = 48;

    /**
     * Seals `message_bytes` into `output_bytes`, of `message_bytes.size() + overhead` bytes: the
     * drawn public key, the tag, then the ciphertext.
     *
     * The message may be the first `message_bytes.size()` bytes of `output_bytes`, sealed in place;
     * it overlaps `output_bytes` in no other way.
     *
     * The sizes are checked first; their refusal leaves `output_bytes` untouched. A failure of
     * the work zeroes it.
     *
     * @param recipient_public_key The recipient's X25519 public key.
     * @param message_bytes The message.
     * @param output_bytes `message_bytes.size() + overhead` bytes.
     * @return Nothing; `invalid_input_size` for an `output_bytes` of another size;
     * `weak_public_key` for a key of small order; `backend_failure`.
     */
    [[nodiscard]] static boost::system::result<void> seal(
        public_key_type const& recipient_public_key, std::span<std::uint8_t const> message_bytes,
        std::span<std::uint8_t> output_bytes) noexcept {
        detail::timing_guard const timing_scope;
        if (output_bytes.size() < overhead ||
            output_bytes.size() - overhead != message_bytes.size()) {
            return error::invalid_input_size;
        }
        auto const seal_result =
            engine::seal(std::span<std::uint8_t const, key_size>(recipient_public_key.bytes()),
                         message_bytes, output_bytes);
        if (!seal_result) {
            detail::wipe(output_bytes.data(), output_bytes.size());
            return seal_result.error();
        }
        return {};
    }

    /**
     * Opens `sealed_bytes` into `output_bytes`, of `sealed_bytes.size() - overhead` bytes, with the
     * recipient's key pair.
     *
     * `output_bytes` overlaps neither `sealed_bytes` nor the key pair.
     *
     * The sizes are checked first, then the key pair; a refusal of theirs leaves `output_bytes`
     * untouched. When the box does not open, or the backend fails, `output_bytes` is zeroed.
     *
     * @param recipient_keypair The recipient's X25519 key pair.
     * @param sealed_bytes A sealed box, at least `overhead` bytes.
     * @param output_bytes `sealed_bytes.size() - overhead` bytes.
     * @return Nothing; `invalid_input_size` for a `sealed_bytes` shorter than `overhead` or an
     * `output_bytes` of another size; `invalid_state` for a key pair moved from;
     * `authentication_failed` when the box was not sealed to this key pair, or was changed;
     * `backend_failure`.
     */
    [[nodiscard]] static boost::system::result<void> open(
        keypair_type const& recipient_keypair, std::span<std::uint8_t const> sealed_bytes,
        std::span<std::uint8_t> output_bytes) noexcept {
        detail::timing_guard const timing_scope;
        if (sealed_bytes.size() < overhead ||
            output_bytes.size() != sealed_bytes.size() - overhead) {
            return error::invalid_input_size;
        }
        if (!detail::x25519_access::keyed(recipient_keypair)) {
            return error::invalid_state;
        }
        auto const open_result = engine::open(
            detail::x25519_access::public_bytes(recipient_keypair),
            detail::x25519_access::secret_bytes(recipient_keypair), sealed_bytes, output_bytes);
        if (!open_result) {
            detail::wipe(output_bytes.data(), output_bytes.size());
            return open_result.error();
        }
        return {};
    }

private:
    using engine = detail::sealed_box_engine<families::sealed_box, Backend>;
};

/** Sealed boxes on their default backend. */
using sealed_box = basic_sealed_box<>;

}  // namespace webcpp::crypto::public_key_encryption

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

/** Defined once this header's declarations are, which libsodium's engine specialises. */
// NOLINTNEXTLINE(modernize-macro-to-enum): read by backends/sodium.hpp's #if, not a value
#define WEBCPP_CRYPTO_DETAIL_SEALED_BOX_DECLARED 1

// The default backend's engine, when the program links it (design D32): libsodium on every
// target. Its header specialises it for this header, wherever it was first included.
#if defined(WEBCPP_CRYPTO_DETAIL_DEFAULT_SEALED_BOX_SODIUM) && defined(WEBCPP_CRYPTO_HAS_SODIUM)
#include <webcpp/crypto/backends/sodium.hpp>
#endif

#endif  // WEBCPP_CRYPTO_PUBLIC_KEY_ENCRYPTION_SEALED_BOX_HPP
