// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 `basic_box`, NaCl's and libsodium's `crypto_box`: X25519 agrees a key with a peer's public key
 once (libsodium's `beforenm`), then each message is sealed and opened in place with
 XSalsa20-Poly1305, or XChaCha20-Poly1305, the tag apart. `box` and `box_xchacha20poly1305` name
 the two families on their default backend, libsodium on every target, whose header this one
 includes when the program links it; a program that uses them without linking it stops where it
 calls them, with the Jamfile line that links it.

 @see "Boxes", in the guide.
*/
#ifndef WEBCPP_CRYPTO_HYBRID_BOX_HPP
#define WEBCPP_CRYPTO_HYBRID_BOX_HPP

#include <webcpp/crypto/config.hpp>

#include <webcpp/crypto/detail/capabilities.hpp>
#include <webcpp/crypto/detail/defaults.hpp>
#include <webcpp/crypto/detail/engines.hpp>
#include <webcpp/crypto/detail/limits.hpp>
#include <webcpp/crypto/detail/timing.hpp>
#include <webcpp/crypto/detail/wipe.hpp>
#include <webcpp/crypto/error.hpp>

#include <boost/hash2/digest.hpp>
#include <boost/system/result.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <type_traits>
#include <utility>

namespace webcpp::crypto::detail {

/**
 * What a `hybrid::basic_box` of the family `Family` stores on a backend whose header does not
 * specialise it: nothing, since its engine refuses the backend where the box is used.
 */
template <class Family, class Backend>
struct box_state {};

/**
 * The work of a box on a backend, whose specialisation provides
 * `init(state&, secret_key, peer_public_key)`, `seal(state&, iv, data, tag&)`,
 * `open(state&, iv, data, tag const&)`, `move(to, from)` and `reset(state&)`; the primary refuses
 * (defined at the end of this header).
 */
template <class Family, class Backend>
struct box_engine;

/** Whether `Family` is one of the families `hybrid::basic_box` takes. */
template <class Family>
inline constexpr bool box_family = false;

/** X25519-XSalsa20-Poly1305, `crypto_box`, is a box family. */
template <>
inline constexpr bool box_family<families::box_xsalsa20poly1305> = true;

/** X25519-XChaCha20-Poly1305, `crypto_box_curve25519xchacha20poly1305`, is a box family. */
template <>
inline constexpr bool box_family<families::box_xchacha20poly1305> = true;

/**
 * The family whose default backend `hybrid::basic_box` takes: `Family` itself when it is a box
 * family, and otherwise `families::box_xsalsa20poly1305`, so that a type with no default of its
 * own reaches `basic_box`'s refusal of it, and adds no error of its own before it.
 */
template <class Family>
using box_default_family =
    std::conditional_t<box_family<Family>, Family, families::box_xsalsa20poly1305>;

}  // namespace webcpp::crypto::detail

namespace webcpp::crypto::hybrid {

/**
 * `crypto_box`: authenticated encryption between two key pairs.
 *
 * `make` agrees a key from the own secret key and the peer's public key, once per pair of keys
 * (libsodium's `beforenm`); `seal` and `open` then work in place, the tag apart, under that key.
 * Either party of the pair can have written a message: the box proves that it comes from one of
 * them, not which.
 *
 * An object holds the agreed key, the state that every message uses: it is used by one thread
 * at a time, moved and not copied, and wiped when moved from and destroyed. A nonce (the IV) is
 * never repeated for one pair of keys, in either direction: two messages under one pair and
 * one nonce reveal the XOR of their plaintexts and let an attacker forge tags. Its 24 bytes are
 * safe to draw at random for every message.
 *
 * @tparam Family `families::box_xsalsa20poly1305`, NaCl's `crypto_box`, or
 * `families::box_xchacha20poly1305`, libsodium's `crypto_box_curve25519xchacha20poly1305`.
 * @tparam Backend The backend; by default the family's.
 */
template <class Family = families::box_xsalsa20poly1305,
          class Backend = default_backend_t<detail::box_default_family<Family>>>
class basic_box {
    // The first error a program that names another type sees, and its only one: the default
    // backend reads a box family's default in the type's place.
    static_assert(detail::box_family<Family>,
                  "webcpp::crypto: hybrid::basic_box takes a box family: "
                  "families::box_xsalsa20poly1305 or families::box_xchacha20poly1305.");

    using state_type = detail::box_state<Family, Backend>;
    using engine = detail::box_engine<Family, Backend>;

public:
    /** The backend. */
    using backend_type = Backend;
    /** The family of the capability table, which `supports_v` reads. */
    using family_type = Family;
    /** The algorithm of the capability table: the family's own tag, its one algorithm. */
    using name_type = Family;
    /** The tag, Boost.Hash2's digest of `tag_size` bytes. */
    using result_type = boost::hash2::digest<16>;
    /** The secret key's and the peer's public key's size. */
    static constexpr std::size_t key_size = 32;
    /** The nonce's size, exactly. */
    static constexpr std::size_t iv_size = 24;
    /** The tag's size. */
    static constexpr std::size_t tag_size = 16;
    /**
     * The longest message, 2^64 - 17 bytes: libsodium's `crypto_box_MESSAGEBYTES_MAX` on a 64-bit
     * target.
     *
     * On a 32-bit target, wasm32 among them, libsodium's is 2^32 - 17 bytes, more than a
     * message there can be, since the 4 GiB of memory also hold the program.
     */
    static constexpr std::uint64_t max_message_size = ~std::uint64_t{0} - 16;

    /**
     * Agrees the box's key from the own secret key and the peer's public key.
     *
     * @param secret_key The own X25519 secret key, `key_size` bytes.
     * @param peer_public_key The peer's X25519 public key, `key_size` bytes.
     * @return The box; `invalid_key_size`; `invalid_public_key` for a peer key of another
     * size; `weak_public_key` for a peer key of small order, whose shared secret an attacker
     * knows; `backend_failure` when the backend cannot start.
     */
    [[nodiscard]] static boost::system::result<basic_box> make(
        std::span<std::uint8_t const> secret_key,
        std::span<std::uint8_t const> peer_public_key) noexcept {
        detail::timing_guard const timing_scope;
        if (secret_key.size() != key_size) {
            return error::invalid_key_size;
        }
        if (peer_public_key.size() != key_size) {
            return error::invalid_public_key;
        }
        basic_box made_object;
        auto const agreement_result = engine::init(made_object.state_, secret_key.first<key_size>(),
                                                   peer_public_key.first<key_size>());
        if (!agreement_result) {
            return agreement_result.error();
        }
        made_object.keyed_ = true;
        return made_object;
    }

    /**
     * Moves the key; the source is wiped and empty.
     *
     * Moving an empty object gives an empty one.
     *
     * @param moved_source The source, empty afterwards.
     */
    basic_box(basic_box&& moved_source) noexcept
        : keyed_(std::exchange(moved_source.keyed_, false)) {
        if (keyed_) {
            engine::move(state_, moved_source.state_);
        }
    }

    /**
     * Moves the key over this one, which is wiped first; an empty source gives an empty object.
     *
     * @param moved_source The source, empty afterwards.
     * @return This object.
     */
    basic_box& operator=(basic_box&& moved_source) noexcept {
        if (this != &moved_source) {
            engine::reset(state_);
            keyed_ = std::exchange(moved_source.keyed_, false);
            if (keyed_) {
                engine::move(state_, moved_source.state_);
            }
        }
        return *this;
    }

    /** Not copyable: a key has one owner, which wipes it. */
    basic_box(basic_box const&) = delete;
    /** Not copyable: a key has one owner, which wipes it. */
    basic_box& operator=(basic_box const&) = delete;

    /** Wipes the key. */
    ~basic_box() { engine::reset(state_); }

    /**
     * Seals a message in place: `data_bytes` holds the plaintext before and the ciphertext
     * after.
     *
     * The nonce may lie in `data_bytes`: it is read before the first byte is written.
     *
     * When the backend fails, `data_bytes` is zeroed, as a failed open's is: neither the
     * plaintext nor bytes that look sealed are left; a guard's refusal leaves it untouched.
     *
     * @param iv_bytes The nonce, `iv_size` bytes, never repeated for this pair of keys.
     * @param data_bytes The message.
     * @return The tag; `invalid_state` moved from; `invalid_iv_size`; `message_too_long`;
     * `backend_failure`.
     */
    [[nodiscard]] boost::system::result<result_type> seal(
        std::span<std::uint8_t const> iv_bytes, std::span<std::uint8_t> data_bytes) noexcept {
        detail::timing_guard const timing_scope;
        auto const guard_result = guard_message(iv_bytes, data_bytes.size(), tag_size);
        if (!guard_result) {
            return guard_result.error();
        }
        result_type tag_bytes{};
        auto const seal_result =
            engine::seal(state_, iv_bytes.first<iv_size>(), data_bytes, tag_bytes);
        if (!seal_result) {
            detail::wipe(data_bytes.data(), data_bytes.size());
            return seal_result.error();
        }
        return tag_bytes;
    }

    /**
     * Opens a message in place: `data_bytes` holds the ciphertext before and the plaintext
     * after.
     *
     * When the tag does not match, or the backend fails, `data_bytes` is zeroed; a guard's
     * refusal leaves it untouched.
     *
     * @param iv_bytes The nonce of the seal, which may lie in `data_bytes`.
     * @param data_bytes The ciphertext.
     * @param tag_bytes The seal's tag, `tag_size` bytes, which may lie anywhere, `data_bytes`
     * included.
     * @return Nothing; `invalid_state` moved from; `invalid_iv_size`; `invalid_tag_size`;
     * `message_too_long`; `authentication_failed`; `backend_failure`.
     */
    [[nodiscard]] boost::system::result<void> open(
        std::span<std::uint8_t const> iv_bytes, std::span<std::uint8_t> data_bytes,
        std::span<std::uint8_t const> tag_bytes) noexcept {
        detail::timing_guard const timing_scope;
        auto const guard_result = guard_message(iv_bytes, data_bytes.size(), tag_bytes.size());
        if (!guard_result) {
            return guard_result.error();
        }
        // The tag may lie in data, which decryption overwrites: a copy is checked.
        std::array<std::uint8_t, tag_size> expected_tag{};
        std::ranges::copy(tag_bytes, expected_tag.begin());
        auto const open_result =
            engine::open(state_, iv_bytes.first<iv_size>(), data_bytes, expected_tag);
        if (!open_result) {
            detail::wipe(data_bytes.data(), data_bytes.size());
            return open_result.error();
        }
        return {};
    }

private:
    basic_box() noexcept = default;

    // Every guard of a message, in the documented order: the state, the nonce, the tag (open's;
    // seal passes tag_size), the length. None reads a byte of the spans.
    [[nodiscard]] boost::system::result<void> guard_message(std::span<std::uint8_t const> iv_bytes,
                                                            std::size_t byte_count,
                                                            std::size_t tag_bytes) const noexcept {
        if (!keyed_) {
            return error::invalid_state;
        }
        if (iv_bytes.size() != iv_size) {
            return error::invalid_iv_size;
        }
        if (tag_bytes != tag_size) {
            return error::invalid_tag_size;
        }
        if (detail::exceeds(byte_count, max_message_size)) {
            return error::message_too_long;
        }
        return {};
    }

    state_type state_{};
    bool keyed_ = false;
};

/** `crypto_box`, X25519-XSalsa20-Poly1305, on its default backend: NaCl's box. */
using box = basic_box<>;

/** `crypto_box_curve25519xchacha20poly1305`, X25519-XChaCha20-Poly1305, on its default backend. */
using box_xchacha20poly1305 = basic_box<families::box_xchacha20poly1305>;

}  // namespace webcpp::crypto::hybrid

namespace webcpp::crypto::detail {

/** The refusal of a box family on a backend whose header does not specialise its engine. */
template <class Family, class Backend>
struct box_refusal {};

/** X25519-XSalsa20-Poly1305's refusal, which names what the program needs. */
template <class Backend>
struct box_refusal<families::box_xsalsa20poly1305, Backend> {
    WEBCPP_CRYPTO_DETAIL_REFUSE_BOX_XSALSA20POLY1305(Backend);
};

/** X25519-XChaCha20-Poly1305's refusal (see the first). */
template <class Backend>
struct box_refusal<families::box_xchacha20poly1305, Backend> {
    WEBCPP_CRYPTO_DETAIL_REFUSE_BOX_XCHACHA20POLY1305(Backend);
};

/**
 * A box's engine on a backend whose header does not specialise it: the family's refusal
 * (`detail/capabilities.hpp`). Its functions are never called: the refusal stops the build
 * where the class is instantiated, and they keep the compiler from adding errors of their own
 * after it; those that return report `backend_failure`, so that a path the refusal missed
 * fails closed.
 */
template <class Family, class Backend>
struct box_engine : box_refusal<Family, Backend> {
    /** Never called; fails closed. */
    template <class... Arguments>
    [[nodiscard]] static boost::system::result<void> init(Arguments&&... /*arguments*/) noexcept {
        return error::backend_failure;
    }

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

    /** Never called. */
    template <class... Arguments>
    static void move(Arguments&&... /*arguments*/) noexcept {}

    /** Never called. */
    template <class... Arguments>
    static void reset(Arguments&&... /*arguments*/) noexcept {}
};

}  // namespace webcpp::crypto::detail

// The default backend's engines, when the program links it (design D32): libsodium on every
// target. Its header specialises them for this header, wherever it was first included.
#if (defined(WEBCPP_CRYPTO_DETAIL_DEFAULT_BOX_XSALSA20POLY1305_SODIUM) ||   \
     defined(WEBCPP_CRYPTO_DETAIL_DEFAULT_BOX_XCHACHA20POLY1305_SODIUM)) && \
    defined(WEBCPP_CRYPTO_HAS_SODIUM)
#include <webcpp/crypto/backends/sodium.hpp>
#endif

#endif  // WEBCPP_CRYPTO_HYBRID_BOX_HPP
