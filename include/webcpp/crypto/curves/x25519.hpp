// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 X25519 key agreement (RFC 7748): the 32-byte public key of a 32-byte secret key, and the 32-byte
 shared secret of a secret key and a peer's public key, refused when it is all zero.

 The family's default backend, libsodium on every target, is included when the program links
 it; a program that uses the family without linking it stops where it calls it, with the
 Jamfile line that links it.

 @see "X25519", in the guide.
*/
#ifndef WEBCPP_CRYPTO_CURVES_X25519_HPP
#define WEBCPP_CRYPTO_CURVES_X25519_HPP

#include <webcpp/crypto/config.hpp>

#include <webcpp/crypto/detail/bytes.hpp>
#include <webcpp/crypto/detail/capabilities.hpp>
#include <webcpp/crypto/detail/defaults.hpp>
#include <webcpp/crypto/detail/engines.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/secret.hpp>

#include <boost/system/result.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace webcpp::crypto::detail {

/** The work of X25519 on a backend; the primary refuses (defined at the end of this header). */
template <class Name, class Backend>
struct x25519_engine;

}  // namespace webcpp::crypto::detail

namespace webcpp::crypto::curves::x25519 {

/**
 * X25519 (RFC 7748) on a backend: the type `supports_v` names, whose functions the free
 * functions below call.
 *
 * @tparam Backend The backend; by default the family's (`default_backend_t<families::x25519>`).
 */
template <class Backend = default_backend_t<families::x25519>>
struct algorithm {
    /** The family, for `supports_v`. */
    using family_type = families::x25519;
    /** The algorithm, for `supports_v`: the family's one name. */
    using name_type = families::x25519;
    /** The backend. */
    using backend_type = Backend;
    /** The secret key's, the public key's and the shared secret's size. */
    static constexpr std::size_t key_size = 32;

    /**
     * The public key of a secret key: its product with the base point, `u = 9`.
     *
     * @param secret_key 32 bytes; any 32 bytes are a secret key (RFC 7748 clamps them).
     * @return 32 bytes; `invalid_key_size`; `backend_failure`.
     */
    static boost::system::result<std::array<std::uint8_t, 32>> public_key(
        std::span<std::uint8_t const> secret_key) noexcept {
        if (secret_key.size() != key_size) {
            return error::invalid_key_size;
        }
        std::array<std::uint8_t, 32> out{};
        auto const done = engine::base(secret_key.first<key_size>(), out);
        if (!done) {
            return done.error();
        }
        return out;
    }

    /**
     * The shared secret of a secret key and a peer's public key, refused when it is all zero.
     *
     * @param secret_key 32 bytes.
     * @param peer_public_key 32 bytes.
     * @return 32 secret bytes; `invalid_key_size`; `invalid_public_key`; `weak_public_key`
     * for a peer key of low order, whose shared secret is all zero; `backend_failure`.
     */
    static boost::system::result<secret<32>> agree(
        std::span<std::uint8_t const> secret_key,
        std::span<std::uint8_t const> peer_public_key) noexcept {
        if (secret_key.size() != key_size) {
            return error::invalid_key_size;
        }
        if (peer_public_key.size() != key_size) {
            return error::invalid_public_key;
        }
        secret<32> shared;
        auto const done = engine::agree(secret_key.first<key_size>(),
                                        peer_public_key.first<key_size>(), shared.writable());
        if (!done) {
            return done.error();
        }
        // Every backend gives the same answer: libsodium refuses an all-zero result itself,
        // and the others are checked here, in constant time (design D8).
        if (detail::is_all_zero(shared.bytes())) {
            return error::weak_public_key;
        }
        return shared;
    }

private:
    using engine = detail::x25519_engine<families::x25519, Backend>;
};

/**
 * The public key of a secret key: `algorithm<Backend>::public_key`.
 *
 * @tparam Backend The backend; by default the family's.
 * @param secret_key 32 bytes.
 * @return 32 bytes; `invalid_key_size`; `backend_failure`.
 */
template <class Backend = default_backend_t<families::x25519>>
boost::system::result<std::array<std::uint8_t, 32>> public_key(
    std::span<std::uint8_t const> secret_key) noexcept {
    return algorithm<Backend>::public_key(secret_key);
}

/**
 * The shared secret, refused when all zero: `algorithm<Backend>::agree`.
 *
 * @tparam Backend The backend; by default the family's.
 * @param secret_key 32 bytes.
 * @param peer_public_key 32 bytes.
 * @return 32 secret bytes; `invalid_key_size`; `invalid_public_key`; `weak_public_key`;
 * `backend_failure`.
 */
template <class Backend = default_backend_t<families::x25519>>
boost::system::result<secret<32>> agree(std::span<std::uint8_t const> secret_key,
                                        std::span<std::uint8_t const> peer_public_key) noexcept {
    return algorithm<Backend>::agree(secret_key, peer_public_key);
}

}  // namespace webcpp::crypto::curves::x25519

namespace webcpp::crypto::detail {

/**
 * X25519's engine on a backend whose header does not specialise it: the family's refusal,
 * which names what the program needs (`detail/capabilities.hpp`). Its functions are never
 * called: the refusal stops the build where the class is instantiated, and they keep the
 * compiler from adding errors of their own after it; they report `backend_failure`, so that a
 * path the refusal missed fails closed.
 */
template <class Name, class Backend>
struct x25519_engine {
    WEBCPP_CRYPTO_DETAIL_REFUSE_X25519(Backend);

    /** Never called; fails closed. */
    template <class... Arguments>
    [[nodiscard]] static boost::system::result<void> base(Arguments&&... /*arguments*/) noexcept {
        return error::backend_failure;
    }

    /** Never called; fails closed. */
    template <class... Arguments>
    [[nodiscard]] static boost::system::result<void> agree(Arguments&&... /*arguments*/) noexcept {
        return error::backend_failure;
    }
};

}  // namespace webcpp::crypto::detail

// The default backend's engine, when the program links it (design D32): libsodium on every
// target. Its header specialises it for this header, wherever it was first included.
#if defined(WEBCPP_CRYPTO_DETAIL_DEFAULT_X25519_SODIUM) && defined(WEBCPP_CRYPTO_HAS_SODIUM)
#include <webcpp/crypto/backends/sodium.hpp>
#endif

#endif  // WEBCPP_CRYPTO_CURVES_X25519_HPP
