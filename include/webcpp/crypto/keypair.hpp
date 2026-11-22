// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 The contract every curve's key pair meets (design D8), the concept `crypto::keypair`: made from
 its secret bytes by `make` or drawn by `generate`, its typed public key, which goes straight into
 `crypto::verify`, its secret bytes back by `secret()`, and `sign(scheme, input)` for every scheme
 its curve declares, at least one, of the library's one list of schemes, `detail::all_schemes`
 in `signing.hpp`.

 Each curve's header checks its own key pair with a `static_assert` where its default backend is
 linked.

 Beside it, the free synchronous forms of the members (design D9, R23): `crypto::make<A>(bytes)`,
 which serves AES-GCM's and the other AEADs' `make` too, `crypto::generate<K>()` and
 `crypto::agree(key_pair, peer)`, each calling the member it is named after.

 @see "Signatures: the scheme and the input", in the guide.
*/
#ifndef WEBCPP_CRYPTO_KEYPAIR_HPP
#define WEBCPP_CRYPTO_KEYPAIR_HPP

#include <webcpp/crypto/config.hpp>

#include <webcpp/crypto/detail/timing.hpp>
#include <webcpp/crypto/secret.hpp>
#include <webcpp/crypto/signing.hpp>

#include <boost/system/result.hpp>

#include <concepts>
#include <cstdint>
#include <span>
#include <utility>

namespace webcpp::crypto {

namespace detail {

/**
 * Whether the key pair `Keypair` keeps its curve's word about `Scheme`: a scheme the curve does
 * not declare for it asks nothing; one it declares (`signs_with_v`) asks that
 * `key.sign(scheme, message)` be a valid call.
 *
 * @tparam Keypair A key pair's type.
 * @tparam Scheme A scheme tag.
 */
template <class Keypair, class Scheme>
concept signs_as_declared =
    !signs_with_v<Keypair, Scheme> ||
    requires(Keypair const& key, Scheme const& scheme, std::span<std::uint8_t const> message) {
        key.sign(scheme, message);
    };

/**
 * Whether the curve of `Keypair` declares at least one scheme of the list `List` for it: false
 * for a type that is not a `scheme_list`.
 *
 * @tparam Keypair A key pair's type.
 * @tparam List A `scheme_list`.
 */
template <class Keypair, class List>
inline constexpr bool signs_some_scheme_v = false;

/**
 * Whether the curve of `Keypair` declares at least one of `Schemes` for it.
 *
 * @tparam Keypair A key pair's type.
 * @tparam Schemes The list's scheme tags.
 */
template <class Keypair, class... Schemes>
inline constexpr bool signs_some_scheme_v<Keypair, scheme_list<Schemes...>> =
    (signs_with_v<Keypair, Schemes> || ...);

/**
 * Whether `Keypair` keeps its curve's word about every scheme of the list `List`
 * (`signs_as_declared`): false for a type that is not a `scheme_list`.
 *
 * @tparam Keypair A key pair's type.
 * @tparam List A `scheme_list`.
 */
template <class Keypair, class List>
inline constexpr bool signs_every_declared_v = false;

/**
 * Whether `Keypair` keeps its curve's word about each of `Schemes`.
 *
 * @tparam Keypair A key pair's type.
 * @tparam Schemes The list's scheme tags.
 */
template <class Keypair, class... Schemes>
inline constexpr bool signs_every_declared_v<Keypair, scheme_list<Schemes...>> =
    (signs_as_declared<Keypair, Schemes> && ...);

/**
 * The key pair contract over the schemes of `List`: `crypto::keypair` is this concept over
 * `all_schemes`, and a test passes a list with a scheme of its own.
 *
 * @tparam Keypair A type, without its reference and qualifiers.
 * @tparam List A `scheme_list`.
 */
template <class Keypair, class List>
concept keypair_over =
    signs_some_scheme_v<Keypair, List> &&
    requires(Keypair const& key, std::span<std::uint8_t const> secret_bytes) {
        typename Keypair::public_key_type;
        { Keypair::make(secret_bytes) } -> std::same_as<boost::system::result<Keypair>>;
        { Keypair::generate() } -> std::same_as<boost::system::result<Keypair>>;
        {
            key.public_key()
        } -> std::same_as<boost::system::result<typename Keypair::public_key_type>>;
        { key.secret() } -> std::same_as<boost::system::result<secret<Keypair::secret_key_size>>>;
    } && signs_every_declared_v<Keypair, List>;

}  // namespace detail

/**
 * Whether `Keypair` is a key pair of the library's contract (design D8):
 * - `Keypair::make(secret_bytes)` and `Keypair::generate()` give `result<Keypair>`;
 * - `key.public_key()` gives `result<typename Keypair::public_key_type>`, the curve's typed
 *   public key, which `crypto::verify` takes;
 * - `key.secret()` gives `result<secret<Keypair::secret_key_size>>`, the bytes `make` takes back;
 * - `key.sign(scheme, message)` is valid for every scheme its curve declares for it
 *   (`detail::signs_with_v`), and it declares at least one; the schemes asked are the library's
 *   one list of them, `detail::all_schemes`, which the concept folds over
 *   (`detail::keypair_over`).
 *
 * @tparam Keypair A type, without its reference and qualifiers.
 */
template <class Keypair>
concept keypair = detail::keypair_over<Keypair, detail::all_schemes>;

/**
 * Makes an object from its key bytes, `Algorithm::make(arguments...)`: the free form of the
 * algorithm's own `make`, which it calls, with its results and its errors.
 *
 * @tparam Algorithm A type whose static `make` takes these arguments: a key pair, a public key,
 * AES-GCM or another AEAD.
 * @tparam Arguments The types of `make`'s arguments.
 * @param arguments `make`'s arguments: the key bytes, and secp256k1's memory resource.
 * @return What `Algorithm::make(arguments...)` returns: the object, or its error.
 */
template <class Algorithm, class... Arguments>
    requires requires(Arguments&&... arguments) {
        Algorithm::make(std::forward<Arguments>(arguments)...);
    }
[[nodiscard]] auto make(Arguments&&... arguments) noexcept(
    noexcept(Algorithm::make(std::forward<Arguments>(arguments)...)))
    -> decltype(Algorithm::make(std::forward<Arguments>(arguments)...)) {
    detail::timing_guard const timing;
    return Algorithm::make(std::forward<Arguments>(arguments)...);
}

/**
 * Makes a key pair from a fresh secret drawn from the system's generator,
 * `Keypair::generate(arguments...)`: the free form of the key pair's own `generate`, which it
 * calls, with its results and its errors.
 *
 * @tparam Keypair A type whose static `generate` takes these arguments: a key pair.
 * @tparam Arguments The types of `generate`'s arguments: none, or secp256k1's memory resource.
 * @param arguments `generate`'s arguments.
 * @return What `Keypair::generate(arguments...)` returns: the key pair, or its error.
 */
template <class Keypair, class... Arguments>
    requires requires(Arguments&&... arguments) {
        Keypair::generate(std::forward<Arguments>(arguments)...);
    }
[[nodiscard]] auto generate(Arguments&&... arguments) noexcept(
    noexcept(Keypair::generate(std::forward<Arguments>(arguments)...)))
    -> decltype(Keypair::generate(std::forward<Arguments>(arguments)...)) {
    detail::timing_guard const timing;
    return Keypair::generate(std::forward<Arguments>(arguments)...);
}

/**
 * Agrees a secret with a peer's public key, `key_pair.agree(peer)`: the free form of the key
 * pair's own `agree`, which it calls, with its results and its errors.
 *
 * @tparam Keypair A key pair's type whose `agree` takes `peer`: P-256's or secp256k1's.
 * @tparam PublicKey The peer's public key's type, the key pair's own `public_key_type`.
 * @param key_pair The key pair.
 * @param peer The peer's public key.
 * @return What `key_pair.agree(peer)` returns: the shared point's x coordinate, or its error.
 */
template <class Keypair, class PublicKey>
    requires requires(Keypair const& key_pair, PublicKey const& peer) { key_pair.agree(peer); }
[[nodiscard]] auto agree(Keypair const& key_pair,
                         PublicKey const& peer) noexcept(noexcept(key_pair.agree(peer)))
    -> decltype(key_pair.agree(peer)) {
    detail::timing_guard const timing;
    return key_pair.agree(peer);
}

/**
 * Stops the build: the key pair has no `agree` that takes this peer, a key pair of a curve without
 * an agreement, or a peer of another curve, another backend, or bytes.
 *
 * @tparam Keypair The key pair's type, a key pair of the contract.
 * @tparam PublicKey The peer's type.
 * @param key_pair The key pair.
 * @param peer The peer.
 * @return Never: the call does not compile.
 */
template <class Keypair, class PublicKey>
    requires(keypair<Keypair> &&
             !requires(Keypair const& key, PublicKey const& other) { key.agree(other); })
[[nodiscard]] boost::system::result<void> agree([[maybe_unused]] Keypair const& key_pair,
                                                [[maybe_unused]] PublicKey const& peer) noexcept {
    static_assert(detail::refused_v<Keypair>,
                  "webcpp::crypto: agree: this key pair does not agree with this peer: a P-256 "
                  "key pair agrees with a curves::p256::basic_public_key of its backend, a "
                  "secp256k1 key pair with a curves::secp256k1::public_key; an Ed25519 key pair "
                  "agrees through X25519, its x25519_secret() and curves::x25519::agree.");
    return {};
}

}  // namespace webcpp::crypto

#endif  // WEBCPP_CRYPTO_KEYPAIR_HPP
