// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 The key pairs' three concepts (design D4), each checked by what a key pair does:
 - `crypto::keypair`, what every curve's key pair is: made from its secret bytes by `from_secret`
   or drawn by `generate`, its typed public key, and its secret bytes back by `secret()`;
 - `crypto::signing_keypair`, a key pair that signs, `sign(scheme, input)` for every scheme its
   curve declares, at least one, of the library's one list of schemes, `detail::all_schemes` in
   `signing.hpp`, each into the scheme's signature type: Ed25519's, P-256's and secp256k1's;
 - `crypto::agreement_keypair`, a key pair that agrees, `agree(peer)` with its own public key
   type, giving a `secure::secret<N>`: X25519's, P-256's and secp256k1's.

 Each curve's header checks its own key pair's row with `static_assert`s where its default backend
 is linked.

 Beside them, the free synchronous forms of the key pairs' `sign` and `agree` (design D9),
 `crypto::sign(key_pair, scheme, input)`, constrained by `signing_keypair`, and
 `crypto::agree(key_pair, peer)`, constrained by `agreement_keypair`; and, through `factories.hpp`,
 which it includes, `crypto::from_secret<K>(bytes)`, `crypto::from_bytes<T>(bytes)`,
 `crypto::from_key<C>(key)` and `crypto::generate<K>()`.

 @see "Signatures: the scheme and the input", in the guide.
*/
#ifndef WEBCPP_CRYPTO_KEYPAIR_HPP
#define WEBCPP_CRYPTO_KEYPAIR_HPP

#include <webcpp/crypto/config.hpp>

#include <webcpp/crypto/detail/signature.hpp>
#include <webcpp/crypto/factories.hpp>
#include <webcpp/crypto/signing.hpp>
#include <webcpp/secure/secret.hpp>
#include <webcpp/secure/timing_guard.hpp>

#include <boost/system/result.hpp>

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>

namespace webcpp::crypto {

/**
 * Whether `Keypair` is a key pair (design D4), what every curve's key pair is, whatever it does:
 * - `Keypair::from_secret(secret_bytes)` and `Keypair::generate()` give `result<Keypair>`;
 * - `key.public_key()` gives `result<typename Keypair::public_key_type>`, the curve's typed public
 *   key;
 * - `key.secret()` gives `result<secure::secret<Keypair::secret_key_size>>`, the bytes
 *   `from_secret` takes back.
 *
 * What it does is the refinements': `signing_keypair` signs, `agreement_keypair` agrees.
 *
 * @tparam Keypair A type, without its reference and qualifiers.
 */
template <class Keypair>
concept keypair = requires {
    typename Keypair::public_key_type;
    {
        Keypair::from_secret(std::declval<std::span<std::uint8_t const>&>())
    } -> std::same_as<boost::system::result<Keypair>>;
    { Keypair::generate() } -> std::same_as<boost::system::result<Keypair>>;
    {
        std::declval<Keypair const&>().public_key()
    } -> std::same_as<boost::system::result<typename Keypair::public_key_type>>;
    {
        std::declval<Keypair const&>().secret()
    } -> std::same_as<boost::system::result<secure::secret<Keypair::secret_key_size>>>;
};

namespace detail {

/**
 * The input `signing_keypair` signs under `Scheme`: a message, as
 * `std::span<std::uint8_t const>`, for a scheme that takes one.
 *
 * @tparam Scheme A scheme tag.
 */
template <class Scheme, bool = takes_message_v<Scheme>>
struct contract_input {
    /** A message. */
    using type = std::span<std::uint8_t const>;
};

/**
 * The input `signing_keypair` signs under a scheme that takes its digest alone,
 * `eddsa_prehashed`: the marker of the scheme's digest size.
 *
 * @tparam Scheme A scheme tag.
 */
template <class Scheme>
struct contract_input<Scheme, false> {
    /** The marker of a digest of the scheme's size. */
    using type = prehashed<scheme_traits<Scheme>::digest_size>;
};

/**
 * Whether the key pair `Keypair` keeps its curve's word about `Scheme`: a scheme the curve does
 * not declare for it asks nothing; one it declares (`signs_with_v`) asks that
 * `key.sign(scheme, input)` be a valid call giving `result<signature_of_t<Keypair, Scheme>>`, the
 * scheme's signature type for the key pair's curve, the input a message, or for a scheme that
 * takes its digest alone (`eddsa_prehashed`) the marker of one (`contract_input`).
 *
 * @tparam Keypair A key pair's type.
 * @tparam Scheme A scheme tag.
 */
template <class Keypair, class Scheme>
concept signs_as_declared = !signs_with_v<Keypair, Scheme> || requires {
    {
        std::declval<Keypair const&>().sign(std::declval<Scheme const&>(),
                                            std::declval<typename contract_input<Scheme>::type&>())
    } -> std::same_as<boost::system::result<signature_of_t<Keypair, Scheme>>>;
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
 * A signing key pair over the schemes of `List`: `crypto::signing_keypair` is this concept over
 * `all_schemes`, and a test passes a list with a scheme of its own.
 *
 * @tparam Keypair A type, without its reference and qualifiers.
 * @tparam List A `scheme_list`.
 */
template <class Keypair, class List>
concept signing_keypair_over =
    keypair<Keypair> && signs_some_scheme_v<Keypair, List> && signs_every_declared_v<Keypair, List>;

/**
 * Whether `Type` is the result of an agreement, `result<secure::secret<N>>`: false for any other
 * type.
 *
 * @tparam Type Any type.
 */
template <class Type>
inline constexpr bool is_secret_result_v = false;

/**
 * Whether `result<secure::secret<N>>` is the result of an agreement: it is.
 *
 * @tparam N The shared secret's size in bytes.
 */
template <std::size_t N>
inline constexpr bool is_secret_result_v<boost::system::result<secure::secret<N>>> = true;

/**
 * Whether `key.sign(scheme, input, extra...)` names a member `sign` of `Keypair` that takes these
 * arguments: the key pair's own signing function, which `crypto::sign` calls.
 *
 * @tparam Keypair A key pair's type, or any type.
 * @tparam Scheme A scheme tag, or any type.
 * @tparam Input The input's type.
 * @tparam Extra The types of the arguments after the input, secp256k1's 32 bytes.
 */
template <class Keypair, class Scheme, class Input, class... Extra>
concept has_sign_member = requires {
    std::declval<Keypair const&>().sign(std::declval<Scheme const&>(), std::declval<Input const&>(),
                                        std::declval<Extra const&>()...);
};

/**
 * Whether `key.agree(peer)` names a member `agree` of `Keypair` that takes this peer: the key
 * pair's own agreement, which `crypto::agree` calls.
 *
 * @tparam Keypair A key pair's type, or any type.
 * @tparam PublicKey The peer's type.
 */
template <class Keypair, class PublicKey>
concept has_agree_member =
    requires { std::declval<Keypair const&>().agree(std::declval<PublicKey const&>()); };

}  // namespace detail

/**
 * Whether `Keypair` is a key pair that signs (design D4): a `keypair` whose
 * `key.sign(scheme, input)` is valid for every scheme its curve declares for it
 * (`detail::signs_with_v`), and it declares at least one, each giving `result` of the scheme's
 * signature type for its curve (`detail::signature_of_t`); the input a message, or the marker of
 * a digest for a scheme that takes its digest alone (`crypto::eddsa_prehashed`).
 *
 * The schemes asked are the library's one list of them, `detail::all_schemes`, which the concept
 * folds over (`detail::signing_keypair_over`).
 *
 * Ed25519's, P-256's and secp256k1's key pairs are; X25519's is not: it agrees.
 *
 * @tparam Keypair A type, without its reference and qualifiers.
 */
template <class Keypair>
concept signing_keypair = detail::signing_keypair_over<Keypair, detail::all_schemes>;

/**
 * Whether `Keypair` is a key pair that agrees (design D4): a `keypair` whose `key.agree(peer)`,
 * `peer` its own `typename Keypair::public_key_type`, gives `result<secure::secret<N>>`, the shared
 * secret.
 *
 * X25519's, P-256's and secp256k1's key pairs are; Ed25519's is not: it signs, and `to_x25519()`
 * converts it to an X25519 key pair, which agrees.
 *
 * @tparam Keypair A type, without its reference and qualifiers.
 */
template <class Keypair>
concept agreement_keypair = keypair<Keypair> && requires {
    requires detail::is_secret_result_v<decltype(std::declval<Keypair const&>().agree(
        std::declval<typename Keypair::public_key_type const&>()))>;
};

/**
 * Signs with a key pair, `key_pair.sign(signing_scheme, signing_input, extra_arguments...)`: the
 * free form of the key pair's own `sign`, which it calls, with its results, its errors and its
 * refusals.
 *
 * A scheme the key pair does not have, or an input the scheme does not take, stops the build with
 * the key pair's own message.
 *
 * @tparam Keypair A `signing_keypair` whose `sign` takes these arguments: Ed25519's, P-256's or
 * secp256k1's.
 * @tparam Scheme A scheme tag.
 * @tparam Input A message, bytes that convert to `std::span<std::uint8_t const>`, or
 * `crypto::prehashed<N>`.
 * @tparam Extra Nothing, or secp256k1's 32 bytes: the hedged ECDSA's extra entropy or BIP340's
 * auxiliary randomness.
 * @param key_pair The key pair.
 * @param signing_scheme The scheme.
 * @param signing_input The message or the marker.
 * @param extra_arguments Nothing, or secp256k1's 32 bytes.
 * @return What `key_pair.sign(signing_scheme, signing_input, extra_arguments...)` returns: the
 * signature, or its error.
 */
template <class Keypair, class Scheme, class Input, class... Extra>
    requires(signing_keypair<Keypair> && detail::has_sign_member<Keypair, Scheme, Input, Extra...>)
[[nodiscard]] auto sign(
    Keypair const& key_pair, Scheme signing_scheme, Input const& signing_input,
    Extra const&... extra_arguments) noexcept(noexcept(key_pair.sign(signing_scheme, signing_input,
                                                                     extra_arguments...)))
    -> decltype(key_pair.sign(signing_scheme, signing_input, extra_arguments...)) {
    secure::timing_guard const timing_scope;
    return key_pair.sign(signing_scheme, signing_input, extra_arguments...);
}

/**
 * Stops the build: the first argument is not a signing key pair whose `sign` takes these
 * arguments: an X25519 key pair, which agrees and does not sign, a public key, or a key pair given
 * arguments its `sign` does not take.
 *
 * @tparam Keypair The first argument's type.
 * @tparam Scheme A scheme tag.
 * @tparam Input The input's type.
 * @tparam Extra The types of the arguments after the input.
 * @param key_pair The first argument.
 * @param signing_scheme The scheme.
 * @param signing_input The input.
 * @param extra_arguments The arguments after the input.
 * @return Never: the call does not compile.
 */
template <class Keypair, class Scheme, class Input, class... Extra>
    requires(detail::is_scheme_v<Scheme> &&
             !(signing_keypair<Keypair> &&
               detail::has_sign_member<Keypair, Scheme, Input, Extra...>))
[[nodiscard]] boost::system::result<void> sign(
    [[maybe_unused]] Keypair const& key_pair, [[maybe_unused]] Scheme signing_scheme,
    [[maybe_unused]] Input const& signing_input,
    [[maybe_unused]] Extra const&... extra_arguments) noexcept {
    if constexpr (agreement_keypair<Keypair> && !signing_keypair<Keypair>) {
        static_assert(detail::refused_v<Keypair>,
                      "webcpp::crypto: sign: X25519 key pairs agree; they do not sign: sign with "
                      "an Ed25519 key pair, which to_x25519() converts for agreement.");
    } else {
        static_assert(
            detail::refused_v<Keypair>,
            "webcpp::crypto: sign: the first argument is a key pair, and the others are "
            "its sign's: crypto::sign(key_pair, scheme, input), and on secp256k1 its 32 "
            "bytes of extra entropy or auxiliary randomness after the input; a public key "
            "verifies, with crypto::verify.");
    }
    return {};
}

/**
 * Agrees a secret with a peer's public key, `key_pair.agree(peer_key)`: the free form of the key
 * pair's own `agree`, which it calls, with its results and its errors.
 *
 * @tparam Keypair An `agreement_keypair` whose `agree` takes `peer_key`: X25519's, P-256's or
 * secp256k1's.
 * @tparam PublicKey The peer's public key's type, the key pair's own `public_key_type`.
 * @param key_pair The key pair.
 * @param peer_key The peer's public key.
 * @return What `key_pair.agree(peer_key)` returns: the shared secret (X25519's, or the shared
 * point's x coordinate), or its error.
 */
template <class Keypair, class PublicKey>
    requires(agreement_keypair<Keypair> && detail::has_agree_member<Keypair, PublicKey>)
[[nodiscard]] auto agree(Keypair const& key_pair,
                         PublicKey const& peer_key) noexcept(noexcept(key_pair.agree(peer_key)))
    -> decltype(key_pair.agree(peer_key)) {
    secure::timing_guard const timing_scope;
    return key_pair.agree(peer_key);
}

/**
 * Stops the build: the key pair is not an agreement key pair whose `agree` takes this peer: an
 * Ed25519 key pair, which signs and does not agree, or a peer of another curve, another backend,
 * or bytes, each with its own message.
 *
 * @tparam Keypair The key pair's type, a `keypair`.
 * @tparam PublicKey The peer's type.
 * @param key_pair The key pair.
 * @param peer_key The peer.
 * @return Never: the call does not compile.
 */
template <class Keypair, class PublicKey>
    requires(keypair<Keypair> &&
             !(agreement_keypair<Keypair> && detail::has_agree_member<Keypair, PublicKey>))
[[nodiscard]] boost::system::result<void> agree(
    [[maybe_unused]] Keypair const& key_pair, [[maybe_unused]] PublicKey const& peer_key) noexcept {
    if constexpr (signing_keypair<Keypair> && !agreement_keypair<Keypair>) {
        static_assert(detail::refused_v<Keypair>,
                      "webcpp::crypto: agree: Ed25519 key pairs sign; they do not agree: convert "
                      "one with to_x25519() and agree with the X25519 key pair.");
    } else {
        static_assert(detail::refused_v<Keypair>,
                      "webcpp::crypto: agree: this key pair does not agree with this peer: an "
                      "X25519 key pair agrees with a curves::x25519::public_key, a P-256 key pair "
                      "with a curves::p256::basic_public_key of its backend, a secp256k1 key pair "
                      "with a curves::secp256k1::public_key.");
    }
    return {};
}

}  // namespace webcpp::crypto

#endif  // WEBCPP_CRYPTO_KEYPAIR_HPP
