// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 The free synchronous forms of the static members that make an object, each named by its input:
 `crypto::from_secret<K>(secret_bytes)`, which serves key pairs, `crypto::from_bytes<T>(bytes)`,
 which serves public values made from their bytes, `crypto::from_key<C>(key_bytes)`, which serves
 AES-GCM and every AEAD, and `crypto::generate<K>()`, each calling the member it is named after.
 The four forms of an operation are crypto/unified-sign's design D9, the header of the free forms
 its R23; the names by input are crypto/uniform-types' D3c, and this header's name its R13.

 It depends on nothing but the configuration and the timing guard, so that `keypair.hpp` and the
 AEAD headers include it without bringing in what the other needs.

 @see "Signatures: the scheme and the input", in the guide.
*/
#ifndef WEBCPP_CRYPTO_FACTORIES_HPP
#define WEBCPP_CRYPTO_FACTORIES_HPP

#include <webcpp/crypto/config.hpp>

#include <webcpp/crypto/detail/timing.hpp>

#include <utility>

namespace webcpp::crypto {

/**
 * Makes a key pair from its secret bytes, `Keypair::from_secret(forwarded_arguments...)`: the free
 * form of the key pair's own `from_secret`, which it calls, with its results and its errors.
 *
 * @tparam Keypair A type whose static `from_secret` takes these arguments: a key pair.
 * @tparam Arguments The types of `from_secret`'s arguments.
 * @param forwarded_arguments `from_secret`'s arguments: the secret bytes, and secp256k1's memory
 * resource.
 * @return What `Keypair::from_secret(forwarded_arguments...)` returns: the key pair, or its error.
 */
template <class Keypair, class... Arguments>
    requires requires { Keypair::from_secret(std::declval<Arguments>()...); }
[[nodiscard]] auto from_secret(Arguments&&... forwarded_arguments) noexcept(
    noexcept(Keypair::from_secret(std::forward<Arguments>(forwarded_arguments)...)))
    -> decltype(Keypair::from_secret(std::forward<Arguments>(forwarded_arguments)...)) {
    detail::timing_guard const timing_scope;
    return Keypair::from_secret(std::forward<Arguments>(forwarded_arguments)...);
}

/**
 * Makes a public value from its bytes, `Type::from_bytes(forwarded_arguments...)`: the free form
 * of the type's own `from_bytes`, which it calls, with its results and its errors.
 *
 * It holds no timing guard, since it calls no backend itself: a member `from_bytes` that checks its
 * bytes with a backend (a point on the curve) holds its own, and one that only checks their size
 * and copies them holds none, as no function without a backend call does.
 *
 * @tparam Type A type whose static `from_bytes` takes these arguments: a public value, such as a
 * public key.
 * @tparam Arguments The types of `from_bytes`'s arguments.
 * @param forwarded_arguments `from_bytes`'s arguments: the bytes.
 * @return What `Type::from_bytes(forwarded_arguments...)` returns: the value, or its error.
 */
template <class Type, class... Arguments>
    requires requires { Type::from_bytes(std::declval<Arguments>()...); }
[[nodiscard]] auto from_bytes(Arguments&&... forwarded_arguments) noexcept(
    noexcept(Type::from_bytes(std::forward<Arguments>(forwarded_arguments)...)))
    -> decltype(Type::from_bytes(std::forward<Arguments>(forwarded_arguments)...)) {
    return Type::from_bytes(std::forward<Arguments>(forwarded_arguments)...);
}

/**
 * Makes a cipher from its key bytes, `Cipher::from_key(forwarded_arguments...)`: the free form of
 * the cipher's own `from_key`, which it calls, with its results and its errors.
 *
 * @tparam Cipher A type whose static `from_key` takes these arguments: AES-GCM or another AEAD.
 * @tparam Arguments The types of `from_key`'s arguments.
 * @param forwarded_arguments `from_key`'s arguments: the key bytes.
 * @return What `Cipher::from_key(forwarded_arguments...)` returns: the cipher, or its error.
 */
template <class Cipher, class... Arguments>
    requires requires { Cipher::from_key(std::declval<Arguments>()...); }
[[nodiscard]] auto from_key(Arguments&&... forwarded_arguments) noexcept(
    noexcept(Cipher::from_key(std::forward<Arguments>(forwarded_arguments)...)))
    -> decltype(Cipher::from_key(std::forward<Arguments>(forwarded_arguments)...)) {
    detail::timing_guard const timing_scope;
    return Cipher::from_key(std::forward<Arguments>(forwarded_arguments)...);
}

/**
 * Makes a key pair from a fresh secret drawn from the system's generator,
 * `Keypair::generate(forwarded_arguments...)`: the free form of the key pair's own `generate`,
 * which it calls, with its results and its errors.
 *
 * @tparam Keypair A type whose static `generate` takes these arguments: a key pair.
 * @tparam Arguments The types of `generate`'s arguments: none, or secp256k1's memory resource.
 * @param forwarded_arguments `generate`'s arguments.
 * @return What `Keypair::generate(forwarded_arguments...)` returns: the key pair, or its error.
 */
template <class Keypair, class... Arguments>
    requires requires { Keypair::generate(std::declval<Arguments>()...); }
[[nodiscard]] auto generate(Arguments&&... forwarded_arguments) noexcept(
    noexcept(Keypair::generate(std::forward<Arguments>(forwarded_arguments)...)))
    -> decltype(Keypair::generate(std::forward<Arguments>(forwarded_arguments)...)) {
    detail::timing_guard const timing_scope;
    return Keypair::generate(std::forward<Arguments>(forwarded_arguments)...);
}

}  // namespace webcpp::crypto

#endif  // WEBCPP_CRYPTO_FACTORIES_HPP
