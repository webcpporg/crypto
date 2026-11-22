// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 The free synchronous forms of the static members that make an object (design D9, R23):
 `crypto::make<A>(bytes)`, which serves key pairs, public keys, AES-GCM and every AEAD, and
 `crypto::generate<K>()`, each calling the member it is named after.

 It depends on nothing but the configuration and the timing guard, so that `keypair.hpp` and the
 AEAD headers include it without bringing in what the other needs.

 @see "Signatures: the scheme and the input", in the guide.
*/
#ifndef WEBCPP_CRYPTO_MAKE_HPP
#define WEBCPP_CRYPTO_MAKE_HPP

#include <webcpp/crypto/config.hpp>

#include <webcpp/crypto/detail/timing.hpp>

#include <utility>

namespace webcpp::crypto {

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

}  // namespace webcpp::crypto

#endif  // WEBCPP_CRYPTO_MAKE_HPP
