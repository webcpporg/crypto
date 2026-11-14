// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

#ifndef WEBCPP_CRYPTO_DETAIL_ENGINES_HPP
#define WEBCPP_CRYPTO_DETAIL_ENGINES_HPP

#include <webcpp/crypto/config.hpp>

#include <cstddef>

namespace webcpp::crypto::detail {

/**
 * What a backend's header specialises, per algorithm: a state, which an object stores and
 * which never refuses, and an engine, used only inside the algorithm's member functions,
 * whose specialisation for a backend without the algorithm holds the `static_assert` that
 * names the backends that have it. A backend whose header is not included leaves both
 * undefined, and the compiler names the specialisation it lacks.
 *
 * Tip: `gcm<aes256<backends::bearssl>>` reads `aes256<backends::bearssl>::key_size`, which
 * instantiates the class and its members' types, so a refusal in the block cipher's state
 * would refuse BearSSL's GCM too.
 */
template <class Backend, std::size_t KeySize>
struct block_state;
/** The work of the AES block cipher on a backend (see @ref block_state). */
template <class Backend, std::size_t KeySize>
struct block_engine;
/** What a `gcm` stores (see @ref block_state). */
template <class Backend, std::size_t KeySize>
struct gcm_state;
/** The work of GCM on a backend (see @ref block_state). */
template <class Backend, std::size_t KeySize>
struct gcm_engine;
/** What a `chacha20_poly1305` stores (see @ref block_state). */
template <class Backend>
struct chacha_state;
/** The work of ChaCha20-Poly1305 on a backend (see @ref block_state). */
template <class Backend>
struct chacha_engine;

/**
 * Reads a backend's canary with a volatile load, which no linker can drop: a program built
 * without the backend's library, or with one of another commit or configuration, then
 * fails to link, naming the canary (spec section 4.3).
 *
 * @param canary The canary's symbol.
 */
inline void read_canary(char const volatile& canary) noexcept {
    static_cast<void>(canary);
}

}  // namespace webcpp::crypto::detail

#endif  // WEBCPP_CRYPTO_DETAIL_ENGINES_HPP
