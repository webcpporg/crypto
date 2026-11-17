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

/** False for every `T`: a `static_assert` on it fires only where its template is instantiated. */
template <class T>
inline constexpr bool dependent_false = false;

/**
 * What a backend's header specialises, per algorithm: a state, which an object stores and
 * which never refuses, and an engine, used only inside the algorithm's member functions. The
 * family's header defines both primaries: an empty state, and an engine whose body is the
 * family's generated refusal (`detail/capabilities.hpp`), which a backend reaches where its
 * header does not specialise the engine: one without the algorithm is refused, naming the
 * backends that have it; the default, not linked, says the Jamfile line that links it and the
 * type that names another backend; one whose header is not included is told to include it.
 *
 * Tip: `ciphers::gcm<aes256<backends::bearssl>>` reads
 * `ciphers::aes256<backends::bearssl>::key_size`, which instantiates the class and its members'
 * types, so a refusal in the block cipher's state would refuse BearSSL's GCM too.
 */
template <class Backend, std::size_t KeySize>
struct block_state;
/** The work of the AES block cipher on a backend (see @ref block_state). */
template <class Backend, std::size_t KeySize>
struct block_engine;
/** What a `ciphers::gcm` stores (see @ref block_state). */
template <class Backend, std::size_t KeySize>
struct gcm_state;
/** The work of GCM on a backend (see @ref block_state). */
template <class Backend, std::size_t KeySize>
struct gcm_engine;
/** What a `ciphers::aead` of the family `Family` stores (see @ref block_state). */
template <class Family, class Backend>
struct aead_state;
/**
 * The work of a `ciphers::aead` of the family `Family` on a backend, whose specialisation
 * provides `init(state&, key)`, `seal(state&, iv, additional_data, data, tag&)`,
 * `open(state&, iv, additional_data, data, tag const&)`, `move(to, from)` and `reset(state&)`
 * (see @ref block_state).
 */
template <class Family, class Backend>
struct aead_engine;

/**
 * Reads a backend's canary with a volatile load, which no linker can drop: a program built
 * without the backend's library, or with one of another commit or configuration, then
 * fails to link, naming the canary.
 *
 * @param canary_byte The canary's symbol.
 */
inline void read_canary(char const volatile& canary_byte) noexcept {
    // The volatile glvalue is converted to a value: a discarded one is not read by gcc
    // ("conversion to void will not access object").
    char const canary_copy = canary_byte;
    static_cast<void>(canary_copy);
}

}  // namespace webcpp::crypto::detail

#endif  // WEBCPP_CRYPTO_DETAIL_ENGINES_HPP
