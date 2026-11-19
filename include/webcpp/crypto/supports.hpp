// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 Whether a backend has an algorithm on the target being compiled, as the capability table,
 `doc/tables/crypto.json`, says.

 @see "The backends", in the guide.
*/
#ifndef WEBCPP_CRYPTO_SUPPORTS_HPP
#define WEBCPP_CRYPTO_SUPPORTS_HPP

#include <webcpp/crypto/config.hpp>

#include <webcpp/crypto/detail/capabilities.hpp>

namespace webcpp::crypto {

/**
 * `true` exactly where the capability table says that `Backend` has `Algorithm` on the target
 * being compiled.
 *
 * A cell decided at run time is `true` too: its `make` then reports `not_supported` on a
 * machine that lacks it. It needs no backend's header and no library: a program asks it of a
 * backend it does not link.
 *
 * @tparam Algorithm An algorithm's type, which names its `family_type` and its `name_type`, as
 * `ciphers::aes256_gcm` does.
 * @tparam Backend A backend tag of `backends`.
 */
template <class Algorithm, class Backend>
inline constexpr bool supports_v =
    detail::supported<typename Algorithm::family_type, typename Algorithm::name_type, Backend>;

}  // namespace webcpp::crypto

#endif  // WEBCPP_CRYPTO_SUPPORTS_HPP
