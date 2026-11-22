// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

#ifndef WEBCPP_CRYPTO_DETAIL_ASYNCHRONOUS_HPP
#define WEBCPP_CRYPTO_DETAIL_ASYNCHRONOUS_HPP

#include <webcpp/crypto/config.hpp>

namespace webcpp::crypto::detail {

/**
 * Whether `Backend` completes by itself, asynchronously: no backend yet; part B's
 * `backends::browser` alone will, through `async.hpp`'s `async_engine`.
 *
 * Every synchronous form of an operation on such a backend stops the build with a message that
 * names its `async_` form (design D9); the AEAD headers and the curves' read it here, with no
 * other dependency.
 *
 * @tparam Backend A backend.
 */
template <class Backend>
inline constexpr bool asynchronous_backend_v = false;

}  // namespace webcpp::crypto::detail

#endif  // WEBCPP_CRYPTO_DETAIL_ASYNCHRONOUS_HPP
