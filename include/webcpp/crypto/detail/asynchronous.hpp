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
 * names its `async_` form (design D9), but for the constructions WebCrypto lacks, which name a
 * native backend (`refuse_aead_on_asynchronous_backend`); the AEAD headers and the curves' read
 * it here, with no other dependency.
 *
 * @tparam Backend A backend.
 */
template <class Backend>
inline constexpr bool asynchronous_backend_v = false;

/**
 * Stops the build: a construction WebCrypto lacks (ChaCha20-Poly1305 and its forms, the secret
 * boxes, crypto_box), asked of a backend that completes by itself (design D6, the controller's
 * ruling "D6 text for constructions WebCrypto lacks, sync and async alike").
 *
 * Every form of such a construction on such a backend, synchronous or asynchronous, member or
 * free, calls it first after its guard, before any member of the type or its engine is named
 * (ruling P12), so that its text is the build's one message, is written once, and points to a
 * native backend: no form of these constructions completes there. AES-GCM, which WebCrypto has,
 * keeps its own refusal, which names its `async_` form.
 *
 * @tparam Backend The backend, whose `asynchronous_backend_v` is true.
 */
template <class Backend>
constexpr void refuse_aead_on_asynchronous_backend() noexcept {
    static_assert(!asynchronous_backend_v<Backend>,
                  "webcpp::crypto: WebCrypto has no ChaCha20-Poly1305, XChaCha20-Poly1305, "
                  "secret box or crypto_box: their async_seal, async_open and async_from_key run "
                  "on a native backend; on the browser's backend only AES-GCM is asynchronous.");
}

}  // namespace webcpp::crypto::detail

#endif  // WEBCPP_CRYPTO_DETAIL_ASYNCHRONOUS_HPP
