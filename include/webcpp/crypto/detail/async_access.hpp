// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

#ifndef WEBCPP_CRYPTO_DETAIL_ASYNC_ACCESS_HPP
#define WEBCPP_CRYPTO_DETAIL_ASYNC_ACCESS_HPP

#include <webcpp/crypto/config.hpp>

#include <webcpp/crypto/detail/defaults.hpp>

namespace webcpp::crypto {

/**
 * The backend of the asynchronous family when a call names none (ruling R-A4): the synchronous
 * function's, `default_backend_t<Family>`, on every target, Emscripten included.
 *
 * The browser's backend is never a default: a program names it in the type to reach WebCrypto.
 * Declared here, beside the asynchronous family's other shared pieces, so that a curve's header
 * defaults its asynchronous members' backend to it as `<webcpp/crypto/async.hpp>` defaults the free
 * forms', without including Asio.
 *
 * @tparam Family A family tag of `families` that has a default.
 */
template <class Family>
using default_async_backend_t = default_backend_t<Family>;

}  // namespace webcpp::crypto

namespace webcpp::crypto::detail {

/**
 * The empty objects of the asynchronous family's error completions (ruling R-A3): an operation
 * that completes with `void(error_code, T)` gives, on an error, the object a move leaves (a
 * `secret<N>` or an array of zeros, a `gcm` or a key pair without a key), whose every member
 * refuses with `invalid_state` where it has members.
 *
 * Each such type whose default constructor is private befriends this class; a type whose
 * default constructor is public (`secret<N>`, `std::array`) needs no friendship.
 */
struct async_access {
    /**
     * An empty `T`: its default constructor, private through friendship or public, or the
     * value-initialisation of an aggregate (an array of zeros).
     *
     * @tparam T The completion's value type.
     * @return The empty object.
     */
    template <class T>
    [[nodiscard]] static T empty() noexcept {
        static_assert(noexcept(T{}),
                      "webcpp::crypto: an error completion's empty value is made without failing");
        return T{};
    }
};

}  // namespace webcpp::crypto::detail

#endif  // WEBCPP_CRYPTO_DETAIL_ASYNC_ACCESS_HPP
