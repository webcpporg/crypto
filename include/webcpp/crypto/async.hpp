// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 The asynchronous family (design D23), webcpp::hash's `<webcpp/hash/async.hpp>`'s twin: each
 function an Asio asynchronous operation in webcpp::asio's model, initiated through
 `async_initiate`, so that one call works with a callback, `use_awaitable`, Cobalt's `use_op`,
 `deferred`, `as_tuple`, `use_future` and every other completion token. An operation that returns
 a value completes with `void(boost::system::error_code, T)`, the value second, and on an error
 the empty object a move leaves (a `secret<N>` or an array of zeros, a `gcm` or a key pair without
 a key, whose every member refuses with `invalid_state`); one without a value completes with
 `void(boost::system::error_code)`.

 - The cheap functions exist on every target, for the algorithms the browser's WebCrypto has.
   Each takes the executor its completion is posted to first. On a synchronous backend, their
   default, they run the synchronous call at once (its guards and its work, on the caller's
   thread) and complete through a post to that executor, whence the completion reaches the
   handler's associated executor, never inside the initiating call.
 - The heavy functions (design D32's list) take the work executor first (a
   `webcpp::asio::thread_pool`'s): they check their guards on the caller's thread, run the work on
   the work executor and complete on the handler's associated executor, with webcpp::hash's
   cancellation rules (`detail/heavy.hpp`). They exist only where the build has threads
   (`WEBCPP_CRYPTO_HAS_THREADS`); elsewhere each name refuses at compile time.

 The default backend of each is the synchronous function's, `default_async_backend_t<Family>`,
 `default_backend_t<Family>` on every target, Emscripten included: the browser's backend is used
 only where a type names it, so that one program gives the same bytes on every target.

 What a call reads (the object, the spans) is the caller's until the completion: a synchronous
 backend reads it before the call returns, the browser's later.

 The header needs webcpp::asio, `<library>/webcpp/asio//asio` in the program's Jamfile, which
 `<webcpp/crypto.hpp>` does not bring: include it by itself.

 @code
 // exe app : app.cpp /webcpp/crypto//crypto /webcpp/crypto//gcm-default /webcpp/asio//asio ;
 // A coroutine seals in place on the default backend; the completion, the error code and the
 // tag, is posted to the coroutine's executor.
 namespace asio = webcpp::asio;
 auto const executor = co_await asio::this_coro::executor;
 auto [code, tag] = co_await webcpp::crypto::async_seal(executor, aead, iv, ad, data,
                                                        asio::as_tuple(asio::use_awaitable));
 @endcode

 @see "Asynchronous calls", in the guide.
*/
#ifndef WEBCPP_CRYPTO_ASYNC_HPP
#define WEBCPP_CRYPTO_ASYNC_HPP

#include <webcpp/crypto/config.hpp>

#include <webcpp/crypto/ciphers/gcm.hpp>
#include <webcpp/crypto/curves/ed25519.hpp>
#include <webcpp/crypto/curves/x25519.hpp>
#include <webcpp/crypto/detail/async_access.hpp>
#include <webcpp/crypto/detail/defaults.hpp>
#include <webcpp/crypto/detail/heavy.hpp>

#include <webcpp/asio/append.hpp>
#include <webcpp/asio/async_result.hpp>
#include <webcpp/asio/post.hpp>

#include <boost/system/error_code.hpp>
#include <boost/system/result.hpp>

#include <type_traits>
#include <utility>

namespace webcpp::crypto {

/**
 * The backend of the asynchronous family when a call names none (ruling R-A4): the synchronous
 * function's, `default_backend_t<Family>`, on every target, Emscripten included. The browser's
 * backend is never a default: a program names it in the type to reach WebCrypto.
 *
 * @tparam Family A family tag of `families` that has a default.
 */
template <class Family>
using default_async_backend_t = default_backend_t<Family>;

namespace detail {

/**
 * Whether `Backend` completes by itself, asynchronously: no backend yet; part B's
 * `backends::browser` alone will, through @ref async_engine.
 *
 * @tparam Backend A backend.
 */
template <class Backend>
inline constexpr bool asynchronous_backend_v = false;

/**
 * The operations of a backend that completes by itself: part B specialises it for
 * `backends::browser`, with a static member function per asynchronous function, taking its
 * arguments and returning its result. Declared only: no synchronous backend reaches it.
 *
 * @tparam Backend `backends::browser`.
 */
template <class Backend>
struct async_engine;

/**
 * The initiation of a cheap function on a synchronous backend: runs the synchronous call (its
 * guards first) at once and posts the completion, its result split by @ref completion_of, to
 * `executor`, whence it reaches the handler's associated executor; the post's storage is the
 * handler's associated allocator's.
 */
struct post_initiation {
    /**
     * Runs `operation` and posts `handler` with its error code and, for a call that returns a
     * value, the value, or on an error the empty one (ruling R-A3).
     *
     * @param handler The completion handler.
     * @param executor The executor the completion is posted to.
     * @param operation The synchronous call, bound to its arguments.
     */
    template <class Handler, class Executor, class Operation>
    void operator()(Handler&& handler, Executor const& executor, Operation operation) const {
        auto done = operation();
        using value_type = completion_of<decltype(done)>::value_type;
        if constexpr (std::is_void_v<value_type>) {
            boost::system::error_code const code =
                done ? boost::system::error_code{} : done.error();
            webcpp::asio::post(executor,
                               webcpp::asio::append(std::forward<Handler>(handler), code));
        } else if (done) {
            webcpp::asio::post(executor,
                               webcpp::asio::append(std::forward<Handler>(handler),
                                                    boost::system::error_code{}, std::move(*done)));
        } else {
            webcpp::asio::post(executor,
                               webcpp::asio::append(std::forward<Handler>(handler), done.error(),
                                                    async_access::empty<value_type>()));
        }
    }
};

/**
 * Initiates a cheap function on a synchronous backend (design D23): runs `operation()` at once,
 * on the caller's thread, and completes through a post to `executor`, never inside the call,
 * with `operation()`'s result split into its error code and its value.
 *
 * @tparam CompletionToken Any completion token, of signature `completion_of<R>::type`, `R`
 * `operation()`'s result.
 * @param executor The executor the completion is posted to, whence it reaches the handler's
 * associated executor.
 * @param token The completion token.
 * @param operation The synchronous call, bound to its arguments: a `noexcept` call without
 * arguments returning `boost::system::result<T>` or `boost::system::result<void>`, called once.
 * @return What the completion token's `async_result` gives.
 */
template <class CompletionToken, class Executor, class Operation>
auto complete_by_post(Executor const& executor, CompletionToken& token, Operation operation) {
    static_assert(std::is_nothrow_invocable_v<Operation&>,
                  "webcpp::crypto: an asynchronous operation's call reports its errors as values");
    using signature = completion_of<std::invoke_result_t<Operation&>>::type;
    return webcpp::asio_backend::async_initiate<CompletionToken, signature>(
        post_initiation{}, token, executor, std::move(operation));
}

}  // namespace detail

}  // namespace webcpp::crypto

#endif  // WEBCPP_CRYPTO_ASYNC_HPP
