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
   default, they run the synchronous call when the operation is initiated (its guards and its
   work, on the thread that initiates it: the caller's for a callback or `use_awaitable`, the one
   that launches the operation for `deferred`) and complete through a post to that executor,
   whence the completion reaches the handler's associated executor, never inside the initiating
   call.
   - AES-GCM: `async_make`, `async_seal` and `async_open`, over `ciphers::gcm`. The other AEADs
     (ChaCha20-Poly1305 and its forms, the secret boxes) are not in WebCrypto: call their `seal`.
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
 namespace asio = webcpp::asio;
 namespace crypto = webcpp::crypto;
 using gcm = crypto::ciphers::gcm<crypto::ciphers::aes256<>>;

 // A coroutine makes a key and seals in place on the default backend; each completion, the error
 // code and the value, is posted to the coroutine's executor.
 asio::awaitable<void> seal_message(std::span<std::uint8_t const> key,
                                    std::span<std::uint8_t const> iv,
                                    std::span<std::uint8_t const> additional_data,
                                    std::span<std::uint8_t> data) {
     auto const executor = co_await asio::this_coro::executor;
     auto [made_code, aead] =
         co_await crypto::async_make<gcm>(executor, key, asio::as_tuple(asio::use_awaitable));
     if (made_code) { co_return; }
     auto [code, tag] = co_await crypto::async_seal(executor, aead, iv, additional_data, data,
                                                    asio::as_tuple(asio::use_awaitable));
     // `data` holds the ciphertext and `tag` the tag when `code` is clear.
 }
 @endcode

 @see "Asynchronous calls", in the guide.
*/
#ifndef WEBCPP_CRYPTO_ASYNC_HPP
#define WEBCPP_CRYPTO_ASYNC_HPP

#include <webcpp/crypto/config.hpp>

#include <webcpp/crypto/ciphers/gcm.hpp>
#include <webcpp/crypto/detail/async_access.hpp>
#include <webcpp/crypto/detail/defaults.hpp>
#include <webcpp/crypto/detail/heavy.hpp>
#include <webcpp/crypto/detail/timing.hpp>

#include <webcpp/asio/append.hpp>
#include <webcpp/asio/async_result.hpp>
#include <webcpp/asio/post.hpp>

#include <boost/system/error_code.hpp>
#include <boost/system/result.hpp>

#include <cstdint>
#include <span>
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
 * Initiates a cheap function on a synchronous backend (design D23): runs `operation()` when the
 * operation is initiated (on the initiating thread; for `deferred`, when the deferred operation
 * is launched), and completes through a post to `executor`, never inside the call,
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

/** Whether `Type` is an AES-GCM, `ciphers::gcm<Cipher>`. */
template <class Type>
inline constexpr bool is_gcm_v = false;

template <class Cipher>
inline constexpr bool is_gcm_v<ciphers::gcm<Cipher>> = true;

/** False for every type, so that a refusal's `static_assert` fires only when it is reached. */
template <class Type>
inline constexpr bool refused_v = false;

}  // namespace detail

/**
 * Makes an AES-GCM object from a key, asynchronously: `Algorithm::make(key_bytes)` run when the
 * operation is initiated, its result posted to `executor` (design D23). The key is read before
 * the call returns on a synchronous backend, later on the browser's: it is the caller's until the
 * completion.
 *
 * @tparam Algorithm A `ciphers::gcm<Cipher>`, on any backend of AES-GCM; the other algorithms
 * WebCrypto has are made by their own overloads of the key pairs' functions.
 * @param executor The executor the completion is posted to.
 * @param key_bytes `Algorithm::key_size` bytes.
 * @param token The completion token, of signature `void(boost::system::error_code, Algorithm)`;
 * on an error the object is empty, and every member refuses with `invalid_state`
 * (`invalid_key_size`, `errc::not_enough_memory`, `backend_failure`).
 * @return What the completion token's `async_result` gives.
 */
template <class Algorithm, class Executor, class CompletionToken>
auto async_make(Executor const& executor, std::span<std::uint8_t const> key_bytes,
                CompletionToken&& token) {
    detail::timing_guard const timing;
    if constexpr (!detail::is_gcm_v<Algorithm>) {
        static_assert(detail::refused_v<Algorithm>,
                      "webcpp::crypto: async_make takes AES-GCM, the algorithm WebCrypto has: "
                      "call make for the others.");
    } else {
        using backend = Algorithm::backend_type;
        if constexpr (detail::asynchronous_backend_v<backend>) {
            return detail::async_engine<backend>::template make<Algorithm>(
                executor, key_bytes, std::forward<CompletionToken>(token));
        } else {
            return detail::complete_by_post(
                executor, token, [key_bytes]() noexcept { return Algorithm::make(key_bytes); });
        }
    }
}

/**
 * Seals a message in place, asynchronously: `aead.seal(iv_bytes, additional_data_bytes,
 * data_bytes)` run when the operation is initiated, its result posted to `executor`.
 *
 * `aead` and the spans are the caller's until the completion: a synchronous backend reads and
 * writes them before the call returns, the browser's later. `data_bytes` holds the ciphertext at
 * the completion. A guard's refusal (`invalid_iv_size`, `message_too_long`, `invalid_state`)
 * leaves it untouched, a backend's failure zeroes it, as `seal` does.
 *
 * @tparam Gcm A `ciphers::gcm<Cipher>`; the other AEADs are not in WebCrypto: call their `seal`.
 * @param executor The executor the completion is posted to.
 * @param aead The keyed object.
 * @param iv_bytes 1 to `max_iv_size` bytes, never reused under this key.
 * @param additional_data_bytes Authenticated, not encrypted.
 * @param data_bytes The message.
 * @param token The completion token, of signature `void(boost::system::error_code,
 * Gcm::result_type)`: the tag; on an error the zeroed tag.
 * @return What the completion token's `async_result` gives.
 */
template <class Gcm, class Executor, class CompletionToken>
auto async_seal(Executor const& executor, Gcm& aead, std::span<std::uint8_t const> iv_bytes,
                std::span<std::uint8_t const> additional_data_bytes,
                std::span<std::uint8_t> data_bytes, CompletionToken&& token) {
    detail::timing_guard const timing;
    if constexpr (!detail::is_gcm_v<Gcm>) {
        static_assert(detail::refused_v<Gcm>,
                      "webcpp::crypto: async_seal takes AES-GCM, the AEAD WebCrypto has: call seal "
                      "for the others.");
    } else {
        using backend = Gcm::backend_type;
        if constexpr (detail::asynchronous_backend_v<backend>) {
            return detail::async_engine<backend>::seal(executor, aead, iv_bytes,
                                                       additional_data_bytes, data_bytes,
                                                       std::forward<CompletionToken>(token));
        } else {
            return detail::complete_by_post(
                executor, token, [&aead, iv_bytes, additional_data_bytes, data_bytes]() noexcept {
                    return aead.seal(iv_bytes, additional_data_bytes, data_bytes);
                });
        }
    }
}

/**
 * Opens a message in place, asynchronously: `aead.open(iv_bytes, additional_data_bytes,
 * data_bytes, tag_bytes)` run when the operation is initiated, its result posted to `executor`.
 *
 * `aead` and the spans are the caller's until the completion. `data_bytes` holds the plaintext at
 * a successful completion; a wrong tag (`authentication_failed`) or a backend's failure zeroes
 * it, a guard's refusal leaves it untouched, as `open` does.
 *
 * @tparam Gcm A `ciphers::gcm<Cipher>`; the other AEADs are not in WebCrypto: call their `open`.
 * @param executor The executor the completion is posted to.
 * @param aead The keyed object.
 * @param iv_bytes The IV of the seal.
 * @param additional_data_bytes The additional data of the seal.
 * @param data_bytes The ciphertext.
 * @param tag_bytes The seal's tag, 16 bytes.
 * @param token The completion token, of signature `void(boost::system::error_code)`.
 * @return What the completion token's `async_result` gives.
 */
template <class Gcm, class Executor, class CompletionToken>
auto async_open(Executor const& executor, Gcm& aead, std::span<std::uint8_t const> iv_bytes,
                std::span<std::uint8_t const> additional_data_bytes,
                std::span<std::uint8_t> data_bytes, std::span<std::uint8_t const> tag_bytes,
                CompletionToken&& token) {
    detail::timing_guard const timing;
    if constexpr (!detail::is_gcm_v<Gcm>) {
        static_assert(detail::refused_v<Gcm>,
                      "webcpp::crypto: async_open takes AES-GCM, the AEAD WebCrypto has: call open "
                      "for the others.");
    } else {
        using backend = Gcm::backend_type;
        if constexpr (detail::asynchronous_backend_v<backend>) {
            return detail::async_engine<backend>::open(executor, aead, iv_bytes,
                                                       additional_data_bytes, data_bytes, tag_bytes,
                                                       std::forward<CompletionToken>(token));
        } else {
            return detail::complete_by_post(
                executor, token,
                [&aead, iv_bytes, additional_data_bytes, data_bytes, tag_bytes]() noexcept {
                    return aead.open(iv_bytes, additional_data_bytes, data_bytes, tag_bytes);
                });
        }
    }
}

}  // namespace webcpp::crypto

#endif  // WEBCPP_CRYPTO_ASYNC_HPP
