// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 The heavy operations' `async_` variants (design D23): in a build with threads
 (`WEBCPP_CRYPTO_HAS_THREADS`), `detail::run_heavy` runs the synchronous call on the executor
 the program gives and completes on the handler's associated executor; without threads, the
 variant's first statement, `WEBCPP_CRYPTO_DETAIL_REQUIRE_THREADS`, stops the build where the
 program calls it.

 The heavy operations are stated (design D32): RSA key generation at every size and RSA private
 operations at 3072 bits and above; SLH-DSA key generation, signing and verification; ML-DSA key
 generation and signing; BLS12-381 verification, aggregate verification, fast aggregate
 verification and aggregation; KZG's commitments and proofs over a blob and their batch
 verification; BN254's `pairing_check`. Everything else is cheap and synchronous only.
*/
#ifndef WEBCPP_CRYPTO_DETAIL_HEAVY_HPP
#define WEBCPP_CRYPTO_DETAIL_HEAVY_HPP

#include <webcpp/crypto/config.hpp>

#include <webcpp/crypto/detail/engines.hpp>

#include <type_traits>
#include <utility>

#ifdef WEBCPP_CRYPTO_HAS_THREADS
#include <boost/asio/associated_executor.hpp>         // lint-world: async_ variants (D23)
#include <boost/asio/async_result.hpp>                // lint-world: async_ variants (D23)
#include <boost/asio/dispatch.hpp>                    // lint-world: async_ variants (D23)
#include <boost/asio/execution/outstanding_work.hpp>  // lint-world: async_ variants (D23)
#include <boost/asio/post.hpp>                        // lint-world: async_ variants (D23)
#include <boost/asio/prefer.hpp>                      // lint-world: async_ variants (D23)
#endif

namespace webcpp::crypto::detail {

/**
 The refusal of a heavy operation's `async_` variant in a build without threads (design D23).
 Each such variant's body starts with it, so that a program fails only where it calls one.
 The variant's completion token is its parameter `token`.
*/
#ifdef WEBCPP_CRYPTO_HAS_THREADS
#define WEBCPP_CRYPTO_DETAIL_REQUIRE_THREADS(async_name, sync_name)
#else
#define WEBCPP_CRYPTO_DETAIL_REQUIRE_THREADS(async_name, sync_name)                            \
    static_assert(::webcpp::crypto::detail::dependent_false<decltype(token)>,                  \
                  "webcpp::crypto: " async_name                                                \
                  " runs on another thread and needs a build with threads (natively b2 "       \
                  "threading=multi; on Emscripten -pthread). Without threads, call " sync_name \
                  ".")
#endif

#ifdef WEBCPP_CRYPTO_HAS_THREADS

/**
 * Runs a heavy operation's synchronous call on another thread: posts `function` to `executor`
 * (natively a `thread_pool`'s; on Emscripten a pool whose threads are Web Workers) and
 * dispatches its result to the handler's associated executor, which by default is `executor`.
 * The handler's executor is kept busy until then, so that an `io_context` the handler runs on
 * does not run out of work while the call runs elsewhere.
 *
 * @tparam Executor The executor the call runs on.
 * @tparam Function A call without arguments that reports its errors as values, not by throwing.
 * @tparam CompletionToken Any completion token; the completion signature is `void(R)`, `R` the
 * call's result.
 * @param executor Where the call runs.
 * @param function The synchronous call.
 * @param token How the program is told of the result.
 * @return What the completion token makes of the operation.
 */
template <class Executor, class Function, class CompletionToken>
auto run_heavy(Executor executor, Function function, CompletionToken&& token) {
    static_assert(std::is_nothrow_invocable_v<Function&>,
                  "webcpp::crypto: a heavy operation's call reports its errors as values");
    using result_type = std::invoke_result_t<Function&>;
    auto initiation = [](auto handler, Executor const& work_executor, Function call) {
        auto completion_executor =
            boost::asio::prefer(boost::asio::get_associated_executor(handler, work_executor),
                                boost::asio::execution::outstanding_work_t::tracked);
        boost::asio::post(
            work_executor, [handler = std::move(handler), call = std::move(call),
                            completion_executor = std::move(completion_executor)]() mutable {
                boost::asio::dispatch(completion_executor,
                                      [handler = std::move(handler), result = call()]() mutable {
                                          std::move(handler)(std::move(result));
                                      });
            });
    };
    return boost::asio::async_initiate<CompletionToken, void(result_type)>(
        std::move(initiation), token, std::move(executor), std::move(function));
}

#else

/**
 * Without threads, a stand-in that does nothing: a refused variant's body compiles past its
 * refusal, which has stopped the build already, without errors of its own.
 */
template <class Executor, class Function, class CompletionToken>
void run_heavy(Executor&& /*executor*/, Function&& /*function*/,
               CompletionToken&& /*token*/) noexcept {}

#endif

}  // namespace webcpp::crypto::detail

#endif  // WEBCPP_CRYPTO_DETAIL_HEAVY_HPP
