// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A heavy operation's async_ variant called in a build without threads (natively with
// WEBCPP_CRYPTO_NO_THREADS; on WASI always) stops where it is called, with the synchronous
// operation to call instead (design D23). The operation is a test's own, declared as every heavy
// operation declares its variant. The refusal is the first error (heavy_without_threads_first
// pins the order); detail::run_on_work's stand-in adds its own after it, which defers to an error
// above that names the synchronous call. The test is alone: these two errors are the compile's
// only ones. The page shows the refusal alone (doc/tables/generate.py lists a test's directives
// in source order and skips one marked knock-on): its directive comes first, and the stand-in's
// is marked knock-on, since the wildcards let -verify match them in any order.

// clang-format off
// expected-error@*:* {{webcpp::crypto: async_slow runs on another thread and needs a build with threads (natively without WEBCPP_CRYPTO_NO_THREADS; on Emscripten -pthread). Without threads, call slow.}}
// expected-error@webcpp/crypto/detail/heavy.hpp:* {{webcpp::crypto: a heavy operation's async_ variant needs a build with threads; if no error above names the synchronous call, this variant lacks WEBCPP_CRYPTO_DETAIL_REQUIRE_THREADS.}} (knock-on)
// clang-format on

#include <webcpp/crypto/detail/heavy.hpp>

#include <boost/system/result.hpp>

namespace {

/** The test-only heavy operation, synchronous. */
boost::system::result<int> slow(int value) noexcept {
    return value + 1;
}

/** Its async_ variant, as every heavy operation declares one. */
template <class Executor, class CompletionToken>
auto async_slow(Executor const& work, int value, CompletionToken&& completion_token) {
    WEBCPP_CRYPTO_DETAIL_REQUIRE_THREADS("async_slow", "slow");
    return webcpp::crypto::detail::run_on_work(
        work, []() noexcept { return boost::system::result<void>(); },
        [value]() noexcept { return slow(value); }, completion_token);
}

/** An executor and a completion token, which a build without threads never uses. */
struct executor {};

struct token {};

}  // namespace

int main() {
    async_slow(executor{}, 41, token{});
    return *slow(0) == 1 ? 0 : 1;
}
