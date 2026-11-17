// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A heavy operation's async_ variant called in a build without threads (natively with
// WEBCPP_CRYPTO_NO_THREADS; on WASI always) stops where it is called, with the synchronous
// operation to call instead (design D23). The operation is a test's own, declared as every heavy
// operation declares its variant.

// clang-format off
// expected-error@*:* {{webcpp::crypto: async_slow runs on another thread and needs a build with threads (natively b2 threading=multi; on Emscripten -pthread). Without threads, call slow.}}
// clang-format on

#include <webcpp/crypto/detail/heavy.hpp>

#include <utility>

namespace {

/** The test-only heavy operation, synchronous. */
int slow(int value) noexcept {
    return value + 1;
}

/** Its async_ variant, as every heavy operation declares one. */
template <class Executor, class CompletionToken>
auto async_slow(Executor executor, int value, CompletionToken&& token) {
    WEBCPP_CRYPTO_DETAIL_REQUIRE_THREADS("async_slow", "slow");
    return webcpp::crypto::detail::run_heavy(
        std::move(executor), [value]() noexcept { return slow(value); },
        std::forward<CompletionToken>(token));
}

/** An executor and a completion token, which a build without threads never uses. */
struct executor {};

struct token {};

}  // namespace

int main() {
    async_slow(executor{}, 41, token{});
    return slow(0) == 1 ? 0 : 1;
}
