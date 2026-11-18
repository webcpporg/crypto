// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A heavy operation's async_ variant that forgets WEBCPP_CRYPTO_DETAIL_REQUIRE_THREADS, called in a
// build without threads (natively with WEBCPP_CRYPTO_NO_THREADS; on WASI always), stops at
// detail::run_heavy's stand-in, which names the missing refusal, and with that error alone:
// without it, the variant would compile, never run the work and never call the handler.

// clang-format off
// expected-error@webcpp/crypto/detail/heavy.hpp:* {{webcpp::crypto: a heavy operation's async_ variant needs a build with threads; if no error above names the synchronous call, this variant lacks WEBCPP_CRYPTO_DETAIL_REQUIRE_THREADS.}}
// clang-format on

#include <webcpp/crypto/detail/heavy.hpp>

#include <utility>

namespace {

/** The test-only heavy operation, synchronous. */
int slow(int value) noexcept {
    return value + 1;
}

/** Its async_ variant, which forgets the refusal. */
template <class Executor, class CompletionToken>
auto async_slow(Executor executor, int value, CompletionToken&& token) {
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
