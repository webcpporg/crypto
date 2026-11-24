// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// heavy_without_threads' program compiled with -ferror-limit=1: clang stops after the first
// error, so the refusal that names the synchronous call is that first error, before
// detail::run_on_work's stand-in, whose text defers to "an error above". The test is alone: the
// refusal and clang's fatal "too many errors emitted" are the compile's only errors, so a
// regression that puts the stand-in, or any other error, first fails it. -verify cannot order
// its directives; the limit does. The refusal's directive comes last, as the message the page
// shows (doc/tables/generate.py reads a test's last directive).

// clang-format off
// expected-error@*:* {{too many errors emitted, stopping now}} (knock-on)
// expected-error@*:* {{webcpp::crypto: async_slow runs on another thread and needs a build with threads (natively without WEBCPP_CRYPTO_NO_THREADS; on Emscripten -pthread). Without threads, call slow.}}
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
