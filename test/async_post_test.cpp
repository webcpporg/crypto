// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The cheap functions of the asynchronous family on a synchronous backend (ruling R-A4: the
// default everywhere), through detail::complete_by_post, the initiation each of them makes: the
// synchronous call runs at once, inside the initiating call, and its result, split by
// detail::completion_of, completes through a post, never inside the call (rulings R-A2, R-A3).
// Three test-only operations, declared as the family's functions are, exercise it on every
// result shape: async_key (a secret<32> of bytes all `value`), async_block (an array of 64 bytes
// all `value`) and async_check (no value); each refuses `value == 0` with invalid_input_size.
// - post_never_inline: a flag the callback sets is unset when the call returns and set after
//   run; the synchronous call has run once when the call returns.
// - post_bound_executor: with one io_context's executor given and the handler bound to a second
//   io_context, the completion runs on the second (review focus 1), never on the first.
// - post_allocator: the handler's associated allocator, bound by bind_allocator, holds the post,
//   and has every block back before the handler runs; the replaced global operator new
//   (support/counting.hpp) is not called.
// - post_tokens: a callback, use_future (in the build with exceptions alone, a refusal thrown as
//   system_error), deferred (the call runs when the operation is launched), as_tuple, and
//   use_awaitable in a coroutine of the context (a refusal through as_tuple; with exceptions a
//   plain use_awaitable throws).
// - post_error_value: an error completes with its code and the empty value (ruling R-A3): a
//   secret<32> and an array of zeros.
// Tasks 4.A3 and 4.A4 add async_seal's and async_verify's cases to each check: each check takes
// the operation's start as a callable of (executor, token).

#include <webcpp/crypto/async.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/secret.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/counting.hpp"

#include <webcpp/asio/as_tuple.hpp>
#include <webcpp/asio/awaitable.hpp>
#include <webcpp/asio/bind_allocator.hpp>
#include <webcpp/asio/bind_executor.hpp>
#include <webcpp/asio/co_spawn.hpp>
#include <webcpp/asio/deferred.hpp>
#include <webcpp/asio/io_context.hpp>
#include <webcpp/asio/this_coro.hpp>
#include <webcpp/asio/use_awaitable.hpp>
#ifndef WEBCPP_CRYPTO_NO_EXCEPTIONS
#include <webcpp/asio/use_future.hpp>
#endif

#include <boost/core/lightweight_test.hpp>
#include <boost/system/error_code.hpp>
#include <boost/system/result.hpp>
#ifndef WEBCPP_CRYPTO_NO_EXCEPTIONS
#include <boost/system/system_error.hpp>
#endif

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <tuple>
#include <type_traits>
#include <utility>

namespace asio = webcpp::asio;
namespace crypto = webcpp::crypto;

namespace {

using key = crypto::secret<32>;
using block = std::array<std::uint8_t, 64>;

// How many times a test-only operation's synchronous call has run.
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): counted by the calls
int sync_runs = 0;

/** The synchronous call of async_key: a secret of bytes all `value`, 0 refused. */
boost::system::result<key> make_key(std::uint8_t value) noexcept {
    ++sync_runs;
    if (value == 0) {
        return crypto::error::invalid_input_size;
    }
    key made;
    std::ranges::fill(made.writable(), value);
    return made;
}

/** The synchronous call of async_block: 64 bytes all `value`, 0 refused. */
boost::system::result<block> make_block(std::uint8_t value) noexcept {
    ++sync_runs;
    if (value == 0) {
        return crypto::error::invalid_input_size;
    }
    block made{};
    made.fill(value);
    return made;
}

/** The synchronous call of async_check: no value, 0 refused. */
boost::system::result<void> check(std::uint8_t value) noexcept {
    ++sync_runs;
    if (value == 0) {
        return crypto::error::invalid_input_size;
    }
    return {};
}

/** A cheap operation completing with `void(error_code, secret<32>)`, as the family declares. */
template <class Executor, class CompletionToken>
auto async_key(Executor const& executor, std::uint8_t value, CompletionToken&& token) {
    return crypto::detail::complete_by_post(executor, token,
                                            [value]() noexcept { return make_key(value); });
}

/** A cheap operation completing with `void(error_code, std::array<std::uint8_t, 64>)`. */
template <class Executor, class CompletionToken>
auto async_block(Executor const& executor, std::uint8_t value, CompletionToken&& token) {
    return crypto::detail::complete_by_post(executor, token,
                                            [value]() noexcept { return make_block(value); });
}

/** A cheap operation completing with `void(error_code)`. */
template <class Executor, class CompletionToken>
auto async_check(Executor const& executor, std::uint8_t value, CompletionToken&& token) {
    return crypto::detail::complete_by_post(executor, token,
                                            [value]() noexcept { return check(value); });
}

/** Whether every byte of `bytes` is `value`. */
template <class Bytes>
bool all_bytes(Bytes const& bytes, std::uint8_t value) {
    return std::ranges::all_of(bytes, [value](std::uint8_t byte) { return byte == value; });
}

bool all_bytes(key const& made, std::uint8_t value) {
    return all_bytes(made.bytes(), value);
}

// What a callback saw: its calls, whether the initiating call had returned, the error code and
// the value, if the operation has one.
template <class... Value>
struct seen {
    int calls = 0;
    bool after_return = false;
    boost::system::error_code code;
    std::tuple<Value...> value;
};

// Starts `start(executor, token)` with a callback, checks that the synchronous call ran inside
// the call and the completion did not, then runs the context and checks one completion after
// the return.
template <class... Value, class Start>
seen<Value...> complete_by_callback(asio::io_context& context, Start start) {
    seen<Value...> done;
    bool returned = false;
    int const runs_before = sync_runs;
    start(context.get_executor(),
          [&done, &returned](boost::system::error_code code, Value... value) {
              ++done.calls;
              done.after_return = returned;
              done.code = code;
              done.value = std::tuple<Value...>(std::move(value)...);
          });
    returned = true;
    BOOST_TEST_EQ(done.calls, 0);               // never inside the call
    BOOST_TEST_EQ(sync_runs, runs_before + 1);  // the synchronous call ran at once
    context.restart();
    context.run();  // lint-run: the test's event loop
    BOOST_TEST_EQ(done.calls, 1);
    BOOST_TEST(done.after_return);
    return done;
}

// The starts of the test-only operations, of `value`.
auto key_of(std::uint8_t value) {
    return [value](auto const& executor, auto&& token) {
        return async_key(executor, value, std::forward<decltype(token)>(token));
    };
}

auto block_of(std::uint8_t value) {
    return [value](auto const& executor, auto&& token) {
        return async_block(executor, value, std::forward<decltype(token)>(token));
    };
}

auto check_of(std::uint8_t value) {
    return [value](auto const& executor, auto&& token) {
        return async_check(executor, value, std::forward<decltype(token)>(token));
    };
}

void post_never_inline(asio::io_context& context) {
    auto const made = complete_by_callback<key>(context, key_of(0x42));
    BOOST_TEST(!made.code);
    BOOST_TEST(all_bytes(std::get<0>(made.value), 0x42));
    auto const filled = complete_by_callback<block>(context, block_of(0x17));
    BOOST_TEST(!filled.code);
    BOOST_TEST(all_bytes(std::get<0>(filled.value), 0x17));
    auto const checked = complete_by_callback<>(context, check_of(1));
    BOOST_TEST(!checked.code);
}

// One start given the executor of `given`, its handler bound to `bound`: the completion runs on
// `bound` alone, after `given` has run.
template <class... Value, class Start>
void complete_on_bound(Start start) {
    asio::io_context given;
    asio::io_context bound;
    int calls = 0;
    bool on_bound = false;
    bool on_given = true;
    start(given.get_executor(),
          asio::bind_executor(bound.get_executor(), [&](boost::system::error_code code, Value...) {
              ++calls;
              on_bound = bound.get_executor().running_in_this_thread();
              on_given = given.get_executor().running_in_this_thread();
              BOOST_TEST(!code);
          }));
    given.run();  // lint-run: the test's event loop, which hands the completion over
    BOOST_TEST_EQ(calls, 0);
    bound.run();  // lint-run: the event loop the handler is bound to
    BOOST_TEST_EQ(calls, 1);
    BOOST_TEST(on_bound);
    BOOST_TEST(!on_given);
}

void post_bound_executor() {
    complete_on_bound<key>(key_of(3));
    complete_on_bound<block>(block_of(3));
    complete_on_bound<>(check_of(3));
}

// What a holding_allocator counts, shared by its rebound copies: the blocks it holds now, and
// every block it has given.
struct holding {
    int held = 0;
    int taken = 0;
};

// An allocator that counts the blocks it holds and gives. Its blocks are the C library's, so
// that a call of operator new is never its own.
template <class T>
struct holding_allocator {
    using value_type = T;
    holding* counts;

    explicit holding_allocator(holding* counter) noexcept : counts(counter) {}

    // Allocator rebind conversions must be implicit (Allocator requirements).
    template <class U>
    // NOLINTNEXTLINE(misc-explicit-constructor)
    holding_allocator(holding_allocator<U> const& other) noexcept : counts(other.counts) {}

    T* allocate(std::size_t count) {
        static_assert(alignof(T) <= alignof(std::max_align_t), "malloc's alignment suffices");
        void* const block = std::malloc(count * sizeof(T));
        if (block == nullptr) {
            webcpp_test_out_of_memory();
        }
        ++counts->held;
        ++counts->taken;
        return static_cast<T*>(block);
    }

    void deallocate(T* pointer, std::size_t /*count*/) noexcept {
        std::free(pointer);
        --counts->held;
    }

    template <class U>
    bool operator==(holding_allocator<U> const& other) const noexcept {
        return counts == other.counts;
    }
};

// What the handler of one counted start saw.
struct allocator_call {
    int calls = 0;
    int held_at_call = -1;
    int taken = 0;
    std::size_t news = 0;
    boost::system::error_code code;
};

// One start with a handler whose associated allocator holds; `call` records what the allocator
// holds when the handler runs, what it gave since the start, and the calls of operator new.
template <class... Value, class Start>
void start_counted(asio::io_context& context, Start start, allocator_call& call) {
    holding counts;
    std::size_t const news_before = webcpp::test::counted_new.load();
    start(context.get_executor(),
          asio::bind_allocator(
              holding_allocator<char>(&counts),
              [&call, &counts, news_before](boost::system::error_code code, Value...) {
                  call.news = webcpp::test::counted_new.load() - news_before;
                  ++call.calls;
                  call.held_at_call = counts.held;
                  call.taken = counts.taken;
                  call.code = code;
              }));
    context.restart();
    context.run();  // lint-run: the test's event loop
    BOOST_TEST_EQ(counts.held, 0);
}

// The start's success and its refusal each post through the handler's allocator alone.
template <class... Value, class Start>
void check_allocator(asio::io_context& context, Start made, Start refused) {
    allocator_call done;
    start_counted<Value...>(context, made, done);
    BOOST_TEST_EQ(done.calls, 1);
    BOOST_TEST(!done.code);
    BOOST_TEST_EQ(done.held_at_call, 0);
    BOOST_TEST_GE(done.taken, 1);
    BOOST_TEST_EQ(done.news, 0U);

    allocator_call failed;
    start_counted<Value...>(context, refused, failed);
    BOOST_TEST_EQ(failed.calls, 1);
    BOOST_TEST(failed.code == crypto::error::invalid_input_size);
    BOOST_TEST_EQ(failed.held_at_call, 0);
    BOOST_TEST_GE(failed.taken, 1);
    BOOST_TEST_EQ(failed.news, 0U);
}

void post_allocator(asio::io_context& context) {
    // One uncounted call first, so that what the runtime makes once is outside the windows.
    allocator_call warm;
    start_counted<key>(context, key_of(1), warm);
    BOOST_TEST_EQ(warm.calls, 1);

    check_allocator<key>(context, key_of(1), key_of(0));
    check_allocator<block>(context, block_of(1), block_of(0));
    check_allocator<>(context, check_of(1), check_of(0));
}

void post_tokens(asio::io_context& context) {
    auto const executor = context.get_executor();

#ifndef WEBCPP_CRYPTO_NO_EXCEPTIONS
    // use_future: a single-threaded program runs the context before get().
    auto made = async_key(executor, 5, asio::use_future);
    auto filled = async_block(executor, 5, asio::use_future);
    auto checked = async_check(executor, 5, asio::use_future);
    auto refused = async_key(executor, 0, asio::use_future);
    context.restart();
    context.run();  // lint-run: the test's event loop
    BOOST_TEST(all_bytes(made.get(), 5));
    BOOST_TEST(all_bytes(filled.get(), 5));
    checked.get();
    bool thrown = false;
    try {
        static_cast<void>(refused.get());
    } catch (boost::system::system_error const& failure) {
        thrown = failure.code() == crypto::error::invalid_input_size;
    }
    BOOST_TEST(thrown);
#endif

    // deferred: the operation runs when it is launched, and completes through the post.
    int const runs_before = sync_runs;
    auto operation = async_key(executor, 6, asio::deferred);
    BOOST_TEST_EQ(sync_runs, runs_before);
    int deferred_calls = 0;
    std::move(operation)([&](boost::system::error_code code, key value) {
        ++deferred_calls;
        BOOST_TEST(!code);
        BOOST_TEST(all_bytes(value, 6));
    });
    BOOST_TEST_EQ(sync_runs, runs_before + 1);
    BOOST_TEST_EQ(deferred_calls, 0);
    auto checking = async_check(executor, 0, asio::deferred);
    std::move(checking)([&](boost::system::error_code code) {
        ++deferred_calls;
        BOOST_TEST(code == crypto::error::invalid_input_size);
    });
    context.restart();
    context.run();  // lint-run: the test's event loop
    BOOST_TEST_EQ(deferred_calls, 2);

    // as_tuple: the error code and the value in one argument.
    int tuples = 0;
    async_block(executor, 7, asio::as_tuple([&](std::tuple<boost::system::error_code, block> done) {
                    ++tuples;
                    BOOST_TEST(!std::get<0>(done));
                    BOOST_TEST(all_bytes(std::get<1>(done), 7));
                }));
    async_check(executor, 0, asio::as_tuple([&](std::tuple<boost::system::error_code> done) {
                    ++tuples;
                    BOOST_TEST(std::get<0>(done) == crypto::error::invalid_input_size);
                }));
    context.restart();
    context.run();  // lint-run: the test's event loop
    BOOST_TEST_EQ(tuples, 2);

    // use_awaitable in a coroutine of the context.
    bool done = false;
    asio::co_spawn(
        context,
        [&]() -> asio::awaitable<void> {
            auto const coro = co_await asio::this_coro::executor;
            auto [made_code, made_key] =
                co_await async_key(coro, 8, asio::as_tuple(asio::use_awaitable));
            BOOST_TEST(!made_code);
            BOOST_TEST(all_bytes(made_key, 8));
            auto [refused_code, refused_block] =
                co_await async_block(coro, 0, asio::as_tuple(asio::use_awaitable));
            BOOST_TEST(refused_code == crypto::error::invalid_input_size);
            BOOST_TEST(all_bytes(refused_block, 0));
            auto [checked_code] =
                co_await async_check(coro, 8, asio::as_tuple(asio::use_awaitable));
            BOOST_TEST(!checked_code);
#ifndef WEBCPP_CRYPTO_NO_EXCEPTIONS
            key const awaited = co_await async_key(coro, 9, asio::use_awaitable);
            BOOST_TEST(all_bytes(awaited, 9));
            co_await async_check(coro, 9, asio::use_awaitable);
            bool thrown = false;
            try {
                co_await async_check(coro, 0, asio::use_awaitable);
            } catch (boost::system::system_error const& failure) {
                thrown = failure.code() == crypto::error::invalid_input_size;
            }
            BOOST_TEST(thrown);
#endif
            done = true;
        },
        [](std::exception_ptr const& failure) { BOOST_TEST(!failure); });
    context.restart();
    context.run();  // lint-run: the test's event loop
    BOOST_TEST(done);
}

void post_error_value(asio::io_context& context) {
    auto const refused_key = complete_by_callback<key>(context, key_of(0));
    BOOST_TEST(refused_key.code == crypto::error::invalid_input_size);
    BOOST_TEST(all_bytes(std::get<0>(refused_key.value), 0));
    auto const refused_block = complete_by_callback<block>(context, block_of(0));
    BOOST_TEST(refused_block.code == crypto::error::invalid_input_size);
    BOOST_TEST(all_bytes(std::get<0>(refused_block.value), 0));
    auto const refused_check = complete_by_callback<>(context, check_of(0));
    BOOST_TEST(refused_check.code == crypto::error::invalid_input_size);
}

// The asynchronous default is the synchronous one, on every target (ruling R-A4), and no
// synchronous backend completes by itself: part B's backends::browser alone will.
template <class Family>
constexpr bool same_default =
    std::is_same_v<crypto::default_async_backend_t<Family>, crypto::default_backend_t<Family>>;
static_assert(same_default<crypto::families::gcm> && same_default<crypto::families::ed25519> &&
              same_default<crypto::families::x25519>);
static_assert(!crypto::detail::asynchronous_backend_v<crypto::backends::bearssl> &&
              !crypto::detail::asynchronous_backend_v<crypto::backends::openssl> &&
              !crypto::detail::asynchronous_backend_v<crypto::backends::sodium>);

}  // namespace

int main() {
    asio::io_context context;
    post_never_inline(context);
    post_bound_executor();
    post_allocator(context);
    post_tokens(context);
    post_error_value(context);
    return webcpp::test::exit_status(boost::report_errors());
}
