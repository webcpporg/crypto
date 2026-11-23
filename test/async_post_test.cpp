// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The cheap functions of the asynchronous family on a synchronous backend (ruling R-A4: the
// default everywhere), through detail::complete_by_post, the initiation each of them makes: the
// synchronous call runs when the operation is initiated, and its result, split by
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
// - post_gcm: the same cases through AES-GCM's async_from_key, async_seal and async_open (the
//   functions the family really has, Task 4.A3): never inside the call, the work done when the
//   call returns, a bound executor, the handler's allocator, every token, an error's empty
//   value.
// - post_verify_*: the same cases through Ed25519's async_verify (no value), RFC 8032's test 2,
//   and, for the value shapes, async_sign (an array) and async_agree (a secret<32>): never
//   inside the call, the work done when the call returns, a bound executor, the handler's
//   allocator, every token, an error's empty value.
// Each check takes the operation's start as a callable of (executor, token).

#include <webcpp/crypto/async.hpp>
#include <webcpp/crypto/ciphers/aes256_gcm.hpp>
#include <webcpp/crypto/curves/ed25519.hpp>
#include <webcpp/crypto/curves/x25519.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/secret.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/counting.hpp"
#include "support/hex.hpp"

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
#include <span>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

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

// check_allocator for a start whose refusal is `expected`, the value type spelled.
template <class Value, class Made, class Refused>
void check_allocator_with(asio::io_context& context, Made made, Refused refused,
                          boost::system::error_code expected) {
    allocator_call done;
    start_counted<Value>(context, made, done);
    BOOST_TEST_EQ(done.calls, 1);
    BOOST_TEST(!done.code);
    BOOST_TEST_EQ(done.held_at_call, 0);
    BOOST_TEST_GE(done.taken, 1);
    BOOST_TEST_EQ(done.news, 0U);

    allocator_call failed;
    start_counted<Value>(context, refused, failed);
    BOOST_TEST_EQ(failed.calls, 1);
    BOOST_TEST(failed.code == expected);
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

#ifndef WEBCPP_CRYPTO_NO_EXCEPTIONS
void post_future_token(asio::io_context& context) {
    auto const executor = context.get_executor();
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
}
#endif

void post_deferred_token(asio::io_context& context) {
    auto const executor = context.get_executor();
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
}

void post_tuple_token(asio::io_context& context) {
    auto const executor = context.get_executor();
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
}

void post_awaitable_token(asio::io_context& context) {
    // use_awaitable in a coroutine of the context.
    bool done = false;
    asio::co_spawn(
        context,
        [&]() -> asio::awaitable<void> {
            auto const coro = co_await asio::this_coro::executor;
            auto made_code_result =
                co_await async_key(coro, 8, asio::as_tuple(asio::use_awaitable));
            auto& [made_code, made_key] = made_code_result;
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

void post_tokens(asio::io_context& context) {
#ifndef WEBCPP_CRYPTO_NO_EXCEPTIONS
    post_future_token(context);
#endif
    post_deferred_token(context);
    post_tuple_token(context);
    post_awaitable_token(context);
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

// AES-GCM through the family's real functions, on the default backend. The fixture: a key, an IV,
// four bytes of additional data and forty of data, which a seal changes.
struct gcm_fixture {
    using gcm = crypto::ciphers::aes256_gcm;
    std::array<std::uint8_t, 32> key{};
    std::array<std::uint8_t, 12> iv{};
    std::array<std::uint8_t, 4> additional_data{1, 2, 3, 4};
    std::array<std::uint8_t, 40> data{};
    std::array<std::uint8_t, 129> long_iv{};
    std::array<std::uint8_t, 16> tag{};
    gcm aead;

    gcm_fixture() : aead(*gcm::from_key(key)) { data.fill(0x5a); }

    auto seal() {
        return [this](auto const& executor, auto&& token) {
            return crypto::async_seal(executor, aead, iv, additional_data, data,
                                      std::forward<decltype(token)>(token));
        };
    }

    auto seal_refused() {
        return [this](auto const& executor, auto&& token) {
            return crypto::async_seal(executor, aead, long_iv, additional_data, data,
                                      std::forward<decltype(token)>(token));
        };
    }

    auto open() {
        return [this](auto const& executor, auto&& token) {
            return crypto::async_open(executor, aead, iv, additional_data, data, tag,
                                      std::forward<decltype(token)>(token));
        };
    }

    auto open_refused() {
        return [this](auto const& executor, auto&& token) {
            return crypto::async_open(executor, aead, long_iv, additional_data, data, tag,
                                      std::forward<decltype(token)>(token));
        };
    }

    auto from_key() {
        return [this](auto const& executor, auto&& token) {
            return crypto::async_from_key<gcm>(executor, key, std::forward<decltype(token)>(token));
        };
    }

    auto from_key_refused() {
        return [this](auto const& executor, auto&& token) {
            return crypto::async_from_key<gcm>(executor, std::span(key).first(31),
                                               std::forward<decltype(token)>(token));
        };
    }
};

using gcm_tag = gcm_fixture::gcm::result_type;

void post_gcm_inline(asio::io_context& context) {
    gcm_fixture fixture;
    auto const plaintext = fixture.data;
    // The seal ran when the call returned (the data is the ciphertext), the completion after.
    seen<gcm_tag> sealed;
    bool returned = false;
    fixture.seal()(context.get_executor(), [&](boost::system::error_code code, gcm_tag tag) {
        ++sealed.calls;
        sealed.after_return = returned;
        sealed.code = code;
        sealed.value = std::tuple<gcm_tag>(tag);
    });
    returned = true;
    BOOST_TEST_EQ(sealed.calls, 0);
    BOOST_TEST(fixture.data != plaintext);
    context.restart();
    context.run();  // lint-run: the test's event loop
    BOOST_TEST_EQ(sealed.calls, 1);
    BOOST_TEST(sealed.after_return);
    BOOST_TEST(!sealed.code);
    std::ranges::copy(std::get<0>(sealed.value), fixture.tag.begin());

    // The open, no value: the plaintext is back when the call returns.
    seen<> opened;
    returned = false;
    fixture.open()(context.get_executor(), [&](boost::system::error_code code) {
        ++opened.calls;
        opened.after_return = returned;
        opened.code = code;
    });
    returned = true;
    BOOST_TEST_EQ(opened.calls, 0);
    BOOST_TEST(fixture.data == plaintext);
    context.restart();
    context.run();  // lint-run: the test's event loop
    BOOST_TEST_EQ(opened.calls, 1);
    BOOST_TEST(opened.after_return);
    BOOST_TEST(!opened.code);

    // A refusal is posted too, with the zeroed tag, and leaves the data untouched.
    seen<gcm_tag> refused;
    fixture.seal_refused()(context.get_executor(),
                           [&](boost::system::error_code code, gcm_tag tag) {
                               ++refused.calls;
                               refused.code = code;
                               refused.value = std::tuple<gcm_tag>(tag);
                           });
    BOOST_TEST_EQ(refused.calls, 0);
    context.restart();
    context.run();  // lint-run: the test's event loop
    BOOST_TEST_EQ(refused.calls, 1);
    BOOST_TEST(refused.code == crypto::error::invalid_iv_size);
    BOOST_TEST(all_bytes(std::get<0>(refused.value), 0));
    BOOST_TEST(fixture.data == plaintext);
}

void post_gcm_bound_executor() {
    gcm_fixture fixture;
    // The open needs a sealed message.
    auto const sealed = fixture.aead.seal(fixture.iv, fixture.additional_data, fixture.data);
    if (BOOST_TEST(sealed.has_value())) {
        std::ranges::copy(*sealed, fixture.tag.begin());
    }
    complete_on_bound<>(fixture.open());
    complete_on_bound<gcm_tag>(fixture.seal());
    complete_on_bound<gcm_fixture::gcm>(fixture.from_key());
}

void post_gcm_allocator(asio::io_context& context) {
    gcm_fixture fixture;
    allocator_call warm;
    start_counted<gcm_tag>(context, fixture.seal(), warm);
    BOOST_TEST_EQ(warm.calls, 1);
    // A seal changes the data and tag; the open of the next call needs its tag.
    allocator_call sealed;
    start_counted<gcm_tag>(context, fixture.seal(), sealed);
    BOOST_TEST(!sealed.code);
    BOOST_TEST_EQ(sealed.held_at_call, 0);
    BOOST_TEST_GE(sealed.taken, 1);
    BOOST_TEST_EQ(sealed.news, 0U);
    allocator_call refused;
    start_counted<gcm_tag>(context, fixture.seal_refused(), refused);
    BOOST_TEST(refused.code == crypto::error::invalid_iv_size);
    BOOST_TEST_EQ(refused.held_at_call, 0);
    BOOST_TEST_GE(refused.taken, 1);
    BOOST_TEST_EQ(refused.news, 0U);
    // An open (no value) with a refusal, then a from_key (an object) and its refusal.
    allocator_call open_refused;
    start_counted<>(context, fixture.open_refused(), open_refused);
    BOOST_TEST(open_refused.code == crypto::error::invalid_iv_size);
    BOOST_TEST_EQ(open_refused.held_at_call, 0);
    BOOST_TEST_GE(open_refused.taken, 1);
    BOOST_TEST_EQ(open_refused.news, 0U);
    check_allocator_with<gcm_fixture::gcm>(context, fixture.from_key(), fixture.from_key_refused(),
                                           crypto::error::invalid_key_size);
}

#ifndef WEBCPP_CRYPTO_NO_EXCEPTIONS
void post_gcm_future_token(asio::io_context& context, gcm_fixture& fixture,
                           std::array<std::uint8_t, 40> const& plaintext) {
    auto const executor = context.get_executor();
    auto future_tag = crypto::async_seal(executor, fixture.aead, fixture.iv,
                                         fixture.additional_data, fixture.data, asio::use_future);
    context.restart();
    context.run();  // lint-run: the test's event loop
    std::ranges::copy(future_tag.get(), fixture.tag.begin());
    BOOST_TEST(fixture.data != plaintext);
    auto future_open =
        crypto::async_open(executor, fixture.aead, fixture.iv, fixture.additional_data,
                           fixture.data, fixture.tag, asio::use_future);
    context.restart();
    context.run();  // lint-run: the test's event loop
    future_open.get();
    BOOST_TEST(fixture.data == plaintext);
    auto future_made =
        crypto::async_from_key<gcm_fixture::gcm>(executor, fixture.key, asio::use_future);
    auto future_refused = crypto::async_from_key<gcm_fixture::gcm>(
        executor, std::span(fixture.key).first(31), asio::use_future);
    context.restart();
    context.run();  // lint-run: the test's event loop
    static_cast<void>(future_made.get());
    bool thrown = false;
    try {
        static_cast<void>(future_refused.get());
    } catch (boost::system::system_error const& failure) {
        thrown = failure.code() == crypto::error::invalid_key_size;
    }
    BOOST_TEST(thrown);
}
#endif

void post_gcm_deferred_token(asio::io_context& context, gcm_fixture& fixture,
                             std::array<std::uint8_t, 40> const& plaintext) {
    auto const executor = context.get_executor();
    // deferred: the synchronous call runs when the operation is launched, not when it is made.
    auto operation = crypto::async_seal(executor, fixture.aead, fixture.iv, fixture.additional_data,
                                        fixture.data, asio::deferred);
    BOOST_TEST(fixture.data == plaintext);
    int deferred_calls = 0;
    std::move(operation)([&](boost::system::error_code code, gcm_tag tag) {
        ++deferred_calls;
        BOOST_TEST(!code);
        std::ranges::copy(tag, fixture.tag.begin());
    });
    BOOST_TEST(fixture.data != plaintext);
    BOOST_TEST_EQ(deferred_calls, 0);
    context.restart();
    context.run();  // lint-run: the test's event loop
    BOOST_TEST_EQ(deferred_calls, 1);
}

void post_gcm_tuple_token(asio::io_context& context, gcm_fixture& fixture,
                          std::array<std::uint8_t, 40> const& plaintext) {
    auto const executor = context.get_executor();
    // as_tuple: the code and the value in one argument; the open, the code alone.
    int tuples = 0;
    crypto::async_open(executor, fixture.aead, fixture.iv, fixture.additional_data, fixture.data,
                       fixture.tag, asio::as_tuple([&](std::tuple<boost::system::error_code> done) {
                           ++tuples;
                           BOOST_TEST(!std::get<0>(done));
                       }));
    crypto::async_seal(executor, fixture.aead, fixture.long_iv, fixture.additional_data,
                       fixture.data,
                       asio::as_tuple([&](std::tuple<boost::system::error_code, gcm_tag> done) {
                           ++tuples;
                           BOOST_TEST(std::get<0>(done) == crypto::error::invalid_iv_size);
                           BOOST_TEST(all_bytes(std::get<1>(done), 0));
                       }));
    context.restart();
    context.run();  // lint-run: the test's event loop
    BOOST_TEST_EQ(tuples, 2);
    BOOST_TEST(fixture.data == plaintext);
}

void post_gcm_awaitable_token(asio::io_context& context, gcm_fixture& fixture,
                              std::array<std::uint8_t, 40> const& plaintext) {
    // use_awaitable in a coroutine of the context: a refusal through as_tuple.
    bool done = false;
    asio::co_spawn(
        context,
        [&]() -> asio::awaitable<void> {
            auto const coro = co_await asio::this_coro::executor;
            auto made_code_result = co_await crypto::async_from_key<gcm_fixture::gcm>(
                coro, std::span(fixture.key).first(31), asio::as_tuple(asio::use_awaitable));
            auto& [made_code, made] = made_code_result;
            BOOST_TEST(made_code == crypto::error::invalid_key_size);
            BOOST_TEST(made.seal(fixture.iv, {}, fixture.data).error() ==
                       crypto::error::invalid_state);
            auto [seal_code, tag] =
                co_await crypto::async_seal(coro, fixture.aead, fixture.iv, fixture.additional_data,
                                            fixture.data, asio::as_tuple(asio::use_awaitable));
            BOOST_TEST(!seal_code);
            BOOST_TEST(fixture.data != plaintext);
            auto [open_code] = co_await crypto::async_open(
                coro, fixture.aead, fixture.iv, fixture.additional_data, fixture.data,
                std::span(tag.data(), tag.size()), asio::as_tuple(asio::use_awaitable));
            BOOST_TEST(!open_code);
            BOOST_TEST(fixture.data == plaintext);
            done = true;
        },
        [](std::exception_ptr const& failure) { BOOST_TEST(!failure); });
    context.restart();
    context.run();  // lint-run: the test's event loop
    BOOST_TEST(done);
}

void post_gcm_tokens(asio::io_context& context) {
    gcm_fixture fixture;
    auto const plaintext = fixture.data;
#ifndef WEBCPP_CRYPTO_NO_EXCEPTIONS
    post_gcm_future_token(context, fixture, plaintext);
#endif
    post_gcm_deferred_token(context, fixture, plaintext);
    post_gcm_tuple_token(context, fixture, plaintext);
    post_gcm_awaitable_token(context, fixture, plaintext);
}

// Ed25519's async_verify, async_sign and X25519's async_agree through the family's real
// functions, on the default backend. The fixture: RFC 8032's test 2 and RFC 7748's section 6.1.
struct verify_fixture {
    std::vector<std::uint8_t> seed =
        webcpp::test::from_hex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
    // value(): a key not made throws, or ends the program without exceptions.
    crypto::curves::ed25519::public_key public_key =
        crypto::curves::ed25519::public_key::from_bytes(
            webcpp::test::from_hex(
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"))
            .value();
    std::vector<std::uint8_t> message = webcpp::test::from_hex("72");
    // clang-format off
    std::vector<std::uint8_t> signature = webcpp::test::from_hex("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");
    // clang-format on
    std::vector<std::uint8_t> secret_key =
        webcpp::test::from_hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    std::vector<std::uint8_t> peer_key =
        webcpp::test::from_hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    crypto::curves::ed25519::keypair key_pair =
        *crypto::curves::ed25519::keypair::from_secret(seed);

    auto verify() {
        return [this](auto const& executor, auto&& token) {
            return crypto::async_verify(executor, crypto::eddsa, signature, message, public_key,
                                        std::forward<decltype(token)>(token));
        };
    }

    auto verify_refused() {
        return [this](auto const& executor, auto&& token) {
            return crypto::async_verify(executor, crypto::eddsa, std::span(signature).first(63),
                                        message, public_key, std::forward<decltype(token)>(token));
        };
    }

    auto sign() {
        return [this](auto const& executor, auto&& token) {
            return crypto::async_sign(executor, key_pair, crypto::eddsa, message,
                                      std::forward<decltype(token)>(token));
        };
    }

    auto agree() {
        return [this](auto const& executor, auto&& token) {
            return crypto::async_agree(executor, secret_key, peer_key,
                                       std::forward<decltype(token)>(token));
        };
    }

    auto agree_refused() {
        return [this](auto const& executor, auto&& token) {
            return crypto::async_agree(executor, std::span(secret_key).first(31), peer_key,
                                       std::forward<decltype(token)>(token));
        };
    }
};

// complete_by_callback of a real function, whose synchronous call is not counted by sync_runs: the
// completion comes after the initiating call returned, never inside it.
template <class... Value, class Start>
seen<Value...> complete_later(asio::io_context& context, Start start) {
    seen<Value...> done;
    bool returned = false;
    start(context.get_executor(),
          [&done, &returned](boost::system::error_code code, Value... value) {
              ++done.calls;
              done.after_return = returned;
              done.code = code;
              done.value = std::tuple<Value...>(std::move(value)...);
          });
    returned = true;
    BOOST_TEST_EQ(done.calls, 0);
    context.restart();
    context.run();  // lint-run: the test's event loop
    BOOST_TEST_EQ(done.calls, 1);
    BOOST_TEST(done.after_return);
    return done;
}

void post_verify_inline(asio::io_context& context) {
    verify_fixture fixture;
    auto const verified = complete_later<>(context, fixture.verify());
    BOOST_TEST(!verified.code);
    // A changed signature is refused.
    ++fixture.signature[3];
    auto const refused = complete_later<>(context, fixture.verify());
    BOOST_TEST(refused.code == crypto::error::invalid_signature);
    --fixture.signature[3];
    auto const short_signature = complete_later<>(context, fixture.verify_refused());
    BOOST_TEST(short_signature.code == crypto::error::invalid_signature);
    // The value shapes: a signature (an array) and a shared secret, and an error's empty value.
    auto const signed_message = complete_later<block>(context, fixture.sign());
    BOOST_TEST(!signed_message.code);
    BOOST_TEST(std::ranges::equal(std::get<0>(signed_message.value), fixture.signature));
    auto const agreed = complete_later<key>(context, fixture.agree());
    BOOST_TEST(!agreed.code);
    auto const agree_refused = complete_later<key>(context, fixture.agree_refused());
    BOOST_TEST(agree_refused.code == crypto::error::invalid_key_size);
    BOOST_TEST(all_bytes(std::get<0>(agree_refused.value), 0));
}

void post_verify_bound_executor() {
    verify_fixture fixture;
    complete_on_bound<>(fixture.verify());
    complete_on_bound<block>(fixture.sign());
    complete_on_bound<key>(fixture.agree());
}

void post_verify_allocator(asio::io_context& context) {
    verify_fixture fixture;
    allocator_call warm;
    start_counted<>(context, fixture.verify(), warm);
    BOOST_TEST_EQ(warm.calls, 1);
    allocator_call verified;
    start_counted<>(context, fixture.verify(), verified);
    BOOST_TEST(!verified.code);
    BOOST_TEST_EQ(verified.held_at_call, 0);
    BOOST_TEST_GE(verified.taken, 1);
    BOOST_TEST_EQ(verified.news, 0U);
    allocator_call refused;
    start_counted<>(context, fixture.verify_refused(), refused);
    BOOST_TEST(refused.code == crypto::error::invalid_signature);
    BOOST_TEST_EQ(refused.held_at_call, 0);
    BOOST_TEST_GE(refused.taken, 1);
    BOOST_TEST_EQ(refused.news, 0U);
    check_allocator_with<key>(context, fixture.agree(), fixture.agree_refused(),
                              crypto::error::invalid_key_size);
}

void post_verify_tokens(asio::io_context& context) {
    verify_fixture fixture;
    auto const executor = context.get_executor();

#ifndef WEBCPP_CRYPTO_NO_EXCEPTIONS
    auto future_ok = fixture.verify()(executor, asio::use_future);
    auto future_refused = fixture.verify_refused()(executor, asio::use_future);
    auto future_secret = fixture.agree()(executor, asio::use_future);
    context.restart();
    context.run();  // lint-run: the test's event loop
    future_ok.get();
    BOOST_TEST(!all_bytes(future_secret.get(), 0));
    bool thrown = false;
    try {
        future_refused.get();
    } catch (boost::system::system_error const& failure) {
        thrown = failure.code() == crypto::error::invalid_signature;
    }
    BOOST_TEST(thrown);
#endif

    // deferred: the synchronous call runs when the operation is launched, not when it is made.
    ++fixture.signature[0];
    auto operation = fixture.verify()(executor, asio::deferred);
    --fixture.signature[0];
    int deferred_calls = 0;
    // The signature is intact again when the operation is launched: the call reads it then.
    std::move(operation)([&](boost::system::error_code code) {
        ++deferred_calls;
        BOOST_TEST(!code);
    });
    BOOST_TEST_EQ(deferred_calls, 0);
    context.restart();
    context.run();  // lint-run: the test's event loop
    BOOST_TEST_EQ(deferred_calls, 1);

    // as_tuple: the code alone, and the code with the value of an error.
    int tuples = 0;
    fixture.verify_refused()(executor,
                             asio::as_tuple([&](std::tuple<boost::system::error_code> done) {
                                 ++tuples;
                                 BOOST_TEST(std::get<0>(done) == crypto::error::invalid_signature);
                             }));
    fixture.agree_refused()(executor,
                            asio::as_tuple([&](std::tuple<boost::system::error_code, key> done) {
                                ++tuples;
                                BOOST_TEST(std::get<0>(done) == crypto::error::invalid_key_size);
                                BOOST_TEST(all_bytes(std::get<1>(done), 0));
                            }));
    context.restart();
    context.run();  // lint-run: the test's event loop
    BOOST_TEST_EQ(tuples, 2);

    // use_awaitable in a coroutine of the context: a refusal through as_tuple.
    bool done = false;
    asio::co_spawn(
        context,
        [&]() -> asio::awaitable<void> {
            auto const coro = co_await asio::this_coro::executor;
            auto [verify_code] =
                co_await fixture.verify()(coro, asio::as_tuple(asio::use_awaitable));
            BOOST_TEST(!verify_code);
            auto [sign_code, signature] =
                co_await fixture.sign()(coro, asio::as_tuple(asio::use_awaitable));
            BOOST_TEST(!sign_code);
            BOOST_TEST(std::ranges::equal(signature, fixture.signature));
            auto [refused_code] =
                co_await fixture.verify_refused()(coro, asio::as_tuple(asio::use_awaitable));
            BOOST_TEST(refused_code == crypto::error::invalid_signature);
            done = true;
        },
        [](std::exception_ptr const& failure) { BOOST_TEST(!failure); });
    context.restart();
    context.run();  // lint-run: the test's event loop
    BOOST_TEST(done);
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
    post_gcm_inline(context);
    post_gcm_bound_executor();
    post_gcm_allocator(context);
    post_gcm_tokens(context);
    post_verify_inline(context);
    post_verify_bound_executor();
    post_verify_allocator(context);
    post_verify_tokens(context);
    return webcpp::test::exit_status(boost::report_errors());
}
