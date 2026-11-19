// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// detail::run_heavy, the initiator of every heavy operation's async_ variant (design D23), in a
// build with threads, on a test-only heavy operation: the work runs on the executor given (a
// thread_pool's), not on the caller's thread; the caller's io_context goes on meanwhile (a 10 ms
// timer on it fires while the work waits for it); the completion runs on the handler's
// associated executor (the caller's io_context, on the caller's thread), whose io_context does
// not run out of work before it; a move-only result reaches the handler; any completion token
// works (asio's deferred); and the handler's associated allocator and cancellation slot are
// those of the function posted to the work's executor and of the one dispatched to the
// completion's, as asio asks of an operation's intermediate handlers.

#include <webcpp/crypto/detail/heavy.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/asio/associated_allocator.hpp>
#include <boost/asio/associated_cancellation_slot.hpp>
#include <boost/asio/bind_allocator.hpp>
#include <boost/asio/bind_cancellation_slot.hpp>
#include <boost/asio/bind_executor.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <boost/asio/deferred.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/prefer.hpp>
#include <boost/asio/query.hpp>
#include <boost/asio/require.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/thread_pool.hpp>
#include <boost/core/lightweight_test.hpp>
#include <boost/system/error_code.hpp>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <memory>
#include <thread>
#include <type_traits>
#include <utility>

#ifndef WEBCPP_CRYPTO_HAS_THREADS
#error "test/Jamfile builds this test with threading=multi, where the build has threads"
#endif

namespace crypto = webcpp::crypto;

namespace {

/** The test-only heavy operation, synchronous. */
int slow(int value) noexcept {
    return value + 1;
}

/** Its async_ variant, as every heavy operation declares one. */
template <class Executor, class CompletionToken>
auto async_slow(Executor executor, int value, CompletionToken&& token) {
    WEBCPP_CRYPTO_DETAIL_REQUIRE_THREADS("async_slow", "slow");
    return crypto::detail::run_heavy(
        std::move(executor), [value]() noexcept { return slow(value); },
        std::forward<CompletionToken>(token));
}

/** Waits, at most 5 s, until `flag` is set; whether it was. */
bool wait_for(std::atomic<bool> const& flag) noexcept {
    auto const deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (!flag.load() && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return flag.load();
}

void runs_elsewhere_and_completes_on_the_caller() {
    boost::asio::io_context caller;
    boost::asio::thread_pool pool(1);
    auto const caller_thread = std::this_thread::get_id();
    std::atomic<bool> fired{false};
    boost::asio::steady_timer timer(caller, std::chrono::milliseconds(10));
    timer.async_wait([&fired](boost::system::error_code const& error) {
        BOOST_TEST(!error);
        fired.store(true);
    });
    std::thread::id work_thread;
    std::thread::id completion_thread;
    bool timer_fired_meanwhile = false;
    bool completed = false;
    crypto::detail::run_heavy(
        pool.get_executor(),
        [&work_thread, &fired]() noexcept {
            work_thread = std::this_thread::get_id();
            return wait_for(fired);
        },
        boost::asio::bind_executor(caller.get_executor(), [&](bool timer_fired) {
            completion_thread = std::this_thread::get_id();
            timer_fired_meanwhile = timer_fired;
            completed = true;
        }));
    // The completion keeps the caller's io_context busy: run returns after it, not before.
    caller.run();  // lint-run: that run waits for the tracked work is what this test proves
    pool.join();
    BOOST_TEST(completed);
    BOOST_TEST(timer_fired_meanwhile);
    BOOST_TEST(work_thread != caller_thread);
    BOOST_TEST(work_thread != std::thread::id{});
    BOOST_TEST(completion_thread == caller_thread);
}

void move_only_result() {
    boost::asio::io_context caller;
    boost::asio::thread_pool pool(1);
    std::unique_ptr<int> received;
    crypto::detail::run_heavy(
        pool.get_executor(), []() noexcept { return std::make_unique<int>(7); },
        boost::asio::bind_executor(caller.get_executor(), [&received](std::unique_ptr<int> result) {
            received = std::move(result);
        }));
    caller.run();  // lint-run: waits for the pool's thread to post the completion
    pool.join();
    BOOST_TEST(received != nullptr);
    if (received) {
        BOOST_TEST_EQ(*received, 7);
    }
}

void heavy_operation_with_any_token() {
    boost::asio::io_context caller;
    boost::asio::thread_pool pool(1);
    int received = 0;
    auto operation = async_slow(pool.get_executor(), 41, boost::asio::deferred);
    std::move(operation)(boost::asio::bind_executor(
        caller.get_executor(), [&received](int result) { received = result; }));
    caller.run();  // lint-run: waits for the pool's thread to post the completion
    pool.join();
    BOOST_TEST_EQ(received, 42);
}

/** An allocator the test recognises by its type; it allocates as std::allocator does. */
template <class T>
struct tagged_allocator {
    using value_type = T;

    tagged_allocator() noexcept = default;

    template <class U>
    explicit(false) tagged_allocator(tagged_allocator<U> const& /*other*/) noexcept {}

    [[nodiscard]] T* allocate(std::size_t count) { return std::allocator<T>{}.allocate(count); }

    void deallocate(T* pointer, std::size_t count) noexcept {
        std::allocator<T>{}.deallocate(pointer, count);
    }

    friend bool operator==(tagged_allocator const& /*left*/,
                           tagged_allocator const& /*right*/) noexcept {
        return true;
    }
};

/** What a recording executor saw of the functions it was given to run. */
struct record {
    /** How many functions it ran. */
    std::atomic<int> functions{0};
    /** How many of them had the handler's allocator associated. */
    std::atomic<int> allocators{0};
    /** How many of them had the handler's cancellation slot associated. */
    std::atomic<int> slots{0};
};

/** An executor that records, of each function it runs, its associated allocator and
 * cancellation slot, then runs it on `Inner`; properties are `Inner`'s. */
template <class Inner>
class recording_executor {
public:
    recording_executor(Inner inner, std::shared_ptr<record> seen) noexcept
        : inner_(std::move(inner)), seen_(std::move(seen)) {}

    template <class Function>
    void execute(Function&& function) const {
        ++seen_->functions;
        if constexpr (std::is_same_v<
                          std::decay_t<decltype(boost::asio::get_associated_allocator(function))>,
                          tagged_allocator<void>>) {
            ++seen_->allocators;
        }
        if (boost::asio::get_associated_cancellation_slot(function).is_connected()) {
            ++seen_->slots;
        }
        inner_.execute(std::forward<Function>(function));
    }

    template <class Property>
    [[nodiscard]] auto query(Property const& property) const noexcept
        -> decltype(boost::asio::query(std::declval<Inner const&>(), property)) {
        return boost::asio::query(inner_, property);
    }

    template <class Property>
    [[nodiscard]] auto require(Property const& property) const -> recording_executor<
        std::decay_t<decltype(boost::asio::require(std::declval<Inner const&>(), property))>> {
        return {boost::asio::require(inner_, property), seen_};
    }

    friend bool operator==(recording_executor const& left,
                           recording_executor const& right) noexcept {
        return left.inner_ == right.inner_ && left.seen_ == right.seen_;
    }

private:
    template <class>
    friend class recording_executor;

    Inner inner_;
    std::shared_ptr<record> seen_;
};

void carries_the_handlers_allocator_and_cancellation_slot() {
    boost::asio::io_context caller;
    boost::asio::thread_pool pool(1);
    auto const work = std::make_shared<record>();
    auto const completion = std::make_shared<record>();
    boost::asio::cancellation_signal signal;
    int received = 0;
    crypto::detail::run_heavy(
        recording_executor(pool.get_executor(), work), []() noexcept { return slow(41); },
        boost::asio::bind_cancellation_slot(
            signal.slot(),
            boost::asio::bind_allocator(
                tagged_allocator<void>{},
                boost::asio::bind_executor(recording_executor(caller.get_executor(), completion),
                                           [&received](int result) { received = result; }))));
    caller.run();  // lint-run: waits for the pool's thread to post the completion
    pool.join();
    BOOST_TEST_EQ(received, 42);
    BOOST_TEST_EQ(work->functions.load(), 1);
    BOOST_TEST_EQ(work->allocators.load(), 1);
    BOOST_TEST_EQ(work->slots.load(), 1);
    BOOST_TEST_EQ(completion->functions.load(), 1);
    BOOST_TEST_EQ(completion->allocators.load(), 1);
    BOOST_TEST_EQ(completion->slots.load(), 1);
}

}  // namespace

int main() {
    runs_elsewhere_and_completes_on_the_caller();
    move_only_result();
    heavy_operation_with_any_token();
    carries_the_handlers_allocator_and_cancellation_slot();
    return webcpp::test::exit_status(boost::report_errors());
}
