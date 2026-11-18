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
// not run out of work before it; a move-only result reaches the handler; and any completion
// token works (asio's deferred).

#include <webcpp/crypto/detail/heavy.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/asio/bind_executor.hpp>
#include <boost/asio/deferred.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/thread_pool.hpp>
#include <boost/core/lightweight_test.hpp>
#include <boost/system/error_code.hpp>

#include <atomic>
#include <chrono>
#include <memory>
#include <thread>
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

}  // namespace

int main() {
    runs_elsewhere_and_completes_on_the_caller();
    move_only_result();
    heavy_operation_with_any_token();
    return webcpp::test::exit_status(boost::report_errors());
}
