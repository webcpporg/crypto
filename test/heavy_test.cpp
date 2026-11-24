// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// detail::run_on_work, the initiator of every heavy operation's async_ variant (design D23,
// ruling R-A5: webcpp::hash's heavy machinery, libs/hash/include/webcpp/hash/async.hpp, ported),
// in a build with threads (natively, and on Emscripten with -pthread under node), on a test-only
// heavy operation, async_slow, whose work makes a secret<32> of bytes all `value` and whose
// guard refuses `value == 0` with invalid_input_size:
// - heavy_runs_on_pool: the work runs on a thread of the pool, never the caller's; the completion
//   runs on the caller's io_context, to which the handler is bound, with the work's value.
// - heavy_loop_goes_on: a latch holds the work until a 1 ms timer on the loop has fired (ruling
//   R-A8, never by timing); the completion follows the timer.
// - heavy_guard_refused: a guard's refusal completes on the loop with its error and an all-zero
//   secret, while the pool's one thread is held, and the pool runs nothing.
// - heavy_cancel_before_start: with the pool's one thread held, a cancellation of every type
//   emitted on the loop completes at once with operation_aborted, and the work never runs.
// - heavy_cancel_while_running: once the work has started (latched), a terminal or partial
//   cancellation lets it end, then destroys its value (a sentinel shows it gone before the
//   handler runs) and completes with operation_aborted and the empty value; a total one is
//   ignored and the value arrives.
// - heavy_signal_outlives: the signal declared before the loop and the pool, as hash's page asks;
//   a pool destroyed with the job queued destroys the handler unrun, whether the handler is bound
//   to the loop (which then runs, or is destroyed without running) or has no executor of its own,
//   and the signal emitted after it reaches nothing.
// - heavy_tokens: a callback without an executor of its own (completing on the pool), use_future
//   (in the build with exceptions, a refusal thrown as system_error), deferred and as_tuple; and
//   a type-erased work executor (any_io_executor), whose job falls back to std::allocator.
// - heavy_allocator: the handler's associated allocator, bound by bind_allocator, holds the
//   operation's state and every completion, and gets every block back before the handler runs, on
//   each way an operation completes; the job queued in the pool is the work executor's, given
//   back by the pool; and the replaced global operator new (support/counting.hpp) is not called.

#include <webcpp/crypto/detail/heavy.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/secret.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/counting.hpp"

#include <webcpp/asio/any_io_executor.hpp>
#include <webcpp/asio/as_tuple.hpp>
#include <webcpp/asio/bind_cancellation_slot.hpp>
#include <webcpp/asio/bind_executor.hpp>
#include <webcpp/asio/cancellation_signal.hpp>
#include <webcpp/asio/cancellation_type.hpp>
#include <webcpp/asio/deferred.hpp>
#include <webcpp/asio/error.hpp>
#include <webcpp/asio/execution/allocator.hpp>
#include <webcpp/asio/io_context.hpp>
#include <webcpp/asio/post.hpp>
#include <webcpp/asio/require.hpp>
#include <webcpp/asio/steady_timer.hpp>
#include <webcpp/asio/thread_pool.hpp>
#include <webcpp/asio/use_future.hpp>

#include <boost/core/lightweight_test.hpp>
#include <boost/system/error_code.hpp>
#include <boost/system/result.hpp>
#include <boost/system/system_error.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <future>
#include <memory>
#include <thread>
#include <tuple>
#include <type_traits>
#include <utility>

#ifndef WEBCPP_CRYPTO_HAS_THREADS
#error "test/Jamfile builds this test with threading=multi, where the build has threads"
#endif

namespace asio = webcpp::asio;
namespace crypto = webcpp::crypto;

namespace {

using key = crypto::secret<32>;

// The caller's thread, set by main before any work, and where the work of async_slow ran. Global:
// the work is a function of its own, which the test does not reach otherwise.
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): set once by main
std::thread::id caller_thread;
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): written by the pool's threads
std::atomic<int> runs_off_caller{0};
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): written by the pool's threads
std::atomic<int> runs_on_caller{0};

// The latch of the work: while engaged, a work that has started says so and waits until the test
// opens it, so that the test, never the scheduler, orders the work's end. Global, as the counters.
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): set by the test
std::atomic<bool> latch_engaged{false};
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): written by the pool's thread
std::atomic<bool> latch_entered{false};
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): set by the test
std::atomic<bool> latch_open{false};

/** Engages the latch: the next work waits until open_latch. */
void engage_latch() noexcept {
    latch_entered = false;
    latch_open = false;
    latch_engaged = true;
}

/** Waits until the work has started and waits at the latch. */
void wait_until_entered() noexcept {
    while (!latch_entered) {
        std::this_thread::yield();
    }
}

/** Lets the work end, and disengages the latch for the next one. */
void open_latch() noexcept {
    latch_engaged = false;
    latch_open = true;
}

/** The work's first step: where it runs is recorded, then it waits at the latch if engaged. */
void enter_work() noexcept {
    if (std::this_thread::get_id() == caller_thread) {
        ++runs_on_caller;
    } else {
        ++runs_off_caller;
    }
    if (latch_engaged) {
        latch_entered = true;
        while (!latch_open) {
            std::this_thread::yield();
        }
    }
}

/** How many works have run, on any thread. */
int runs() noexcept {
    return runs_off_caller.load() + runs_on_caller.load();
}

/** The guard of the test-only heavy operation: `value` 0 is refused. */
boost::system::result<void> slow_guards(std::uint8_t value) noexcept {
    if (value == 0) {
        return crypto::error::invalid_input_size;
    }
    return {};
}

/** The test-only heavy operation, synchronous: a secret of bytes all `value`. */
boost::system::result<key> slow(std::uint8_t value) noexcept {
    enter_work();
    key made;
    std::ranges::fill(made.writable(), value);
    return made;
}

/** Its async_ variant, as every heavy operation declares one (ruling R-A6). */
template <class WorkExecutor, class CompletionToken>
auto async_slow(WorkExecutor const& work, std::uint8_t value, CompletionToken&& completion_token) {
    WEBCPP_CRYPTO_DETAIL_REQUIRE_THREADS("async_slow", "slow");
    return crypto::detail::run_on_work(
        work, [value]() noexcept { return slow_guards(value); },
        [value]() noexcept { return slow(value); }, completion_token);
}

/** A value whose destruction the test sees: the sentinel's last owner, empty by default. */
struct tracked {
    std::shared_ptr<int> sentinel;
};

/** A heavy operation whose value is a tracked holding `sentinel`. */
template <class WorkExecutor, class CompletionToken>
auto async_tracked(WorkExecutor const& work, std::shared_ptr<int> sentinel,
                   CompletionToken&& completion_token) {
    WEBCPP_CRYPTO_DETAIL_REQUIRE_THREADS("async_tracked", "tracked");
    return crypto::detail::run_on_work(
        work, []() noexcept { return boost::system::result<void>(); },
        [sentinel = std::move(sentinel)]() mutable noexcept {
            enter_work();
            return boost::system::result<tracked>(tracked{std::move(sentinel)});
        },
        completion_token);
}

/** Whether every byte of `made` is `value`. */
bool all_bytes(key const& made, std::uint8_t value) {
    return std::ranges::all_of(made.bytes(), [value](std::uint8_t byte) { return byte == value; });
}

/** A pool of one thread, held by a job of the test's until release or destruction. */
struct held_pool {
    asio::thread_pool pool{1};
    std::atomic<bool> blocking{false};
    std::atomic<bool> released{false};

    held_pool() {
        asio::post(pool, [this] {
            blocking = true;
            while (!released) {
                std::this_thread::yield();
            }
        });
        while (!blocking) {
            std::this_thread::yield();
        }
    }

    held_pool(held_pool const&) = delete;
    held_pool& operator=(held_pool const&) = delete;
    held_pool(held_pool&&) = delete;
    held_pool& operator=(held_pool&&) = delete;

    ~held_pool() {
        release();
        pool.join();
    }

    void release() noexcept { released = true; }
};

/** What a callback of async_slow saw. */
struct seen {
    int calls = 0;
    std::thread::id thread;
    boost::system::error_code code;
    key value;
};

/** A callback bound to `loop` that records into `into`. */
auto recorder(asio::io_context& loop, seen& into) {
    return asio::bind_executor(loop.get_executor(),
                               [&into](boost::system::error_code code, key value) {
                                   ++into.calls;
                                   into.thread = std::this_thread::get_id();
                                   into.code = code;
                                   into.value = std::move(value);
                               });
}

void heavy_runs_on_pool(asio::io_context& loop, asio::thread_pool& pool) {
    int const off_before = runs_off_caller.load();
    int const on_before = runs_on_caller.load();
    seen done;
    async_slow(pool.get_executor(), 0x42, recorder(loop, done));
    BOOST_TEST_EQ(done.calls, 0);  // never inside the call
    loop.restart();
    loop.run();  // lint-run: the test's event loop, kept busy until the completion
    BOOST_TEST_EQ(done.calls, 1);
    BOOST_TEST(!done.code);
    BOOST_TEST(done.thread == caller_thread);
    BOOST_TEST(all_bytes(done.value, 0x42));
    BOOST_TEST_EQ(runs_off_caller.load(), off_before + 1);
    BOOST_TEST_EQ(runs_on_caller.load(), on_before);
}

void heavy_loop_goes_on(asio::io_context& loop, asio::thread_pool& pool) {
    engage_latch();
    seen done;
    async_slow(pool.get_executor(), 7, recorder(loop, done));
    wait_until_entered();
    bool timer_fired = false;
    bool timer_first = false;
    asio::steady_timer timer(loop, std::chrono::milliseconds(1));
    timer.async_wait([&](boost::system::error_code code) {
        BOOST_TEST(!code);
        timer_fired = true;
        timer_first = done.calls == 0;
        open_latch();
    });
    loop.restart();
    loop.run();  // lint-run: the test's event loop, going on while the work runs
    BOOST_TEST(timer_fired);
    BOOST_TEST(timer_first);
    BOOST_TEST_EQ(done.calls, 1);
    BOOST_TEST(!done.code);
    BOOST_TEST(all_bytes(done.value, 7));
}

void heavy_guard_refused(asio::io_context& loop) {
    held_pool held;
    int const before = runs();
    seen refused;
    async_slow(held.pool.get_executor(), 0, recorder(loop, refused));
    BOOST_TEST_EQ(refused.calls, 0);
    loop.restart();
    loop.run();  // lint-run: the test's event loop; the pool is held, the refusal needs it not
    BOOST_TEST_EQ(refused.calls, 1);
    BOOST_TEST(refused.code == crypto::error::invalid_input_size);
    BOOST_TEST(refused.thread == caller_thread);
    BOOST_TEST(all_bytes(refused.value, 0));
    held.release();
    held.pool.join();
    BOOST_TEST_EQ(runs(), before);
}

void heavy_cancel_before_start(asio::io_context& loop) {
    for (auto const type : {
             asio::cancellation_type::terminal,
             asio::cancellation_type::partial,
             asio::cancellation_type::total,
         }) {
        held_pool held;
        int const before = runs();
        asio::cancellation_signal signal;
        seen cancelled;
        async_slow(held.pool.get_executor(), 9,
                   asio::bind_cancellation_slot(signal.slot(), recorder(loop, cancelled)));
        asio::post(loop, [&signal, type] { signal.emit(type); });
        loop.restart();
        loop.run();  // lint-run: the test's event loop; the pool is still held
        BOOST_TEST_EQ(cancelled.calls, 1);
        BOOST_TEST(cancelled.code == asio::error::operation_aborted);
        BOOST_TEST(cancelled.thread == caller_thread);
        BOOST_TEST(all_bytes(cancelled.value, 0));
        held.release();
        held.pool.join();
        BOOST_TEST_EQ(runs(), before);
        BOOST_TEST_EQ(cancelled.calls, 1);
    }
}

void heavy_cancel_while_running(asio::io_context& loop) {
    for (auto const type : {asio::cancellation_type::terminal, asio::cancellation_type::partial}) {
        asio::thread_pool pool(1);
        engage_latch();
        asio::cancellation_signal signal;
        seen cancelled;
        async_slow(pool.get_executor(), 5,
                   asio::bind_cancellation_slot(signal.slot(), recorder(loop, cancelled)));
        wait_until_entered();
        signal.emit(type);
        open_latch();
        loop.restart();
        loop.run();  // lint-run: the test's event loop
        BOOST_TEST_EQ(cancelled.calls, 1);
        BOOST_TEST(cancelled.code == asio::error::operation_aborted);
        BOOST_TEST(all_bytes(cancelled.value, 0));

        // The value the work made is destroyed before the handler runs: a secret is wiped so.
        engage_latch();
        auto sentinel = std::make_shared<int>(1);
        std::weak_ptr<int> const alive = sentinel;
        asio::cancellation_signal tracked_signal;
        int calls = 0;
        bool alive_at_call = true;
        bool empty_value = false;
        boost::system::error_code tracked_code;
        async_tracked(
            pool.get_executor(), std::move(sentinel),
            asio::bind_cancellation_slot(
                tracked_signal.slot(),
                asio::bind_executor(loop.get_executor(),
                                    [&](boost::system::error_code code, tracked const& value) {
                                        ++calls;
                                        alive_at_call = !alive.expired();
                                        empty_value = value.sentinel == nullptr;
                                        tracked_code = code;
                                    })));
        wait_until_entered();
        tracked_signal.emit(type);
        open_latch();
        loop.restart();
        loop.run();  // lint-run: the test's event loop
        BOOST_TEST_EQ(calls, 1);
        BOOST_TEST(tracked_code == asio::error::operation_aborted);
        BOOST_TEST(!alive_at_call);
        BOOST_TEST(empty_value);
        pool.join();
    }

    asio::thread_pool pool(1);
    engage_latch();
    asio::cancellation_signal signal;
    seen total;
    async_slow(pool.get_executor(), 5,
               asio::bind_cancellation_slot(signal.slot(), recorder(loop, total)));
    wait_until_entered();
    signal.emit(asio::cancellation_type::total);
    open_latch();
    loop.restart();
    loop.run();  // lint-run: the test's event loop
    BOOST_TEST_EQ(total.calls, 1);
    BOOST_TEST(!total.code);
    BOOST_TEST(all_bytes(total.value, 5));
    pool.join();
}

/** The handler of an operation that never completes: destroyed, never called. */
struct unrun_handler {
    std::shared_ptr<int> sentinel;
    bool* called;

    void operator()(boost::system::error_code /*code*/, key /*value*/) const { *called = true; }
};

/** A pool of one held thread destroyed with the job of async_slow queued, its handler bound. */
template <class Bind>
void destroy_pool_with_job_queued(std::weak_ptr<int>& alive, bool& called, Bind bind) {
    held_pool held;
    auto sentinel = std::make_shared<int>(1);
    alive = sentinel;
    async_slow(held.pool.get_executor(), 3,
               bind(unrun_handler{.sentinel = std::move(sentinel), .called = &called}));
    held.pool.stop();
}

void heavy_signal_outlives() {
    // The signal outlives the loop and the pool: a signal must outlive the operation connected to
    // its slot, which clears the slot when its handler is destroyed.
    asio::cancellation_signal signal;
    std::weak_ptr<int> alive;
    bool called = false;
    {
        asio::io_context loop;
        destroy_pool_with_job_queued(alive, called, [&](auto handler) {
            return asio::bind_cancellation_slot(
                signal.slot(), asio::bind_executor(loop.get_executor(), std::move(handler)));
        });
        loop.run();  // lint-run: the discarded operation's turn
        BOOST_TEST(alive.expired());
        BOOST_TEST(!called);
    }
    signal.emit(asio::cancellation_type::terminal);
    BOOST_TEST(!called);

    {
        asio::io_context elsewhere;
        destroy_pool_with_job_queued(alive, called, [&](auto handler) {
            return asio::bind_cancellation_slot(
                signal.slot(), asio::bind_executor(elsewhere.get_executor(), std::move(handler)));
        });
    }
    BOOST_TEST(alive.expired());
    BOOST_TEST(!called);
    signal.emit(asio::cancellation_type::terminal);

    destroy_pool_with_job_queued(alive, called, [&](auto handler) {
        return asio::bind_cancellation_slot(signal.slot(), std::move(handler));
    });
    BOOST_TEST(alive.expired());
    BOOST_TEST(!called);
    signal.emit(asio::cancellation_type::terminal);
    BOOST_TEST(!called);
}

void heavy_tokens(asio::io_context& loop) {
    {
        // A callback without an executor of its own completes on the work executor.
        asio::thread_pool pool(1);
        std::atomic<int> calls{0};
        std::atomic<bool> off_caller{false};
        std::atomic<bool> right{false};
        async_slow(pool.get_executor(), 1, [&](boost::system::error_code code, key value) {
            ++calls;
            off_caller = std::this_thread::get_id() != caller_thread;
            right = !code && all_bytes(value, 1);
        });
        pool.join();
        BOOST_TEST_EQ(calls.load(), 1);
        BOOST_TEST(off_caller.load());
        BOOST_TEST(right.load());
    }

    asio::thread_pool pool(1);
#ifndef WEBCPP_CRYPTO_NO_EXCEPTIONS
    std::future<key> made = async_slow(pool.get_executor(), 2, asio::use_future);
    BOOST_TEST(all_bytes(made.get(), 2));
    std::future<key> refused = async_slow(pool.get_executor(), 0, asio::use_future);
    bool thrown = false;
    try {
        static_cast<void>(refused.get());
    } catch (boost::system::system_error const& failure) {
        thrown = failure.code() == crypto::error::invalid_input_size;
    }
    BOOST_TEST(thrown);
#endif

    seen deferred;
    auto operation = async_slow(pool.get_executor(), 3, asio::deferred);
    std::move(operation)(recorder(loop, deferred));
    loop.restart();
    loop.run();  // lint-run: the test's event loop
    BOOST_TEST_EQ(deferred.calls, 1);
    BOOST_TEST(!deferred.code);
    BOOST_TEST(all_bytes(deferred.value, 3));

    // A type-erased work executor, which does not answer the allocator query: the job's storage
    // is then Asio's recycling std::allocator<void>.
    static_assert(std::is_same_v<crypto::detail::heavy_job_allocator_t<asio::any_io_executor>,
                                 std::allocator<void>>);
    asio::any_io_executor const erased_work(pool.get_executor());
    seen erased;
    async_slow(erased_work, 6, recorder(loop, erased));
    loop.restart();
    loop.run();  // lint-run: the test's event loop
    BOOST_TEST_EQ(erased.calls, 1);
    BOOST_TEST(!erased.code);
    BOOST_TEST(erased.thread == caller_thread);
    BOOST_TEST(all_bytes(erased.value, 6));

    int tuples = 0;
    async_slow(pool.get_executor(), 4,
               asio::as_tuple(asio::bind_executor(
                   loop.get_executor(), [&](std::tuple<boost::system::error_code, key> done) {
                       ++tuples;
                       BOOST_TEST(!std::get<0>(done));
                       BOOST_TEST(all_bytes(std::get<1>(done), 4));
                   })));
    async_slow(pool.get_executor(), 0,
               asio::as_tuple(asio::bind_executor(
                   loop.get_executor(), [&](std::tuple<boost::system::error_code, key> done) {
                       ++tuples;
                       BOOST_TEST(std::get<0>(done) == crypto::error::invalid_input_size);
                       BOOST_TEST(all_bytes(std::get<1>(done), 0));
                   })));
    loop.restart();
    loop.run();  // lint-run: the test's event loop
    BOOST_TEST_EQ(tuples, 2);
    pool.join();
}

// What a holding_allocator counts, shared by its rebound copies: the blocks it holds now, and
// every block it has given.
struct holding {
    std::atomic<int> held{0};
    std::atomic<int> taken{0};
};

// An allocator that counts the blocks it holds and gives; its deallocation may run on a pool's
// thread. Its blocks are the C library's, so that a call of operator new is never its own.
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
        counts->held.fetch_add(1);
        counts->taken.fetch_add(1);
        return static_cast<T*>(block);
    }

    void deallocate(T* pointer, std::size_t /*count*/) noexcept {
        std::free(pointer);
        counts->held.fetch_sub(1);
    }

    template <class U>
    bool operator==(holding_allocator<U> const& other) const noexcept {
        return counts == other.counts;
    }
};

// What the handler of one call of heavy_allocator saw.
struct allocator_call {
    int calls = 0;
    int held_at_call = -1;
    int taken = 0;
    int jobs_held_at_call = -1;
    std::size_t news = 0;
    boost::system::error_code code;
};

// The handler of one call of heavy_allocator: it records what the allocators hold when it runs,
// what was taken since it was made, and the calls of operator new since then. It names its
// executor, its allocator and its cancellation slot itself, as hash's test does: three binders
// nested make MSVC's compiler stop without a diagnostic.
struct held_handler {
    using executor_type = asio::io_context::executor_type;
    using allocator_type = holding_allocator<char>;
    using cancellation_slot_type = asio::cancellation_slot;

    executor_type executor;
    allocator_type allocator;
    cancellation_slot_type slot;
    holding* jobs;
    allocator_call* call;
    int taken_before;
    std::size_t news_before;

    [[nodiscard]] executor_type get_executor() const noexcept { return executor; }

    [[nodiscard]] allocator_type get_allocator() const noexcept { return allocator; }

    [[nodiscard]] cancellation_slot_type get_cancellation_slot() const noexcept { return slot; }

    void operator()(boost::system::error_code done, key /*value*/) const {
        call->news = webcpp::test::counted_new.load() - news_before;
        ++call->calls;
        call->held_at_call = allocator.counts->held.load();
        call->taken = allocator.counts->taken.load() - taken_before;
        call->jobs_held_at_call = jobs->held.load();
        call->code = done;
    }
};

// async_slow of `value` on `pool`, its job in storage of a holding_allocator over `jobs`, its
// handler on the loop's executor with `slot` and a holding_allocator over `counts`.
void start_held(asio::io_context& loop, asio::thread_pool& pool, holding& jobs, holding& counts,
                std::uint8_t value, asio::cancellation_slot slot, allocator_call& call) {
    auto const work = asio::require(pool.get_executor(),
                                    asio::execution::allocator(holding_allocator<void>(&jobs)));
    held_handler handler{
        .executor = loop.get_executor(),
        .allocator = holding_allocator<char>(&counts),
        .slot = slot,
        .jobs = &jobs,
        .call = &call,
        .taken_before = counts.taken.load(),
        .news_before = webcpp::test::counted_new.load(),
    };
    async_slow(work, value, std::move(handler));
}

void heavy_allocator(asio::io_context& loop) {
    holding counts;
    holding jobs;
    asio::thread_pool pool(1);

    // One uncounted call first, so that what the runtime makes once (a thread's first use of a
    // facility) is outside the windows below.
    allocator_call warm;
    start_held(loop, pool, jobs, counts, 1, {}, warm);
    loop.restart();
    loop.run();  // lint-run: the test's event loop
    BOOST_TEST_EQ(warm.calls, 1);

    // The work done, no slot connected: the state and the completion are the handler's, the job
    // the work executor's, and nothing calls operator new.
    allocator_call done;
    start_held(loop, pool, jobs, counts, 1, {}, done);
    loop.restart();
    loop.run();  // lint-run: the test's event loop
    BOOST_TEST_EQ(done.calls, 1);
    BOOST_TEST(!done.code);
    BOOST_TEST_EQ(done.held_at_call, 0);
    BOOST_TEST_GE(done.taken, 2);
    BOOST_TEST_EQ(done.news, 0U);

    // A guard's refusal: its post alone, the handler's.
    allocator_call refused;
    start_held(loop, pool, jobs, counts, 0, {}, refused);
    loop.restart();
    loop.run();  // lint-run: the test's event loop
    BOOST_TEST_EQ(refused.calls, 1);
    BOOST_TEST(refused.code == crypto::error::invalid_input_size);
    BOOST_TEST_EQ(refused.held_at_call, 0);
    BOOST_TEST_GE(refused.taken, 1);
    BOOST_TEST_EQ(refused.news, 0U);

    // The work done with a connected slot. The slot's cancellation handler is in the signal's
    // storage, which Asio allocates itself (cancellation_slot::prepare_memory): operator new is
    // not counted here.
    asio::cancellation_signal done_signal;
    allocator_call slotted;
    start_held(loop, pool, jobs, counts, 1, done_signal.slot(), slotted);
    loop.restart();
    loop.run();  // lint-run: the test's event loop
    BOOST_TEST_EQ(slotted.calls, 1);
    BOOST_TEST(!slotted.code);
    BOOST_TEST_EQ(slotted.held_at_call, 0);
    BOOST_TEST_GE(slotted.taken, 2);
    pool.join();

    // A cancellation before the work starts, the pool held: the handler gets every block back,
    // while the job, the work executor's, still waits in the pool's queue.
    {
        held_pool held;
        asio::cancellation_signal signal;
        allocator_call cancelled;
        start_held(loop, held.pool, jobs, counts, 1, signal.slot(), cancelled);
        signal.emit(asio::cancellation_type::terminal);
        loop.restart();
        loop.run();  // lint-run: the test's event loop
        BOOST_TEST_EQ(cancelled.calls, 1);
        BOOST_TEST(cancelled.code == asio::error::operation_aborted);
        BOOST_TEST_EQ(cancelled.held_at_call, 0);
        BOOST_TEST_GE(cancelled.taken, 2);
        BOOST_TEST_EQ(cancelled.jobs_held_at_call, 1);
    }

    // A cancellation once the work has started.
    {
        asio::thread_pool one(1);
        engage_latch();
        asio::cancellation_signal signal;
        allocator_call running;
        start_held(loop, one, jobs, counts, 1, signal.slot(), running);
        wait_until_entered();
        signal.emit(asio::cancellation_type::terminal);
        open_latch();
        loop.restart();
        loop.run();  // lint-run: the test's event loop
        BOOST_TEST_EQ(running.calls, 1);
        BOOST_TEST(running.code == asio::error::operation_aborted);
        BOOST_TEST_EQ(running.held_at_call, 0);
        BOOST_TEST_GE(running.taken, 2);
        one.join();
    }
    BOOST_TEST_EQ(counts.held.load(), 0);
    BOOST_TEST_EQ(jobs.held.load(), 0);
    BOOST_TEST_GE(jobs.taken.load(), 4);
}

}  // namespace

int main() {
    caller_thread = std::this_thread::get_id();
    asio::io_context loop;
    asio::thread_pool pool(2);
    heavy_runs_on_pool(loop, pool);
    heavy_loop_goes_on(loop, pool);
    pool.join();
    heavy_guard_refused(loop);
    heavy_cancel_before_start(loop);
    heavy_cancel_while_running(loop);
    heavy_signal_outlives();
    heavy_tokens(loop);
    heavy_allocator(loop);
    return webcpp::test::exit_status(boost::report_errors());
}
