// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 The heavy operations' `async_` variants (design D23): in a build with threads
 (`WEBCPP_CRYPTO_HAS_THREADS`), `detail::run_on_work` checks the operation's guards on the
 caller's thread, runs its synchronous call on the work executor the program gives and completes
 on the handler's associated executor, with webcpp::hash's cancellation rules; without threads,
 the variant's first statement, `WEBCPP_CRYPTO_DETAIL_REQUIRE_THREADS`, stops the build where the
 program calls it.

 The machinery is webcpp::hash's (`libs/hash/include/webcpp/hash/async.hpp`, its `heavy_phase`,
 `heavy_state`, `heavy_job`, `heavy_initiation` and `run_on_work`), ported, not shared (ruling
 R-A5): hash's work writes into the caller's span, crypto's returns a value, which the state
 carries and the completion gives as its second argument, `void(error_code, T)`, or none,
 `void(error_code)`. Lifting the state into webcpp::asio is that library's change, for when a third
 library needs it.

 The heavy operations are stated (design D32): RSA key generation at every size and RSA private
 operations at 3072 bits and above; SLH-DSA key generation, signing and verification; ML-DSA key
 generation and signing; BLS12-381 verification, aggregate verification, fast aggregate
 verification and aggregation; KZG's commitments and proofs over a blob and their batch
 verification; BN254's `pairing_check`. Everything else is cheap: its `async_` variant completes
 through a post, and its synchronous call runs at once.
*/
#ifndef WEBCPP_CRYPTO_DETAIL_HEAVY_HPP
#define WEBCPP_CRYPTO_DETAIL_HEAVY_HPP

#include <webcpp/crypto/config.hpp>

#include <webcpp/crypto/detail/async_access.hpp>
#include <webcpp/crypto/detail/engines.hpp>

#include <boost/system/error_code.hpp>
#include <boost/system/result.hpp>

#ifdef WEBCPP_CRYPTO_HAS_THREADS
#include <webcpp/asio/append.hpp>
#include <webcpp/asio/associated_allocator.hpp>
#include <webcpp/asio/associated_cancellation_slot.hpp>
#include <webcpp/asio/associated_executor.hpp>
#include <webcpp/asio/async_result.hpp>
#include <webcpp/asio/bind_allocator.hpp>
#include <webcpp/asio/cancellation_type.hpp>
#include <webcpp/asio/dispatch.hpp>
#include <webcpp/asio/error.hpp>
#include <webcpp/asio/execution/allocator.hpp>
#include <webcpp/asio/executor_work_guard.hpp>
#include <webcpp/asio/post.hpp>
#include <webcpp/asio/query.hpp>

#include <atomic>
#include <cstdint>
#include <memory>
#include <new>
#include <optional>
#include <thread>  // lint-world: std::this_thread::yield, the state's spin lock
#endif

#include <type_traits>
#include <utility>

namespace webcpp::crypto::detail {

/**
 * The completion signature of an asynchronous operation whose synchronous call returns
 * `Result`: `void(boost::system::error_code, T)` for `boost::system::result<T>`, and
 * `void(boost::system::error_code)` for `boost::system::result<void>` (ruling R-A3).
 *
 * @tparam Result The synchronous call's result.
 */
template <class Result>
struct completion_of {
    static_assert(dependent_false<Result>,
                  "webcpp::crypto: an asynchronous operation's call returns a "
                  "boost::system::result");
};

/**
 * The completion of a call that returns a value.
 *
 * @tparam T The value.
 */
template <class T>
struct completion_of<boost::system::result<T>> {
    /** The completion signature. */
    using type = void(boost::system::error_code, T);
    /** The value the completion gives after its error code. */
    using value_type = T;
};

/** The completion of a call that returns no value. */
template <>
struct completion_of<boost::system::result<void>> {
    /** The completion signature. */
    using type = void(boost::system::error_code);
    /** No value. */
    using value_type = void;
};

/**
 The refusal of a heavy operation's `async_` variant in a build without threads (design D23).
 Each such variant's body starts with it, so that a program fails only where it calls one,
 with this error first; a variant that forgets it stops at `run_on_work`'s stand-in instead.
 The variant's completion token is its parameter `token`.
*/
#ifdef WEBCPP_CRYPTO_HAS_THREADS
#define WEBCPP_CRYPTO_DETAIL_REQUIRE_THREADS(async_name, sync_name)
#else
#define WEBCPP_CRYPTO_DETAIL_REQUIRE_THREADS(async_name, sync_name)                 \
    static_assert(                                                                  \
        ::webcpp::crypto::detail::dependent_false<decltype(token)>,                 \
        "webcpp::crypto: " async_name                                               \
        " runs on another thread and needs a build with threads (natively without " \
        "WEBCPP_CRYPTO_NO_THREADS; on Emscripten -pthread). Without threads, call " sync_name ".")
#endif

#ifdef WEBCPP_CRYPTO_HAS_THREADS

/**
 * The error code of a synchronous call's result.
 *
 * @tparam T The result's value.
 * @param done The result.
 * @return Its error, or the empty code on success.
 */
template <class T>
boost::system::error_code code_of(boost::system::result<T> const& done) noexcept {
    return done ? boost::system::error_code{} : done.error();
}

/** Where a heavy operation is: waiting in the work executor's queue, running, or completed. */
enum class heavy_phase : std::uint8_t {
    /** Posted to the work executor, not started. */
    queued,
    /** Running on a thread of the work executor. */
    running,
    /** Completed, or abandoned by a work executor that destroyed it unrun. */
    finished,
};

/**
 * The value a heavy operation's state carries from its work to its completion: engaged by the
 * work on success, destroyed (a `secret<N>` or a key pair wipes itself) when a cancellation
 * aborts the completion.
 *
 * @tparam T The value; `void` for an operation without one.
 */
template <class T>
struct heavy_value {
    /** The work's value, until the completion takes it. */
    std::optional<T> value;
};

/** An operation without a value carries nothing. */
template <>
struct heavy_value<void> {};

/**
 * The allocator of a heavy operation's job: the work executor's own, where the executor
 * answers the query (a `thread_pool`'s), else `std::allocator<void>`, which Asio's posting
 * recycles. Never the handler's: the job may wait in the work executor's queue after the
 * handler has run.
 *
 * @tparam WorkExecutor The work executor.
 */
template <class WorkExecutor, bool = webcpp::asio::can_query_v<
                                  WorkExecutor const&, webcpp::asio::execution::allocator_t<void>>>
struct heavy_job_allocator_of {
    /** An executor that does not answer the query: Asio's recycling `std::allocator<void>`. */
    using type = std::allocator<void>;
};

/**
 * The allocator of a work executor that answers the query, named only then.
 *
 * @tparam WorkExecutor The work executor.
 */
template <class WorkExecutor>
struct heavy_job_allocator_of<WorkExecutor, true> {
    /** The executor's own allocator. */
    using type =
        std::decay_t<webcpp::asio::query_result_t<WorkExecutor const&,
                                                  webcpp::asio::execution::allocator_t<void>>>;
};

/**
 * The allocator of a heavy operation's job, as @ref heavy_job_allocator_of chooses it.
 *
 * @tparam WorkExecutor The work executor.
 */
template <class WorkExecutor>
using heavy_job_allocator_t = heavy_job_allocator_of<WorkExecutor>::type;

/**
 * The work executor's allocator, for its job.
 *
 * @param work The work executor.
 * @return Its allocator, or `std::allocator<void>`.
 */
template <class WorkExecutor>
heavy_job_allocator_t<WorkExecutor> heavy_job_allocator(WorkExecutor const& work) noexcept {
    if constexpr (webcpp::asio::can_query_v<WorkExecutor const&,
                                            webcpp::asio::execution::allocator_t<void>>) {
        return webcpp::asio::query(work, webcpp::asio::execution::allocator);
    } else {
        return std::allocator<void>{};
    }
}

/**
 * A heavy operation (design D23), in storage of the handler's associated allocator, as every
 * Asio operation's is; webcpp::hash's `heavy_state`, carrying the work's value.
 *
 * Whoever moves the phase from `queued` produces the completion, exactly once: the job, which
 * runs the synchronous call on the work executor's thread; or a cancellation before the work
 * starts, on the handler's executor, which completes with `operation_aborted` at once, the
 * value empty (every type is honoured then: nothing has happened yet). Once the work runs, only
 * `terminal` and `partial` are (no C library here can be interrupted: the work ends, then its
 * value is destroyed, which wipes a `secret<N>` or a key pair, and the completion is
 * `operation_aborted` with the empty value, a side effect that `total` does not allow).
 *
 * The completion runs on the handler's associated executor (`work` by default), where the
 * slot's signal is emitted: it clears the cancellation slot, moves the handler and the value
 * out, destroys the state and gives its storage back to the handler's allocator, and only then
 * calls the handler, so that nothing of that allocator outlives the call (Asio's rule). The job
 * queued in the work executor holds the state through one atomic pointer, whose location the
 * state records under a lock each time the job moves; a cancellation before the work starts
 * takes the state back from that location, so that the job, which may wait behind other work
 * for long, holds nothing of the handler's when the handler runs. The handler's executor has
 * outstanding work until the completion, so that the caller's event loop does not return early.
 *
 * @tparam Handler The completion handler.
 * @tparam WorkExecutor The work executor.
 * @tparam Work The synchronous call, bound to its arguments.
 */
template <class Handler, class WorkExecutor, class Work>
class heavy_state {
public:
    /** The handler's associated executor, `work` by default. */
    using executor_type = webcpp::asio::associated_executor_t<Handler, WorkExecutor>;
    /** The handler's associated allocator, rebound to the state. */
    using allocator_type = std::allocator_traits<
        webcpp::asio::associated_allocator_t<Handler>>::template rebind_alloc<heavy_state>;
    /** The work's value, `void` for an operation without one. */
    using value_type = completion_of<std::invoke_result_t<Work&>>::value_type;

    /** Not copyable: the job and the slot reach one state. */
    heavy_state(heavy_state const&) = delete;
    /** Not movable: the job and the slot hold its address. */
    heavy_state(heavy_state&&) = delete;
    /** Not copyable: the job and the slot reach one state. */
    heavy_state& operator=(heavy_state const&) = delete;
    /** Not movable: the job and the slot hold its address. */
    heavy_state& operator=(heavy_state&&) = delete;
    /** Destroys the handler, the value and the work's guard; the storage is freed by its owner. */
    ~heavy_state() = default;

    /**
     * A new state, in storage of the handler's associated allocator.
     *
     * @param handler The completion handler.
     * @param work The work executor.
     * @param run The synchronous call, bound to its arguments.
     * @return The state.
     */
    static heavy_state* make(Handler handler, WorkExecutor const& work, Work run) {
        allocator_type allocator(webcpp::asio::get_associated_allocator(handler));
        auto* const storage = std::allocator_traits<allocator_type>::allocate(allocator, 1);
        try_construct(allocator, storage, std::move(handler), work, std::move(run));
        return storage;
    }

    /** Installs the cancellation handler, when the handler's slot is connected. */
    void install_cancellation() {
        // NOLINTNEXTLINE(bugprone-unchecked-optional-access): engaged until the completion
        auto slot = webcpp::asio::get_associated_cancellation_slot(*handler_);
        if (slot.is_connected()) {
            slot.template emplace<cancellation>(this);
        }
    }

    /**
     * Records where the job holds the state, or that it holds it no longer (null).
     *
     * @param location The job's atomic pointer.
     */
    void relocate(std::atomic<heavy_state*>* location) noexcept {
        lock();
        location_ = location;
        unlock();
    }

    /** The job's turn on the work executor's thread, the state taken out of the job. */
    void run_work() {
        relocate(nullptr);
        auto expected = heavy_phase::queued;
        if (!phase_.compare_exchange_strong(expected, heavy_phase::running,
                                            std::memory_order_acq_rel)) {
            // A cancellation won, and found the job holding the state no more: complete for it.
            complete_on_handler(webcpp::asio::error::operation_aborted);
            return;
        }
        auto done = run_();
        auto code = code_of(done);
        if constexpr (has_value) {
            if (done) {
                value_.value.emplace(std::move(*done));
            }
        }
        if (cancelled_.load(std::memory_order_acquire)) {
            if constexpr (has_value) {
                value_.value.reset();
            }
            code = webcpp::asio::error::operation_aborted;
        }
        phase_.store(heavy_phase::finished, std::memory_order_release);
        complete_on_handler(code);
    }

    /** The job destroyed unrun (its executor shut down): the handler is destroyed, never called. */
    void abandon() {
        relocate(nullptr);
        auto expected = heavy_phase::queued;
        if (!phase_.compare_exchange_strong(expected, heavy_phase::finished,
                                            std::memory_order_acq_rel)) {
            complete_on_handler(webcpp::asio::error::operation_aborted);
            return;
        }
        auto const executor = handler_work_.get_executor();
        webcpp::asio::post(executor, bound_completion({}, false));
    }

    /**
     * A cancellation of type `type`, on the handler's executor, where the signal is emitted.
     *
     * @param type The cancellation's type.
     */
    void cancel(webcpp::asio::cancellation_type_t type) {
        auto expected = heavy_phase::queued;
        if (phase_.compare_exchange_strong(expected, heavy_phase::finished,
                                           std::memory_order_acq_rel)) {
            // Take the state back from the queued job; a job that has just taken it out itself
            // completes for this cancellation instead.
            bool taken = false;
            lock();
            if (location_ != nullptr) {
                taken = location_->exchange(nullptr, std::memory_order_acq_rel) != nullptr;
                location_ = nullptr;
            }
            unlock();
            if (taken) {
                auto const executor = handler_work_.get_executor();
                webcpp::asio::post(executor,
                                   bound_completion(webcpp::asio::error::operation_aborted));
            }
            return;
        }
        using webcpp::asio::cancellation_type;
        if ((type & (cancellation_type::terminal | cancellation_type::partial)) !=
            cancellation_type::none) {
            cancelled_.store(true, std::memory_order_release);
        }
    }

private:
    static constexpr bool has_value = !std::is_void_v<value_type>;

    // The handler installed in the cancellation slot; the completion clears the slot before the
    // state is destroyed.
    class cancellation {
    public:
        explicit cancellation(heavy_state* state) noexcept : state_(state) {}

        void operator()(webcpp::asio::cancellation_type_t type) { state_->cancel(type); }

    private:
        heavy_state* state_;
    };

    // The completion, on the handler's executor, its storage the handler's allocator's. It owns
    // the state: run, it frees the state and calls the handler (`invoke`), or, for a job
    // destroyed unrun, only frees it, the handler with it; destroyed without running (its
    // executor shut down or destroyed with it queued, as Asio destroys a queued operation), it
    // frees the state and the handler too, never calling it, so that nothing of the handler's
    // allocator is left and a handler that owns a promise breaks it.
    class completion {
    public:
        completion(heavy_state* state, boost::system::error_code code, bool invoke) noexcept
            : state_(state), code_(code), invoke_(invoke) {}

        completion(completion&& other) noexcept
            : state_(std::exchange(other.state_, nullptr)),
              code_(other.code_),
              invoke_(other.invoke_) {}

        completion(completion const&) = delete;
        completion& operator=(completion const&) = delete;
        completion& operator=(completion&&) = delete;

        ~completion() {
            if (state_ != nullptr) {
                state_->destroy();
            }
        }

        void operator()() {
            auto* const state = std::exchange(state_, nullptr);
            if (invoke_) {
                state->complete(code_);
            } else {
                state->destroy();
            }
        }

    private:
        heavy_state* state_;
        boost::system::error_code code_;
        bool invoke_;
    };

    heavy_state(Handler handler, WorkExecutor const& work, Work run)
        : handler_work_(
              webcpp::asio::make_work_guard(webcpp::asio::get_associated_executor(handler, work))),
          handler_(std::in_place, std::move(handler)),
          run_(std::move(run)) {}

    // Constructs the state in `storage`, which is given back if the construction throws.
    static void try_construct(allocator_type& allocator, heavy_state* storage, Handler handler,
                              WorkExecutor const& work, Work run) {
        struct give_back {
            allocator_type& allocator;
            heavy_state* storage;

            ~give_back() {
                if (storage != nullptr) {
                    std::allocator_traits<allocator_type>::deallocate(allocator, storage, 1);
                }
            }
        } guard{allocator, storage};

        ::new (static_cast<void*>(storage)) heavy_state(std::move(handler), work, std::move(run));
        guard.storage = nullptr;
    }

    void lock() noexcept {
        while (lock_.test_and_set(std::memory_order_acquire)) {
            std::this_thread::yield();  // lint-world: to the thread holding the lock, no clock
        }
    }

    void unlock() noexcept { lock_.clear(std::memory_order_release); }

    // The completion bound to the handler's associated allocator; `invoke` false only discards.
    auto bound_completion(boost::system::error_code code, bool invoke = true) {
        // NOLINTNEXTLINE(bugprone-unchecked-optional-access): engaged until the completion
        return webcpp::asio::bind_allocator(webcpp::asio::get_associated_allocator(*handler_),
                                            completion(this, code, invoke));
    }

    // Dispatches the completion to the handler's executor; the caller touches the state no more.
    void complete_on_handler(boost::system::error_code code) {
        auto const executor = handler_work_.get_executor();
        webcpp::asio::dispatch(executor, bound_completion(code));
    }

    // The value the completion gives: the work's, or the empty one (ruling R-A3).
    value_type take_value() noexcept {
        if (value_.value) {
            return std::move(*value_.value);
        }
        return async_access::empty<value_type>();
    }

    // Clears the slot, takes the handler, the value and the executor's work out, frees the
    // state, then calls the handler: nothing of the handler's allocator outlives the call.
    void complete(boost::system::error_code code) {
        clear_slot();
        // NOLINTNEXTLINE(bugprone-unchecked-optional-access): engaged until here
        Handler handler(std::move(*handler_));
        auto work = std::move(handler_work_);
        allocator_type allocator(webcpp::asio::get_associated_allocator(handler));
        if constexpr (has_value) {
            value_type value = take_value();
            release_storage(allocator);
            std::move(handler)(code, std::move(value));
        } else {
            release_storage(allocator);
            std::move(handler)(code);
        }
        work.reset();
    }

    // Clears the slot, then destroys the state, the handler and the value with it, and gives its
    // storage back.
    void destroy() {
        clear_slot();
        // NOLINTNEXTLINE(bugprone-unchecked-optional-access): engaged until here
        allocator_type allocator(webcpp::asio::get_associated_allocator(*handler_));
        release_storage(allocator);
    }

    // Removes the cancellation handler, on the handler's executor, before the state goes.
    void clear_slot() {
        // NOLINTNEXTLINE(bugprone-unchecked-optional-access): engaged until here
        auto slot = webcpp::asio::get_associated_cancellation_slot(*handler_);
        if (slot.is_connected()) {
            slot.clear();
        }
    }

    // Destroys the state and gives its storage back to a copy of the handler's allocator.
    void release_storage(allocator_type& allocator) {
        std::allocator_traits<allocator_type>::destroy(allocator, this);
        std::allocator_traits<allocator_type>::deallocate(allocator, this, 1);
    }

    std::atomic_flag lock_ = ATOMIC_FLAG_INIT;
    std::atomic<heavy_state*>* location_ = nullptr;
    std::atomic<heavy_phase> phase_{heavy_phase::queued};
    std::atomic<bool> cancelled_{false};
    webcpp::asio::executor_work_guard<executor_type> handler_work_;
    std::optional<Handler> handler_;
    Work run_;
    heavy_value<value_type> value_;
};

/**
 * The job a heavy operation posts to the work executor: runs its state's work, or, destroyed
 * unrun (the executor shut down), abandons it. Move-only; webcpp::hash's `heavy_job`. It holds
 * the state through one atomic pointer, whose location it records in the state at each move,
 * so that a cancellation before the work starts can take the state back: the job's own storage
 * is the work executor's (its associated allocator is the executor's, @ref heavy_job_allocator),
 * never the handler's.
 *
 * @tparam State The operation's @ref heavy_state.
 * @tparam Allocator The work executor's allocator.
 */
template <class State, class Allocator>
class heavy_job {
public:
    /** The work executor's allocator, which Asio's post reads for the job's storage. */
    using allocator_type = Allocator;

    /**
     * Holds `state`, before the state can be cancelled.
     *
     * @param state The operation's state.
     * @param allocator The work executor's allocator.
     */
    heavy_job(State* state, Allocator const& allocator) noexcept
        : allocator_(allocator), state_(state) {
        state->relocate(&state_);
    }

    /**
     * Takes `other`'s hold, and records the new location; a hold taken back by a cancellation
     * is null, and the state is then touched no more.
     *
     * @param other The job moved from.
     */
    heavy_job(heavy_job&& other) noexcept
        : allocator_(other.allocator_),
          state_(other.state_.exchange(nullptr, std::memory_order_acq_rel)) {
        if (auto* const held = state_.load(std::memory_order_relaxed); held != nullptr) {
            held->relocate(&state_);
        }
    }

    /** Not copyable: one job holds the state once. */
    heavy_job(heavy_job const&) = delete;
    /** Not copyable: one job holds the state once. */
    heavy_job& operator=(heavy_job const&) = delete;
    /** Not assignable: a job is moved into its executor once. */
    heavy_job& operator=(heavy_job&&) = delete;

    /** Abandons the state when the job never ran and still holds it. */
    // A post that fails while a work executor destroys its queue ends the program, as an
    // exception from any of Asio's destructors does.
    // NOLINTNEXTLINE(bugprone-exception-escape): see above
    ~heavy_job() {
        if (auto* const held = state_.exchange(nullptr, std::memory_order_acq_rel);
            held != nullptr) {
            held->abandon();
        }
    }

    /**
     * The work executor's allocator.
     *
     * @return The allocator.
     */
    [[nodiscard]] allocator_type get_allocator() const noexcept { return allocator_; }

    /** Runs the work on the work executor's thread, unless a cancellation took the state back. */
    void operator()() {
        if (auto* const held = state_.exchange(nullptr, std::memory_order_acq_rel);
            held != nullptr) {
            held->run_work();
        }
    }

private:
    Allocator allocator_;
    std::atomic<State*> state_;
};

/**
 * The initiation of a heavy operation (design D23), webcpp::hash's `heavy_initiation`: its
 * guards first, whose refusal is posted to the handler's associated executor with the guard's
 * error and the empty value, never waiting for the work executor (unless the handler has no
 * executor of its own: the work executor is then its executor); then the work posted to the
 * work executor. The operation's state and its completion are in storage of the handler's
 * associated allocator, all given back before the handler runs.
 */
struct heavy_initiation {
    /**
     * Checks the guards, then posts the work or the refusal.
     *
     * @param handler The completion handler.
     * @param work The work executor.
     * @param guards The guards, bound to the arguments.
     * @param run The synchronous call, bound to its arguments.
     */
    template <class Handler, class WorkExecutor, class Guards, class Work>
    void operator()(Handler&& handler, WorkExecutor const& work, Guards const& guards,
                    Work run) const {
        using value_type = completion_of<std::invoke_result_t<Work&>>::value_type;
        auto const guarded = guards();
        if (!guarded) {
            auto const executor = webcpp::asio::get_associated_executor(handler, work);
            if constexpr (std::is_void_v<value_type>) {
                webcpp::asio::post(executor, webcpp::asio::append(std::forward<Handler>(handler),
                                                                  guarded.error()));
            } else {
                webcpp::asio::post(
                    executor, webcpp::asio::append(std::forward<Handler>(handler), guarded.error(),
                                                   async_access::empty<value_type>()));
            }
            return;
        }
        using state = heavy_state<std::decay_t<Handler>, WorkExecutor, Work>;
        // The job holds the state from its making on, so that a failure to install the
        // cancellation or to post abandons it rather than leak it with the executor's work.
        auto* const made = state::make(std::forward<Handler>(handler), work, std::move(run));
        heavy_job<state, heavy_job_allocator_t<WorkExecutor>> job(made, heavy_job_allocator(work));
        made->install_cancellation();
        webcpp::asio::post(work, std::move(job));
    }
};

/**
 * Initiates a heavy operation (design D23): checks `guards()` on the caller's thread (a refusal
 * is posted to the handler's associated executor with its error and the empty value); then runs
 * `run()` on `work`, completing on the handler's associated executor with `run()`'s result split
 * into its error code and its value. Cancellation through the handler's slot as
 * @ref heavy_state states.
 *
 * @tparam CompletionToken Any completion token, of signature `completion_of<R>::type`, `R`
 * `run()`'s result.
 * @param work The work executor, a `webcpp::asio::thread_pool`'s, typically.
 * @param guards The guards, bound to the arguments: a call without arguments returning
 * `boost::system::result<void>`.
 * @param run The synchronous call, bound to its arguments: a `noexcept` call without arguments
 * returning `boost::system::result<T>` or `boost::system::result<void>`, called once.
 * @param token The completion token.
 * @return What the completion token's `async_result` gives.
 */
template <class CompletionToken, class WorkExecutor, class Guards, class Work>
auto run_on_work(WorkExecutor const& work, Guards guards, Work run, CompletionToken& token) {
    static_assert(std::is_same_v<std::invoke_result_t<Guards const&>, boost::system::result<void>>,
                  "webcpp::crypto: a heavy operation's guards return boost::system::result<void>");
    static_assert(std::is_nothrow_invocable_v<Work&>,
                  "webcpp::crypto: a heavy operation's call reports its errors as values");
    using value_type = completion_of<std::invoke_result_t<Work&>>::value_type;
    static_assert(std::is_void_v<value_type> || std::is_nothrow_move_constructible_v<value_type>,
                  "webcpp::crypto: a heavy operation's value moves without failing");
    using signature = completion_of<std::invoke_result_t<Work&>>::type;
    return webcpp::asio_backend::async_initiate<CompletionToken, signature>(
        heavy_initiation{}, token, work, std::move(guards), std::move(run));
}

#else

/**
 * Without threads, a stand-in that is never meant to compile: a variant that starts with its
 * refusal stops there first, then here, with a text that defers to that refusal; one that
 * forgets `WEBCPP_CRYPTO_DETAIL_REQUIRE_THREADS` stops here alone, rather than compile into a
 * call that never runs the work nor calls the handler.
 */
template <class CompletionToken, class WorkExecutor, class Guards, class Work>
void run_on_work(WorkExecutor const& /*work*/, Guards&& /*guards*/, Work&& /*run*/,
                 CompletionToken& /*token*/) noexcept {
    static_assert(::webcpp::crypto::detail::dependent_false<CompletionToken>,
                  "webcpp::crypto: a heavy operation's async_ variant needs a build with "
                  "threads; if no error above names the synchronous call, this variant lacks "
                  "WEBCPP_CRYPTO_DETAIL_REQUIRE_THREADS.");
}

#endif

}  // namespace webcpp::crypto::detail

#endif  // WEBCPP_CRYPTO_DETAIL_HEAVY_HPP
