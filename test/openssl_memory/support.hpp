// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// What every program of the memory option shares: a counting resource that is never
// destroyed (spec section 3.7), on a fixed buffer through a synchronized pool whose
// upstream is null_memory_resource(), so that the resource itself never calls the C
// library; its table of the blocks it gave, which finds a free of another's block; and the
// exit check: main returns 3, and when OpenSSL's cleanup has given every block back after
// main, the resource writes its line and ends the process with 0. Its destructor, which
// must never run, writes a line and ends it with 4 (C7); a table with no free slot left
// writes a line and ends it with 6; an armed failure without exceptions writes a line and
// ends it with 7, since a resource never returns null (doc/memory.adoc). The C library's
// counter is the interposer's (interpose_*.cpp, picked by the Jamfile per target-os).
// Beside them: OpenSSL's error queue drained and an entry of the test's raised in it, and
// another party's memory functions, which a test installs as a library other than webcpp would.
// Each program includes this header once: it defines openssl_memory_resource().

#ifndef WEBCPP_TEST_CRYPTO_OPENSSL_MEMORY_SUPPORT_HPP
#define WEBCPP_TEST_CRYPTO_OPENSSL_MEMORY_SUPPORT_HPP

#include <webcpp/crypto/backends/openssl.hpp>

#include <boost/throw_exception.hpp>

#include <openssl/crypto.h>
#include <openssl/err.h>

#include <array>
#include <atomic>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <memory_resource>
#include <mutex>
#include <new>
#include <string_view>

#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

/** The C library's allocations and non-null releases counted while counting is on. */
extern "C" std::size_t webcpp_test_c_allocations(void);
/** Turns the counting of the C library's allocations on (non-zero) or off (0). */
extern "C" void webcpp_test_count_c_allocations(int on);

namespace webcpp::test {

/**
 * Writes text to standard output unbuffered: after main the C library's streams may be gone
 * (spec section 8.5).
 */
inline void write_out(std::string_view text) noexcept {
#ifdef _WIN32
    static_cast<void>(_write(1, text.data(), static_cast<unsigned>(text.size())));
#else
    static_cast<void>(::write(1, text.data(), text.size()));
#endif
}

/** Says, on a target where the interposer counts nothing, that the C library is not counted. */
inline void say_whether_c_is_counted() noexcept {
#ifdef _WIN32
    write_out("the C library's allocator is not counted on Windows\n");
#endif
}

/**
 * The memory option's resource for the tests: counts the blocks it gives and keeps a table of
 * them, so that a free of a block it did not give is found; fails on demand (`arm`); and, once
 * `main_returned()` was called, ends the process with 0 when the last block comes back. It never
 * calls the C library: its blocks come from a fixed buffer in the object itself.
 */
class counting_resource final : public std::pmr::memory_resource {
public:
    /** An empty resource over its own buffer; made once, by `the_counting_resource()`. */
    counting_resource() : pool_(&monotonic_) {}

    counting_resource(counting_resource const&) = delete;
    counting_resource& operator=(counting_resource const&) = delete;
    counting_resource(counting_resource&&) = delete;
    counting_resource& operator=(counting_resource&&) = delete;

    /**
     * Never runs: the resource lives in static storage and is never destroyed. If it ran, it
     * writes its line and ends the process with 4, which fails the test.
     */
    ~counting_resource() override {
        write_out("the resource was destroyed\n");
        end(4);
    }

    /**
     * Ends the process with status, now. OpenSSL is linked static (R5): its cleanup runs from
     * the program's own exit handlers, never under a DLL's loader lock.
     */
    [[noreturn]] static void end(int status) noexcept { std::_Exit(status); }

    /** The blocks given so far. */
    std::size_t allocations() const { return allocations_.load(); }

    /** The blocks given and not yet given back. */
    std::size_t live() const { return live_.load(); }

    /** Whether a block the resource did not give was given back to it. */
    bool foreign_free() const { return foreign_.load(); }

    /**
     * Makes an allocation fail, as a resource fails: by throwing `std::bad_alloc`; without
     * exceptions, by ending the process with 7, since `allocate` is declared never to return
     * null and a null would be written through in a release build. The failing tests therefore
     * run with exceptions only.
     *
     * @param after The allocations that still succeed before the one that fails.
     */
    void arm(std::size_t after) { fail_after_.store(after + 1); }

    /**
     * Says that main is returning: from now on, the last block given back ends the process with
     * 0 (the exit check), or with 5 after a foreign free.
     */
    void main_returned() noexcept { main_returned_.store(true); }

private:
    // An open-addressing table of the blocks given (linear probing): one slot always stays
    // free, so that a search for a block not in it ends. 65,536 slots: the most blocks live at
    // once in everything_test on OpenSSL 3.5.9 is 4,452 (measured on macOS, 2026-11-17).
    static constexpr std::size_t slots = std::size_t{1} << 16U;
    static_assert(std::has_single_bit(slots), "the table's index is the hash's top bits");
    // The hash's top bits that index the table.
    static constexpr unsigned shift = 64U - static_cast<unsigned>(std::bit_width(slots - 1));

    static std::size_t home(void const* block) noexcept {
        auto const bits = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(block));
        return static_cast<std::size_t>(((bits >> 4U) * 0x9E3779B97F4A7C15ULL) >> shift);
    }

    static std::size_t next(std::size_t slot) noexcept { return (slot + 1) & (slots - 1); }

    void remember(void* block) {
        if (used_ + 1 == slots) {
            write_out("the resource's table is full\n");
            end(6);
        }
        std::size_t slot = home(block);
        while (given_[slot] != nullptr) {
            slot = next(slot);
        }
        given_[slot] = block;
        ++used_;
    }

    // Removes block from the table, shifting back the entries after it; false if it is absent.
    bool forget(void* block) {
        std::size_t slot = home(block);
        while (given_[slot] != block) {
            if (given_[slot] == nullptr) {
                return false;
            }
            slot = next(slot);
        }
        std::size_t hole = slot;
        for (std::size_t probe = next(hole); given_[probe] != nullptr; probe = next(probe)) {
            std::size_t const wanted = home(given_[probe]);
            // The entry at probe stays unless its home is cyclically outside (hole, probe].
            bool const stays = hole <= probe ? (hole < wanted && wanted <= probe)
                                             : (hole < wanted || wanted <= probe);
            if (!stays) {
                given_[hole] = given_[probe];
                hole = probe;
            }
        }
        given_[hole] = nullptr;
        --used_;
        return true;
    }

    void* do_allocate(std::size_t size, std::size_t alignment) override {
        if (fail_after_.load() != 0 && fail_after_.fetch_sub(1) == 1) {
#ifdef WEBCPP_CRYPTO_NO_EXCEPTIONS
            write_out(
                "the resource cannot allocate, and without exceptions that ends the process\n");
            end(7);
#else
            boost::throw_exception(std::bad_alloc());
#endif
        }
        std::scoped_lock const lock(mutex_);
        void* const block = pool_.allocate(size, alignment);
        remember(block);
        ++allocations_;
        ++live_;
        return block;
    }

    void do_deallocate(void* block, std::size_t size, std::size_t alignment) override {
        {
            std::scoped_lock const lock(mutex_);
            if (!forget(block)) {
                foreign_.store(true);
                return;
            }
            pool_.deallocate(block, size, alignment);
        }
        if (--live_ == 0 && main_returned_.load()) {
            if (foreign_.load()) {
                write_out("a foreign block was freed through the adapter\n");
                end(5);
            }
            write_out("OpenSSL gave every block back after main\n");
            end(0);
        }
    }

    bool do_is_equal(memory_resource const& other) const noexcept override {
        return this == &other;
    }

    // 16 MiB. On OpenSSL 3.5.9 (measured on macOS, 2026-11-17) everything_test's first from_key
    // takes 5,027 blocks, 4,441 still live after it; the whole test asks for 5,042 blocks and
    // 388,040 bytes, at most 349,350 of them live at once. A buffer that runs out makes
    // null_memory_resource() throw std::bad_alloc. With exceptions, the adapter catches it
    // and gives OpenSSL null, so the OpenSSL call fails and so does the test's check of it.
    // Without exceptions (the program is built so, the C++ library is not) nothing catches
    // it, and std::terminate ends the process with SIGABRT.
    alignas(std::max_align_t) std::array<std::byte, std::size_t{16} << 20U> buffer_{};
    std::pmr::monotonic_buffer_resource monotonic_{buffer_.data(), buffer_.size(),
                                                   std::pmr::null_memory_resource()};
    std::pmr::synchronized_pool_resource pool_;
    std::mutex mutex_;
    std::array<void*, slots> given_{};
    std::size_t used_ = 0;
    std::atomic<std::size_t> allocations_{0};
    std::atomic<std::size_t> live_{0};
    std::atomic<std::size_t> fail_after_{0};
    std::atomic<bool> foreign_{false};
    std::atomic<bool> main_returned_{false};
};

/** The one resource, in static storage, constructed by placement and never destroyed. */
inline counting_resource& the_counting_resource() noexcept {
    alignas(counting_resource) static std::array<unsigned char, sizeof(counting_resource)> storage;
    static auto* const resource = new (storage.data()) counting_resource;
    return *resource;
}

/**
 * Empties the calling thread's OpenSSL error queue.
 *
 * @param first Set to the oldest entry's code, or 0 when the queue was empty.
 * @return The number of entries the queue held.
 */
inline std::size_t drain(unsigned long& first) {
    std::size_t count = 0;
    first = ERR_peek_error();
    while (ERR_get_error() != 0) {
        ++count;
    }
    return count;
}

/**
 * Another party's memory functions for OpenSSL: the C library's, each call counted. A test
 * installs them with `CRYPTO_set_mem_functions`, as a library other than webcpp would.
 */
struct other_party {
    /** The calls of the three functions so far. */
    static std::size_t& calls() noexcept {
        static std::size_t count = 0;
        return count;
    }

    /** `malloc`, counted. */
    static void* allocate(std::size_t size, char const* /*file*/, int /*line*/) noexcept {
        ++calls();
        return std::malloc(size);
    }

    /** `realloc`, counted. */
    static void* reallocate(void* address, std::size_t size, char const* /*file*/,
                            int /*line*/) noexcept {
        ++calls();
        return std::realloc(address, size);
    }

    /** `free`, counted. */
    static void release(void* address, char const* /*file*/, int /*line*/) noexcept {
        ++calls();
        std::free(address);
    }

    /**
     * Installs the three as OpenSSL's memory functions.
     *
     * @return `CRYPTO_set_mem_functions`'s answer: 1 when OpenSSL took them.
     */
    static int install() noexcept {
        return CRYPTO_set_mem_functions(&allocate, &reallocate, &release);
    }

    /** Whether OpenSSL's memory functions are the three. */
    static bool installed() noexcept {
        CRYPTO_malloc_fn m = nullptr;
        CRYPTO_realloc_fn r = nullptr;
        CRYPTO_free_fn f = nullptr;
        CRYPTO_get_mem_functions(&m, &r, &f);
        return m == &allocate && r == &reallocate && f == &release;
    }
};

/**
 * Raises an entry of the test's own in the thread's OpenSSL error queue.
 *
 * @return The entry's code, or 0 when OpenSSL could not raise it.
 */
inline unsigned long raise_entry() {
    // NOLINTNEXTLINE(bugprone-signed-bitwise): OpenSSL's reason macro ORs signed flags
    ERR_raise(ERR_LIB_USER, ERR_R_PASSED_INVALID_ARGUMENT);
    return ERR_peek_last_error();
}

}  // namespace webcpp::test

// The program's one definition: each program includes this header once.
// NOLINTNEXTLINE(misc-definitions-in-headers)
std::pmr::memory_resource& webcpp::crypto::openssl_memory_resource() noexcept {
    return webcpp::test::the_counting_resource();
}

#endif
