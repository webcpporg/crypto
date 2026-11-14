// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Counts every allocation of the program that includes this header once (spec section 8.5):
// every form of the global operator new, and the C library's malloc, calloc, realloc,
// aligned_alloc and posix_memalign, where a program can see them: glibc's replaced and
// forwarded to its __libc_* functions, Emscripten's replaced and forwarded to its
// emscripten_builtin_* (its dlmalloc defines them weak), macOS's through malloc_logger, the
// hook libsystem_malloc calls on every allocation. WASI's wasi-libc defines malloc and its
// __libc_malloc in one object (dlmalloc.c.obj, measured with nm), so a program cannot
// replace one and keep the other, and MSVC's C runtime has no hook: there the C library's
// allocations are not counted, and c_allocations_counted says so, which the tests print.
// A block of operator new is counted twice where the C library is counted (once by new, once
// by the malloc it calls): every test compares a count before and after a window, so this
// changes no verdict. Nothing here reads a thread_local: on macOS the first read of one on a
// thread allocates through dyld (_tlv_get_addr), inside malloc_logger, which recursed until
// the stack ended (N1, measured in the review's rr1/logger.cpp).

#ifndef WEBCPP_TEST_CRYPTO_SUPPORT_COUNTING_HPP
#define WEBCPP_TEST_CRYPTO_SUPPORT_COUNTING_HPP

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <new>

#if defined(__APPLE__)
#include <malloc/malloc.h>
#elif defined(__EMSCRIPTEN__)
#include <emscripten/heap.h>
#endif

namespace webcpp::test {

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): the replaced new's count
inline std::atomic<std::size_t> counted_new{0};
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): the C library's count
inline std::atomic<std::size_t> counted_c{0};
static_assert(std::atomic<std::size_t>::is_always_lock_free,
              "the counters are called from inside the allocator and must not allocate or lock");

/** Every allocation counted so far: operator new's and the C library's. */
inline std::size_t allocations() {
    return counted_new.load() + counted_c.load();
}

/** Whether this target counts the C library's allocations too. */
inline constexpr bool c_allocations_counted =
#if defined(__GLIBC__) || defined(__EMSCRIPTEN__) || defined(__APPLE__)
    true;
#else
    false;
#endif

inline void count_c() noexcept {
    ++counted_c;
}

inline void* new_block(std::size_t size, std::size_t alignment) {
    ++counted_new;
    void* p = nullptr;
    if (alignment <= alignof(std::max_align_t)) {
        p = std::malloc(size == 0 ? 1 : size);
    } else {
#ifdef _WIN32
        p = _aligned_malloc(size == 0 ? 1 : size, alignment);
#else
        p = std::aligned_alloc(alignment, (size + alignment - 1) / alignment * alignment);
#endif
    }
    return p;
}

}  // namespace webcpp::test

[[noreturn]] inline void webcpp_test_out_of_memory() {
#ifdef __cpp_exceptions
    throw std::bad_alloc();  // the replaced operator's contract
#else
    std::abort();
#endif
}

void* operator new(std::size_t size) {
    if (void* const p = webcpp::test::new_block(size, alignof(std::max_align_t))) {
        return p;
    }
    webcpp_test_out_of_memory();
}

void* operator new[](std::size_t size) {
    return operator new(size);
}

void* operator new(std::size_t size, std::align_val_t alignment) {
    if (void* const p = webcpp::test::new_block(size, static_cast<std::size_t>(alignment))) {
        return p;
    }
    webcpp_test_out_of_memory();
}

void* operator new[](std::size_t size, std::align_val_t alignment) {
    return operator new(size, alignment);
}

void* operator new(std::size_t size, std::nothrow_t const&) noexcept {
    return webcpp::test::new_block(size, alignof(std::max_align_t));
}

void* operator new[](std::size_t size, std::nothrow_t const&) noexcept {
    return webcpp::test::new_block(size, alignof(std::max_align_t));
}

void operator delete(void* p) noexcept {
    std::free(p);
}

void operator delete[](void* p) noexcept {
    std::free(p);
}

void operator delete(void* p, std::size_t) noexcept {
    std::free(p);
}

void operator delete[](void* p, std::size_t) noexcept {
    std::free(p);
}
#ifdef _WIN32
void operator delete(void* p, std::align_val_t) noexcept {
    _aligned_free(p);
}

void operator delete[](void* p, std::align_val_t) noexcept {
    _aligned_free(p);
}

void operator delete(void* p, std::size_t, std::align_val_t) noexcept {
    _aligned_free(p);
}

void operator delete[](void* p, std::size_t, std::align_val_t) noexcept {
    _aligned_free(p);
}
#else
void operator delete(void* p, std::align_val_t) noexcept {
    std::free(p);
}

void operator delete[](void* p, std::align_val_t) noexcept {
    std::free(p);
}

void operator delete(void* p, std::size_t, std::align_val_t) noexcept {
    std::free(p);
}

void operator delete[](void* p, std::size_t, std::align_val_t) noexcept {
    std::free(p);
}
#endif

#if defined(__GLIBC__) || defined(__EMSCRIPTEN__)
#ifdef __GLIBC__
extern "C" {
void* __libc_malloc(std::size_t);
void* __libc_calloc(std::size_t, std::size_t);
void* __libc_realloc(void*, std::size_t);
void* __libc_memalign(std::size_t, std::size_t);
void __libc_free(void*);
}
#define WEBCPP_TEST_C(name) __libc_##name
#else
#define WEBCPP_TEST_C(name) emscripten_builtin_##name
#endif
// The C library's allocation functions, replaced for this program alone; cert-dcl58-cpp takes
// a replacement of what <cstdlib> declares for a change to namespace std.
// NOLINTBEGIN(readability-inconsistent-declaration-parameter-name,cert-dcl58-cpp)
extern "C" {
void* malloc(std::size_t size) {
    webcpp::test::count_c();
    return WEBCPP_TEST_C(malloc)(size);
}

void* calloc(std::size_t count, std::size_t size) {
    webcpp::test::count_c();
    return WEBCPP_TEST_C(calloc)(count, size);
}

void* realloc(void* p, std::size_t size) {
    webcpp::test::count_c();
    return WEBCPP_TEST_C(realloc)(p, size);
}

void* aligned_alloc(std::size_t alignment, std::size_t size) {
    webcpp::test::count_c();
    return WEBCPP_TEST_C(memalign)(alignment, size);
}

int posix_memalign(void** p, std::size_t alignment, std::size_t size) {
    webcpp::test::count_c();
    *p = WEBCPP_TEST_C(memalign)(alignment, size);
    return *p == nullptr ? 12 /* ENOMEM */ : 0;
}

void free(void* p) {
    WEBCPP_TEST_C(free)(p);
}
}
// NOLINTEND(readability-inconsistent-declaration-parameter-name,cert-dcl58-cpp)
#elif defined(__APPLE__)
// libsystem_malloc's hook, called on every allocation and release of the process.
using webcpp_test_malloc_logger = void(std::uint32_t, std::uintptr_t, std::uintptr_t,
                                       std::uintptr_t, std::uintptr_t, std::uint32_t);
extern "C" webcpp_test_malloc_logger* malloc_logger;

inline void webcpp_test_count_c_allocation(std::uint32_t type, std::uintptr_t, std::uintptr_t,
                                           std::uintptr_t, std::uintptr_t, std::uint32_t) {
    constexpr std::uint32_t allocate = 2;  // MALLOC_LOG_TYPE_ALLOCATE
    if ((type & allocate) != 0) {
        webcpp::test::count_c();
    }
}

namespace webcpp::test {
/** Installs the hook once, from the first counting call. */
inline bool const logger_installed = (malloc_logger = &webcpp_test_count_c_allocation, true);
}  // namespace webcpp::test
#endif

#endif
