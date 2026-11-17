// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Counts the C library's allocations and releases on Linux, from any caller, while the test
// says so (spec section 8.5): the program's own malloc and its kin replace glibc's in the
// whole process, OpenSSL's calls included, and forward to glibc's __libc_* functions, never
// through dlsym, which itself allocates. A free of a non-null block counts too.

#include <atomic>
#include <cerrno>
#include <cstddef>

// glibc's own entry points, which the replacements forward to.
// NOLINTBEGIN(readability-inconsistent-declaration-parameter-name,cert-dcl58-cpp)
extern "C" {
void* __libc_malloc(std::size_t);
void* __libc_calloc(std::size_t, std::size_t);
void* __libc_realloc(void*, std::size_t);
void* __libc_memalign(std::size_t, std::size_t);
void __libc_free(void*);
}

namespace {
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): the interposer's count
std::atomic<std::size_t> counted{0};
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): the interposer's switch
std::atomic<bool> counting{false};

void count() noexcept {
    if (counting.load(std::memory_order_relaxed)) {
        counted.fetch_add(1, std::memory_order_relaxed);
    }
}
}  // namespace

extern "C" {
std::size_t webcpp_test_c_allocations(void) {
    return counted.load();
}

void webcpp_test_count_c_allocations(int on) {
    counting.store(on != 0);
}

// glibc declares these with __THROW, noexcept in C++11 and later: a replacement must match.
void* malloc(std::size_t size) noexcept {
    count();
    return __libc_malloc(size);
}

void* calloc(std::size_t count_of, std::size_t size) noexcept {
    count();
    return __libc_calloc(count_of, size);
}

void* realloc(void* block, std::size_t size) noexcept {
    count();
    return __libc_realloc(block, size);
}

void free(void* block) noexcept {
    if (block != nullptr) {
        count();
    }
    __libc_free(block);
}

void* aligned_alloc(std::size_t alignment, std::size_t size) noexcept {
    count();
    return __libc_memalign(alignment, size);
}

int posix_memalign(void** block, std::size_t alignment, std::size_t size) noexcept {
    count();
    *block = __libc_memalign(alignment, size);
    return *block == nullptr ? ENOMEM : 0;
}
}
// NOLINTEND(readability-inconsistent-declaration-parameter-name,cert-dcl58-cpp)
