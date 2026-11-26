// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Gives the secp256k1 key pair its one allocation from a fixed buffer owned by the program, and
// counts it. With a null upstream nothing else can allocate, so a program with strict memory
// limits knows exactly what the library needs and that it never reaches for the heap.
// tag::program[]
#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/signing.hpp>
#include <webcpp/secure/erase_secret.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <memory_resource>

namespace crypto = webcpp::crypto;
namespace secure = webcpp::secure;
namespace secp256k1 = webcpp::crypto::curves::secp256k1;

namespace {

// tag::counting[]
// Counts allocations and forwards them to the arena.
class counting_resource : public std::pmr::memory_resource {
public:
    explicit counting_resource(std::pmr::memory_resource* upstream) : upstream_(upstream) {}

    [[nodiscard]] std::size_t allocations() const { return count_; }

private:
    void* do_allocate(std::size_t bytes, std::size_t alignment) override {
        ++count_;
        return upstream_->allocate(bytes, alignment);
    }

    void do_deallocate(void* pointer, std::size_t bytes, std::size_t alignment) override {
        upstream_->deallocate(pointer, bytes, alignment);
    }

    [[nodiscard]] bool do_is_equal(std::pmr::memory_resource const& other) const noexcept override {
        return this == &other;
    }

    std::pmr::memory_resource* upstream_;
    std::size_t count_ = 0;
};

// end::counting[]

}  // namespace

int main() {
    // tag::arena[]
    // The buffer is the only memory there is: the upstream refuses everything else.
    std::array<std::byte, 8192> storage{};
    std::pmr::monotonic_buffer_resource arena(storage.data(), storage.size(),
                                              std::pmr::null_memory_resource());
    counting_resource counting(&arena);

    // A demonstration secret, so that the output is the same on every run; a real one is drawn
    // from random_device.
    std::array<std::uint8_t, 32> secret{};
    secret.fill(0x42);
    auto key = secp256k1::keypair::from_secret(secret, &counting);
    secure::erase_secret(secret);
    if (!key) {
        return 1;
    }
    std::array<std::uint8_t, 32> message{};
    message.fill(0x17);
    std::array<std::uint8_t, 32> const aux{};
    auto const public_key = key->public_key();
    auto const signature = key->sign(crypto::schnorr, message, aux);
    if (!public_key || !signature ||
        !crypto::verify(crypto::schnorr, *signature, message, *public_key)) {
        return 1;
    }
    std::printf("allocations in the arena: %zu\n", counting.allocations());
    // end::arena[]
    std::printf("signed and verified\n");
    return 0;
}

// end::program[]
