// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A program of crypto's that calls nothing of any backend: it draws 16 bytes with random_device
// and prints them in hex. Built with a backend named and without it, the two programs are the
// same bytes (spec sections 4.2 and 8.7).

#include <webcpp/crypto/random_device.hpp>

#include <array>
#include <cstdint>
#include <cstdio>

int main() {
    std::array<std::uint8_t, 16> bytes{};
    webcpp::crypto::random_device device;
    if (!device.fill(bytes)) {
        return 1;
    }
    for (std::uint8_t const b : bytes) {
        std::printf("%02x", static_cast<unsigned>(b));
    }
    std::printf("\n");
    return 0;
}
