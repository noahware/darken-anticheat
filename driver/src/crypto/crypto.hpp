#pragma once
#include <ntifs.h>
#include <bcrypt.h>
#include <array.hpp>
#include <span.hpp>
#include <expected.hpp>

namespace crypto
{
    constexpr uint32_t sha256_size = 32;
    using sha256_hash_t = cstd::array<uint8_t, sha256_size>;

    NTSTATUS init();
    void cleanup();

    [[nodiscard]] cstd::expected<sha256_hash_t, NTSTATUS> sha256(cstd::span<const uint8_t> data);
    [[nodiscard]] cstd::expected<sha256_hash_t, NTSTATUS> sha256(
        cstd::span<const cstd::span<const uint8_t>> chunks);
}
