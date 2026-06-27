#include "crypto.hpp"
#include "../log.hpp"

namespace
{
    BCRYPT_ALG_HANDLE algorithm_ = nullptr;
}

namespace crypto
{
    NTSTATUS init()
    {
        const auto status = BCryptOpenAlgorithmProvider(
            &algorithm_,
            BCRYPT_SHA256_ALGORITHM,
            nullptr,
            0
        );

        if (!NT_SUCCESS(status))
        {
            DBG_LOG("BCryptOpenAlgorithmProvider failed: 0x%x\n", status);
        }

        return status;
    }

    void cleanup()
    {
        if (algorithm_)
        {
            BCryptCloseAlgorithmProvider(algorithm_, 0);
            algorithm_ = nullptr;
        }
    }

    cstd::expected<sha256_hash_t, NTSTATUS> sha256(cstd::span<const uint8_t> data)
    {
        const cstd::span<const cstd::span<const uint8_t>> single(&data, 1);
        return sha256(single);
    }

    cstd::expected<sha256_hash_t, NTSTATUS> sha256(
        cstd::span<const cstd::span<const uint8_t>> chunks)
    {
        BCRYPT_HASH_HANDLE hash_handle = nullptr;

        auto status = BCryptCreateHash(algorithm_, &hash_handle, nullptr, 0, nullptr, 0, 0);

        if (!NT_SUCCESS(status))
        {
            return cstd::unexpected(status);
        }

        for (const auto& chunk : chunks)
        {
            status = BCryptHashData(
                hash_handle,
                const_cast<uint8_t*>(chunk.data()),
                static_cast<ULONG>(chunk.size()),
                0
            );

            if (!NT_SUCCESS(status))
            {
                BCryptDestroyHash(hash_handle);
                return cstd::unexpected(status);
            }
        }

        sha256_hash_t result{};

        status = BCryptFinishHash(hash_handle, result.data(), sha256_size, 0);
        BCryptDestroyHash(hash_handle);

        if (!NT_SUCCESS(status))
        {
            return cstd::unexpected(status);
        }

        return result;
    }
}
