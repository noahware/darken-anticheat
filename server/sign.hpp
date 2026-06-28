#pragma once
#include <cstdint>
#include <span>

namespace sign
{
    bool verify_embedded(std::span<const std::uint8_t> pkcs7_der);

    bool verify_catalog(std::span<const std::uint8_t> catalog_pkcs7,
                        std::span<const std::uint8_t> authenticode_hash);
}
