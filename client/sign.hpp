#pragma once
#include <cstdint>
#include <string>
#include <variant>
#include <vector>

namespace sign
{
    struct embedded_data
    {
        std::vector<std::uint8_t> pkcs7;
        std::vector<std::uint8_t> authenticode_hash;
    };

    struct catalog_data
    {
        std::vector<std::uint8_t> authenticode_hash;
        std::vector<std::uint8_t> catalog_pkcs7;
    };

    using extraction_result = std::variant<std::monostate, embedded_data, catalog_data>;

    extraction_result extract(const std::string& nt_path);
}
