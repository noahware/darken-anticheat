#include "sign.hpp"
#include "log.hpp"

#include <Windows.h>
#include <Softpub.h>
#include <mscat.h>

#pragma comment(lib, "wintrust.lib")

#include <portable_executable/dos_header.hpp>
#include <portable_executable/data_directory.hpp>

#include <fstream>
#include <cstdint>

namespace
{
    constexpr std::size_t win_certificate_header_size = 8;

    std::string resolve_nt_path(const std::string& nt_path)
    {
        if (nt_path.starts_with("\\SystemRoot\\"))
        {
            char win_dir[MAX_PATH]{};
            GetWindowsDirectoryA(win_dir, MAX_PATH);
            return std::string(win_dir) + nt_path.substr(11);
        }

        if (nt_path.starts_with("\\??\\"))
        {
            return nt_path.substr(4);
        }

        return nt_path;
    }

    std::vector<std::uint8_t> read_file(const std::string& path)
    {
        std::ifstream file(path, std::ios::binary | std::ios::ate);
        if (!file)
        {
            return {};
        }

        const auto size = file.tellg();
        if (size <= 0)
        {
            return {};
        }

        std::vector<std::uint8_t> data(static_cast<std::size_t>(size));
        file.seekg(0);
        file.read(reinterpret_cast<char*>(data.data()), size);

        return data;
    }

    std::optional<sign::embedded_data> extract_embedded(const std::vector<std::uint8_t>& file_data)
    {
        if (file_data.size() < sizeof(portable_executable::dos_header_t))
        {
            return std::nullopt;
        }

        const auto* dos = reinterpret_cast<const portable_executable::dos_header_t*>(file_data.data());

        if (!dos->valid())
        {
            return std::nullopt;
        }

        if (static_cast<std::size_t>(dos->e_lfanew) + sizeof(portable_executable::nt_headers_t) > file_data.size())
        {
            return std::nullopt;
        }

        const auto* nt = dos->nt_headers();

        if (!nt->valid())
        {
            return std::nullopt;
        }

        const auto& security_dir = nt->optional_header.data_directories.security_directory;

        if (!security_dir.present())
        {
            return std::nullopt;
        }

        const auto cert_va = security_dir.virtual_address;
        const auto cert_size = security_dir.size;

        if (cert_size <= win_certificate_header_size ||
            static_cast<std::size_t>(cert_va) + cert_size > file_data.size())
        {
            return std::nullopt;
        }

        const auto pkcs7_offset = cert_va + win_certificate_header_size;
        const auto pkcs7_size = cert_size - win_certificate_header_size;

        return sign::embedded_data{
            std::vector<std::uint8_t>(
                file_data.begin() + pkcs7_offset,
                file_data.begin() + pkcs7_offset + pkcs7_size
            )
        };
    }

    std::optional<sign::catalog_data> find_matching_catalog(const std::string& file_path)
    {
        auto* file_handle = CreateFileA(
            file_path.c_str(), GENERIC_READ, FILE_SHARE_READ,
            nullptr, OPEN_EXISTING, 0, nullptr);

        if (file_handle == INVALID_HANDLE_VALUE)
        {
            return std::nullopt;
        }

        HCATADMIN admin = nullptr;

        if (!CryptCATAdminAcquireContext2(&admin, nullptr,
                BCRYPT_SHA256_ALGORITHM, nullptr, 0))
        {
            if (!CryptCATAdminAcquireContext(&admin, nullptr, 0))
            {
                CloseHandle(file_handle);
                return std::nullopt;
            }
        }

        DWORD hash_size = 0;
        CryptCATAdminCalcHashFromFileHandle2(admin, file_handle, &hash_size, nullptr, 0);

        std::vector<BYTE> cat_hash(hash_size);
        if (!CryptCATAdminCalcHashFromFileHandle2(
                admin, file_handle, &hash_size, cat_hash.data(), 0))
        {
            CryptCATAdminCalcHashFromFileHandle(file_handle, &hash_size, nullptr, 0);
            cat_hash.resize(hash_size);
            if (!CryptCATAdminCalcHashFromFileHandle(
                    file_handle, &hash_size, cat_hash.data(), 0))
            {
                CloseHandle(file_handle);
                CryptCATAdminReleaseContext(admin, 0);
                return std::nullopt;
            }
        }

        CloseHandle(file_handle);

        auto* cat_info = CryptCATAdminEnumCatalogFromHash(
            admin, cat_hash.data(), hash_size, 0, nullptr);

        if (!cat_info)
        {
            CryptCATAdminReleaseContext(admin, 0);
            return std::nullopt;
        }

        CATALOG_INFO ci{};
        ci.cbStruct = sizeof(ci);

        std::optional<sign::catalog_data> result;

        if (CryptCATCatalogInfoFromContext(cat_info, &ci, 0))
        {
            char cat_path[MAX_PATH]{};
            WideCharToMultiByte(CP_ACP, 0, ci.wszCatalogFile, -1,
                cat_path, MAX_PATH, nullptr, nullptr);

            auto cat_bytes = read_file(cat_path);
            if (!cat_bytes.empty())
            {
                result = sign::catalog_data{
                    std::vector<std::uint8_t>(cat_hash.begin(), cat_hash.end()),
                    std::move(cat_bytes)
                };
            }
        }

        CryptCATAdminReleaseCatalogContext(admin, cat_info, 0);
        CryptCATAdminReleaseContext(admin, 0);

        return result;
    }
}

namespace sign
{
    extraction_result extract(const std::string& nt_path)
    {
        const auto resolved = resolve_nt_path(nt_path);
        const auto file_data = read_file(resolved);

        if (file_data.empty())
        {
            LOG_WARN("could not read file: {}", resolved);
            return std::monostate{};
        }

        auto catalog = find_matching_catalog(resolved);
        if (catalog)
        {
            return std::move(*catalog);
        }

        auto embedded = extract_embedded(file_data);
        if (embedded)
        {
            return std::move(*embedded);
        }

        return std::monostate{};
    }
}
