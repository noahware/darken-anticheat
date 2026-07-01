#pragma once
#include <ntifs.h>
#include <vector.hpp>
#include <string_view.hpp>
#include <portable_executable/image.hpp>
#include "../crypto/crypto.hpp"

#include "types.hpp"
#include "list.hpp"

extern "C" PLIST_ENTRY PsLoadedModuleList;

namespace krnl
{
    class module
    {
    public:
        using address_type = uint64_t;
        using size_type = uint32_t;
        using entry_type = list_entry<_KLDR_DATA_TABLE_ENTRY, &_KLDR_DATA_TABLE_ENTRY::InLoadOrderLinks>;

        explicit module(const entry_type& entry) noexcept
            : entry_(entry) { }

        [[nodiscard]] cstd::wstring_view base_name() const noexcept
        {
            const auto& name = entry_->BaseDllName;
            return { name.Buffer, name.Length / sizeof(wchar_t) };
        }

        [[nodiscard]] cstd::wstring_view full_name() const noexcept
        {
            const auto& name = entry_->FullDllName;
            return { name.Buffer, name.Length / sizeof(wchar_t) };
        }

        [[nodiscard]] address_type base_address() const noexcept
        {
            return reinterpret_cast<address_type>(entry_->DllBase);
        }

        [[nodiscard]] size_type size_of_image() const noexcept
        {
            return static_cast<size_type>(entry_->SizeOfImage);
        }

        [[nodiscard]] portable_executable::image_t* image() const noexcept
        {
            return static_cast<portable_executable::image_t*>(entry_->DllBase);
        }

        [[nodiscard]] bool operator==(const module& other) const noexcept
        {
            return entry_ == other.entry_;
        }

        [[nodiscard]] bool operator!=(const module& other) const noexcept
        {
            return entry_ != other.entry_;
        }

        module& operator++() noexcept
        {
            ++entry_;
            return *this;
        }

        module& operator*() noexcept { return *this; }
        const module& operator*() const noexcept { return *this; }

    protected:
        entry_type entry_;
    };

    class module_list
    {
    public:
        using range_type = list_range<_KLDR_DATA_TABLE_ENTRY, &_KLDR_DATA_TABLE_ENTRY::InLoadOrderLinks>;

        module_list() noexcept
            : range_(PsLoadedModuleList) { }

        [[nodiscard]] module begin() const noexcept
        {
            return module{ range_.begin() };
        }

        [[nodiscard]] module end() const noexcept
        {
            return module{ range_.end() };
        }

    protected:
        range_type range_;
    };

    [[nodiscard]] cstd::expected<crypto::sha256_hash_t, nt_status> hash_nonwritable_sections(portable_executable::image_t* image);
    [[nodiscard]] portable_executable::image_t* find_module_image(cstd::wstring_view module_name);
    [[nodiscard]] cstd::vector<uint8_t> get_module_list();
}
