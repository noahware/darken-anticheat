#pragma once
#include <ntdef.h>
#include <cstdint>

namespace kernel
{
    template <class T, LIST_ENTRY T::* Field>
    class list_entry
    {
    public:
        using entry_type = PLIST_ENTRY;
        using size_type = uint64_t;

        using pointer = T*;
        using const_pointer = const T*;
        using reference = T&;
        using const_reference = const T&;

        list_entry() noexcept = default;

        explicit list_entry(const entry_type entry) noexcept
                :   entry_(entry) { }

        [[nodiscard]] entry_type entry() const noexcept
        {
            return entry_;
        }

        [[nodiscard]] pointer value() noexcept
        {
            return reinterpret_cast<pointer>(
                reinterpret_cast<uint8_t*>(entry_) - field_offset()
            );
        }

        [[nodiscard]] const_pointer value() const noexcept
        {
            return reinterpret_cast<const_pointer>(
                reinterpret_cast<const uint8_t*>(entry_) - field_offset()
            );
        }

        [[nodiscard]] pointer operator->() noexcept
        {
            return value();
        }

        [[nodiscard]] const_pointer operator->() const noexcept
        {
            return value();
        }

        [[nodiscard]] reference operator*() noexcept
        {
            return *value();
        }

        [[nodiscard]] const_reference operator*() const noexcept
        {
            return *value();
        }

        list_entry& operator++() noexcept
        {
            entry_ = entry_->Flink;

            return *this;
        }

        [[nodiscard]] bool operator!=(const list_entry& other) const noexcept
        {
            return entry_ != other.entry_;
        }

        [[nodiscard]] bool operator==(const list_entry& other) const noexcept
        {
            return entry_ == other.entry_;
        }

    protected:
        static constexpr size_type field_offset() noexcept
        {
            return reinterpret_cast<size_type>(&(reinterpret_cast<const T*>(0)->*Field));
        }

        entry_type entry_ = nullptr;
    };

    template <class T, LIST_ENTRY T::* Field>
    class list_range
    {
    public:
        using iterator = list_entry<T, Field>;
        using entry_type = PLIST_ENTRY;

        explicit list_range(const entry_type head) noexcept
                :   head_(head) { }

        [[nodiscard]] iterator begin() const noexcept
        {
            return iterator{ head_->Flink };
        }

        [[nodiscard]] iterator end() const noexcept
        {
            return iterator{ head_ };
        }

    protected:
        entry_type head_;
    };
}
