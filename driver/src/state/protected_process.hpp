#pragma once
#include <types.hpp>
#include <list.hpp>
#include <algorithm.hpp>

class protected_process_t
{
public:
    using id_type = uint64_t;

    constexpr protected_process_t() noexcept = default;

    explicit constexpr protected_process_t(const id_type id) noexcept
        : id_(id) { }

    [[nodiscard]] constexpr id_type id() const noexcept
    {
        return id_;
    }

    [[nodiscard]] constexpr bool operator==(const protected_process_t& other) const noexcept
    {
        return id_ == other.id_;
    }

    [[nodiscard]] constexpr bool operator!=(const protected_process_t& other) const noexcept
    {
        return id_ != other.id_;
    }

    static void add(const id_type id)
    {
        list_.push_back(protected_process_t(id));
    }

    [[nodiscard]] static protected_process_t* find(const id_type id)
    {
        const protected_process_t target(id);
        auto it = cstd::find(list_, target);

        if (it == list_.end())
        {
            return nullptr;
        }

        return &(*it);
    }

protected:
    id_type id_ = 0;
    static inline cstd::single_linked_list<protected_process_t> list_;
};
