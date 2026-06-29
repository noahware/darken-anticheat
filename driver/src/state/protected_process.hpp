#pragma once
#include <types.hpp>

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

protected:
    id_type id_ = 0;
};
