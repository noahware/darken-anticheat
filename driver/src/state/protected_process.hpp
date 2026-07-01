#pragma once
#include <types.hpp>
#include <list.hpp>
#include <algorithm.hpp>
#include <mutex.hpp>

class protected_process
{
public:
    using id_type = uint64_t;

    constexpr protected_process() noexcept = default;

    explicit constexpr protected_process(const id_type id) noexcept
        : id_(id) { }

    [[nodiscard]] constexpr id_type id() const noexcept
    {
        return id_;
    }

    [[nodiscard]] constexpr bool operator==(const protected_process& other) const noexcept
    {
        return id_ == other.id_;
    }

    [[nodiscard]] constexpr bool operator!=(const protected_process& other) const noexcept
    {
        return id_ != other.id_;
    }

    static void add(const id_type id)
    {
        cstd::lock_guard<cstd::mutex> guard(mutex_);
        list_.push_back(protected_process(id));
    }

    [[nodiscard]] static const cstd::single_linked_list<protected_process>& all() noexcept
    {
        return list_;
    }

    [[nodiscard]] static bool is_protected(const id_type id)
    {
        return find(id) != nullptr;
    }

    [[nodiscard]] static protected_process* find(const id_type id)
    {
        cstd::lock_guard<cstd::mutex> guard(mutex_);
        const protected_process target(id);
        auto it = cstd::find(list_, target);

        if (it == list_.end())
        {
            return nullptr;
        }

        return &(*it);
    }

    template <typename Fn>
    static void for_each(Fn&& fn)
    {
        cstd::lock_guard<cstd::mutex> guard(mutex_);
        for (auto& proc : list_)
        {
            fn(proc);
        }
    }

protected:
    id_type id_ = 0;
    static inline cstd::single_linked_list<protected_process> list_;
    static inline cstd::mutex mutex_;
};
