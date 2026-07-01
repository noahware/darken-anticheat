#pragma once
#include <ntdef.h>

class nt_status
{
public:
    using value_type = NTSTATUS;

    constexpr nt_status() noexcept
        : value_(0) { }

    constexpr nt_status(const value_type value) noexcept
        : value_(value) { }

    [[nodiscard]] constexpr value_type value() const noexcept
    {
        return value_;
    }

    constexpr operator NTSTATUS() const noexcept
    {
        return value_;
    }

    explicit constexpr operator bool() const noexcept
    {
        return value_ >= 0;
    }

    static constexpr nt_status success() noexcept { return nt_status(static_cast<value_type>(0x00000000)); }
    static constexpr nt_status abandoned() noexcept { return nt_status(static_cast<value_type>(0x00000080)); }
    static constexpr nt_status unsuccessful() noexcept { return nt_status(static_cast<value_type>(0xC0000001)); }
    static constexpr nt_status not_implemented() noexcept { return nt_status(static_cast<value_type>(0xC0000002)); }
    static constexpr nt_status invalid_parameter() noexcept { return nt_status(static_cast<value_type>(0xC000000D)); }
    static constexpr nt_status invalid_device_request() noexcept { return nt_status(static_cast<value_type>(0xC0000010)); }
    static constexpr nt_status buffer_too_small() noexcept { return nt_status(static_cast<value_type>(0xC0000023)); }
    static constexpr nt_status access_denied() noexcept { return nt_status(static_cast<value_type>(0xC0000022)); }
    static constexpr nt_status insufficient_resources() noexcept { return nt_status(static_cast<value_type>(0xC000009A)); }
    static constexpr nt_status info_length_mismatch() noexcept { return nt_status(static_cast<value_type>(0xC0000004)); }
    static constexpr nt_status debugger_inactive() noexcept { return nt_status(static_cast<value_type>(0xC0000354)); }

protected:
    value_type value_;
};
