#pragma once
#include <ntdef.h>

class nt_status
{
public:
    using value_type = NTSTATUS;

    constexpr nt_status() noexcept
        : value_(STATUS_SUCCESS) { }

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
        return NT_SUCCESS(value_);
    }

    static constexpr nt_status success() noexcept { return STATUS_SUCCESS; }
    static constexpr nt_status abandoned() noexcept { return STATUS_ABANDONED; }
    static constexpr nt_status unsuccessful() noexcept { return STATUS_UNSUCCESSFUL; }
    static constexpr nt_status not_implemented() noexcept { return STATUS_NOT_IMPLEMENTED; }
    static constexpr nt_status invalid_parameter() noexcept { return STATUS_INVALID_PARAMETER; }
    static constexpr nt_status invalid_device_request() noexcept { return STATUS_INVALID_DEVICE_REQUEST; }
    static constexpr nt_status buffer_too_small() noexcept { return STATUS_BUFFER_TOO_SMALL; }
    static constexpr nt_status access_denied() noexcept { return STATUS_ACCESS_DENIED; }
    static constexpr nt_status insufficient_resources() noexcept { return STATUS_INSUFFICIENT_RESOURCES; }
    static constexpr nt_status info_length_mismatch() noexcept { return STATUS_INFO_LENGTH_MISMATCH; }
    static constexpr nt_status debugger_inactive() noexcept { return STATUS_DEBUGGER_INACTIVE; }

protected:
    value_type value_;
};
