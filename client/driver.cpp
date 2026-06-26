#include "driver.hpp"
#include "log.hpp"
#include <driver/ioctl.h>
#include <Windows.h>

namespace
{
    HANDLE device_handle = INVALID_HANDLE_VALUE;
}

namespace driver
{
    bool open()
    {
        device_handle = CreateFileW(
            DARKEN_USERMODE_PATH,
            GENERIC_READ | GENERIC_WRITE,
            0,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        );

        if (device_handle == INVALID_HANDLE_VALUE)
        {
            LOG_ERR("failed to open driver device (error: {})", GetLastError());
            return false;
        }

        LOG_INFO("driver device opened");
        return true;
    }

    bool is_open()
    {
        return device_handle != INVALID_HANDLE_VALUE;
    }

    void close()
    {
        if (device_handle != INVALID_HANDLE_VALUE)
        {
            CloseHandle(device_handle);
            device_handle = INVALID_HANDLE_VALUE;
        }
    }

    std::optional<std::vector<std::uint8_t>> run_check(const std::uint8_t check_id)
    {
        if (!is_open())
        {
            return std::nullopt;
        }

        constexpr DWORD output_buffer_size = 4096;
        std::vector<std::uint8_t> output(output_buffer_size);
        DWORD bytes_returned = 0;

        auto id = check_id;

        const BOOL success = DeviceIoControl(
            device_handle,
            IOCTL_DARKEN_FBS_REQUEST,
            &id,
            sizeof(id),
            output.data(),
            output_buffer_size,
            &bytes_returned,
            nullptr
        );

        if (!success)
        {
            LOG_ERR("DeviceIoControl failed (error: {})", GetLastError());
            return std::nullopt;
        }

        output.resize(bytes_returned);
        return output;
    }
}
