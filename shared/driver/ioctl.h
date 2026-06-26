#pragma once

#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
#include <winioctl.h>
#endif

#define DARKEN_DEVICE_NAME    L"\\Device\\DarkenAC"
#define DARKEN_SYMLINK_NAME   L"\\DosDevices\\DarkenAC"
#define DARKEN_USERMODE_PATH  L"\\\\.\\DarkenAC"

#define IOCTL_DARKEN_FBS_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
