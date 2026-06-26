#pragma once
#include <ntddk.h>

namespace ioctl
{
	NTSTATUS dispatch(PDEVICE_OBJECT device, PIRP irp);
}
