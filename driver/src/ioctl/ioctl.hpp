#pragma once
#include <ntifs.h>

namespace ioctl
{
	NTSTATUS dispatch(PDEVICE_OBJECT device, PIRP irp);
}
