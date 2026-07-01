#pragma once
#include <ntifs.h>

#include "../krnl/nt_status.hpp"

namespace ioctl
{
	NTSTATUS dispatch(PDEVICE_OBJECT device, PIRP irp);
}
