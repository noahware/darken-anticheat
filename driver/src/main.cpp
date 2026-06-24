#include <ntifs.h>

NTSTATUS driver_entry([[maybe_unused]] const PDRIVER_OBJECT driver_object, [[maybe_unused]] const PUNICODE_STRING registry_path)
{
	return STATUS_SUCCESS;
}
