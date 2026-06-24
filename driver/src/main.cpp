#include <ntifs.h>
#include "string.hpp"

NTSTATUS driver_entry([[maybe_unused]] const PDRIVER_OBJECT driver_object, [[maybe_unused]] const PUNICODE_STRING registry_path)
{
	cstd::string message("darken anticheat");

	message = message + " loaded";

	DbgPrint("%s\n", message.c_str());

	return STATUS_SUCCESS;
}
