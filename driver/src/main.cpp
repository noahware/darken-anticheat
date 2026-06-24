#include <ntifs.h>
#include <string.hpp>
#include "emu/emu.hpp"
#include "krnl/list.hpp"
#include "krnl/types.hpp"

uint8_t* get_ntoskrnl_base_addr(const PDRIVER_OBJECT driver_object)
{
	const auto curr = static_cast<_KLDR_DATA_TABLE_ENTRY*>(driver_object->DriverSection);

	auto it = krnl::loaded_module_list_entry_t(
		&curr->InLoadOrderLinks
	);

	++it;

	return static_cast<uint8_t*>(it->DllBase);
}

NTSTATUS driver_entry([[maybe_unused]] const PDRIVER_OBJECT driver_object, [[maybe_unused]] const PUNICODE_STRING registry_path)
{
	if (emu::is_emulated())
	{
		return STATUS_ABANDONED;
	}

	cstd::string message("darken anticheat");

	message = message + " loaded";

	DbgPrint("%s\n", message.c_str());

	return STATUS_SUCCESS;
}
