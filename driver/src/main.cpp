#include <ntifs.h>
#include <string.hpp>
#include <portable_executable/image.hpp>
#include "emu/emu.hpp"
#include "krnl/krnl.hpp"
#include "krnl/list.hpp"
#include "krnl/types.hpp"

[[nodiscard]] static portable_executable::image_t* get_ntoskrnl(const PDRIVER_OBJECT driver_object)
{
	const auto curr = static_cast<_KLDR_DATA_TABLE_ENTRY*>(driver_object->DriverSection);

	auto it = krnl::loaded_module_list_entry_t(
		&curr->InLoadOrderLinks
	);

	++it;

	return static_cast<portable_executable::image_t*>(it->DllBase);
}

/*[[nodiscard]] static uint8_t* resolve_rip_rel(uint8_t* const addr, const uint32_t rva_offset, const uint32_t rip_offset)
{
	uint8_t* const rip = addr + rip_offset;

	return rip + *reinterpret_cast<int32_t*>(rva_offset);
}*/

[[nodiscard]] static uint8_t* get_mm_pfn_database()
{
	const auto sig = krnl::nt->signature_scan("48 B8 ? ? ? ? ? ? ? ? 48 8B 04 D0 48 C1 E0");

	if (!sig)
	{
		return nullptr;
	}

	return *reinterpret_cast<uint8_t**>(sig + 2) - 8;
}

NTSTATUS driver_entry([[maybe_unused]] const PDRIVER_OBJECT driver_object, [[maybe_unused]] const PUNICODE_STRING registry_path)
{
	krnl::nt = get_ntoskrnl(driver_object);
	krnl::mm_pfn_database = reinterpret_cast<_MMPFN*>(get_mm_pfn_database());

	if (emu::is_emulated())
	{
		return STATUS_ABANDONED;
	}

	cstd::string message("darken anticheat");

	message = message + " loaded";

	DbgPrint("%s\n", message.c_str());

	return STATUS_SUCCESS;
}
