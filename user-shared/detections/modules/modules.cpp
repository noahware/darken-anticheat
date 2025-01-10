#include "modules.h"
#include <utilities/pe/pe.h>

#include <Windows.h>
#include <winternl.h>

#include <vector>

namespace detections
{
	namespace modules
	{
		namespace local_process
		{
			std::vector<std::wstring_view> modules_checked_already = { };
		}
	}
}

// todo: check for 'expected' modules to see if list has been tampered with
communication::e_detection_status detections::modules::local_process::is_unsigned_module_present()
{
	PPEB process_peb = reinterpret_cast<PPEB>(__readgsqword(0x60));

	LIST_ENTRY peb_ldr_data = process_peb->Ldr->InMemoryOrderModuleList;

	// start AFTER the first entry (the process executable itself) as it may not be signed.
	// if you get a certificate going for the protected process / user process feel free to monitor the process executable too
	for (PLIST_ENTRY current_module = peb_ldr_data.Flink->Flink; current_module->Blink != peb_ldr_data.Blink; current_module = current_module->Flink)
	{
		PLDR_DATA_TABLE_ENTRY module_entry = CONTAINING_RECORD(current_module, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

		std::wstring_view module_path = std::wstring_view(module_entry->FullDllName.Buffer);

		if (std::find(modules_checked_already.begin(), modules_checked_already.end(), module_path) != modules_checked_already.end())
		{
			continue;
		}

		if (utilities::pe::is_digitally_signed(module_path) == false)
		{
			return communication::e_detection_status::flagged;
		}

		modules_checked_already.push_back(module_path);
	}

	return communication::e_detection_status::clean;
}
