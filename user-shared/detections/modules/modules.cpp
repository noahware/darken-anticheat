#include "modules.h"
#include <driver/driver.h>
#include <utilities/pe/pe.h>
#include <utilities/system/system.h>
#include <utilities/datatype/datatype.h>

#include <Windows.h>
#include <winternl.h>

#include <filesystem>
#include <vector>

namespace detections
{
	namespace modules
	{
		namespace local_process
		{
			std::vector<std::wstring> modules_checked_already = { };
		}

		namespace kernel
		{
			std::vector<std::string> modules_checked_already = { };
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

		std::wstring module_path = std::wstring(module_entry->FullDllName.Buffer, module_entry->FullDllName.Length / 2);

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

communication::e_detection_status detections::modules::kernel::is_unsigned_module_present()
{
	std::vector<std::string> loaded_kernel_modules = utilities::system::query_loaded_kernel_modules();

	if (loaded_kernel_modules.empty() == true)
	{
		return communication::e_detection_status::runtime_error;
	}

	for (std::string& module_path : loaded_kernel_modules)
	{
		if (std::find(modules_checked_already.begin(), modules_checked_already.end(), module_path) != modules_checked_already.end())
		{
			continue;
		}

		// todo: exclude the anticheat driver

		// check if it exists due to dump drivers sometimes not being on disk
		// todo: find a better way to identify dump drivers
		if (std::filesystem::exists(module_path) == true && utilities::pe::is_digitally_signed(utilities::datatype::ascii_string::to_unicode(module_path)) == false)
		{
			return communication::e_detection_status::flagged;
		}

		modules_checked_already.push_back(module_path);
	}


	return communication::e_detection_status::clean;
}

communication::e_detection_status detections::modules::kernel::validate_ntoskrnl_integrity()
{
	return driver::send_call(communication::e_control_code::validate_ntoskrnl_integrity, { }).detection_status;
}

communication::e_detection_status detections::modules::kernel::validate_kernel_drivers_integrity()
{
	return driver::send_call(communication::e_control_code::validate_kernel_drivers_integrity, { }).detection_status;
}
