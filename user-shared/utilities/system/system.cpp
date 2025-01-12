#include "system.h"
#include "system_def.h"
#include <Windows.h>
#include <winternl.h>

#include <utilities/filesystem/filesystem.h>
#include <imports.h>

std::vector<std::string> utilities::system::query_loaded_kernel_modules()
{
	uint32_t information_size = 0;

	constexpr SYSTEM_INFORMATION_CLASS system_information_class = static_cast<SYSTEM_INFORMATION_CLASS>(11);

	d_import(NtQuerySystemInformation)(system_information_class, 0, 0, reinterpret_cast<ULONG*>(&information_size));

	if (information_size == 0)
	{
		return { };
	}

	std::vector<uint8_t> information_buffer(information_size);

	if (NT_SUCCESS(d_import(NtQuerySystemInformation)(system_information_class, information_buffer.data(), information_size, reinterpret_cast<ULONG*>(&information_size))) == false)
	{
		return { };
	}

	s_rtl_process_modules* system_process_modules = reinterpret_cast<s_rtl_process_modules*>(information_buffer.data());

	std::vector<std::string> loaded_modules_list = { };

	for (uint32_t i = 0; i < system_process_modules->module_count; i++)
	{
		std::string module_path = system_process_modules->modules[i].full_path_name;

		loaded_modules_list.push_back(module_path);
	}

	return loaded_modules_list;
}
