#include "ntkrnl.h"
#include "../context/context.h"
#include "../offsets/offsets.h"
#include "../structures/kldr_data_table_entry.h"

#include <ntifs.h>
#include <intrin.h>

#define d_lstar_msr 0xC0000082

uint64_t ntkrnl::get_eprocess(uint64_t target_process_id)
{
	context::s_context* context = context::get_decrypted();

	if (target_process_id == 4)
	{
		return context->initial_system_process;
	}

	return get_eprocess(target_process_id, context->initial_system_process);
}

uint64_t ntkrnl::get_eprocess(uint64_t target_process_id, uint64_t valid_eprocess)
{
	PLIST_ENTRY list_head = reinterpret_cast<PLIST_ENTRY>(valid_eprocess + offsets::eprocess::active_process_links);

	for (PLIST_ENTRY current_entry = list_head->Flink; current_entry != list_head; current_entry = current_entry->Flink)
	{
		uint64_t current_entry_eprocess = reinterpret_cast<uint64_t>(current_entry) - offsets::eprocess::active_process_links;
		uint64_t current_entry_process_id = get_process_id(current_entry_eprocess);

		if (current_entry_process_id == target_process_id)
		{
			return current_entry_eprocess;
		}
	}

	return 0;
}

uint64_t ntkrnl::get_process_id(uint64_t eprocess)
{
	return *reinterpret_cast<uint64_t*>(eprocess + offsets::eprocess::unique_process_id);
}

uint64_t ntkrnl::get_process_base_address(uint64_t eprocess)
{
	return *reinterpret_cast<uint64_t*>(eprocess + offsets::eprocess::section_base_address);
}

uint64_t ntkrnl::get_process_directory_table_base(uint64_t eprocess)
{
	return *reinterpret_cast<uint64_t*>(eprocess + offsets::eprocess::directory_table_base);
}

uint64_t ntkrnl::get_process_peb(uint64_t eprocess)
{
	return *reinterpret_cast<uint64_t*>(eprocess + offsets::eprocess::peb);
}

uint64_t ntkrnl::get_thread_eprocess(uint64_t ethread)
{
	return *reinterpret_cast<uint64_t*>(ethread + offsets::kthread::process);
}

uint64_t ntkrnl::get_thread_apc_eprocess(uint64_t ethread)
{
	return *reinterpret_cast<uint64_t*>(ethread + offsets::kthread::apc_state + offsets::kapc_state::process);
}

uint64_t ntkrnl::get_thread_win32_start_address(uint64_t ethread)
{
	return *reinterpret_cast<uint64_t*>(ethread + offsets::ethread::win32_start_address);
}

uint64_t ntkrnl::get_thread_process_id(uint64_t ethread)
{
	return *reinterpret_cast<uint64_t*>(ethread + offsets::ethread::cid);
}

uint8_t ntkrnl::get_current_processor_number()
{
	return __readgsbyte(0x184);
}

uint64_t ntkrnl::get_current_process()
{
	uint64_t current_thread = get_current_thread();

	if (current_thread == 0)
	{
		return 0;
	}

	return get_thread_eprocess(current_thread);
}

uint64_t ntkrnl::get_current_thread()
{
	return __readgsqword(0x188);
}

void ntkrnl::enumerate_system_modules(context::s_context* context, t_enumerate_modules_callback callback, void* ctx)
{
	PLIST_ENTRY ps_loaded_module_list = reinterpret_cast<PLIST_ENTRY>(context->imports.ps_loaded_module_list);

	for (PLIST_ENTRY current_list_entry = ps_loaded_module_list->Flink; current_list_entry != ps_loaded_module_list; current_list_entry = current_list_entry->Flink)
	{
		_KLDR_DATA_TABLE_ENTRY* current_module_info = CONTAINING_RECORD(current_list_entry, _KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

		if (callback(reinterpret_cast<uint64_t>(current_module_info), ctx) == true)
		{
			return;
		}
	}
}

uint64_t ntkrnl::pre_initialization::find_ntoskrnl_base()
{
	// thanks to papstuc for the idea of walking back from lstar msr
	uint64_t ki_system_call_handler = __readmsr(d_lstar_msr);

	// ntoskrnl is always aligned to 2mb where large pages is supported
	// todo: check large page support

	// todo: add some sanity check so we dont go too far down, should always be found though
	for (uint64_t system_2mb_boundary = ki_system_call_handler & 0xFFFFFFFFFFE00000; system_2mb_boundary != 0; system_2mb_boundary -= 0x200000)
	{
		uint16_t header_magic = *reinterpret_cast<uint16_t*>(system_2mb_boundary);

		if (header_magic == 0x5a4d)
		{
			return system_2mb_boundary;
		}
	}

	return 0;
}
