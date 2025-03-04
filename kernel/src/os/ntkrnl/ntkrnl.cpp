#include "ntkrnl.h"
#include "../../offsets/offsets.h"
#include "../../structures/kldr_data_table_entry.h"
#include <portable_executable/pe_crt/crt_string.hpp>

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

uint64_t ntkrnl::get_current_pcr()
{
	// evaluates to reading qword from gs:18h
	return __readgsqword(FIELD_OFFSET(KPCR, Self));
}

uint64_t ntkrnl::get_tss_base_from_pcr(uint64_t pcr)
{
	return *reinterpret_cast<uint64_t*>(pcr + offsets::kpcr::tss_base);
}

uint64_t ntkrnl::get_current_tss_base()
{
	uint64_t current_pcr = get_current_pcr();

	return get_tss_base_from_pcr(current_pcr);
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

void ntkrnl::enumerate_system_modules(context::s_context* context, t_enumerate_modules_callback callback, void* ctx, int64_t start_index)
{
	PLIST_ENTRY ps_loaded_module_list = reinterpret_cast<PLIST_ENTRY>(context->imports.ps_loaded_module_list);

	int64_t current_index = 0;

	for (PLIST_ENTRY current_list_entry = ps_loaded_module_list->Flink; current_list_entry != ps_loaded_module_list; current_list_entry = current_list_entry->Flink, current_index++)
	{
		if (start_index <= current_index)
		{
			_KLDR_DATA_TABLE_ENTRY* current_module_info = CONTAINING_RECORD(current_list_entry, _KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

			if (callback(reinterpret_cast<uint64_t>(current_module_info), ctx) == true)
			{
				return;
			}
		}
	}
}

struct s_module_name_search_callback_ctx
{
	const wchar_t* name;
	uint64_t module_ldr_info;
};

bool check_module_has_certain_name_callback(uint64_t current_module_info, void* context_in)
{
	_KLDR_DATA_TABLE_ENTRY* current_module = reinterpret_cast<_KLDR_DATA_TABLE_ENTRY*>(current_module_info);

	s_module_name_search_callback_ctx* module_name_search_context = reinterpret_cast<s_module_name_search_callback_ctx*>(context_in);

	if (portable_executable::pe_crt::wcsstr(current_module->BaseDllName.Buffer, module_name_search_context->name) != nullptr)
	{
		module_name_search_context->module_ldr_info = current_module_info;

		return true;
	}

	return false;
}

uint64_t ntkrnl::get_system_module_ldr_info(context::s_context* context, const wchar_t* name)
{
	s_module_name_search_callback_ctx callback_ctx = { };

	callback_ctx.name = name;

	ntkrnl::enumerate_system_modules(context, check_module_has_certain_name_callback, &callback_ctx);

	return callback_ctx.module_ldr_info;
}

struct s_thread_in_module_callback_ctx
{
	uint64_t address;
	bool is_in_module;
};

bool check_address_in_module_callback(uint64_t current_module_info, void* context)
{
	_KLDR_DATA_TABLE_ENTRY* current_module = reinterpret_cast<_KLDR_DATA_TABLE_ENTRY*>(current_module_info);

	uint64_t win32_thread_start_address = *reinterpret_cast<uint64_t*>(context);

	uint64_t current_module_base_address = reinterpret_cast<uint64_t>(current_module->DllBase);
	uint64_t current_module_end_address = current_module_base_address + current_module->SizeOfImage;

	if (current_module_base_address < win32_thread_start_address && win32_thread_start_address <= current_module_end_address)
	{
		reinterpret_cast<s_thread_in_module_callback_ctx*>(context)->is_in_module = true;

		return true;
	}

	return false;
}

bool ntkrnl::is_address_within_system_module(context::s_context* context, uint64_t address)
{
	s_thread_in_module_callback_ctx callback_ctx = { };

	callback_ctx.address = address;

	ntkrnl::enumerate_system_modules(context, check_address_in_module_callback, &callback_ctx);

	return callback_ctx.is_in_module;
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
