#pragma once
#include "../../context/context.h"

namespace ntkrnl
{
	uint64_t get_eprocess(uint64_t target_process_id);

	// valid_eprocess is any eprocess in the system, so we can traverse the linked list
	uint64_t get_eprocess(uint64_t target_process_id, uint64_t valid_eprocess);

	uint64_t get_process_id(uint64_t eprocess);
	uint64_t get_process_base_address(uint64_t eprocess);
	uint64_t get_process_directory_table_base(uint64_t eprocess);
	uint64_t get_process_peb(uint64_t eprocess);

	uint64_t get_thread_eprocess(uint64_t ethread);
	uint64_t get_thread_apc_eprocess(uint64_t ethread);
	uint64_t get_thread_win32_start_address(uint64_t ethread);
	uint64_t get_thread_process_id(uint64_t ethread);

	uint8_t get_current_processor_number();
	uint64_t get_current_pcr();
	uint64_t get_tss_base_from_pcr(uint64_t pcr);
	uint64_t get_current_tss_base();

	uint64_t get_current_process();
	uint64_t get_current_thread();

	// return value signals if needs to continue enumerating
	// current_module_info will contain a pointer to: _KLDR_DATA_TABLE_ENTRY
	typedef bool(*t_enumerate_modules_callback)(uint64_t current_module_info, void* ctx);

	void enumerate_system_modules(context::s_context* context, t_enumerate_modules_callback callback, void* ctx);

	uint64_t get_system_module_ldr_info(context::s_context* context, const wchar_t* name);
	bool is_address_within_system_module(context::s_context* context, uint64_t address);

	namespace pre_initialization
	{
		// note: to be used only when in when setting up context (to resolve imports before we have any indication of build number to get offsets)
		uint64_t find_ntoskrnl_base();
	}
}
