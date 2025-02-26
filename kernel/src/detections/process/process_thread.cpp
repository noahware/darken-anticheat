#include "process_thread.h"
#include "../../os/ntkrnl/ntkrnl.h"
#include "../../offsets/offsets.h"
#include "../../memory/memory.h"
#include "../../memory/page_tables.h"
#include "../../log.h"

#include "../../structures/ldr_data_table_entry.h"
#include "../../structures/_peb.h"
#include <ntifs.h>
#include <intrin.h>

extern "C" NTKERNELAPI PPEB PsGetProcessPeb(PEPROCESS);

#pragma warning(push)
#pragma warning(disable: 6387) // explanation to this given in identical line in: /src/system/system_thread.cpp

communication::e_detection_status process::process_thread::is_suspicious_thread_present(context::s_context* context, communication::s_is_suspicious_process_thread_present is_suspicious_process_thread_present)
{
	if (is_suspicious_process_thread_present.process_id == 0)
	{
		return communication::e_detection_status::runtime_error;
	}

	uint64_t protected_eprocess = ntkrnl::get_eprocess(is_suspicious_process_thread_present.process_id);

	if (protected_eprocess == 0)
	{
		return communication::e_detection_status::runtime_error;
	}

	PPEB protected_process_peb = reinterpret_cast<PPEB>(ntkrnl::get_process_peb(protected_eprocess));

	cr3 original_cr3 = memory::current_context::read_cr3();

	memory::current_context::write_cr3(page_tables::pt_cr3);

	bool is_process_peb_virtual_address_valid = memory::is_address_valid(reinterpret_cast<uint64_t>(protected_process_peb), ntkrnl::get_process_directory_table_base(protected_eprocess));

	memory::current_context::write_cr3(original_cr3);

	if (is_process_peb_virtual_address_valid == false)
	{
		d_log("[darken-anticheat][process::process_thread::is_suspicious_thread_present] unable to get peb of protected process with id: 0x%llx.\n", is_suspicious_process_thread_present.process_id);

		return communication::e_detection_status::runtime_error;
	}

	KAPC_STATE apc_state = { };

	// todo: implement our own 'attaching' by directly reading memory of process
	context->imports.ke_stack_attach_process(protected_eprocess, &apc_state);

	uint64_t our_executing_thread = ntkrnl::get_current_thread();

	// context to this enumeration given in /src/system/system_thread.cpp
	for (uint64_t current_thread_id = 4; current_thread_id <= 0x4000; current_thread_id += 4)
	{
		uint64_t current_ethread = 0;

		if (NT_SUCCESS(context->imports.ps_lookup_thread_by_thread_id(current_thread_id, &current_ethread)) == false)
		{
			continue;
		}

		if (our_executing_thread == current_ethread || context->imports.ps_is_system_thread(current_ethread) == 1)
		{
			continue;
		}

		uint64_t current_ethread_process = ntkrnl::get_thread_eprocess(current_ethread);

		if (current_ethread_process == 0)
		{
			continue;
		}

		uint64_t current_ethread_process_id = ntkrnl::get_process_id(current_ethread_process);

		if (current_ethread_process_id != is_suspicious_process_thread_present.process_id)
		{
			continue;
		}

		uint64_t current_thread_win32_start_address = *reinterpret_cast<uint64_t*>(current_ethread + offsets::ethread::win32_start_address);

		bool is_thread_inside_registered_module = false;

		PLIST_ENTRY module_list_head = &protected_process_peb->Ldr->InMemoryOrderModuleList;

		for (PLIST_ENTRY module_list = module_list_head->Flink; module_list != module_list_head; module_list = module_list->Flink)
		{
			_LDR_DATA_TABLE_ENTRY* current_module = CONTAINING_RECORD(module_list, _LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

			uint64_t module_base = reinterpret_cast<uint64_t>(current_module->DllBase);
			uint64_t module_size = static_cast<uint64_t>(current_module->SizeOfImage);

			// check if thread start address is inside an existing module, if it isn't then we will then flag the user

			if (module_base <= current_thread_win32_start_address && current_thread_win32_start_address <= module_base + module_size)
			{
				is_thread_inside_registered_module = true;

				break;
			}
		}

		if (is_thread_inside_registered_module == false)
		{
			d_log("[darken-anticheat] thread id: %llx has a Win32StartAddress (0x%llx) which resides outside of a valid module of process with id: %llx.\n", current_thread_id, current_thread_win32_start_address, is_suspicious_process_thread_present.process_id);

			context->imports.ke_unstack_detach_process(&apc_state);

			return communication::e_detection_status::flagged;
		}
	}

	context->imports.ke_unstack_detach_process(&apc_state);

	return communication::e_detection_status::clean;
}

#pragma warning(pop)
