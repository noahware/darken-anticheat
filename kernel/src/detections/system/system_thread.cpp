#include "system_thread.h"
#include "../../context/context.h"
#include "../../os/ntkrnl/ntkrnl.h"
#include "../../offsets/offsets.h"
#include "../../structures/kldr_data_table_entry.h"
#include "../../log.h"

#include <ntifs.h>

bool is_thread_attached_to_process(uint64_t ethread, uint64_t eprocess)
{
	uint64_t thread_eprocess = *reinterpret_cast<uint64_t*>(ethread + offsets::kthread::apc_state + offsets::kapc_state::process);

	return thread_eprocess == eprocess;
}

#pragma warning(push)
#pragma warning(disable: 6387) // for some reason msvc is throwing a warning that current_thread_id could be 0, even when i added a check before executing PsLookupThreadByThreadId

communication::e_detection_status system::system_thread::is_suspicious_thread_present(context::s_context* context)
{
	uint64_t our_executing_thread = ntkrnl::get_current_thread();

	// todo: enumerate pspcid table to find threads 'manually'
	// with my testing on Windows 11 24H2, thread ids go past 0x3000 boundary
	// i believe that 0x4000 is the limit but feel free to make a change if its not

	// reason we dont just enumerate the system process's thread list is because it can be unlinked easily
	// for this they need to unlink it from pspcid table which is a lot more tedious than just modifying a linked list
	for (uint64_t current_thread_id = 4; current_thread_id <= 0x4000; current_thread_id += 4)
	{
		uint64_t current_ethread = 0;

		// they can just remove it from pspcid table
		// and we won't be able to find their thread by these means anymore
		// todo: iterate system process thread linked list (can also be unlinked from)
		if (NT_SUCCESS(context->imports.ps_lookup_thread_by_thread_id(current_thread_id, &current_ethread)) == false)
		{
			continue;
		}

		if (context->imports.ps_is_system_thread(current_ethread) == false)
		{
			continue;
		}

		uint64_t current_ethread_process = ntkrnl::get_thread_eprocess(current_ethread);

		if (current_ethread_process == 0)
		{
			continue;
		}

		uint64_t current_ethread_process_id = ntkrnl::get_process_id(current_ethread_process);

		if (current_ethread_process_id != context->protected_processes.anticheat_usermode_id && current_ethread_process_id != context->protected_processes.protected_process_id)
		{
			// will detect KeStackAttachProcess and hence MmCopyVirtualMemory
			if (is_thread_attached_to_process(current_ethread, context->protected_processes.anticheat_usermode_id) == true
				|| is_thread_attached_to_process(current_ethread, context->protected_processes.protected_process_id) == true)
			{
				d_log("[darken-anticheat] thread id: %llx was attached to a protected process.\n", current_thread_id);

				return communication::e_detection_status::flagged;
			}
		}

		if (current_ethread_process_id != 4)
		{
			continue;
		}

		if (our_executing_thread == current_ethread) // won't happen cause our currently executing thread is not one pertaining to the system process
		{
			continue;
		}

		// check if Win32StartAddress is outside of any legitimate kernel module.
		// can be bypassed by changing the value in the ETHREAD struct
		// or using a (jmp rcx) gadget which is in legitimate module and passing the real start address as context

		uint64_t current_thread_win32_start_address = ntkrnl::get_thread_win32_start_address(current_ethread);

		if (current_thread_win32_start_address == 0) // yes, people do set it to 0 for some odd reason
		{
			d_log("[darken-anticheat] thread id: %llx has a NULL Win32StartAddress.\n", current_thread_id);

			return communication::e_detection_status::flagged;
		}

		if (ntkrnl::is_address_within_system_module(context, current_thread_win32_start_address) == false)
		{
			d_log("[darken-anticheat] thread id: %llx has a Win32StartAddress (0x%llx) which resides outside of a valid kernel module.\n", current_thread_id, current_thread_win32_start_address);

			return communication::e_detection_status::flagged;
		}
	}

	return communication::e_detection_status::clean;
}

#pragma warning(pop)
