#include "non_maskable_interrupts.h"
#include "../../os/ntkrnl/ntkrnl.h"
#include "../../log.h"
#include <ntifs.h>
#include <intrin.h>

#include "../../structures/kaffinity_ex.h"
#include "../../structures/machine_frame.h"
#include <ia32/ia32.h>

struct s_nmi_per_core_info
{
	uint64_t rip;
	bool processed;
};

uint8_t nmi_callback_handler(s_nmi_per_core_info* context, uint8_t handled)
{
	UNREFERENCED_PARAMETER(handled);

	task_state_segment_64* current_task_state_segment = reinterpret_cast<task_state_segment_64*>(ntkrnl::get_current_tss_base());
	s_machine_frame* machine_frame = reinterpret_cast<s_machine_frame*>(current_task_state_segment->ist3 - sizeof(s_machine_frame));

	uint8_t current_processor_number = ntkrnl::get_current_processor_number();

	s_nmi_per_core_info* current_core_info = &context[current_processor_number];

	current_core_info->rip = machine_frame->rip;
	current_core_info->processed = true;

	return TRUE;
}

void fire_nmi_on_core(context::s_context* context, _KAFFINITY_EX* processor_affinity, uint32_t processor_number)
{
	context->imports.ke_initialize_affinity_ex(processor_affinity);
	context->imports.ke_add_processor_affinity_ex(processor_affinity, processor_number);

	context->imports.hal_send_nmi(processor_affinity);
}

bool dispatch_nmi_on_all_cores(context::s_context* context, s_nmi_per_core_info* nmi_per_core_info, _KAFFINITY_EX* processor_affinity, uint32_t processor_count, uint32_t our_current_processor_number)
{
	uint64_t callback_handle = context->imports.ke_register_nmi_callback(nmi_callback_handler, nmi_per_core_info);

	if (callback_handle == 0)
	{
		return false;
	}

	for (uint32_t i = 0; i < processor_count; i++)
	{
		if (i == our_current_processor_number)
		{
			continue;
		}

		fire_nmi_on_core(context, processor_affinity, i);
	}

	LARGE_INTEGER sleep_period = { .QuadPart = -100000 };

	context->imports.ke_delay_execution_thread(KernelMode, FALSE, &sleep_period);

	context->imports.ke_deregister_nmi_callback(callback_handle);

	return true;
}

communication::e_detection_status system::non_maskable_interrupts::send_and_analyze(context::s_context* context)
{
	_KAFFINITY_EX* processor_affinity = reinterpret_cast<_KAFFINITY_EX*>(context->imports.ex_allocate_pool_2(POOL_FLAG_NON_PAGED, sizeof(_KAFFINITY_EX), d_pool_tag));

	if (processor_affinity == nullptr)
	{
		return communication::e_detection_status::runtime_error;
	}

	uint32_t processor_count = context->imports.ke_query_active_processor_count(nullptr);

	// todo: allocate 1 less core info (due to us not launching on our current core obviously), and 
	s_nmi_per_core_info* nmi_per_core_info = reinterpret_cast<s_nmi_per_core_info*>(context->imports.ex_allocate_pool_2(POOL_FLAG_NON_PAGED, sizeof(s_nmi_per_core_info) * processor_count, d_pool_tag));

	if (nmi_per_core_info == nullptr)
	{
		context->imports.ex_free_pool_with_tag(reinterpret_cast<uint64_t>(processor_affinity), d_pool_tag);

		return communication::e_detection_status::runtime_error;
	}

	_disable();

	uint32_t our_current_processor_number = static_cast<uint32_t>(ntkrnl::get_current_processor_number());

	bool were_nmis_dispatch_successfully = dispatch_nmi_on_all_cores(context, nmi_per_core_info, processor_affinity, processor_count, our_current_processor_number);

	_enable();

	if (were_nmis_dispatch_successfully == false)
	{
		context->imports.ex_free_pool_with_tag(reinterpret_cast<uint64_t>(processor_affinity), d_pool_tag);
		context->imports.ex_free_pool_with_tag(reinterpret_cast<uint64_t>(nmi_per_core_info), d_pool_tag);

		return communication::e_detection_status::runtime_error;
	}

	for (uint32_t i = 0; i < processor_count; i++)
	{
		if (i == our_current_processor_number)
		{
			continue;
		}

		s_nmi_per_core_info current_core_info = nmi_per_core_info[i];

		if (current_core_info.processed == false)
		{
			// should probably signal that this core's interrupt callback wasn't processed, is a flag if happens often

			d_log("[darken-anticheat] processor: %u failed to process nmi callback in time.\n", i);

			return communication::e_detection_status::runtime_error;
		}

		// check if in lower 256 pml4es, we will start to handle usermode rips (if they belong to our process) later on

		if (current_core_info.rip < (256ull << 39))
		{
			continue;
		}

		if (ntkrnl::is_address_within_system_module(context, current_core_info.rip) == false)
		{
			d_log("[darken-anticheat] interrupted processor: %u was interrupted in kernel code which had a rip outside of a valid module (0x%llx).\n", i, current_core_info.rip);

			context->imports.ex_free_pool_with_tag(reinterpret_cast<uint64_t>(processor_affinity), d_pool_tag);

			return communication::e_detection_status::flagged;
		}
	}

	context->imports.ex_free_pool_with_tag(reinterpret_cast<uint64_t>(processor_affinity), d_pool_tag);

	return communication::e_detection_status::clean;
}
