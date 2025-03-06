#include "data_section_integrity.h"
#include "../../crypto/crypto.h"
#include "../../context/context.h"
#include "../../os/ntkrnl/ntkrnl.h"
#include "../../structures/kldr_data_table_entry.h"
#include "../../memory/memory.h"
#include <portable_executable/image.hpp>
#include "../../log.h"

#include <ntifs.h>
#include <intrin.h>

bool are_pages_executable(context::s_context* context, int64_t start_virtual_address, uint64_t end_virtual_address)
{
	_disable();

	cr3 original_cr3 = memory::current_context::read_cr3();

	memory::current_context::write_cr3(context->memory.pt_cr3);

	bool found_executable_page = false;

	uint64_t current_virtual_address = start_virtual_address;

	while (current_virtual_address < end_virtual_address)
	{
		uint64_t size_left_of_page = 0;

		uint64_t physical_address = memory::translate_virtual_address({ current_virtual_address }, original_cr3, &size_left_of_page, &found_executable_page);

		// if for some reason invalid pfn, we just assume its a 4kb page, and keep on searching
		// 
		// reason why we dont just break:
		// if we broke on invalid pfn (assuming rest of section is invalid),
		// then attackers could just set first page in a section to an invalid pfn, and the rest be valid
		if (physical_address == 0)
		{
			size_left_of_page = 0x1000 - (current_virtual_address & 0xFFF);
		}

		if (found_executable_page == true)
		{
			break;
		}

		current_virtual_address += size_left_of_page;
	}

	memory::current_context::write_cr3(original_cr3);

	_enable();

	return found_executable_page;
}

bool is_data_section_executable(context::s_context* context, uint64_t image_base_address)
{
	const portable_executable::image_t* image = reinterpret_cast<const portable_executable::image_t*>(image_base_address);

	for (const auto& current_section : image->sections())
	{
		bool should_section_be_executable = current_section.characteristics.mem_execute == 1;

		if (should_section_be_executable == false)
		{
			uint64_t section_start_virtual_address = image_base_address + current_section.virtual_address;

			uint64_t section_end_virtual_address = section_start_virtual_address + current_section.virtual_size;

			if (are_pages_executable(context, section_start_virtual_address, section_end_virtual_address) == true)
			{
				return true;
			}
		}
	}

	return false;
}

struct s_driver_section_processor_callback_ctx
{
	context::s_context* global_context;
	bool has_found_tampered_page;
};

bool driver_section_processor_callback(uint64_t current_module_info, void* context_in)
{
	_KLDR_DATA_TABLE_ENTRY* current_module = reinterpret_cast<_KLDR_DATA_TABLE_ENTRY*>(current_module_info);
	s_driver_section_processor_callback_ctx* context = reinterpret_cast<s_driver_section_processor_callback_ctx*>(context_in);

	context->has_found_tampered_page = is_data_section_executable(context->global_context, reinterpret_cast<uint64_t>(current_module->DllBase));

	if (context->has_found_tampered_page == true)
	{
		d_log("[darken-anticheat] kernel module '%ls' has a data section set to executable.\n", current_module->BaseDllName.Buffer);

		return true;
	}

	return false;
}

communication::e_detection_status integrity::data_section::is_any_driver_data_section_executable(context::s_context* context)
{
	s_driver_section_processor_callback_ctx callback_ctx = { };

	callback_ctx.global_context = context;

	ntkrnl::enumerate_system_modules(context, driver_section_processor_callback, &callback_ctx);

	return callback_ctx.has_found_tampered_page == true ? communication::e_detection_status::flagged : communication::e_detection_status::clean;
}
