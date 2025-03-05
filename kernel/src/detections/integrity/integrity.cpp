#include "integrity.h"
#include "../../crypto/crypto.h"
#include "../../context/context.h"
#include "../../os/ntkrnl/ntkrnl.h"
#include "../../structures/kldr_data_table_entry.h"

#include <portable_executable/image.hpp>
#include <string_encryption.h>

#include "../../log.h"
#include <ntifs.h>

int32_t integrity::calculate_image_section_hash(context::s_context* context, uint64_t image_base, const char* section_name, crypto::s_hash* hash_out)
{
	if (image_base == 0)
	{
		return STATUS_INVALID_PARAMETER;
	}

	const portable_executable::image_t* image = reinterpret_cast<const portable_executable::image_t*>(image_base);

	const portable_executable::section_header_t* text_section = image->find_section(section_name);

	if (text_section == nullptr)
	{
		return STATUS_NOT_FOUND;
	}

	return crypto::sha256(context, reinterpret_cast<uint8_t*>(image_base + text_section->virtual_address), text_section->virtual_size, hash_out);
}

communication::e_detection_status integrity::validate_ntoskrnl_integrity(context::s_context* context)
{
	crypto::s_hash current_ntoskrnl_text_hash = { };
	
	int32_t hash_status = integrity::calculate_image_section_hash(context, context->ntoskrnl_base_address, d_encrypt_string(".text"), &current_ntoskrnl_text_hash);

	if (NT_SUCCESS(hash_status) == false)
	{
		return communication::e_detection_status::runtime_error;
	}

	bool is_hash_same = context->integrity.ntoskrnl_text_hash.is_same(current_ntoskrnl_text_hash);

	current_ntoskrnl_text_hash.free_hash_buffer(context);

	if (is_hash_same == true)
	{
		return communication::e_detection_status::clean;
	}
	else
	{
		d_log("[darken-anticheat] hash of ntoskrnl's .text section does not match (.text changed).\n");

		return communication::e_detection_status::flagged;
	}
}

struct s_hash_callback_ctx
{
	context::s_context* global_context;

	communication::e_detection_status status = communication::e_detection_status::clean;
};

void add_system_module_to_list(context::s_context* context, uint64_t module_base_address, crypto::s_hash& current_module_hash, crypto::s_hash_list_entry* last_valid_list_entry)
{
	crypto::s_hash_list_entry* new_entry = nullptr;

	if (context->integrity.kernel_module_hash_list_head == nullptr)
	{
		context->integrity.kernel_module_hash_list_head = new_entry = crypto::s_hash_list_entry::create_first_entry(context);
	}
	else
	{
		new_entry = last_valid_list_entry->add_entry(context);
	}

	if (new_entry != nullptr)
	{
		new_entry->set_identifier(module_base_address);

		new_entry->buffer = current_module_hash.buffer;
		new_entry->buffer_size = current_module_hash.buffer_size;
	}
}

bool hash_kernel_module_callback(uint64_t current_module_info, void* context_in)
{
	_KLDR_DATA_TABLE_ENTRY* current_module = reinterpret_cast<_KLDR_DATA_TABLE_ENTRY*>(current_module_info);
	s_hash_callback_ctx* context = reinterpret_cast<s_hash_callback_ctx*>(context_in);

	uint64_t module_base_address = reinterpret_cast<uint64_t>(current_module->DllBase);

	crypto::s_hash current_module_hash = { };

	int32_t hash_status = integrity::calculate_image_section_hash(context->global_context, module_base_address, d_encrypt_string(".text"), &current_module_hash);

	if (NT_SUCCESS(hash_status) == false)
	{
		context->status = communication::e_detection_status::runtime_error;

		return true;
	}

	crypto::s_hash_list_entry* list_entry = context->global_context->integrity.kernel_module_hash_list_head;
	crypto::s_hash_list_entry* last_valid_list_entry = list_entry;

	bool current_module_in_list = false;

	while (list_entry != nullptr)
	{
		if (list_entry->get_identifier() == module_base_address)
		{
			if (list_entry->is_same(current_module_hash) == false)
			{
				d_log("[darken-anticheat] module '%ls' has a differing .text section.\n", current_module->BaseDllName.Buffer);

				context->status = communication::e_detection_status::flagged;

				return true;
			}

			current_module_in_list = true;

			break;
		}

		last_valid_list_entry = list_entry;
		list_entry = list_entry->get_next();
	}

	if (current_module_in_list == false)
	{
		add_system_module_to_list(context->global_context, module_base_address, current_module_hash, last_valid_list_entry);
	}

	return false;
}

communication::e_detection_status integrity::validate_kernel_drivers_integrity(context::s_context* context)
{
	s_hash_callback_ctx ctx = { };

	ctx.global_context = context;
	ctx.status = communication::e_detection_status::clean;

	ntkrnl::enumerate_system_modules(context, hash_kernel_module_callback, &ctx, 2);

	return ctx.status;
}
