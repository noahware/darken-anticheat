#include "integrity.h"
#include "../../crypto/crypto.h"
#include "../../context/context.h"
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

	current_ntoskrnl_text_hash.free(context);

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
