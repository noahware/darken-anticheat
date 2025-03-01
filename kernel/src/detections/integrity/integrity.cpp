#include "integrity.h"
#include "../../crypto/crypto.h"
#include <portable_executable/image.hpp>

#include <ntifs.h>
#include "../../log.h"

crypto::s_hash integrity::calculate_image_section_hash(context::s_context* context, uint64_t image_base, const char* section_name)
{
	if (image_base == 0)
	{
		return { };
	}

	const portable_executable::image_t* image = reinterpret_cast<const portable_executable::image_t*>(image_base);

	const portable_executable::section_header_t* text_section = image->find_section(section_name);

	return crypto::sha256(context, reinterpret_cast<uint8_t*>(image_base + text_section->virtual_address), text_section->virtual_size);
}
