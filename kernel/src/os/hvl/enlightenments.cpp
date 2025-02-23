#include "enlightenments.h"
#include "../../context/context.h"

uint32_t hvl::get_enlightenments()
{
	return *context::get_decrypted()->imports.hvl_enlightenments;
}
