#include "context.h"
#include "../crypto/crypto.h"
#include "../memory/memory.h"
#include "../os/ntkrnl/ntkrnl.h"
#include <portable_executable/image.hpp>
#include <string_encryption.h>
#include <ntifs.h>

#define d_context_xor_key 0xAC54EF7B5AD4E

// this function must be heavily virtualized in production
bool context::load()
{
	uint64_t ntoskrnl_base_address = ntkrnl::pre_initialization::find_ntoskrnl_base();

	if (ntoskrnl_base_address == 0)
	{
		return false;
	}

	const portable_executable::image_t* ntoskrnl_image = reinterpret_cast<const portable_executable::image_t*>(ntoskrnl_base_address);

	t_ex_allocate_pool_2 ex_allocate_pool_2 = reinterpret_cast<t_ex_allocate_pool_2>(ntoskrnl_image->find_export(d_encrypt_string("ExAllocatePool2")));

	if (ex_allocate_pool_2 == nullptr)
	{
		return false;
	}

	s_context* context = reinterpret_cast<s_context*>(ex_allocate_pool_2(POOL_FLAG_NON_PAGED, sizeof(s_context), 'drac'));

	if (context == nullptr)
	{
		return false;
	}

	memset(context, 0, sizeof(s_context));

	context->imports.ex_allocate_pool_2 = ex_allocate_pool_2;
	context->ntoskrnl_base_address = ntoskrnl_base_address;
	context->initial_system_process = ntkrnl::get_current_process(); // will be the initial system process on driver entry

	encrypted_context_pointer = crypto::xor64(reinterpret_cast<uint64_t>(context), d_context_xor_key);

	return true;
}

void context::unload()
{
	if (encrypted_context_pointer == 0)
	{
		return;
	}

	context::s_context* context = get_decrypted();

	memory::free_pool(context, reinterpret_cast<uint64_t>(context));

	encrypted_context_pointer = 0;
}

context::s_context* context::get_decrypted()
{
	// todo: implement return address check, we dont want this to be called from anywhere outside of our driver

	return reinterpret_cast<s_context*>(crypto::xor64(encrypted_context_pointer, d_context_xor_key));
}
