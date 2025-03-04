#include "crypto.h"
#include "../memory/memory.h"

#include <string_encryption.h>

#include <ntifs.h>
#include <bcrypt.h>

#include "../log.h"

bool crypto::s_hash::is_same(s_hash& other)
{
	if (this->buffer == nullptr || other.buffer == nullptr || this->buffer_size != other.buffer_size)
	{
		return false;
	}

	return (memcmp(this->buffer, other.buffer, other.buffer_size) == 0);
}

void crypto::s_hash::free_hash_buffer(context::s_context* context)
{
	if (this->buffer != nullptr)
	{
		memory::free_pool(context, reinterpret_cast<uint64_t>(this->buffer));

		this->buffer = nullptr;
	}
}

crypto::s_hash_list_entry* crypto::s_hash_list_entry::allocate_memory_for_entry(context::s_context* context)
{
	return reinterpret_cast<crypto::s_hash_list_entry*>(memory::allocate_pool(context, sizeof(s_hash_list_entry), POOL_FLAG_NON_PAGED));
}

crypto::s_hash_list_entry* crypto::s_hash_list_entry::create_first_entry(context::s_context* context)
{
	crypto::s_hash_list_entry* first_entry = allocate_memory_for_entry(context);

	if (first_entry == nullptr)
	{
		return nullptr;
	}

	first_entry->set_previous(nullptr);
	first_entry->set_next(nullptr);

	return first_entry;
}

crypto::s_hash_list_entry* crypto::s_hash_list_entry::add_entry(context::s_context* context)
{
	if (this->get_next() != nullptr)
	{
		return nullptr;
	}

	crypto::s_hash_list_entry* new_entry = this->allocate_memory_for_entry(context);

	if (new_entry == nullptr)
	{
		return nullptr;
	}

	this->set_next(new_entry);
	new_entry->set_previous(this);

	return new_entry;
}

crypto::s_hash_list_entry* crypto::s_hash_list_entry::add_entry(context::s_context* context, s_hash hash)
{
	crypto::s_hash_list_entry* new_entry = this->add_entry(context);

	if (new_entry != nullptr)
	{
		new_entry->buffer = hash.buffer;
		new_entry->buffer_size = hash.buffer_size;
	}

	return new_entry;
}

void crypto::s_hash_list_entry::delete_self(context::s_context* context)
{
	this->free_hash_buffer(context);

	s_hash_list_entry* next_entry = this->get_next();
	s_hash_list_entry* previous_entry = this->get_previous();

	if (next_entry != nullptr)
	{
		next_entry->set_previous(previous_entry);
	}

	if (previous_entry != nullptr)
	{
		previous_entry->set_next(next_entry);
	}

	memory::free_pool(context, reinterpret_cast<uint64_t>(this));
}

crypto::s_hash_list_entry* crypto::s_hash_list_entry::get_next()
{
	return this->next;
}

void crypto::s_hash_list_entry::set_next(s_hash_list_entry* new_next)
{
	this->next = new_next;
}

crypto::s_hash_list_entry* crypto::s_hash_list_entry::get_previous()
{
	return this->previous;
}

void crypto::s_hash_list_entry::set_previous(s_hash_list_entry* new_previous)
{
	this->previous = new_previous;
}

uint64_t crypto::s_hash_list_entry::get_identifier()
{
	return this->identifier;
}

void crypto::s_hash_list_entry::set_identifier(uint64_t new_identifier)
{
	this->identifier = new_identifier;
}

uint64_t crypto::xor64(uint64_t input, uint64_t key)
{
	return input ^= key;
}

int32_t crypto_algorithm_get_property(context::s_context* context, BCRYPT_ALG_HANDLE algorithm_handle, LPCWSTR property, uint32_t* buffer_size_out)
{
	uint32_t bytes_returned = 0;

	return context->imports.bcrypt_get_property(algorithm_handle, property, reinterpret_cast<uint8_t*>(buffer_size_out), sizeof(uint32_t), &bytes_returned, 0);
}

int32_t crypto_set_up_algorithm_property(context::s_context* context, BCRYPT_ALG_HANDLE algorithm_handle, LPCWSTR property, uint8_t** buffer_out, uint32_t* buffer_size_out)
{
	int32_t status = crypto_algorithm_get_property(context, algorithm_handle, property, buffer_size_out);

	if (NT_SUCCESS(status) == false)
	{
		return status;
	}

	*buffer_out = reinterpret_cast<uint8_t*>(memory::allocate_pool(context, *buffer_size_out, POOL_FLAG_NON_PAGED));

	if (*buffer_out == 0)
	{
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	return STATUS_SUCCESS;
}

int32_t crypto_set_up_algorithm(context::s_context* context, BCRYPT_ALG_HANDLE* algorithm_handle, LPCWSTR algorithm_id, uint64_t* hash_buffer, uint32_t* hash_size, uint64_t* hash_object_buffer, uint32_t* hash_object_size)
{
	uint32_t status = context->imports.bcrypt_open_algorithm_provider(algorithm_handle, algorithm_id, nullptr, 0);

	if (NT_SUCCESS(status) == false)
	{
		return status;
	}

	status = crypto_set_up_algorithm_property(context, *algorithm_handle, d_encrypt_string(BCRYPT_OBJECT_LENGTH), reinterpret_cast<uint8_t**>(hash_object_buffer), hash_object_size);

	if (NT_SUCCESS(status) == false)
	{
		return status;
	}

	return crypto_set_up_algorithm_property(context, *algorithm_handle, d_encrypt_string(BCRYPT_HASH_LENGTH), reinterpret_cast<uint8_t**>(hash_buffer), hash_size);
}

int32_t crypto_close_algorithm(context::s_context* context, BCRYPT_ALG_HANDLE algorithm_handle)
{
	return algorithm_handle != nullptr ? context->imports.bcrypt_close_algorithm_provider(algorithm_handle, 0) : STATUS_INVALID_PARAMETER;
}

int32_t crypto_destroy_hash_handle(context::s_context* context, BCRYPT_HASH_HANDLE hash_handle)
{
	return hash_handle != nullptr ? context->imports.bcrypt_destroy_hash(hash_handle) : STATUS_INVALID_PARAMETER;
}

int32_t crypto_algorithm_generate_hash(context::s_context* context, BCRYPT_ALG_HANDLE algorithm_handle, uint8_t* buffer, uint32_t buffer_size, uint64_t hash_buffer, uint32_t hash_size, uint64_t hash_object_buffer, uint32_t hash_object_size)
{
	BCRYPT_HASH_HANDLE hash_handle = nullptr;

	int32_t status = context->imports.bcrypt_create_hash(algorithm_handle, &hash_handle, reinterpret_cast<uint8_t*>(hash_object_buffer), hash_object_size, nullptr, 0, 0);

	if (NT_SUCCESS(status) == false)
	{
		return status;
	}

	status = context->imports.bcrypt_hash_data(hash_handle, buffer, buffer_size, 0);

	if (NT_SUCCESS(status) == false)
	{
		crypto_destroy_hash_handle(context, hash_handle);

		return status;
	}

	status = context->imports.bcrypt_finish_hash(hash_handle, reinterpret_cast<uint8_t*>(hash_buffer), hash_size, 0);

	crypto_destroy_hash_handle(context, hash_handle);

	return status;
}

// note: pool described by: (*hash_buffer) must beed freed eventually after returned hash buffer is no longer needed
int32_t crypto_algorithm_hash_buffer(context::s_context* context, LPCWSTR algorithm_id, uint8_t* buffer, uint32_t buffer_size, uint8_t** hash_buffer, uint32_t* hash_size)
{
	BCRYPT_ALG_HANDLE algorithm_handle = nullptr;

	uint64_t hash_object_buffer = 0;
	uint32_t hash_object_size = 0;

	int32_t status = crypto_set_up_algorithm(context, &algorithm_handle, algorithm_id, reinterpret_cast<uint64_t*>(hash_buffer), hash_size, &hash_object_buffer, &hash_object_size);

	if (NT_SUCCESS(status) == false)
	{
		return status;
	}

	status = crypto_algorithm_generate_hash(context, algorithm_handle, buffer, buffer_size, reinterpret_cast<uint64_t>(*hash_buffer), *hash_size, hash_object_buffer, hash_object_size);

	memory::free_pool(context, hash_object_buffer);

	crypto_close_algorithm(context, algorithm_handle);

	if (NT_SUCCESS(status) == false)
	{
		return status;
	}

	return STATUS_SUCCESS;
}

int32_t crypto::sha256(context::s_context* context, uint8_t* buffer, uint32_t buffer_size, uint8_t** hash_buffer, uint32_t* hash_size)
{
	return crypto_algorithm_hash_buffer(context, d_encrypt_string(BCRYPT_SHA256_ALGORITHM), buffer, buffer_size, hash_buffer, hash_size);
}

int32_t crypto::sha256(context::s_context* context, uint8_t* buffer, uint32_t buffer_size, crypto::s_hash* hash_out)
{
	return sha256(context, buffer, buffer_size, &hash_out->buffer, &hash_out->buffer_size);
}
