#include "crypto.h"
#include "../memory/memory.h"

#include <ntifs.h>
#include <bcrypt.h>

#include "../log.h"

uint64_t crypto::xor64(uint64_t input, uint64_t key)
{
	return input ^= key;
}

int32_t crypto_algorithm_get_property(BCRYPT_ALG_HANDLE algorithm_handle, LPCWSTR property, uint32_t* buffer_size_out)
{
	int32_t bytes_returned = 0;

	return BCryptGetProperty(algorithm_handle, property, reinterpret_cast<uint8_t*>(buffer_size_out), sizeof(uint32_t), reinterpret_cast<ULONG*>(&bytes_returned), 0);
}

int32_t crypto_set_up_algorithm_property(context::s_context* context, BCRYPT_ALG_HANDLE algorithm_handle, LPCWSTR property, uint8_t** buffer_out, uint32_t* buffer_size_out)
{
	int32_t status = crypto_algorithm_get_property(algorithm_handle, property, buffer_size_out);

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
	uint32_t status = BCryptOpenAlgorithmProvider(algorithm_handle, algorithm_id, nullptr, 0);

	if (NT_SUCCESS(status) == false)
	{
		return status;
	}

	status = crypto_set_up_algorithm_property(context, *algorithm_handle, BCRYPT_OBJECT_LENGTH, reinterpret_cast<uint8_t**>(hash_object_buffer), hash_object_size);

	if (NT_SUCCESS(status) == false)
	{
		return status;
	}

	return crypto_set_up_algorithm_property(context, *algorithm_handle, BCRYPT_HASH_LENGTH, reinterpret_cast<uint8_t**>(hash_buffer), hash_size);
}

int32_t crypto_close_algorithm(BCRYPT_ALG_HANDLE algorithm_handle)
{
	return algorithm_handle != nullptr ? BCryptCloseAlgorithmProvider(algorithm_handle, 0) : STATUS_INVALID_PARAMETER;
}

int32_t crypto_destroy_hash_handle(BCRYPT_HASH_HANDLE hash_handle)
{
	return hash_handle != nullptr ? BCryptDestroyHash(hash_handle) : STATUS_INVALID_PARAMETER;
}

int32_t crypto_algorithm_generate_hash(BCRYPT_ALG_HANDLE algorithm_handle, uint8_t* buffer, uint32_t buffer_size, uint64_t hash_buffer, uint32_t hash_size, uint64_t hash_object_buffer, uint32_t hash_object_size)
{
	BCRYPT_HASH_HANDLE hash_handle = nullptr;

	int32_t status = BCryptCreateHash(algorithm_handle, &hash_handle, reinterpret_cast<uint8_t*>(hash_object_buffer), hash_object_size, nullptr, 0, 0);

	if (NT_SUCCESS(status) == false)
	{
		return status;
	}

	status = BCryptHashData(hash_handle, buffer, buffer_size, 0);

	if (NT_SUCCESS(status) == false)
	{
		crypto_destroy_hash_handle(hash_handle);

		return status;
	}

	status = BCryptFinishHash(hash_handle, reinterpret_cast<uint8_t*>(hash_buffer), hash_size, 0);

	crypto_destroy_hash_handle(hash_handle);

	return status;
}

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

	status = crypto_algorithm_generate_hash(algorithm_handle, buffer, buffer_size, reinterpret_cast<uint64_t>(*hash_buffer), *hash_size, hash_object_buffer, hash_object_size);

	memory::free_pool(context, hash_object_buffer);

	crypto_close_algorithm(algorithm_handle);

	if (NT_SUCCESS(status) == false)
	{
		return status;
	}

	return STATUS_SUCCESS;
}

int32_t crypto::sha256(context::s_context* context, uint8_t* buffer, uint32_t buffer_size, uint8_t** hash_buffer, uint32_t* hash_size)
{
	return crypto_algorithm_hash_buffer(context, BCRYPT_SHA256_ALGORITHM, buffer, buffer_size, hash_buffer, hash_size);
}
