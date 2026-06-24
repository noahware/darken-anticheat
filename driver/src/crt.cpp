#include <ntifs.h>
#include "crt.hpp"

constexpr unsigned long pool_tag = 'nkrd';

void* operator new(const size_t size)
{
	return cstd::crt::malloc(size);
}

void* operator new[](const size_t size)
{
	return cstd::crt::malloc(size);
}

void* operator new([[maybe_unused]] const size_t size, void* const buffer) noexcept
{
	return buffer;
}

void* operator new[]([[maybe_unused]] const size_t size, void* const buffer) noexcept
{
	return buffer;
}

void operator delete(void* buffer) noexcept
{
	if (!buffer)
	{
		return;
	}

	cstd::crt::free(buffer);
}

void operator delete(void* buffer, [[maybe_unused]] const size_t size) noexcept
{
	if (!buffer)
	{
		return;
	}

	cstd::crt::free(buffer);
}

void operator delete[](void* buffer) noexcept
{
	if (!buffer)
	{
		return;
	}

	cstd::crt::free(buffer);
}

void operator delete[](void* buffer, [[maybe_unused]] const size_t size) noexcept
{
	if (!buffer)
	{
		return;
	}

	cstd::crt::free(buffer);
}

void* cstd::crt::malloc(const size_t size)
{
	return ExAllocatePool2(POOL_FLAG_NON_PAGED, size, pool_tag);
}

void cstd::crt::free(void* const buffer)
{
	ExFreePoolWithTag(buffer, pool_tag);
}

void cstd::crt::memcpy(void* const destination, const void* const source, const size_t size)
{
	__movsb(static_cast<unsigned char*>(destination), static_cast<const unsigned char*>(source), size);
}

void cstd::crt::memset(void* const destination, const int32_t value, const size_t size)
{
	__stosb(static_cast<unsigned char*>(destination), static_cast<unsigned char>(value), size);
}

extern "C"
{
#pragma function(memset)
	void* memset(void* const destination, const int value, const size_t size)
	{
		cstd::crt::memset(destination, value, size);

		return destination;
	}

#pragma function(memcpy)
	void* memcpy(void* const destination, const void* const source, const size_t size)
	{
		cstd::crt::memcpy(destination, source, size);

		return destination;
	}
}
