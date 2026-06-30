#include <ntifs.h>
#include "crt.hpp"
#include "util/import.hpp"

constexpr unsigned long pool_tag = 'nkrd';

using _PVFV = void(__cdecl*)();

#pragma section(".CRT$XCA", long, read)
#pragma section(".CRT$XCZ", long, read)

#pragma comment(linker, "/merge:.CRT=.rdata")

__declspec(allocate(".CRT$XCA")) _PVFV __xc_a[] = { nullptr };
__declspec(allocate(".CRT$XCZ")) _PVFV __xc_z[] = { nullptr };

namespace
{
    constexpr uint32_t max_atexit_entries = 64;

    _PVFV atexit_table[max_atexit_entries] = {};
    uint32_t atexit_count = 0;

}

int atexit(_PVFV func)
{
    if (atexit_count >= max_atexit_entries)
    {
        return 1;
    }

    atexit_table[atexit_count++] = func;
    return 0;
}

extern "C" void crt_global_init()
{
    for (auto* fn = __xc_a; fn < __xc_z; ++fn)
    {
        if (*fn)
        {
            (*fn)();
        }
    }

}

extern "C" void crt_global_shutdown()
{
    for (auto i = atexit_count; i > 0; --i)
    {
        if (atexit_table[i - 1])
        {
            atexit_table[i - 1]();
        }
    }

    atexit_count = 0;
}

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
	return LIMPORT(ExAllocatePool2)(POOL_FLAG_NON_PAGED, size, pool_tag);
}

void cstd::crt::free(void* const buffer)
{
	LIMPORT(ExFreePoolWithTag)(buffer, pool_tag);
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
	void* malloc(const size_t size)
	{
		return cstd::crt::malloc(size);
	}

	void free(void* const ptr)
	{
		cstd::crt::free(ptr);
	}

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

#pragma function(memcmp)
	int memcmp(const void* const lhs, const void* const rhs, const size_t size)
	{
		const auto* a = static_cast<const unsigned char*>(lhs);
		const auto* b = static_cast<const unsigned char*>(rhs);

		for (size_t i = 0; i < size; ++i)
		{
			if (a[i] != b[i])
			{
				return a[i] < b[i] ? -1 : 1;
			}
		}

		return 0;
	}

#pragma function(strlen)
	size_t strlen(const char* const str)
	{
		return cstd::crt::strlen(str);
	}

#pragma function(strcmp)
	int strcmp(const char* const lhs, const char* const rhs)
	{
		return cstd::crt::strcmp(lhs, rhs);
	}
}
