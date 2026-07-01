#pragma once
#include "types.hpp"

void* operator new(cstd::size_t size);
void* operator new[](cstd::size_t size);
void* operator new(cstd::size_t size, void* buffer) noexcept;
void* operator new[](cstd::size_t size, void* buffer) noexcept;
void operator delete(void* buffer) noexcept;
void operator delete[](void* buffer) noexcept;
void operator delete(void* buffer, cstd::size_t size) noexcept;
void operator delete[](void* buffer, cstd::size_t size) noexcept;

namespace cstd::crt
{
	void* malloc(size_t size);
	void free(void* buffer);
	void memcpy(void* destination, const void* source, size_t size);
	void memset(void* destination, int32_t value, size_t size);

	constexpr size_t strlen(const char* const str)
	{
		const char* current = str;

		while (*current)
		{
			current++;
		}

		return current - str;
	}

	constexpr size_t wcslen(const wchar_t* const str)
	{
		const wchar_t* current = str;

		while (*current)
		{
			current++;
		}

		return current - str;
	}

	constexpr int32_t strcmp(const char* first_str, const char* second_str)
	{
		while (*first_str != 0 && *first_str == *second_str)
		{
			first_str++;
			second_str++;
		}

		return static_cast<uint8_t>(*first_str) - static_cast<uint8_t>(*second_str);
	}

	constexpr int32_t wcscmp(const wchar_t* first_str, const wchar_t* second_str)
	{
		while (*first_str != 0 && *first_str == *second_str)
		{
			first_str++;
			second_str++;
		}

		return static_cast<uint32_t>(*first_str) - static_cast<uint32_t>(*second_str);
	}

	constexpr int32_t strncmp(const char* first_str, const char* second_str, size_t size)
	{
		while (0 < size--)
		{
			const uint8_t first = static_cast<uint8_t>(*first_str++);
			const uint8_t second = static_cast<uint8_t>(*second_str++);

			if (first != second)
			{
				return first - second;
			}

			if (first == '\0')
			{
				return 0;
			}
		}

		return 0;
	}

	constexpr int32_t wcsncmp(const wchar_t* first_str, const wchar_t* second_str, size_t size)
	{
		while (0 < size--)
		{
			const uint32_t first = static_cast<uint32_t>(*first_str++);
			const uint32_t second = static_cast<uint32_t>(*second_str++);

			if (first != second)
			{
				return first - second;
			}

			if (first == '\0')
			{
				return 0;
			}
		}

		return 0;
	}

	constexpr const char* strchr(const char* str, const char target)
	{
		do
		{
			if (*str == target)
			{
				return str;
			}
		} while (*str++);

		return nullptr;
	}

	constexpr const wchar_t* wcschr(const wchar_t* str, const wchar_t target)
	{
		do
		{
			if (*str == target)
			{
				return str;
			}
		} while (*str++);

		return nullptr;
	}

	constexpr const char* strstr(const char* const str, const char* const substr)
	{
		const size_t length = strlen(substr);

		if (!length)
		{
			return str;
		}

		for (const char* i = str; (i = strchr(i, *substr)) != nullptr; i++)
		{
			if (!strncmp(i, substr, length))
			{
				return i;
			}
		}

		return nullptr;
	}

	constexpr const wchar_t* wcsstr(const wchar_t* const str, const wchar_t* const substr)
	{
		const size_t length = wcslen(substr);

		if (!length)
		{
			return str;
		}

		for (const wchar_t* i = str; (i = wcschr(i, *substr)) != nullptr; i++)
		{
			if (!wcsncmp(i, substr, length))
			{
				return i;
			}
		}

		return nullptr;
	}
}
