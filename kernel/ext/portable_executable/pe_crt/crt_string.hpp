#pragma once

#include "crt_types.hpp"

namespace portable_executable::pe_crt
{
	pe_crt::size_t strlen(const char* str);
	pe_crt::size_t wstrlen(const wchar_t* str);

	pe_crt::int32_t strcmp(const char* str1, const char* str2);

	pe_crt::int32_t strncmp(const char* s1, const char* s2, pe_crt::size_t n);
	pe_crt::int32_t wstrncmp(const wchar_t* s1, const wchar_t* s2, pe_crt::size_t n);

	char* strstr(const char* s, const char* find);
	wchar_t* wcsstr(const wchar_t* s, const wchar_t* find);

	char* strcpy(char* to, const char* from);
}