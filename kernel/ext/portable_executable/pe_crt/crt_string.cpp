#include "crt_string.hpp"

portable_executable::pe_crt::size_t portable_executable::pe_crt::strlen(const char* str)
{
    const char* temp;

    for (temp = str; *temp; ++temp);

    return (temp - str);
}

portable_executable::pe_crt::size_t portable_executable::pe_crt::wstrlen(const wchar_t* str)
{
	const wchar_t* temp;

	for (temp = str; *temp; ++temp);

	return (temp - str) / sizeof(wchar_t);
}

portable_executable::pe_crt::int32_t portable_executable::pe_crt::strcmp(const char* str1, const char* str2)
{
    for (; *str1 == *str2; str1++, str2++)
    {
        if (*str1 == '\0')
        {
            return 0;
        }
    }

    return ((*reinterpret_cast<const pe_crt::uint8_t*>(str1) < *reinterpret_cast<const pe_crt::uint8_t*>(str2)) ? -1 : +1);
}

portable_executable::pe_crt::int32_t portable_executable::pe_crt::strncmp(const char* s1, const char* s2, pe_crt::size_t n)
{
	if (n == 0)
	{
		return 0;
	}

	do
	{
		if (*s1 != *s2++)
		{
			return (*reinterpret_cast<const pe_crt::uint8_t*>(s1) - *reinterpret_cast<const pe_crt::uint8_t*>(--s2));
		}

		if (*s1++ == 0)
		{
			break;
		}
	}
	while (--n != 0);

	return 0;
}

portable_executable::pe_crt::int32_t portable_executable::pe_crt::wstrncmp(const wchar_t* s1, const wchar_t* s2, pe_crt::size_t n)
{
	if (n == 0)
	{
		return 0;
	}

	do
	{
		if (*s1 != *s2++)
		{
			return (*reinterpret_cast<const pe_crt::uint8_t*>(s1) - *reinterpret_cast<const pe_crt::uint8_t*>(--s2));
		}

		if (*s1++ == 0)
		{
			break;
		}
	} while (--n != 0);

	return 0;
}

portable_executable::pe_crt::wchar_t* portable_executable::pe_crt::wcsstr(const wchar_t* s, const wchar_t* find)
{
	wchar_t c, sc;

	pe_crt::size_t len;

	if ((c = *find++) != 0)
	{
		len = pe_crt::wstrlen(find);

		do
		{
			do
			{
				if ((sc = *s++) == 0)
				{
					return nullptr;
				}
			}
			while (sc != c);
		}
		while (pe_crt::wstrncmp(s, find, len) != 0);

		s--;
	}

	return const_cast<wchar_t*>(s);
}

char* portable_executable::pe_crt::strstr(const char* s, const char* find)
{
	char c, sc;

	pe_crt::size_t len;

	if ((c = *find++) != 0)
	{
		len = pe_crt::strlen(find);

		do
		{
			do
			{
				if ((sc = *s++) == 0)
				{
					return nullptr;
				}
			} while (sc != c);
		} while (pe_crt::strncmp(s, find, len) != 0);

		s--;
	}

	return const_cast<char*>(s);
}

char* portable_executable::pe_crt::strcpy(char* to, const char* from)
{
	char* save = to;

	for (; (*to = *from) != '\0'; ++from, ++to);

	return(save);
}
