#pragma once

namespace portable_executable::pe_crt
{
	using int8_t		= __int8;
	using int16_t		= __int16;
	using int32_t		= __int32;
	using int64_t		= __int64;

	using uint8_t		= unsigned __int8;
	using uint16_t		= unsigned __int16;
	using uint32_t		= unsigned __int32;
	using uint64_t		= unsigned __int64;

	using size_t = unsigned __int64;
	using uintptr_t = unsigned __int64;

	using wchar_t = unsigned __int16;
}