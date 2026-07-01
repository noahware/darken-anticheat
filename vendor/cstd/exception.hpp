#pragma once

#if defined(_MSC_VER)
	#define CSTD_TRAP() __debugbreak()
#elif defined(__GNUC__) || defined(__clang__)
	#define CSTD_TRAP() __builtin_trap()
#else
	#define CSTD_TRAP() (*static_cast<volatile int*>(nullptr) = 0)
#endif

#define CSTD_ASSERT(condition, info_str) do { if (!(condition)) { CSTD_TRAP(); } } while (0)
