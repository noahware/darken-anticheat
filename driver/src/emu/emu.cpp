#include "emu.hpp"
#include "array.hpp"

#include <ntddk.h>

[[nodiscard]] static bool check_dbgprompt()
{
	__try
	{
		cstd::array<char, 32> response;

		DbgPrompt("Hello? ", response.data(), sizeof(response));
	}
	__except (1)
	{
		return false;
	}

	return true;
}

bool emu::is_emulated()
{
	return check_dbgprompt();
}
