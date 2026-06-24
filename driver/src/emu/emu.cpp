#include "emu.hpp"

#include <intrin.h>

#include "array.hpp"

#include <ntddk.h>

extern "C" NTSTATUS NTAPI NtSystemDebugControl(ULONG Command, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, PULONG ReturnLength);

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

[[nodiscard]] static bool check_dbgctl_unchanged()
{
	_disable();

	constexpr uint32_t dbgctl_msr_id = 0x1D9;
	const uint64_t original_value = __readmsr(dbgctl_msr_id);

	__writemsr(dbgctl_msr_id, original_value ^ 3);

	const uint64_t written_value = __readmsr(dbgctl_msr_id);
	__writemsr(dbgctl_msr_id, original_value);

	_enable();

	// was the write shadowed? this happens in certain environments like WHP
	return written_value == original_value;
}

[[nodiscard]] static bool check_user_shared_data()
{
	return SharedUserData->KdDebuggerEnabled;
}

[[nodiscard]] static bool check_nt_debugger_fields()
{
	return KdDebuggerEnabled || !KdDebuggerNotPresent;
}

[[nodiscard]] static bool check_debugger_status_funcs()
{
	return NtSystemDebugControl(0, nullptr, 0, nullptr, 0, nullptr) != STATUS_DEBUGGER_INACTIVE;
}

bool emu::is_emulated()
{
	return check_dbgprompt() || check_dbgctl_unchanged() || check_user_shared_data() || check_nt_debugger_fields() || check_debugger_status_funcs();
}
