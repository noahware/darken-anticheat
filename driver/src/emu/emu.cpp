#include "emu.hpp"

#include <intrin.h>

#include "array.hpp"

#include <ntddk.h>

#include "../log.hpp"
#include "../util/import.hpp"
#include "../krnl/krnl.hpp"
#include "../krnl/types.hpp"
#include "../krnl/nt_status.hpp"

using zw_system_debug_control_t = NTSTATUS(NTAPI*)(ULONG, PVOID, ULONG, PVOID, ULONG, PULONG);

[[nodiscard]] static bool check_dbgprompt()
{
	__try
	{
		cstd::array<char, 32> response;

		LIMPORT(DbgPrompt)("Hello? ", response.data(), sizeof(response));
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
	UNICODE_STRING name = { };
	LIMPORT(RtlInitUnicodeString)(&name, L"ZwSystemDebugControl");

	const auto ZwSystemDebugControl = static_cast<zw_system_debug_control_t>(
		LIMPORT(MmGetSystemRoutineAddress)(&name)
	);

	if (!ZwSystemDebugControl)
	{
		return false;
	}

	return ZwSystemDebugControl(0, nullptr, 0, nullptr, 0, nullptr) != nt_status::debugger_inactive();
}

bool emu::is_emulated()
{
	return check_dbgprompt() || check_dbgctl_unchanged() || check_user_shared_data() || check_nt_debugger_fields() ||
		check_debugger_status_funcs();
}
