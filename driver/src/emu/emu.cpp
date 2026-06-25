#include "emu.hpp"

#include <intrin.h>

#include "array.hpp"

#include <ntddk.h>

#include "../krnl/krnl.hpp"
#include "../krnl/types.hpp"

using nt_system_debug_control_t = NTSTATUS(NTAPI*)(ULONG, PVOID, ULONG, PVOID, ULONG, PULONG);

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
	UNICODE_STRING name = { };
	RtlInitUnicodeString(&name, L"NtSystemDebugControl");

	const auto NtSystemDebugControl = static_cast<nt_system_debug_control_t>(
		MmGetSystemRoutineAddress(&name)
	);

	return NtSystemDebugControl(0, nullptr, 0, nullptr, 0, nullptr) != STATUS_DEBUGGER_INACTIVE;
}

[[nodiscard]] static _MMPFN* get_mm_pfn_entry(const uintptr_t phys_addr)
{
	const uintptr_t pfn = phys_addr >> PAGE_SHIFT;

	return &krnl::mm_pfn_database[pfn];
}

[[nodiscard]] static uint32_t get_mm_pfn_ref_count(const uintptr_t phys_addr)
{
	const _MMPFN* const entry = get_mm_pfn_entry(phys_addr);

	return entry->u3.ReferenceCount;
}

[[nodiscard]] static bool check_memory_manager_behavior()
{
	/*
		allocate physical page
		check it is in mmpfndatabase
		mmmapiospace that physical page, check if referencecount increments in mmpte
	*/

	constexpr PHYSICAL_ADDRESS low = { .QuadPart = 0 };
	constexpr PHYSICAL_ADDRESS high = { .QuadPart = -1 };  // no upper bound
	constexpr PHYSICAL_ADDRESS skip = { .QuadPart = 0 };

	// todo: handle cases where other things could tamper with this physical address we've just mapped
	const PMDL mdl = MmAllocatePagesForMdlEx(
		low, high, skip,
		PAGE_SIZE,          // one page
		MmCached,
		MM_ALLOCATE_FULLY_REQUIRED
	);

	const auto pfn_array = MmGetMdlPfnArray(mdl);
	const uintptr_t phys_addr = pfn_array[0] << PAGE_SHIFT;

	const auto original_ref_count = get_mm_pfn_ref_count(phys_addr);

	void* const map = MmMapIoSpace(PHYSICAL_ADDRESS{ .QuadPart = static_cast<LONGLONG>(phys_addr) }, PAGE_SIZE, MmCached);

	const auto mapped_ref_count = get_mm_pfn_ref_count(phys_addr);

	MmUnmapIoSpace(map, PAGE_SIZE);
	MmFreePagesFromMdl(mdl);
	ExFreePool(mdl);

	const auto expected_ref_count = mapped_ref_count + 1;

	return original_ref_count != expected_ref_count;
}

bool emu::is_emulated()
{
	return check_dbgprompt() || check_dbgctl_unchanged() || check_user_shared_data() || check_nt_debugger_fields() ||
		check_debugger_status_funcs() || check_memory_manager_behavior();
}
