#include "permission_stripping.h"
#include "../../os/ntkrnl/ntkrnl.h"
#include "../../log.h"
#include <ntifs.h>

#define d_process_query_limited_information 0x1000

void handles::permission_stripping::on_pre_handle_operation(communication::s_protected_processes* protected_processes, _OB_PRE_OPERATION_INFORMATION* information, uint64_t current_process, uint64_t target_process)
{
	if (current_process == target_process)
	{
		return;
	}

	uint64_t target_process_id = ntkrnl::get_process_id(target_process);

	if (target_process_id == protected_processes->anticheat_usermode_id || target_process_id == protected_processes->protected_process_id)
	{
		// todo: send flags when we get here and be able to differenciate between malicious creators or not
		// might have to monitor whitelisted processes too to prevent people abusing them by injecting dlls into them and then opening handles from there

		information->Operation == OB_OPERATION_HANDLE_CREATE ?
			information->Parameters->CreateHandleInformation.DesiredAccess = (SYNCHRONIZE | d_process_query_limited_information) :
			information->Parameters->DuplicateHandleInformation.DesiredAccess = (SYNCHRONIZE | d_process_query_limited_information);

		d_log("[darken-anticheat] blocked handle being opened to (process id: 0x%llx) from (process id: 0x%llx).\n", target_process_id, ntkrnl::get_process_id(current_process));
	}
}
