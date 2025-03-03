#pragma once
#include "../../context/context.h"

struct _OB_PRE_OPERATION_INFORMATION;

namespace handles
{
	namespace permission_stripping
	{
		void on_pre_handle_operation(communication::s_protected_processes* protected_processes, _OB_PRE_OPERATION_INFORMATION* information, uint64_t current_process, uint64_t target_process);
	}
}
