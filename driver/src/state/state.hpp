#pragma once
#include <list.hpp>

#include "protected_process.hpp"

namespace state
{
	inline cstd::single_linked_list<protected_process_t> protected_procs;
}
