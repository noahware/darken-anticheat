#pragma once
#include <communication_types.h>

struct s_machine_frame
{
	uint64_t rip;
	uint64_t cs;
	uint64_t rflags;
	uint64_t rsp;
	uint64_t ss;
};