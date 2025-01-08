#pragma once
#include "../../context/context.h"

namespace system
{
	namespace non_maskable_interrupts
	{
		communication::e_detection_status send_and_analyze(context::s_context* context);
	}
}
