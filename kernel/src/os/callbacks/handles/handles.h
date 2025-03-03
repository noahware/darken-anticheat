#pragma once
#include "../../../context/context.h"

namespace callbacks
{
	namespace handles
	{
		bool load(context::s_context* context);
		void unload(context::s_context* context);
	}
}
