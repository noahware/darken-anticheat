#pragma once
#include <communication_types.h>

namespace detections
{
	namespace modules
	{
		namespace local_process
		{
			communication::e_detection_status is_unsigned_module_present();
		}

		namespace kernel
		{
			communication::e_detection_status is_unsigned_module_present();
		}
	}
}
