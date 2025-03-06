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
			communication::e_detection_status validate_ntoskrnl_integrity();
			communication::e_detection_status validate_kernel_drivers_integrity();
			communication::e_detection_status is_any_driver_data_section_executable();
		}
	}
}
