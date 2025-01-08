#pragma once
#include <communication_types.h>

namespace detections
{
	namespace threads
	{
		communication::e_detection_status is_suspicious_system_thread_present();

		namespace non_maskable_interrupts
		{
			communication::e_detection_status send_and_analyze();
		}
	}
}