#include "threads.h"
#include <driver/driver.h>

communication::e_detection_status detections::threads::is_suspicious_system_thread_present()
{
    return driver::send_call(communication::e_control_code::is_suspicious_system_thread_present, { }).detection_status;
}

communication::e_detection_status detections::threads::non_maskable_interrupts::send_and_analyze()
{
    return driver::send_call(communication::e_control_code::send_and_analyze_non_maskable_interrupts, { }).detection_status;
}

