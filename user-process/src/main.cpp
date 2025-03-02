#include <driver/driver.h>
#include <detections/detections.h>
#include "protected_process/protected_process.h"

#include <Windows.h>

#include <thread>
#include <chrono>
#include <iostream>

int main()
{
	std::cout << "[darken-anticheat] started usermode process of anticheat.\n";

	if (driver::load() == false)
	{
		std::cout << "[darken-anticheat] unable to load driver.\n";

		return false;
	}

	std::cout << "[darken-anticheat] loaded driver successfully.\n";

	if (protected_process::load() == false)
	{
		std::cout << "[darken-anticheat] unable to load protected process.\n";

		return false;
	}

	std::cout << "[darken-anticheat] loaded protected process successfully.\n";

	while (true)
	{
		d_check_detection(detections::anti_debug::is_peb_debug_flag_present);
		d_check_detection(detections::modules::local_process::is_unsigned_module_present);
		d_check_detection(detections::modules::kernel::is_unsigned_module_present);
		d_check_detection(detections::modules::kernel::validate_ntoskrnl_integrity);
		d_check_detection(detections::threads::is_suspicious_system_thread_present);
		d_check_detection(detections::threads::non_maskable_interrupts::send_and_analyze);
		d_check_detection(detections::process::is_suspicious_thread_present, static_cast<std::uint64_t>(GetCurrentProcessId()));
		d_check_detection(detections::process::is_suspicious_thread_present, protected_process::process_id);
		d_check_detection(detections::hypervisor::check_reserved_msr_usage);

		// if patchguard checks are being violated or if patchguard context not present
		// then uncommenting next line will cause a system crash
		//d_check_detection(detections::patchguard::trigger_bugcheck);

		std::this_thread::sleep_for(std::chrono::milliseconds(250));
	}

	driver::unload();

	return 0;
}
