#pragma once

#ifndef _detections_include_guard
#define _detections_include_guard
#include "anti_debug/anti_debug.h"
#endif

#ifndef d_check_detection
// will add 'release' version later which will contain a way to broadcast to server
#define d_check_detection(function)\
	{ e_detection_status detection_status = function();\
	if (detection_status == e_detection_status::flagged)\
	{\
		std::cout << "[darken-anticheat] flagged: '" << #function << "'.\n";\
	}\
	else if (detection_status == e_detection_status::runtime_error)\
	{\
		std::cout << "[darken-anticheat] runtime error at function: '" << #function << "'.\n";\
	}}
#endif
