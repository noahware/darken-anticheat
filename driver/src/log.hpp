#pragma once

#ifdef DEBUG
#define DBG_LOG(format, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, format, __VA_ARGS__)
#else
#define DBG_LOG(format, ...)
#endif
