#pragma once
#include <cstdint>

struct s_rtl_process_module_information
{
	uint64_t section;
	uint64_t mapped_base;
	uint64_t image_base;
	uint32_t image_size;
	uint32_t flags;
	uint16_t load_order_index;
	uint16_t init_order_index;
	uint16_t load_count;
	uint16_t offset_to_file_name;
	char full_path_name[256];
};

struct s_rtl_process_modules
{
	uint32_t module_count;
	s_rtl_process_module_information modules[1];
};
