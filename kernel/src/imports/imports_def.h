#pragma once
#include "generic_types.h"

typedef void(__stdcall* t_iof_complete_request)(void* irp, int8_t priority_boost);
typedef uint64_t(__stdcall* t_ex_allocate_pool_2)(uint64_t pool_flags, uint64_t number_of_bytes, uint32_t tag);
typedef void(__stdcall* t_ex_free_pool_with_tag)(uint64_t pool, uint32_t tag);
typedef uint32_t(__stdcall* t_ob_register_callbacks)(void* callback_registration, void** registration_handle);
typedef void(__stdcall* t_ob_unregister_callbacks)(void* registration_handle);
typedef uint32_t(__stdcall* t_io_create_symbolic_link)(void* symbolic_link_name, void* device_name);
typedef uint32_t(__stdcall* t_io_create_device)(void* driver_object, uint32_t device_extension_size, void* device_name, uint32_t device_type, uint32_t device_characteristics, uint8_t exclusive, void* device_object);
typedef void(__stdcall* t_io_delete_device)(void* device_object);
typedef uint32_t(__stdcall* t_io_delete_symbolic_link)(void* symbolic_link_name);
typedef uint32_t(__stdcall* t_ps_lookup_thread_by_thread_id)(uint64_t thread_id, void* thread_out);
typedef uint8_t(__stdcall* t_ps_is_system_thread)(uint64_t thread);
typedef void(__stdcall* t_ke_stack_attach_process)(uint64_t eprocess, void* apc_state);
typedef void(__stdcall* t_ke_unstack_detach_process)(void* apc_state);
typedef uint64_t(__stdcall* t_mm_get_physical_address)(uint64_t virtual_address);
typedef uint64_t(__stdcall* t_mm_get_virtual_for_physical)(uint64_t physical_address);
typedef void(__stdcall* t_hal_send_nmi)(void* affinity);
typedef uint32_t(__stdcall* t_ke_query_active_processor_count)(void* active_processors_affinity);
typedef void(__stdcall* t_ke_initialize_affinity_ex)(void* affinity);
typedef void(__stdcall* t_ke_add_processor_affinity_ex)(void* affinity, uint32_t index);
typedef uint64_t(__stdcall* t_ke_register_nmi_callback)(void* handler_function, void* context);
typedef uint32_t(__stdcall* t_ke_deregister_nmi_callback)(uint64_t callback_handle);
typedef uint32_t(__stdcall* t_ke_delay_execution_thread)(int8_t wait_mode, uint8_t alertable, void* interval);
typedef uint64_t(__fastcall* t_hvl_switch_virtual_address_space)(int64_t cr3);

namespace imports
{
	struct s_imports
	{
		uint16_t* nt_build_number;
		uint64_t ps_loaded_module_list;
		uint64_t ps_process_type;
		uint32_t* hvl_enlightenments;

		t_ex_allocate_pool_2 ex_allocate_pool_2;
		t_ex_free_pool_with_tag ex_free_pool_with_tag;
		t_iof_complete_request iof_complete_request;
		t_ob_register_callbacks ob_register_callbacks;
		t_ob_unregister_callbacks ob_unregister_callbacks;
		t_io_create_symbolic_link io_create_symbolic_link;
		t_io_create_device io_create_device;
		t_io_delete_device io_delete_device;
		t_io_delete_symbolic_link io_delete_symbolic_link;
		t_ps_lookup_thread_by_thread_id ps_lookup_thread_by_thread_id;
		t_ps_is_system_thread ps_is_system_thread;
		t_ke_stack_attach_process ke_stack_attach_process;
		t_ke_unstack_detach_process ke_unstack_detach_process;
		t_mm_get_physical_address mm_get_physical_address;
		t_mm_get_virtual_for_physical mm_get_virtual_for_physical;
		t_ke_query_active_processor_count ke_query_active_processor_count;
		t_ke_initialize_affinity_ex ke_initialize_affinity_ex;
		t_ke_add_processor_affinity_ex ke_add_processor_affinity_ex;
		t_hal_send_nmi hal_send_nmi;
		t_ke_register_nmi_callback ke_register_nmi_callback;
		t_ke_deregister_nmi_callback ke_deregister_nmi_callback;
		t_ke_delay_execution_thread ke_delay_execution_thread;
		t_hvl_switch_virtual_address_space hvl_switch_virtual_address_space;
	};
}
