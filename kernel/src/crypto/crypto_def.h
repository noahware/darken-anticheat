#pragma once
#include "generic_types.h"

namespace context { struct s_context; }

namespace crypto
{
	class s_hash
	{
	public:
		uint8_t* buffer;
		uint32_t buffer_size;

		bool is_same(s_hash& other);
		void free_hash_buffer(context::s_context* context);
	};

	class s_hash_list_entry : public s_hash
	{
	private:
		s_hash_list_entry* next;
		s_hash_list_entry* previous;

		uint64_t identifier;

		static s_hash_list_entry* allocate_memory_for_entry(context::s_context* context);

	public:
		static s_hash_list_entry* create_first_entry(context::s_context* context);

		s_hash_list_entry* add_entry(context::s_context* context);
		s_hash_list_entry* add_entry(context::s_context* context, s_hash hash);

		void delete_self(context::s_context* context);

		s_hash_list_entry* get_next();
		void set_next(s_hash_list_entry* new_next);

		s_hash_list_entry* get_previous();
		void set_previous(s_hash_list_entry* new_previous);

		uint64_t get_identifier();
		void set_identifier(uint64_t new_identifier);
	};
}
