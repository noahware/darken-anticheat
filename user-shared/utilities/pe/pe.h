#pragma once
#include <string>

namespace utilities
{
	namespace pe
	{
		bool has_embedded_signature(std::wstring_view binary_path);
		bool has_catalog_signature(std::wstring_view binary_path);

		bool is_digitally_signed(std::wstring_view binary_path);
	}
}
