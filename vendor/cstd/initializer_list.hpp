#pragma once
#include "types.hpp"

namespace cstd
{
	template <class T>
	class initializer_list
	{
	public:
		using size_type = size_t;
		using value_type = T;
		using const_pointer = const value_type*;

		constexpr initializer_list() = default;

		constexpr initializer_list(const_pointer const begin, const_pointer const end)
				:	begin_(begin),
					end_(end) { }

		template <size_type Count>
		explicit constexpr initializer_list(const T(&array)[Count])
				:	begin_(array),
					end_(array + Count) {}

		[[nodiscard]] constexpr const_pointer begin() const noexcept
		{
			return begin_;
		}

		[[nodiscard]] constexpr const_pointer end() const noexcept
		{
			return end_;
		}

		[[nodiscard]] constexpr size_type size() const noexcept
		{
			return end_ - begin_;
		}

	protected:
		const_pointer begin_ = nullptr;
		const_pointer end_ = nullptr;
	};
}
