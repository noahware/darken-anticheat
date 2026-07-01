#pragma once
#include "exception.hpp"
#include "utility.hpp"
#include "crt.hpp"
#include "types.hpp"

namespace cstd
{
	template <class T, size_t Count>
	class array
	{
	public:
		using size_type = size_t;
		using value_type = T;
		using pointer = value_type*;
		using const_pointer = const value_type*;
		using reference = value_type&;
		using const_reference = const value_type&;

		[[nodiscard]] constexpr pointer begin() noexcept
		{
			return elements;
		}

		[[nodiscard]] constexpr pointer end() noexcept
		{
			return elements + Count;
		}

		[[nodiscard]] constexpr const_pointer begin() const noexcept
		{
			return elements;
		}

		[[nodiscard]] constexpr const_pointer end() const noexcept
		{
			return elements + Count;
		}

		[[nodiscard]] constexpr reference operator[](const size_type index)
		{
			CSTD_ASSERT(index < Count, "[array] attempted to access outside of range of elements");

			return elements[index];
		}

		[[nodiscard]] constexpr const_reference operator[](const size_type index) const
		{
			CSTD_ASSERT(index < Count, "[array] attempted to access outside of range of elements");

			return elements[index];
		}

		[[nodiscard]] constexpr reference at(const size_type index)
		{
			CSTD_ASSERT(index < Count, "[array] at() index out of range");

			return elements[index];
		}

		[[nodiscard]] constexpr const_reference at(const size_type index) const
		{
			CSTD_ASSERT(index < Count, "[array] at() index out of range");

			return elements[index];
		}

		[[nodiscard]] constexpr reference front()
		{
			CSTD_ASSERT(Count != 0, "[array] front() called on an empty array");

			return elements[0];
		}

		[[nodiscard]] constexpr const_reference front() const
		{
			CSTD_ASSERT(Count != 0, "[array] front() called on an empty array");

			return elements[0];
		}

		[[nodiscard]] constexpr reference back()
		{
			CSTD_ASSERT(Count != 0, "[array] back() called on an empty array");

			return elements[Count - 1];
		}

		[[nodiscard]] constexpr const_reference back() const
		{
			CSTD_ASSERT(Count != 0, "[array] back() called on an empty array");

			return elements[Count - 1];
		}

		[[nodiscard]] constexpr size_type size() const noexcept
		{
			return Count;
		}

		[[nodiscard]] constexpr bool empty() const noexcept
		{
			return Count == 0;
		}

		[[nodiscard]] constexpr pointer data() noexcept
		{
			return elements;
		}

		[[nodiscard]] constexpr const_pointer data() const noexcept
		{
			return elements;
		}

		constexpr void fill(const_reference value)
		{
			for (size_type i = 0; i < Count; ++i)
			{
				elements[i] = value;
			}
		}

		constexpr void swap(array& right) noexcept
		{
			for (size_type i = 0; i < Count; ++i)
			{
				cstd::swap(elements[i], right.elements[i]);
			}
		}

		value_type elements[Count];
	};

	template <class T, size_t Count>
	[[nodiscard]] constexpr bool operator==(const array<T, Count>& left, const array<T, Count>& right)
	{
		for (size_t i = 0; i < Count; ++i)
		{
			if (!(left[i] == right[i]))
			{
				return false;
			}
		}

		return true;
	}

	template <class T, size_t Count>
	[[nodiscard]] constexpr bool operator!=(const array<T, Count>& left, const array<T, Count>& right)
	{
		return !(left == right);
	}

	template <class T, size_t Count>
	[[nodiscard]] constexpr bool operator<(const array<T, Count>& left, const array<T, Count>& right)
	{
		for (size_t i = 0; i < Count; ++i)
		{
			if (left[i] < right[i])
			{
				return true;
			}

			if (right[i] < left[i])
			{
				return false;
			}
		}

		return false;
	}

	template <class T, size_t Count>
	[[nodiscard]] constexpr bool operator>(const array<T, Count>& left, const array<T, Count>& right)
	{
		return right < left;
	}

	template <class T, size_t Count>
	[[nodiscard]] constexpr bool operator<=(const array<T, Count>& left, const array<T, Count>& right)
	{
		return !(right < left);
	}

	template <class T, size_t Count>
	[[nodiscard]] constexpr bool operator>=(const array<T, Count>& left, const array<T, Count>& right)
	{
		return !(left < right);
	}
}
