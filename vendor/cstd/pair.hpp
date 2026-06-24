#pragma once
#include "utility.hpp"
#include "type_traits.hpp"

namespace cstd
{
	template <class First, class Second>
	class pair
	{
	public:
		using first_type = First;
		using second_type = Second;

		constexpr pair() noexcept = default;

		constexpr explicit pair(const first_type& first_in, const second_type& second_in) noexcept
			:	first(first_in),
				second(second_in) {}

		template <class U1, class U2>
		constexpr pair(U1&& first_in, U2&& second_in)
			:	first(forward<U1>(first_in)),
				second(forward<U2>(second_in)) {}

		template <class U1, class U2>
		constexpr pair(const pair<U1, U2>& right)
			:	first(right.first),
				second(right.second) {}

		constexpr void swap(pair& right) noexcept
		{
			cstd::swap(first, right.first);
			cstd::swap(second, right.second);
		}

		first_type first;
		second_type second;
	};

	template <class First, class Second>
	[[nodiscard]] constexpr bool operator==(const pair<First, Second>& left, const pair<First, Second>& right)
	{
		return left.first == right.first && left.second == right.second;
	}

	template <class First, class Second>
	[[nodiscard]] constexpr bool operator!=(const pair<First, Second>& left, const pair<First, Second>& right)
	{
		return !(left == right);
	}

	template <class First, class Second>
	[[nodiscard]] constexpr bool operator<(const pair<First, Second>& left, const pair<First, Second>& right)
	{
		return left.first < right.first || (!(right.first < left.first) && left.second < right.second);
	}

	template <class First, class Second>
	[[nodiscard]] constexpr bool operator>(const pair<First, Second>& left, const pair<First, Second>& right)
	{
		return right < left;
	}

	template <class First, class Second>
	[[nodiscard]] constexpr bool operator<=(const pair<First, Second>& left, const pair<First, Second>& right)
	{
		return !(right < left);
	}

	template <class First, class Second>
	[[nodiscard]] constexpr bool operator>=(const pair<First, Second>& left, const pair<First, Second>& right)
	{
		return !(left < right);
	}

	template <class First, class Second>
	[[nodiscard]] constexpr pair<decay_t<First>, decay_t<Second>> make_pair(First&& first, Second&& second)
	{
		return pair<decay_t<First>, decay_t<Second>>(forward<First>(first), forward<Second>(second));
	}
}
