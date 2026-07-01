#pragma once
#include "type_traits.hpp"

namespace cstd
{
	template <class T>
	struct remove_reference
	{
		using type = T;
	};

	template <class T>
	struct remove_reference<T&>
	{
		using type = T;
	};

	template <class T>
	struct remove_reference<T&&>
	{
		using type = T;
	};

	template <typename T>
	using remove_reference_t = typename remove_reference<T>::type;

	template <class T, class Y>
	[[nodiscard]] constexpr T bit_cast(const Y& object) noexcept
	{
		static_assert(sizeof(T) == sizeof(Y), "bit_cast types differ in size");
		static_assert(is_trivially_copyable_v<T> && is_trivially_copyable_v<Y>,
			"bit_cast requires types to be trivially copyable");

		return __builtin_bit_cast(T, object);
	}

	template <typename T>
	constexpr remove_reference_t<T>&& move(T&& object) noexcept
	{
		return static_cast<remove_reference_t<T>&&>(object);
	}

	template <class T>
	constexpr T&& forward(remove_reference_t<T>& object) noexcept
	{
		return static_cast<T&&>(object);
	}

	template <class T>
	constexpr T&& forward(remove_reference_t<T>&& object) noexcept
	{
		static_assert(!is_lvalue_reference_v<T>, "cstd::forward must not forward an rvalue as an lvalue");

		return static_cast<T&&>(object);
	}

	template <class T>
	constexpr void swap(T& left, T& right) noexcept
	{
		T temp = move(left);
		left = move(right);
		right = move(temp);
	}

	template <class T, class U = T>
	constexpr T exchange(T& object, U&& new_value)
	{
		T old_value = move(object);
		object = forward<U>(new_value);

		return old_value;
	}

	template <class T>
	[[nodiscard]] constexpr const T& min(const T& left, const T& right) noexcept
	{
		return right < left ? right : left;
	}

	template <class T>
	[[nodiscard]] constexpr const T& max(const T& left, const T& right) noexcept
	{
		return left < right ? right : left;
	}

	template <class T>
	[[nodiscard]] constexpr const T& clamp(const T& value, const T& low, const T& high) noexcept
	{
		return value < low ? low : (high < value ? high : value);
	}
}
