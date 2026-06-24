#pragma once
#include "span.hpp"
#include "array.hpp"
#include "string.hpp"
#include "utility.hpp"

namespace cstd
{
	using hash_type = uint64_t;

	template <class T>
	constexpr static hash_type hash_bytes(const span<const T> input) noexcept
	{
		static_assert(sizeof(T) == sizeof(byte), "T must be size of byte");

		constexpr hash_type basis = 0xcbf29ce484222325;
		constexpr hash_type prime = 0x100000001B3;

		hash_type output = basis;

		for (const T i : input)
		{
			output ^= i;
			output *= prime;
		}

		return output;
	}

	template <class T>
	class hash
	{
	public:
		using size_type = size_t;

		[[nodiscard]] constexpr hash_type operator()(const T& value) const
		{
			static_assert(is_trivially_copyable_v<T>, "T is not trivially copyable");

			using bytes_type = array<byte, sizeof(T)>;
			const bytes_type bytes = bit_cast<bytes_type>(value);

			return hash_bytes(span<const byte>{ bytes.data(), bytes.size() });
		}
	};

	template <>
	class hash<string_view>
	{
	public:
		[[nodiscard]] constexpr hash_type operator()(const string_view& value) const
		{
			return hash_bytes<string_view::character_type>(span{ value.data(), value.size() });
		}
	};

	template <>
	class hash<string>
	{
	public:
		[[nodiscard]] hash_type operator()(const string& value) const
		{
			return hash_bytes(span{ reinterpret_cast<const byte*>(value.data()), value.size() });
		}
	};
}
