#pragma once
#include "exception.hpp"
#include "vector.hpp"
#include "array.hpp"
#include "types.hpp"

namespace cstd
{
	template <class T>
	class span
	{
	public:
		using size_type = size_t;
		using value_type = T;
		using pointer = value_type*;
		using reference = value_type&;

		constexpr static size_type npos = static_cast<size_type>(-1);

		constexpr span() noexcept = default;

		constexpr span(const pointer elements, const size_type count) noexcept
				:	elements_(elements),
					count_(count) { }

		constexpr span(const pointer elements_begin, const pointer elements_end) noexcept
				:	elements_(elements_begin),
					count_(static_cast<size_type>(elements_end - elements_begin)) { }

		constexpr span(vector<T>& elements) noexcept
				:	elements_(elements.begin()),
					count_(elements.size()) { }

		template <class U, size_type Count>
		constexpr span(array<U, Count>& array) noexcept
				:	elements_(array.data()),
					count_(Count) { }

		[[nodiscard]] constexpr pointer begin() const noexcept
		{
			return elements_;
		}

		[[nodiscard]] constexpr pointer end() const noexcept
		{
			return elements_ + count_;
		}

		[[nodiscard]] constexpr reference operator[](const size_type index) const
		{
			CSTD_ASSERT(index < count_, "[span] attempted to access outside of range of elements");

			return elements_[index];
		}

		[[nodiscard]] constexpr reference front() const
		{
			CSTD_ASSERT(count_ != 0, "[span] front() called on an empty span");

			return elements_[0];
		}

		[[nodiscard]] constexpr reference back() const
		{
			CSTD_ASSERT(count_ != 0, "[span] back() called on an empty span");

			return elements_[count_ - 1];
		}

		[[nodiscard]] constexpr size_type size() const noexcept
		{
			return count_;
		}

		[[nodiscard]] constexpr bool empty() const noexcept
		{
			return count_ == 0;
		}

		[[nodiscard]] constexpr pointer data() const noexcept
		{
			return elements_;
		}

		[[nodiscard]] constexpr span first(const size_type count) const noexcept
		{
			CSTD_ASSERT(count <= count_, "[span] first() count exceeds span size");

			return span(elements_, count);
		}

		[[nodiscard]] constexpr span last(const size_type count) const noexcept
		{
			CSTD_ASSERT(count <= count_, "[span] last() count exceeds span size");

			return span(elements_ + (count_ - count), count);
		}

		[[nodiscard]] constexpr span subspan(const size_type offset, const size_type count = npos) const noexcept
		{
			CSTD_ASSERT(offset <= count_, "[span] subspan() offset exceeds span size");

			const size_type length = (count == npos) ? (count_ - offset) : count;

			CSTD_ASSERT(length <= count_ - offset, "[span] subspan() range exceeds span size");

			return span(elements_ + offset, length);
		}

	protected:
		pointer elements_ = nullptr;
		size_type count_ = 0;
	};
}
