#pragma once
#include "exception.hpp"
#include "initializer_list.hpp"
#include "type_traits.hpp"
#include "crt.hpp"
#include "utility.hpp"
#include "types.hpp"

namespace cstd
{
	template <class T>
	class vector
	{
	public:
		using size_type = size_t;
		using value_type = T;
		using pointer = value_type*;
		using const_pointer = const value_type*;
		using reference = value_type&;
		using const_reference = const value_type&;

		vector() = default;

		explicit vector(const size_type size, const_reference default_value = T())
		{
			reserve(size);

			for (size_type i = 0; i < size; i++)
			{
				push_back(default_value);
			}
		}

		explicit vector(const const_pointer buffer, const size_type size)
		{
			reserve(size);

			for (size_type i = 0; i < size; i++)
			{
				push_back(buffer[i]);
			}
		}

		template <class Y>
		vector(const initializer_list<Y> list)
		{
			reserve(list.size());

			for (const Y& entry : list)
			{
				push_back(static_cast<value_type>(entry));
			}
		}

		vector(const vector& right)
		{
			reserve(right.size());

			for (size_type i = 0; i < right.size(); i++)
			{
				push_back(right[i]);
			}
		}

		vector& operator=(const vector& right)
		{
			discard_elements();

			reserve(right.size());

			for (size_type i = 0; i < right.size(); i++)
			{
				push_back(right[i]);
			}

			return *this;
		}

		vector(vector&& right) noexcept
				:	elements_(right.elements_),
					size_(right.size_),
					max_size_(right.max_size_)
		{
			right.elements_ = nullptr;
			right.size_ = 0;
			right.max_size_ = 0;
		}

		vector& operator=(vector&& right) noexcept
		{
			if (this != &right)
			{
				discard_elements();

				elements_ = right.elements_;
				size_ = right.size_;
				max_size_ = right.max_size_;

				right.elements_ = nullptr;
				right.size_ = 0;
				right.max_size_ = 0;
			}

			return *this;
		}

		~vector()
		{
			discard_elements();
		}

		[[nodiscard]] pointer begin() noexcept
		{
			return elements_;
		}

		[[nodiscard]] pointer end() noexcept
		{
			return elements_ + size_;
		}

		[[nodiscard]] const_pointer begin() const noexcept
		{
			return elements_;
		}

		[[nodiscard]] const_pointer end() const noexcept
		{
			return elements_ + size_;
		}

		[[nodiscard]] reference front()
		{
			CSTD_ASSERT(!empty(), "[vector] front() called on an empty vector");

			return *begin();
		}

		[[nodiscard]] const_reference front() const
		{
			CSTD_ASSERT(!empty(), "[vector] front() called on an empty vector");

			return *begin();
		}

		[[nodiscard]] reference back()
		{
			CSTD_ASSERT(!empty(), "[vector] back() called on an empty vector");

			return *(end() - 1);
		}

		[[nodiscard]] const_reference back() const
		{
			CSTD_ASSERT(!empty(), "[vector] back() called on an empty vector");

			return *(end() - 1);
		}

		[[nodiscard]] reference operator[](const size_type index)
		{
			CSTD_ASSERT(index < size_, "[vector] attempted to access outside of range of elements");

			return elements_[index];
		}

		[[nodiscard]] const_reference operator[](const size_type index) const
		{
			CSTD_ASSERT(index < size_, "[vector] attempted to access outside of range of elements");

			return elements_[index];
		}

		[[nodiscard]] reference at(const size_type index)
		{
			CSTD_ASSERT(index < size_, "[vector] at() index out of range");

			return elements_[index];
		}

		[[nodiscard]] const_reference at(const size_type index) const
		{
			CSTD_ASSERT(index < size_, "[vector] at() index out of range");

			return elements_[index];
		}

		[[nodiscard]] size_type size() const noexcept
		{
			return size_;
		}

		[[nodiscard]] size_type max_size() const noexcept
		{
			return max_size_;
		}

		[[nodiscard]] size_type capacity() const noexcept
		{
			return max_size_;
		}

		[[nodiscard]] pointer data() noexcept
		{
			return elements_;
		}

		[[nodiscard]] const_pointer data() const noexcept
		{
			return elements_;
		}

		void push_back(const_reference value)
		{
			if (max_size_ <= size_)
			{
				grow_elements();
			}

			new (elements_ + size_) T(value);

			++size_;
		}

		void push_back(value_type&& value)
		{
			if (max_size_ <= size_)
			{
				grow_elements();
			}

			new (elements_ + size_) T(move(value));

			++size_;
		}

		template <class... Args>
		reference emplace_back(Args&&... args)
		{
			if (max_size_ <= size_)
			{
				grow_elements();
			}

			pointer const slot = elements_ + size_;

			new (slot) T(forward<Args>(args)...);

			++size_;

			return *slot;
		}

		pointer insert(const const_pointer position, const_reference value)
		{
			const size_type index = prepare_insert_range(position, 1);

			new (elements_ + index) T(value);

			return elements_ + index;
		}

		pointer insert(const const_pointer position, value_type&& value)
		{
			const size_type index = prepare_insert_range(position, 1);

			new (elements_ + index) T(move(value));

			return elements_ + index;
		}

		pointer insert(const const_pointer position, const const_pointer first, const const_pointer last)
		{
			const size_type count = static_cast<size_type>(last - first);
			const size_type index = prepare_insert_range(position, count);

			for (size_type i = 0; i < count; ++i)
			{
				new (elements_ + index + i) T(first[i]);
			}

			return elements_ + index;
		}

		void pop_back()
		{
			CSTD_ASSERT(size_ != 0, "[vector] attempted to pop back empty vector");

			size_--;

			const auto current = elements_ + size_;

			deconstruct_elements(current, current + 1);
		}

		pointer erase(const const_pointer position) noexcept
		{
			return erase(position, position + 1);
		}

		pointer erase(const const_pointer first, const const_pointer last) noexcept
		{
			CSTD_ASSERT(begin() <= first && first <= last && last <= end(), "[vector] erase range out of range");

			const size_type index = static_cast<size_type>(first - begin());
			const size_type count = static_cast<size_type>(last - first);

			if (count == 0)
			{
				return begin() + index;
			}

			for (size_type i = index; i + count < size_; ++i)
			{
				elements_[i] = move(elements_[i + count]);
			}

			deconstruct_elements(elements_ + (size_ - count), elements_ + size_);

			size_ -= count;

			return begin() + index;
		}

		void reserve(const size_type size)
		{
			if (0 < size && max_size_ < size)
			{
				pointer const new_elements = allocate_elements(size);

				CSTD_ASSERT(new_elements != nullptr, "[vector] unable to reserve elements");

				move_elements(new_elements);
				free_elements();

				elements_ = new_elements;
				max_size_ = size;
			}
		}

		void resize(const size_type new_size)
		{
			if (new_size < size_)
			{
				pointer const start = begin() + new_size;
				pointer const end = begin() + size_;

				deconstruct_elements(start, end);
			}
			else
			{
				if (max_size_ < new_size)
				{
					reserve(new_size);
				}

				for (size_type i = size_; i < new_size; ++i)
				{
					new (elements_ + i) T();
				}
			}

			size_ = new_size;
		}

		void resize(const size_type new_size, const_reference value)
		{
			if (new_size < size_)
			{
				deconstruct_elements(begin() + new_size, begin() + size_);
			}
			else
			{
				if (max_size_ < new_size)
				{
					reserve(new_size);
				}

				for (size_type i = size_; i < new_size; ++i)
				{
					new (elements_ + i) T(value);
				}
			}

			size_ = new_size;
		}

		void swap(vector& other) noexcept
		{
			pointer const other_elements = other.elements_;
			const size_type other_size = other.size_;
			const size_type other_max_size = other.max_size_;

			other.elements_ = elements_;
			other.size_ = size_;
			other.max_size_ = max_size_;

			elements_ = other_elements;
			size_ = other_size;
			max_size_ = other_max_size;
		}

		void assign(const size_type count, const_reference value)
		{
			clear();
			reserve(count);

			for (size_type i = 0; i < count; ++i)
			{
				push_back(value);
			}
		}

		void assign(const const_pointer first, const const_pointer last)
		{
			const size_type count = static_cast<size_type>(last - first);

			clear();
			reserve(count);

			for (size_type i = 0; i < count; ++i)
			{
				push_back(first[i]);
			}
		}

		template <class Y>
		void assign(const initializer_list<Y> list)
		{
			clear();
			reserve(list.size());

			for (const Y& entry : list)
			{
				push_back(static_cast<value_type>(entry));
			}
		}

		void shrink_to_fit()
		{
			if (size_ == max_size_)
			{
				return;
			}

			if (size_ == 0)
			{
				free_elements();

				max_size_ = 0;

				return;
			}

			pointer const new_elements = allocate_elements(size_);

			CSTD_ASSERT(new_elements != nullptr, "[vector] unable to shrink elements");

			move_elements(new_elements);
			free_elements();

			elements_ = new_elements;
			max_size_ = size_;
		}

		void clear() noexcept
		{
			deconstruct_elements(begin(), end());

			size_ = 0;
		}

		[[nodiscard]] bool empty() const noexcept
		{
			return size_ == 0;
		}

	protected:
		constexpr static size_type growth_factor = 2;

		void grow_elements()
		{
			const size_type new_size = max_size_ ? max_size_ * growth_factor : 1;

			pointer const new_elements = allocate_elements(new_size);

			CSTD_ASSERT(new_elements != nullptr, "[vector] unable to grow elements");

			move_elements(new_elements);
			free_elements();

			elements_ = new_elements;
			max_size_ = new_size;
		}

		size_type prepare_insert_range(const const_pointer position, const size_type count)
		{
			CSTD_ASSERT(begin() <= position && position <= end(), "[vector] insert position out of range");

			const size_type index = static_cast<size_type>(position - begin());

			if (count == 0)
			{
				return index;
			}

			if (max_size_ < size_ + count)
			{
				size_type target = max_size_ ? max_size_ * growth_factor : 1;

				if (target < size_ + count)
				{
					target = size_ + count;
				}

				reserve(target);
			}

			const size_type new_size = size_ + count;

			// Shift the tail right by `count`, walking high-to-low so a source is read
			// before it is overwritten. Slots at or past the old size_ are raw
			// (move-construct); slots still inside the old range are live (move-assign).
			for (size_type destination = new_size; destination-- > index + count; )
			{
				const size_type source = destination - count;

				if (destination >= size_)
				{
					new (elements_ + destination) T(move(elements_[source]));
				}
				else
				{
					elements_[destination] = move(elements_[source]);
				}
			}

			// The hole [index, index + count) now holds moved-from live objects only
			// where it overlaps the old range; destroy those so the caller can construct.
			const size_type live_hole_end = (index + count < size_) ? (index + count) : size_;

			deconstruct_elements(elements_ + index, elements_ + live_hole_end);

			size_ = new_size;

			return index;
		}

		void deconstruct_elements(pointer const start, pointer const end)
		{
			if constexpr (!is_trivially_destructible_v<T>)
			{
				for (pointer current = start; current < end; ++current)
				{
					current->~T();
				}
			}
		}

		void move_elements(pointer const new_elements)
		{
			if (!elements_)
			{
				return;
			}

			if constexpr (is_trivially_copyable_v<T>)
			{
				crt::memcpy(new_elements, elements_, size_ * sizeof(value_type));
			}
			else
			{
				for (size_type i = 0; i < size_; ++i)
				{
					new (new_elements + i) T(move(elements_[i]));

					elements_[i].~T();
				}
			}
		}

		void free_elements()
		{
			if (elements_)
			{
				crt::free(elements_);

				elements_ = nullptr;
			}
		}

		void discard_elements()
		{
			deconstruct_elements(begin(), end());
			free_elements();

			size_ = 0;
			max_size_ = 0;
		}

		static pointer allocate_elements(const size_type new_size)
		{
			if (new_size == 0)
			{
				return nullptr;
			}

			const size_type new_elements_size = new_size * sizeof(value_type);

			return static_cast<pointer>(crt::malloc(new_elements_size));
		}

		pointer elements_ = nullptr;

		size_type size_ = 0;
		size_type max_size_ = 0;
	};

	template <class T>
	[[nodiscard]] bool operator==(const vector<T>& left, const vector<T>& right) noexcept
	{
		if (left.size() != right.size())
		{
			return false;
		}

		for (typename vector<T>::size_type i = 0; i < left.size(); ++i)
		{
			if (!(left[i] == right[i]))
			{
				return false;
			}
		}

		return true;
	}

	template <class T>
	[[nodiscard]] bool operator!=(const vector<T>& left, const vector<T>& right) noexcept
	{
		return !(left == right);
	}

	template <class T>
	[[nodiscard]] bool operator<(const vector<T>& left, const vector<T>& right) noexcept
	{
		const typename vector<T>::size_type min_size = left.size() < right.size() ? left.size() : right.size();

		for (typename vector<T>::size_type i = 0; i < min_size; ++i)
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

		return left.size() < right.size();
	}

	template <class T>
	[[nodiscard]] bool operator>(const vector<T>& left, const vector<T>& right) noexcept
	{
		return right < left;
	}

	template <class T>
	[[nodiscard]] bool operator<=(const vector<T>& left, const vector<T>& right) noexcept
	{
		return !(right < left);
	}

	template <class T>
	[[nodiscard]] bool operator>=(const vector<T>& left, const vector<T>& right) noexcept
	{
		return !(left < right);
	}

	template <class T>
	void swap(vector<T>& left, vector<T>& right) noexcept
	{
		left.swap(right);
	}
}
