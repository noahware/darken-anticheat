#pragma once
#include "exception.hpp"
#include "type_traits.hpp"
#include "crt.hpp"
#include "utility.hpp"
#include "types.hpp"

namespace cstd
{
	template <class T>
	class ring_buffer
	{
	public:
		using size_type = size_t;
		using value_type = T;
		using pointer = value_type*;
		using const_pointer = const value_type*;
		using reference = value_type&;
		using const_reference = const value_type&;

		class iterator
		{
		public:
			iterator() = default;

			[[nodiscard]] reference operator*() const noexcept
			{
				return elements_[(head_ + offset_) % capacity_];
			}

			[[nodiscard]] pointer operator->() const noexcept
			{
				return &elements_[(head_ + offset_) % capacity_];
			}

			iterator& operator++() noexcept
			{
				++offset_;
				return *this;
			}

			iterator operator++(int) noexcept
			{
				iterator tmp = *this;
				++offset_;
				return tmp;
			}

			iterator& operator--() noexcept
			{
				--offset_;
				return *this;
			}

			iterator operator--(int) noexcept
			{
				iterator tmp = *this;
				--offset_;
				return tmp;
			}

			[[nodiscard]] bool operator==(const iterator& right) const noexcept
			{
				return offset_ == right.offset_;
			}

			[[nodiscard]] bool operator!=(const iterator& right) const noexcept
			{
				return offset_ != right.offset_;
			}

		private:
			friend class ring_buffer;
			friend class const_iterator;

			iterator(pointer elements, size_type capacity, size_type head, size_type offset) noexcept
				: elements_(elements), capacity_(capacity), head_(head), offset_(offset) {}

			pointer elements_ = nullptr;
			size_type capacity_ = 0;
			size_type head_ = 0;
			size_type offset_ = 0;
		};

		class const_iterator
		{
		public:
			const_iterator() = default;

			const_iterator(const iterator& it) noexcept
				: elements_(it.elements_), capacity_(it.capacity_), head_(it.head_), offset_(it.offset_) {}

			[[nodiscard]] const_reference operator*() const noexcept
			{
				return elements_[(head_ + offset_) % capacity_];
			}

			[[nodiscard]] const_pointer operator->() const noexcept
			{
				return &elements_[(head_ + offset_) % capacity_];
			}

			const_iterator& operator++() noexcept
			{
				++offset_;
				return *this;
			}

			const_iterator operator++(int) noexcept
			{
				const_iterator tmp = *this;
				++offset_;
				return tmp;
			}

			const_iterator& operator--() noexcept
			{
				--offset_;
				return *this;
			}

			const_iterator operator--(int) noexcept
			{
				const_iterator tmp = *this;
				--offset_;
				return tmp;
			}

			[[nodiscard]] bool operator==(const const_iterator& right) const noexcept
			{
				return offset_ == right.offset_;
			}

			[[nodiscard]] bool operator!=(const const_iterator& right) const noexcept
			{
				return offset_ != right.offset_;
			}

		private:
			friend class ring_buffer;

			const_iterator(const_pointer elements, size_type capacity, size_type head, size_type offset) noexcept
				: elements_(elements), capacity_(capacity), head_(head), offset_(offset) {}

			const_pointer elements_ = nullptr;
			size_type capacity_ = 0;
			size_type head_ = 0;
			size_type offset_ = 0;
		};

		ring_buffer() = default;

		explicit ring_buffer(const size_type capacity)
			: elements_(allocate(capacity)),
			  capacity_(capacity) {}

		ring_buffer(const ring_buffer& right)
			: elements_(allocate(right.capacity_)),
			  capacity_(right.capacity_),
			  head_(0),
			  size_(right.size_)
		{
			for (size_type i = 0; i < right.size_; ++i)
			{
				new (elements_ + i) T(right[i]);
			}
		}

		ring_buffer& operator=(const ring_buffer& right)
		{
			if (this != &right)
			{
				destroy_all();

				if (capacity_ != right.capacity_)
				{
					free_elements();
					elements_ = allocate(right.capacity_);
					capacity_ = right.capacity_;
				}

				head_ = 0;
				size_ = right.size_;

				for (size_type i = 0; i < right.size_; ++i)
				{
					new (elements_ + i) T(right[i]);
				}
			}

			return *this;
		}

		ring_buffer(ring_buffer&& right) noexcept
			: elements_(right.elements_),
			  capacity_(right.capacity_),
			  head_(right.head_),
			  size_(right.size_)
		{
			right.elements_ = nullptr;
			right.capacity_ = 0;
			right.head_ = 0;
			right.size_ = 0;
		}

		ring_buffer& operator=(ring_buffer&& right) noexcept
		{
			if (this != &right)
			{
				destroy_all();
				free_elements();

				elements_ = right.elements_;
				capacity_ = right.capacity_;
				head_ = right.head_;
				size_ = right.size_;

				right.elements_ = nullptr;
				right.capacity_ = 0;
				right.head_ = 0;
				right.size_ = 0;
			}

			return *this;
		}

		~ring_buffer()
		{
			destroy_all();
			free_elements();
		}

		[[nodiscard]] reference front()
		{
			CSTD_ASSERT(!empty(), "[ring_buffer] front() called on empty buffer");

			return elements_[head_];
		}

		[[nodiscard]] const_reference front() const
		{
			CSTD_ASSERT(!empty(), "[ring_buffer] front() called on empty buffer");

			return elements_[head_];
		}

		[[nodiscard]] reference back()
		{
			CSTD_ASSERT(!empty(), "[ring_buffer] back() called on empty buffer");

			return elements_[prev_index(tail_index())];
		}

		[[nodiscard]] const_reference back() const
		{
			CSTD_ASSERT(!empty(), "[ring_buffer] back() called on empty buffer");

			return elements_[prev_index(tail_index())];
		}

		[[nodiscard]] reference operator[](const size_type index)
		{
			CSTD_ASSERT(index < size_, "[ring_buffer] index out of range");

			return elements_[physical_index(index)];
		}

		[[nodiscard]] const_reference operator[](const size_type index) const
		{
			CSTD_ASSERT(index < size_, "[ring_buffer] index out of range");

			return elements_[physical_index(index)];
		}

		[[nodiscard]] reference at(const size_type index)
		{
			CSTD_ASSERT(index < size_, "[ring_buffer] at() index out of range");

			return elements_[physical_index(index)];
		}

		[[nodiscard]] const_reference at(const size_type index) const
		{
			CSTD_ASSERT(index < size_, "[ring_buffer] at() index out of range");

			return elements_[physical_index(index)];
		}

		void push_back(const_reference value)
		{
			CSTD_ASSERT(capacity_ > 0, "[ring_buffer] push_back on zero-capacity buffer");

			if (full())
			{
				destroy_at(head_);
				new (elements_ + head_) T(value);
				head_ = next_index(head_);
			}
			else
			{
				new (elements_ + tail_index()) T(value);
				++size_;
			}
		}

		void push_back(value_type&& value)
		{
			CSTD_ASSERT(capacity_ > 0, "[ring_buffer] push_back on zero-capacity buffer");

			if (full())
			{
				destroy_at(head_);
				new (elements_ + head_) T(move(value));
				head_ = next_index(head_);
			}
			else
			{
				new (elements_ + tail_index()) T(move(value));
				++size_;
			}
		}

		template <class... Args>
		reference emplace_back(Args&&... args)
		{
			CSTD_ASSERT(capacity_ > 0, "[ring_buffer] emplace_back on zero-capacity buffer");

			if (full())
			{
				const size_type slot = head_;
				destroy_at(slot);
				new (elements_ + slot) T(forward<Args>(args)...);
				head_ = next_index(head_);
				return elements_[slot];
			}

			const size_type slot = tail_index();
			new (elements_ + slot) T(forward<Args>(args)...);
			++size_;
			return elements_[slot];
		}

		void push_front(const_reference value)
		{
			CSTD_ASSERT(capacity_ > 0, "[ring_buffer] push_front on zero-capacity buffer");

			if (full())
			{
				destroy_at(prev_index(tail_index()));
				head_ = prev_index(head_);
				new (elements_ + head_) T(value);
			}
			else
			{
				head_ = prev_index(head_);
				new (elements_ + head_) T(value);
				++size_;
			}
		}

		void push_front(value_type&& value)
		{
			CSTD_ASSERT(capacity_ > 0, "[ring_buffer] push_front on zero-capacity buffer");

			if (full())
			{
				destroy_at(prev_index(tail_index()));
				head_ = prev_index(head_);
				new (elements_ + head_) T(move(value));
			}
			else
			{
				head_ = prev_index(head_);
				new (elements_ + head_) T(move(value));
				++size_;
			}
		}

		template <class... Args>
		reference emplace_front(Args&&... args)
		{
			CSTD_ASSERT(capacity_ > 0, "[ring_buffer] emplace_front on zero-capacity buffer");

			if (full())
			{
				destroy_at(prev_index(tail_index()));
				head_ = prev_index(head_);
				new (elements_ + head_) T(forward<Args>(args)...);
				return elements_[head_];
			}

			head_ = prev_index(head_);
			new (elements_ + head_) T(forward<Args>(args)...);
			++size_;
			return elements_[head_];
		}

		void pop_front()
		{
			CSTD_ASSERT(!empty(), "[ring_buffer] pop_front on empty buffer");

			destroy_at(head_);
			head_ = next_index(head_);
			--size_;
		}

		void pop_back()
		{
			CSTD_ASSERT(!empty(), "[ring_buffer] pop_back on empty buffer");

			destroy_at(prev_index(tail_index()));
			--size_;
		}

		[[nodiscard]] bool try_push_back(const_reference value)
		{
			if (full())
			{
				return false;
			}

			new (elements_ + tail_index()) T(value);
			++size_;
			return true;
		}

		[[nodiscard]] bool try_push_back(value_type&& value)
		{
			if (full())
			{
				return false;
			}

			new (elements_ + tail_index()) T(move(value));
			++size_;
			return true;
		}

		[[nodiscard]] bool try_push_front(const_reference value)
		{
			if (full())
			{
				return false;
			}

			head_ = prev_index(head_);
			new (elements_ + head_) T(value);
			++size_;
			return true;
		}

		[[nodiscard]] bool try_push_front(value_type&& value)
		{
			if (full())
			{
				return false;
			}

			head_ = prev_index(head_);
			new (elements_ + head_) T(move(value));
			++size_;
			return true;
		}

		[[nodiscard]] bool try_pop_front(reference out)
		{
			if (empty())
			{
				return false;
			}

			out = move(elements_[head_]);
			destroy_at(head_);
			head_ = next_index(head_);
			--size_;
			return true;
		}

		[[nodiscard]] bool try_pop_back(reference out)
		{
			if (empty())
			{
				return false;
			}

			const size_type slot = prev_index(tail_index());
			out = move(elements_[slot]);
			destroy_at(slot);
			--size_;
			return true;
		}

		void clear() noexcept
		{
			destroy_all();
			head_ = 0;
			size_ = 0;
		}

		[[nodiscard]] size_type size() const noexcept
		{
			return size_;
		}

		[[nodiscard]] size_type capacity() const noexcept
		{
			return capacity_;
		}

		[[nodiscard]] bool empty() const noexcept
		{
			return size_ == 0;
		}

		[[nodiscard]] bool full() const noexcept
		{
			return size_ == capacity_;
		}

		[[nodiscard]] iterator begin() noexcept
		{
			return iterator(elements_, capacity_, head_, 0);
		}

		[[nodiscard]] iterator end() noexcept
		{
			return iterator(elements_, capacity_, head_, size_);
		}

		[[nodiscard]] const_iterator begin() const noexcept
		{
			return const_iterator(elements_, capacity_, head_, 0);
		}

		[[nodiscard]] const_iterator end() const noexcept
		{
			return const_iterator(elements_, capacity_, head_, size_);
		}

		void swap(ring_buffer& other) noexcept
		{
			pointer const tmp_elements = elements_;
			const size_type tmp_capacity = capacity_;
			const size_type tmp_head = head_;
			const size_type tmp_size = size_;

			elements_ = other.elements_;
			capacity_ = other.capacity_;
			head_ = other.head_;
			size_ = other.size_;

			other.elements_ = tmp_elements;
			other.capacity_ = tmp_capacity;
			other.head_ = tmp_head;
			other.size_ = tmp_size;
		}

	private:
		[[nodiscard]] size_type physical_index(const size_type logical) const noexcept
		{
			return (head_ + logical) % capacity_;
		}

		[[nodiscard]] size_type tail_index() const noexcept
		{
			return (head_ + size_) % capacity_;
		}

		[[nodiscard]] size_type next_index(const size_type index) const noexcept
		{
			return (index + 1) % capacity_;
		}

		[[nodiscard]] size_type prev_index(const size_type index) const noexcept
		{
			return (index + capacity_ - 1) % capacity_;
		}

		void destroy_at(const size_type physical)
		{
			if constexpr (!is_trivially_destructible_v<T>)
			{
				elements_[physical].~T();
			}
		}

		void destroy_all() noexcept
		{
			if constexpr (!is_trivially_destructible_v<T>)
			{
				for (size_type i = 0; i < size_; ++i)
				{
					elements_[physical_index(i)].~T();
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

		static pointer allocate(const size_type capacity)
		{
			if (capacity == 0)
			{
				return nullptr;
			}

			pointer const result = static_cast<pointer>(crt::malloc(capacity * sizeof(value_type)));

			CSTD_ASSERT(result != nullptr, "[ring_buffer] allocation failed");

			return result;
		}

		pointer elements_ = nullptr;
		size_type capacity_ = 0;
		size_type head_ = 0;
		size_type size_ = 0;
	};

	template <class T>
	[[nodiscard]] bool operator==(const ring_buffer<T>& left, const ring_buffer<T>& right) noexcept
	{
		if (left.size() != right.size())
		{
			return false;
		}

		for (typename ring_buffer<T>::size_type i = 0; i < left.size(); ++i)
		{
			if (!(left[i] == right[i]))
			{
				return false;
			}
		}

		return true;
	}

	template <class T>
	[[nodiscard]] bool operator!=(const ring_buffer<T>& left, const ring_buffer<T>& right) noexcept
	{
		return !(left == right);
	}

	template <class T>
	[[nodiscard]] bool operator<(const ring_buffer<T>& left, const ring_buffer<T>& right) noexcept
	{
		const typename ring_buffer<T>::size_type min_size = left.size() < right.size() ? left.size() : right.size();

		for (typename ring_buffer<T>::size_type i = 0; i < min_size; ++i)
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
	[[nodiscard]] bool operator>(const ring_buffer<T>& left, const ring_buffer<T>& right) noexcept
	{
		return right < left;
	}

	template <class T>
	[[nodiscard]] bool operator<=(const ring_buffer<T>& left, const ring_buffer<T>& right) noexcept
	{
		return !(right < left);
	}

	template <class T>
	[[nodiscard]] bool operator>=(const ring_buffer<T>& left, const ring_buffer<T>& right) noexcept
	{
		return !(left < right);
	}

	template <class T>
	void swap(ring_buffer<T>& left, ring_buffer<T>& right) noexcept
	{
		left.swap(right);
	}
}
