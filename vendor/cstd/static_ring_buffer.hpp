#pragma once
#include "exception.hpp"
#include "type_traits.hpp"
#include "crt.hpp"
#include "utility.hpp"
#include "types.hpp"

namespace cstd
{
	template <class T, size_t N>
	class static_ring_buffer
	{
		static_assert(N > 0, "static_ring_buffer requires non-zero capacity");

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
				return elements_[(head_ + offset_) % N];
			}

			[[nodiscard]] pointer operator->() const noexcept
			{
				return &elements_[(head_ + offset_) % N];
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
			friend class static_ring_buffer;
			friend class const_iterator;

			iterator(pointer elements, size_type head, size_type offset) noexcept
				: elements_(elements), head_(head), offset_(offset) {}

			pointer elements_ = nullptr;
			size_type head_ = 0;
			size_type offset_ = 0;
		};

		class const_iterator
		{
		public:
			const_iterator() = default;

			const_iterator(const iterator& it) noexcept
				: elements_(it.elements_), head_(it.head_), offset_(it.offset_) {}

			[[nodiscard]] const_reference operator*() const noexcept
			{
				return elements_[(head_ + offset_) % N];
			}

			[[nodiscard]] const_pointer operator->() const noexcept
			{
				return &elements_[(head_ + offset_) % N];
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
			friend class static_ring_buffer;

			const_iterator(const_pointer elements, size_type head, size_type offset) noexcept
				: elements_(elements), head_(head), offset_(offset) {}

			const_pointer elements_ = nullptr;
			size_type head_ = 0;
			size_type offset_ = 0;
		};

		static_ring_buffer() = default;

		static_ring_buffer(const static_ring_buffer& right)
			: head_(0), size_(right.size_)
		{
			for (size_type i = 0; i < size_; ++i)
			{
				new (elements() + i) T(right[i]);
			}
		}

		static_ring_buffer& operator=(const static_ring_buffer& right)
		{
			if (this != &right)
			{
				destroy_all();
				head_ = 0;
				size_ = right.size_;

				for (size_type i = 0; i < size_; ++i)
				{
					new (elements() + i) T(right[i]);
				}
			}

			return *this;
		}

		static_ring_buffer(static_ring_buffer&& right) noexcept
			: head_(0), size_(right.size_)
		{
			for (size_type i = 0; i < size_; ++i)
			{
				new (elements() + i) T(cstd::move(right[i]));
			}

			right.destroy_all();
			right.head_ = 0;
			right.size_ = 0;
		}

		static_ring_buffer& operator=(static_ring_buffer&& right) noexcept
		{
			if (this != &right)
			{
				destroy_all();
				head_ = 0;
				size_ = right.size_;

				for (size_type i = 0; i < size_; ++i)
				{
					new (elements() + i) T(cstd::move(right[i]));
				}

				right.destroy_all();
				right.head_ = 0;
				right.size_ = 0;
			}

			return *this;
		}

		~static_ring_buffer()
		{
			destroy_all();
		}

		[[nodiscard]] reference front()
		{
			CSTD_ASSERT(!empty(), "[static_ring_buffer] front() called on empty buffer");

			return elements()[head_];
		}

		[[nodiscard]] const_reference front() const
		{
			CSTD_ASSERT(!empty(), "[static_ring_buffer] front() called on empty buffer");

			return elements()[head_];
		}

		[[nodiscard]] reference back()
		{
			CSTD_ASSERT(!empty(), "[static_ring_buffer] back() called on empty buffer");

			return elements()[prev_index(tail_index())];
		}

		[[nodiscard]] const_reference back() const
		{
			CSTD_ASSERT(!empty(), "[static_ring_buffer] back() called on empty buffer");

			return elements()[prev_index(tail_index())];
		}

		[[nodiscard]] reference operator[](const size_type index)
		{
			CSTD_ASSERT(index < size_, "[static_ring_buffer] index out of range");

			return elements()[physical_index(index)];
		}

		[[nodiscard]] const_reference operator[](const size_type index) const
		{
			CSTD_ASSERT(index < size_, "[static_ring_buffer] index out of range");

			return elements()[physical_index(index)];
		}

		[[nodiscard]] reference at(const size_type index)
		{
			CSTD_ASSERT(index < size_, "[static_ring_buffer] at() index out of range");

			return elements()[physical_index(index)];
		}

		[[nodiscard]] const_reference at(const size_type index) const
		{
			CSTD_ASSERT(index < size_, "[static_ring_buffer] at() index out of range");

			return elements()[physical_index(index)];
		}

		void push_back(const_reference value)
		{
			if (full())
			{
				destroy_at(head_);
				new (elements() + head_) T(value);
				head_ = next_index(head_);
			}
			else
			{
				new (elements() + tail_index()) T(value);
				++size_;
			}
		}

		void push_back(value_type&& value)
		{
			if (full())
			{
				destroy_at(head_);
				new (elements() + head_) T(cstd::move(value));
				head_ = next_index(head_);
			}
			else
			{
				new (elements() + tail_index()) T(cstd::move(value));
				++size_;
			}
		}

		template <class... Args>
		reference emplace_back(Args&&... args)
		{
			if (full())
			{
				const size_type slot = head_;
				destroy_at(slot);
				new (elements() + slot) T(forward<Args>(args)...);
				head_ = next_index(head_);
				return elements()[slot];
			}

			const size_type slot = tail_index();
			new (elements() + slot) T(forward<Args>(args)...);
			++size_;
			return elements()[slot];
		}

		void push_front(const_reference value)
		{
			if (full())
			{
				destroy_at(prev_index(tail_index()));
				head_ = prev_index(head_);
				new (elements() + head_) T(value);
			}
			else
			{
				head_ = prev_index(head_);
				new (elements() + head_) T(value);
				++size_;
			}
		}

		void push_front(value_type&& value)
		{
			if (full())
			{
				destroy_at(prev_index(tail_index()));
				head_ = prev_index(head_);
				new (elements() + head_) T(cstd::move(value));
			}
			else
			{
				head_ = prev_index(head_);
				new (elements() + head_) T(cstd::move(value));
				++size_;
			}
		}

		template <class... Args>
		reference emplace_front(Args&&... args)
		{
			if (full())
			{
				destroy_at(prev_index(tail_index()));
				head_ = prev_index(head_);
				new (elements() + head_) T(forward<Args>(args)...);
				return elements()[head_];
			}

			head_ = prev_index(head_);
			new (elements() + head_) T(forward<Args>(args)...);
			++size_;
			return elements()[head_];
		}

		void pop_front()
		{
			CSTD_ASSERT(!empty(), "[static_ring_buffer] pop_front on empty buffer");

			destroy_at(head_);
			head_ = next_index(head_);
			--size_;
		}

		void pop_back()
		{
			CSTD_ASSERT(!empty(), "[static_ring_buffer] pop_back on empty buffer");

			destroy_at(prev_index(tail_index()));
			--size_;
		}

		[[nodiscard]] bool try_push_back(const_reference value)
		{
			if (full())
			{
				return false;
			}

			new (elements() + tail_index()) T(value);
			++size_;
			return true;
		}

		[[nodiscard]] bool try_push_back(value_type&& value)
		{
			if (full())
			{
				return false;
			}

			new (elements() + tail_index()) T(cstd::move(value));
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
			new (elements() + head_) T(value);
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
			new (elements() + head_) T(cstd::move(value));
			++size_;
			return true;
		}

		[[nodiscard]] bool try_pop_front(reference out)
		{
			if (empty())
			{
				return false;
			}

			out = cstd::move(elements()[head_]);
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
			out = cstd::move(elements()[slot]);
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

		[[nodiscard]] static constexpr size_type capacity() noexcept
		{
			return N;
		}

		[[nodiscard]] bool empty() const noexcept
		{
			return size_ == 0;
		}

		[[nodiscard]] bool full() const noexcept
		{
			return size_ == N;
		}

		[[nodiscard]] iterator begin() noexcept
		{
			return iterator(elements(), head_, 0);
		}

		[[nodiscard]] iterator end() noexcept
		{
			return iterator(elements(), head_, size_);
		}

		[[nodiscard]] const_iterator begin() const noexcept
		{
			return const_iterator(elements(), head_, 0);
		}

		[[nodiscard]] const_iterator end() const noexcept
		{
			return const_iterator(elements(), head_, size_);
		}

		void swap(static_ring_buffer& other) noexcept
		{
			if (this == &other)
			{
				return;
			}

			if constexpr (is_trivially_copyable_v<T>)
			{
				constexpr size_type chunk = 256;
				byte tmp[chunk];

				for (size_type off = 0; off < sizeof(storage_); off += chunk)
				{
					const size_type len = (sizeof(storage_) - off < chunk) ? sizeof(storage_) - off : chunk;
					crt::memcpy(tmp, storage_ + off, len);
					crt::memcpy(storage_ + off, other.storage_ + off, len);
					crt::memcpy(other.storage_ + off, tmp, len);
				}

				const size_type tmp_head = head_;
				const size_type tmp_size = size_;
				head_ = other.head_;
				size_ = other.size_;
				other.head_ = tmp_head;
				other.size_ = tmp_size;
			}
			else
			{
				const size_type a_size = size_;
				const size_type b_size = other.size_;
				const size_type min_sz = a_size < b_size ? a_size : b_size;

				for (size_type i = 0; i < min_sz; ++i)
				{
					const size_type a_phys = physical_index(i);
					const size_type b_phys = other.physical_index(i);
					T tmp(cstd::move(elements()[a_phys]));
					elements()[a_phys] = cstd::move(other.elements()[b_phys]);
					other.elements()[b_phys] = cstd::move(tmp);
				}

				if (a_size > b_size)
				{
					for (size_type i = min_sz; i < a_size; ++i)
					{
						const size_type a_phys = physical_index(i);
						const size_type b_phys = other.physical_index(i);
						new (other.elements() + b_phys) T(cstd::move(elements()[a_phys]));
						destroy_at(a_phys);
					}
				}
				else if (b_size > a_size)
				{
					for (size_type i = min_sz; i < b_size; ++i)
					{
						const size_type a_phys = physical_index(i);
						const size_type b_phys = other.physical_index(i);
						new (elements() + a_phys) T(cstd::move(other.elements()[b_phys]));
						other.destroy_at(b_phys);
					}
				}

				size_ = b_size;
				other.size_ = a_size;
			}
		}

	private:
		[[nodiscard]] pointer elements() noexcept
		{
			return static_cast<pointer>(static_cast<void*>(storage_));
		}

		[[nodiscard]] const_pointer elements() const noexcept
		{
			return static_cast<const_pointer>(static_cast<const void*>(storage_));
		}

		[[nodiscard]] size_type physical_index(const size_type logical) const noexcept
		{
			return (head_ + logical) % N;
		}

		[[nodiscard]] size_type tail_index() const noexcept
		{
			return (head_ + size_) % N;
		}

		[[nodiscard]] size_type next_index(const size_type index) const noexcept
		{
			return (index + 1) % N;
		}

		[[nodiscard]] size_type prev_index(const size_type index) const noexcept
		{
			return (index + N - 1) % N;
		}

		void destroy_at(const size_type physical)
		{
			if constexpr (!is_trivially_destructible_v<T>)
			{
				elements()[physical].~T();
			}
		}

		void destroy_all() noexcept
		{
			if constexpr (!is_trivially_destructible_v<T>)
			{
				for (size_type i = 0; i < size_; ++i)
				{
					elements()[physical_index(i)].~T();
				}
			}
		}

		alignas(T) byte storage_[N * sizeof(T)];
		size_type head_;
		size_type size_;
	};

	template <class T, size_t N>
	[[nodiscard]] bool operator==(const static_ring_buffer<T, N>& left, const static_ring_buffer<T, N>& right) noexcept
	{
		if (left.size() != right.size())
		{
			return false;
		}

		for (typename static_ring_buffer<T, N>::size_type i = 0; i < left.size(); ++i)
		{
			if (!(left[i] == right[i]))
			{
				return false;
			}
		}

		return true;
	}

	template <class T, size_t N>
	[[nodiscard]] bool operator!=(const static_ring_buffer<T, N>& left, const static_ring_buffer<T, N>& right) noexcept
	{
		return !(left == right);
	}

	template <class T, size_t N>
	[[nodiscard]] bool operator<(const static_ring_buffer<T, N>& left, const static_ring_buffer<T, N>& right) noexcept
	{
		const typename static_ring_buffer<T, N>::size_type min_size = left.size() < right.size() ? left.size() : right.size();

		for (typename static_ring_buffer<T, N>::size_type i = 0; i < min_size; ++i)
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

	template <class T, size_t N>
	[[nodiscard]] bool operator>(const static_ring_buffer<T, N>& left, const static_ring_buffer<T, N>& right) noexcept
	{
		return right < left;
	}

	template <class T, size_t N>
	[[nodiscard]] bool operator<=(const static_ring_buffer<T, N>& left, const static_ring_buffer<T, N>& right) noexcept
	{
		return !(right < left);
	}

	template <class T, size_t N>
	[[nodiscard]] bool operator>=(const static_ring_buffer<T, N>& left, const static_ring_buffer<T, N>& right) noexcept
	{
		return !(left < right);
	}

	template <class T, size_t N>
	void swap(static_ring_buffer<T, N>& left, static_ring_buffer<T, N>& right) noexcept
	{
		left.swap(right);
	}
}
