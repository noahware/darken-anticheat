#pragma once
#include "types.hpp"
#include "atomic.hpp"
#include "utility.hpp"

namespace cstd
{
	template <class T>
	class base_ptr
	{
	public:
		using size_type = size_t;
		using value_type = T;
		using pointer = value_type*;
		using const_pointer = const value_type*;
		using reference = value_type&;
		using const_reference = const value_type&;

		base_ptr() noexcept = default;

		explicit base_ptr(const pointer object)
				:	object_(object) { }

		[[nodiscard]] pointer get() const noexcept
		{
			return object_;
		}

		[[nodiscard]] reference operator*() const noexcept
		{
			return *object_;
		}

		[[nodiscard]] pointer operator->() const noexcept
		{
			return object_;
		}

		[[nodiscard]] explicit operator bool() const noexcept
		{
			return object_ != nullptr;
		}

	protected:
		pointer object_ = nullptr;
	};

	template <class T>
	class unique_ptr : public base_ptr<T>
	{
	public:
		using pointer = typename base_ptr<T>::pointer;

		unique_ptr() noexcept = default;

		explicit unique_ptr(const pointer object)
				:	base_ptr<T>(object) { }

		template <class U> friend class unique_ptr;

		template <class To, class From>
		friend unique_ptr<To> static_pointer_cast(unique_ptr<From>&&) noexcept;

		template <class To, class From>
		friend unique_ptr<To> const_pointer_cast(unique_ptr<From>&&) noexcept;

		template <class To, class From>
		friend unique_ptr<To> reinterpret_pointer_cast(unique_ptr<From>&&) noexcept;

		template <class U>
		unique_ptr(unique_ptr<U>&& right) noexcept
				:	base_ptr<T>(right.object_)
		{
			right.object_ = nullptr;
		}

		unique_ptr(const unique_ptr&) = delete;
		unique_ptr& operator=(const unique_ptr&) = delete;

		unique_ptr(unique_ptr&& right) noexcept
				:	base_ptr<T>(right.object_)
		{
			right.object_ = nullptr;
		}

		unique_ptr& operator=(unique_ptr&& right) noexcept
		{
			if (this != &right)
			{
				reset();

				this->object_ = right.object_;

				right.object_ = nullptr;
			}

			return *this;
		}

		~unique_ptr() noexcept
		{
			reset();
		}

		void reset() noexcept
		{
			if (this->object_)
			{
				delete this->object_;

				this->object_ = nullptr;
			}
		}
	};

	template <class T>
	class shared_ptr : public base_ptr<T>
	{
	public:
		using size_type = typename base_ptr<T>::size_type;
		using pointer = typename base_ptr<T>::pointer;

		shared_ptr() noexcept = default;
		
		explicit shared_ptr(const pointer object, atomic<size_type>* const reference_count)
				:	base_ptr<T>(object),
					reference_count_(reference_count) { }

		shared_ptr(const shared_ptr& right)
				:	base_ptr<T>(right.object_),
					reference_count_(right.reference_count_)
		{
			if (reference_count_)
			{
				reference_count_->fetch_add(1, memory_order::relaxed);
			}
		}

		template <class U> friend class shared_ptr;

		template <class To, class From>
		friend shared_ptr<To> static_pointer_cast(const shared_ptr<From>&) noexcept;

		template <class To, class From>
		friend shared_ptr<To> const_pointer_cast(const shared_ptr<From>&) noexcept;

		template <class To, class From>
		friend shared_ptr<To> reinterpret_pointer_cast(const shared_ptr<From>&) noexcept;

		template <class U>
		shared_ptr(const shared_ptr<U>& right) noexcept
				:	base_ptr<T>(right.object_),
					reference_count_(right.reference_count_)
		{
			if (reference_count_)
			{
				reference_count_->fetch_add(1, memory_order::relaxed);
			}
		}

		template <class U>
		shared_ptr(shared_ptr<U>&& right) noexcept
				:	base_ptr<T>(right.object_),
					reference_count_(right.reference_count_)
		{
			right.object_ = nullptr;
			right.reference_count_ = nullptr;
		}

		shared_ptr& operator=(const shared_ptr& right)
		{
			if (this != &right)
			{
				reset();

				this->object_ = right.object_;
				reference_count_ = right.reference_count_;

				if (reference_count_)
				{
					reference_count_->fetch_add(1, memory_order::relaxed);
				}
			}

			return *this;
		}

		shared_ptr(shared_ptr&& right) noexcept
				:	base_ptr<T>(right.object_),
					reference_count_(right.reference_count_)
		{
			right.object_ = nullptr;
			right.reference_count_ = nullptr;
		}

		shared_ptr& operator=(shared_ptr&& right) noexcept
		{
			if (this != &right)
			{
				reset();

				this->object_ = right.object_;
				reference_count_ = right.reference_count_;

				right.object_ = nullptr;
				right.reference_count_ = nullptr;
			}

			return *this;
		}

		~shared_ptr() noexcept
		{
			reset();
		}

		void reset() noexcept
		{
			if (reference_count_)
			{
				if (reference_count_->fetch_sub(1, memory_order::acq_rel) == 1)
				{
					delete this->object_;
					delete reference_count_;
				}

				this->object_ = nullptr;
				reference_count_ = nullptr;
			}
		}

	protected:
		atomic<size_type>* reference_count_ = nullptr;
	};

	// unique_ptr comparisons

	template <class T, class U>
	[[nodiscard]] bool operator==(const unique_ptr<T>& left, const unique_ptr<U>& right) noexcept
	{
		return left.get() == right.get();
	}

	template <class T, class U>
	[[nodiscard]] bool operator!=(const unique_ptr<T>& left, const unique_ptr<U>& right) noexcept
	{
		return left.get() != right.get();
	}

	template <class T, class U>
	[[nodiscard]] bool operator<(const unique_ptr<T>& left, const unique_ptr<U>& right) noexcept
	{
		return left.get() < right.get();
	}

	template <class T, class U>
	[[nodiscard]] bool operator>(const unique_ptr<T>& left, const unique_ptr<U>& right) noexcept
	{
		return right < left;
	}

	template <class T, class U>
	[[nodiscard]] bool operator<=(const unique_ptr<T>& left, const unique_ptr<U>& right) noexcept
	{
		return !(right < left);
	}

	template <class T, class U>
	[[nodiscard]] bool operator>=(const unique_ptr<T>& left, const unique_ptr<U>& right) noexcept
	{
		return !(left < right);
	}

	template <class T>
	[[nodiscard]] bool operator==(const unique_ptr<T>& left, decltype(nullptr)) noexcept
	{
		return !left;
	}

	template <class T>
	[[nodiscard]] bool operator==(decltype(nullptr), const unique_ptr<T>& right) noexcept
	{
		return !right;
	}

	template <class T>
	[[nodiscard]] bool operator!=(const unique_ptr<T>& left, decltype(nullptr)) noexcept
	{
		return static_cast<bool>(left);
	}

	template <class T>
	[[nodiscard]] bool operator!=(decltype(nullptr), const unique_ptr<T>& right) noexcept
	{
		return static_cast<bool>(right);
	}

	// shared_ptr comparisons

	template <class T, class U>
	[[nodiscard]] bool operator==(const shared_ptr<T>& left, const shared_ptr<U>& right) noexcept
	{
		return left.get() == right.get();
	}

	template <class T, class U>
	[[nodiscard]] bool operator!=(const shared_ptr<T>& left, const shared_ptr<U>& right) noexcept
	{
		return left.get() != right.get();
	}

	template <class T, class U>
	[[nodiscard]] bool operator<(const shared_ptr<T>& left, const shared_ptr<U>& right) noexcept
	{
		return left.get() < right.get();
	}

	template <class T, class U>
	[[nodiscard]] bool operator>(const shared_ptr<T>& left, const shared_ptr<U>& right) noexcept
	{
		return right < left;
	}

	template <class T, class U>
	[[nodiscard]] bool operator<=(const shared_ptr<T>& left, const shared_ptr<U>& right) noexcept
	{
		return !(right < left);
	}

	template <class T, class U>
	[[nodiscard]] bool operator>=(const shared_ptr<T>& left, const shared_ptr<U>& right) noexcept
	{
		return !(left < right);
	}

	template <class T>
	[[nodiscard]] bool operator==(const shared_ptr<T>& left, decltype(nullptr)) noexcept
	{
		return !left;
	}

	template <class T>
	[[nodiscard]] bool operator==(decltype(nullptr), const shared_ptr<T>& right) noexcept
	{
		return !right;
	}

	template <class T>
	[[nodiscard]] bool operator!=(const shared_ptr<T>& left, decltype(nullptr)) noexcept
	{
		return static_cast<bool>(left);
	}

	template <class T>
	[[nodiscard]] bool operator!=(decltype(nullptr), const shared_ptr<T>& right) noexcept
	{
		return static_cast<bool>(right);
	}

	template <class T, class... Args>
	unique_ptr<T> make_unique(Args&&... args)
	{
		T* object = new T(forward<Args>(args)...);

		return unique_ptr<T>(object);
	}

	template <class T, class... Args>
	shared_ptr<T> make_shared(Args&&... args)
	{
		T* object = new T(forward<Args>(args)...);
		auto* count = new atomic<typename shared_ptr<T>::size_type>(1);

		return shared_ptr<T>(object, count);
	}

	template <class To, class From>
	[[nodiscard]] unique_ptr<To> static_pointer_cast(unique_ptr<From>&& ptr) noexcept
	{
		From* raw = ptr.object_;
		ptr.object_ = nullptr;

		return unique_ptr<To>(static_cast<To*>(raw));
	}

	template <class To, class From>
	[[nodiscard]] unique_ptr<To> const_pointer_cast(unique_ptr<From>&& ptr) noexcept
	{
		From* raw = ptr.object_;
		ptr.object_ = nullptr;

		return unique_ptr<To>(const_cast<To*>(raw));
	}

	template <class To, class From>
	[[nodiscard]] unique_ptr<To> reinterpret_pointer_cast(unique_ptr<From>&& ptr) noexcept
	{
		From* raw = ptr.object_;
		ptr.object_ = nullptr;

		return unique_ptr<To>(reinterpret_cast<To*>(raw));
	}

	template <class To, class From>
	[[nodiscard]] shared_ptr<To> static_pointer_cast(const shared_ptr<From>& ptr) noexcept
	{
		if (!ptr)
		{
			return shared_ptr<To>();
		}

		ptr.reference_count_->fetch_add(1, memory_order::relaxed);

		return shared_ptr<To>(static_cast<To*>(ptr.get()), ptr.reference_count_);
	}

	template <class To, class From>
	[[nodiscard]] shared_ptr<To> const_pointer_cast(const shared_ptr<From>& ptr) noexcept
	{
		if (!ptr)
		{
			return shared_ptr<To>();
		}

		ptr.reference_count_->fetch_add(1, memory_order::relaxed);

		return shared_ptr<To>(const_cast<To*>(ptr.get()), ptr.reference_count_);
	}

	template <class To, class From>
	[[nodiscard]] shared_ptr<To> reinterpret_pointer_cast(const shared_ptr<From>& ptr) noexcept
	{
		if (!ptr)
		{
			return shared_ptr<To>();
		}

		ptr.reference_count_->fetch_add(1, memory_order::relaxed);

		return shared_ptr<To>(reinterpret_cast<To*>(ptr.get()), ptr.reference_count_);
	}
}
