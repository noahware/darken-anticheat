#pragma once
#include "crt.hpp"
#include "exception.hpp"
#include "type_traits.hpp"
#include "types.hpp"
#include "utility.hpp"

namespace cstd
{
	template <class>
	class function;

	template <class R, class... Args>
	class function<R(Args...)>
	{
	public:
		using result_type = R;

	private:
		static constexpr size_t sbo_size  = sizeof(void*) * 4;
		static constexpr size_t sbo_align = alignof(void*);

		struct vtable_type
		{
			R    (*invoke)(void*, Args...);
			void (*destroy)(void*) noexcept;
			void (*copy)(void*, const void*);
			void (*move_to)(void*, void*) noexcept;
		};

		template <class F>
		struct callable_ops
		{
			static constexpr bool is_local = sizeof(F) <= sbo_size && alignof(F) <= sbo_align;

			[[nodiscard]] static F* get(void* storage) noexcept
			{
				if constexpr (is_local)
				{
					return static_cast<F*>(storage);
				}
				else
				{
					return *static_cast<F**>(storage);
				}
			}

			[[nodiscard]] static const F* get(const void* storage) noexcept
			{
				if constexpr (is_local)
				{
					return static_cast<const F*>(storage);
				}
				else
				{
					return *static_cast<const F* const*>(storage);
				}
			}

			static R invoke(void* storage, Args... args)
			{
				if constexpr (is_void_v<R>)
				{
					(*get(storage))(cstd::forward<Args>(args)...);
				}
				else
				{
					return (*get(storage))(cstd::forward<Args>(args)...);
				}
			}

			static void destroy(void* storage) noexcept
			{
				if constexpr (is_local)
				{
					get(storage)->~F();
				}
				else
				{
					F* ptr = get(storage);
					ptr->~F();
					crt::free(ptr);
				}
			}

			static void copy(void* dst, const void* src)
			{
				if constexpr (is_local)
				{
					new (dst) F(*get(src));
				}
				else
				{
					void* mem = crt::malloc(sizeof(F));
					F* obj = new (mem) F(*get(src));
					*static_cast<F**>(dst) = obj;
				}
			}

			static void move_to(void* dst, void* src) noexcept
			{
				if constexpr (is_local)
				{
					new (dst) F(cstd::move(*get(src)));
					get(src)->~F();
				}
				else
				{
					*static_cast<F**>(dst) = *static_cast<F**>(src);
					*static_cast<F**>(src) = nullptr;
				}
			}

			static constexpr vtable_type vtable = { &invoke, &destroy, &copy, &move_to };
		};

		alignas(sbo_align) mutable byte storage_[sbo_size];
		const vtable_type* vtable_;

	public:
		constexpr function() noexcept
			:	storage_{}, vtable_(nullptr) { }

		constexpr function(decltype(nullptr)) noexcept
			:	function() { }

		template <class F, class = enable_if_t<!is_same_v<decay_t<F>, function>>>
		function(F&& callable)
			:	vtable_(&callable_ops<decay_t<F>>::vtable)
		{
			using stored_type = decay_t<F>;

			if constexpr (callable_ops<stored_type>::is_local)
			{
				new (static_cast<void*>(storage_)) stored_type(cstd::forward<F>(callable));
			}
			else
			{
				void* mem = crt::malloc(sizeof(stored_type));
				stored_type* obj = new (mem) stored_type(cstd::forward<F>(callable));
				*static_cast<stored_type**>(static_cast<void*>(storage_)) = obj;
			}
		}

		function(const function& other)
			:	vtable_(other.vtable_)
		{
			if (vtable_)
			{
				vtable_->copy(storage_, other.storage_);
			}
		}

		function(function&& other) noexcept
			:	vtable_(other.vtable_)
		{
			if (vtable_)
			{
				vtable_->move_to(storage_, other.storage_);
				other.vtable_ = nullptr;
			}
		}

		~function()
		{
			if (vtable_)
			{
				vtable_->destroy(storage_);
			}
		}

		function& operator=(const function& other)
		{
			if (this != &other)
			{
				if (vtable_)
				{
					vtable_->destroy(storage_);
				}
				vtable_ = other.vtable_;
				if (vtable_)
				{
					vtable_->copy(storage_, other.storage_);
				}
			}
			return *this;
		}

		function& operator=(function&& other) noexcept
		{
			if (this != &other)
			{
				if (vtable_)
				{
					vtable_->destroy(storage_);
				}
				vtable_ = other.vtable_;
				if (vtable_)
				{
					vtable_->move_to(storage_, other.storage_);
				}
				other.vtable_ = nullptr;
			}
			return *this;
		}

		function& operator=(decltype(nullptr)) noexcept
		{
			if (vtable_)
			{
				vtable_->destroy(storage_);
				vtable_ = nullptr;
			}
			return *this;
		}

		R operator()(Args... args) const
		{
			CSTD_ASSERT(vtable_ != nullptr, "[function] called with no target");
			return vtable_->invoke(storage_, cstd::forward<Args>(args)...);
		}

		[[nodiscard]] explicit operator bool() const noexcept
		{
			return vtable_ != nullptr;
		}

		void swap(function& other) noexcept
		{
			function tmp(cstd::move(other));
			other = cstd::move(*this);
			*this = cstd::move(tmp);
		}
	};

	template <class R, class... Args>
	void swap(function<R(Args...)>& left, function<R(Args...)>& right) noexcept
	{
		left.swap(right);
	}

	template <class R, class... Args>
	[[nodiscard]] bool operator==(const function<R(Args...)>& fn, decltype(nullptr)) noexcept
	{
		return !fn;
	}

	template <class R, class... Args>
	[[nodiscard]] bool operator==(decltype(nullptr), const function<R(Args...)>& fn) noexcept
	{
		return !fn;
	}

	template <class R, class... Args>
	[[nodiscard]] bool operator!=(const function<R(Args...)>& fn, decltype(nullptr)) noexcept
	{
		return static_cast<bool>(fn);
	}

	template <class R, class... Args>
	[[nodiscard]] bool operator!=(decltype(nullptr), const function<R(Args...)>& fn) noexcept
	{
		return static_cast<bool>(fn);
	}
}
