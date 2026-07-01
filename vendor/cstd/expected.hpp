#pragma once
#include "exception.hpp"
#include "utility.hpp"
#include "crt.hpp"
#include "type_traits.hpp"

namespace cstd
{
	struct in_place_t
	{
		explicit in_place_t() = default;
	};

	inline constexpr in_place_t in_place{};

	struct unexpect_t
	{
		explicit unexpect_t() = default;
	};

	inline constexpr unexpect_t unexpect{};

	template <class E>
	class unexpected
	{
	public:
		using error_type = E;

		constexpr explicit unexpected(const E& error)
				:	error_(error) { }

		constexpr explicit unexpected(E&& error) noexcept
				:	error_(move(error)) { }

		template <class... Args>
		constexpr explicit unexpected(in_place_t, Args&&... args)
				:	error_(forward<Args>(args)...) { }

		[[nodiscard]] constexpr E& error() & noexcept
		{
			return error_;
		}

		[[nodiscard]] constexpr const E& error() const& noexcept
		{
			return error_;
		}

		[[nodiscard]] constexpr E&& error() && noexcept
		{
			return move(error_);
		}

		constexpr void swap(unexpected& right) noexcept
		{
			cstd::swap(error_, right.error_);
		}

	protected:
		E error_;
	};

	template <class E>
	unexpected(E) -> unexpected<E>;

	template <class E>
	[[nodiscard]] constexpr bool operator==(const unexpected<E>& left, const unexpected<E>& right)
	{
		return left.error() == right.error();
	}

	template <class E>
	[[nodiscard]] constexpr bool operator!=(const unexpected<E>& left, const unexpected<E>& right)
	{
		return !(left == right);
	}

	template <class T, class E>
	class expected
	{
	public:
		using value_type = T;
		using error_type = E;
		using unexpected_type = unexpected<E>;

		constexpr expected()
				:	has_value_(true),
					value_() { }

		constexpr expected(const T& value)
				:	has_value_(true),
					value_(value) { }

		constexpr expected(T&& value) noexcept
				:	has_value_(true),
					value_(move(value)) { }

		template <class... Args>
		constexpr explicit expected(in_place_t, Args&&... args)
				:	has_value_(true),
					value_(forward<Args>(args)...) { }

		template <class... Args>
		constexpr explicit expected(unexpect_t, Args&&... args)
				:	has_value_(false),
					error_(forward<Args>(args)...) { }

		constexpr expected(const unexpected<E>& failure)
				:	has_value_(false),
					error_(failure.error()) { }

		constexpr expected(unexpected<E>&& failure) noexcept
				:	has_value_(false),
					error_(move(failure).error()) { }

		expected(const expected& right)
				:	has_value_(right.has_value_)
		{
			if (has_value_)
			{
				new (&value_) value_type(right.value_);
			}
			else
			{
				new (&error_) error_type(right.error_);
			}
		}

		expected(expected&& right) noexcept
				:	has_value_(right.has_value_)
		{
			if (has_value_)
			{
				new (&value_) value_type(move(right.value_));
			}
			else
			{
				new (&error_) error_type(move(right.error_));
			}
		}

		expected& operator=(const expected& right)
		{
			if (this != &right)
			{
				if (right.has_value_)
				{
					assign_value(right.value_);
				}
				else
				{
					assign_error(right.error_);
				}
			}

			return *this;
		}

		expected& operator=(expected&& right) noexcept
		{
			if (this != &right)
			{
				if (right.has_value_)
				{
					assign_value(move(right.value_));
				}
				else
				{
					assign_error(move(right.error_));
				}
			}

			return *this;
		}

		template <class G>
		expected& operator=(const unexpected<G>& failure)
		{
			assign_error(failure.error());

			return *this;
		}

		template <class G>
		expected& operator=(unexpected<G>&& failure)
		{
			assign_error(move(failure).error());

			return *this;
		}

		constexpr ~expected()
		{
			destroy();
		}

		[[nodiscard]] constexpr bool has_value() const noexcept
		{
			return has_value_;
		}

		[[nodiscard]] explicit constexpr operator bool() const noexcept
		{
			return has_value_;
		}

		[[nodiscard]] constexpr value_type& value() & noexcept
		{
			CSTD_ASSERT(has_value_, "[expected] accessing value of an error state");

			return value_;
		}

		[[nodiscard]] constexpr const value_type& value() const& noexcept
		{
			CSTD_ASSERT(has_value_, "[expected] accessing value of an error state");

			return value_;
		}

		[[nodiscard]] constexpr value_type&& value() && noexcept
		{
			CSTD_ASSERT(has_value_, "[expected] accessing value of an error state");

			return move(value_);
		}

		[[nodiscard]] constexpr error_type& error() & noexcept
		{
			CSTD_ASSERT(!has_value_, "[expected] accessing error of a value state");

			return error_;
		}

		[[nodiscard]] constexpr const error_type& error() const& noexcept
		{
			CSTD_ASSERT(!has_value_, "[expected] accessing error of a value state");

			return error_;
		}

		[[nodiscard]] constexpr error_type&& error() && noexcept
		{
			CSTD_ASSERT(!has_value_, "[expected] accessing error of a value state");

			return move(error_);
		}

		[[nodiscard]] constexpr value_type* operator->() noexcept
		{
			CSTD_ASSERT(has_value_, "[expected] accessing value of an error state");

			return &value_;
		}

		[[nodiscard]] constexpr const value_type* operator->() const noexcept
		{
			CSTD_ASSERT(has_value_, "[expected] accessing value of an error state");

			return &value_;
		}

		[[nodiscard]] constexpr value_type& operator*() & noexcept
		{
			CSTD_ASSERT(has_value_, "[expected] accessing value of an error state");

			return value_;
		}

		[[nodiscard]] constexpr const value_type& operator*() const& noexcept
		{
			CSTD_ASSERT(has_value_, "[expected] accessing value of an error state");

			return value_;
		}

		[[nodiscard]] constexpr value_type&& operator*() && noexcept
		{
			CSTD_ASSERT(has_value_, "[expected] accessing value of an error state");

			return move(value_);
		}

		template <class U>
		[[nodiscard]] constexpr value_type value_or(U&& default_value) const&
		{
			return has_value_ ? value_ : static_cast<value_type>(forward<U>(default_value));
		}

		template <class U>
		[[nodiscard]] constexpr value_type value_or(U&& default_value) &&
		{
			return has_value_ ? move(value_) : static_cast<value_type>(forward<U>(default_value));
		}

	protected:
		constexpr void destroy() noexcept
		{
			if (has_value_)
			{
				value_.~value_type();
			}
			else
			{
				error_.~error_type();
			}
		}

		template <class U>
		void assign_value(U&& incoming)
		{
			destroy();

			new (&value_) value_type(forward<U>(incoming));

			has_value_ = true;
		}

		template <class U>
		void assign_error(U&& incoming)
		{
			destroy();

			new (&error_) error_type(forward<U>(incoming));

			has_value_ = false;
		}

		bool has_value_;

		union
		{
			value_type value_;
			error_type error_;
		};
	};

	template <class E>
	class expected<void, E>
	{
	public:
		using value_type = void;
		using error_type = E;
		using unexpected_type = unexpected<E>;

		constexpr expected() noexcept
				:	has_value_(true) { }

		template <class... Args>
		constexpr explicit expected(unexpect_t, Args&&... args)
				:	has_value_(false),
					error_(forward<Args>(args)...) { }

		constexpr expected(const unexpected<E>& failure)
				:	has_value_(false),
					error_(failure.error()) { }

		constexpr expected(unexpected<E>&& failure) noexcept
				:	has_value_(false),
					error_(move(failure).error()) { }

		expected(const expected& right)
				:	has_value_(right.has_value_)
		{
			if (!has_value_)
			{
				new (&error_) error_type(right.error_);
			}
		}

		expected(expected&& right) noexcept
				:	has_value_(right.has_value_)
		{
			if (!has_value_)
			{
				new (&error_) error_type(move(right.error_));
			}
		}

		expected& operator=(const expected& right)
		{
			if (this != &right)
			{
				if (right.has_value_)
				{
					engage_value();
				}
				else
				{
					assign_error(right.error_);
				}
			}

			return *this;
		}

		expected& operator=(expected&& right) noexcept
		{
			if (this != &right)
			{
				if (right.has_value_)
				{
					engage_value();
				}
				else
				{
					assign_error(move(right.error_));
				}
			}

			return *this;
		}

		template <class G>
		expected& operator=(const unexpected<G>& failure)
		{
			assign_error(failure.error());

			return *this;
		}

		constexpr ~expected()
		{
			destroy();
		}

		[[nodiscard]] constexpr bool has_value() const noexcept
		{
			return has_value_;
		}

		[[nodiscard]] explicit constexpr operator bool() const noexcept
		{
			return has_value_;
		}

		constexpr void value() const noexcept
		{
			CSTD_ASSERT(has_value_, "[expected<void>] accessing value of an error state");
		}

		[[nodiscard]] constexpr error_type& error() & noexcept
		{
			CSTD_ASSERT(!has_value_, "[expected<void>] accessing error of a value state");

			return error_;
		}

		[[nodiscard]] constexpr const error_type& error() const& noexcept
		{
			CSTD_ASSERT(!has_value_, "[expected<void>] accessing error of a value state");

			return error_;
		}

		[[nodiscard]] constexpr error_type&& error() && noexcept
		{
			CSTD_ASSERT(!has_value_, "[expected<void>] accessing error of a value state");

			return move(error_);
		}

	protected:
		constexpr void destroy() noexcept
		{
			if (!has_value_)
			{
				error_.~error_type();
			}
		}

		void engage_value() noexcept
		{
			destroy();

			has_value_ = true;
		}

		template <class U>
		void assign_error(U&& incoming)
		{
			destroy();

			new (&error_) error_type(forward<U>(incoming));

			has_value_ = false;
		}

		bool has_value_;

		union
		{
			error_type error_;
		};
	};

	template <class T, class E>
	[[nodiscard]] constexpr bool operator==(const expected<T, E>& left, const expected<T, E>& right)
	{
		if (left.has_value() != right.has_value())
		{
			return false;
		}

		return left.has_value() ? (*left == *right) : (left.error() == right.error());
	}

	template <class T, class E>
	[[nodiscard]] constexpr bool operator!=(const expected<T, E>& left, const expected<T, E>& right)
	{
		return !(left == right);
	}

	template <class T, class E, class E2>
	[[nodiscard]] constexpr bool operator==(const expected<T, E>& left, const unexpected<E2>& right)
	{
		return !left.has_value() && (left.error() == right.error());
	}

	template <class T, class E, class E2>
	[[nodiscard]] constexpr bool operator!=(const expected<T, E>& left, const unexpected<E2>& right)
	{
		return !(left == right);
	}
}
