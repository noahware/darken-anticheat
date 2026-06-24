#pragma once
#include "atomic.hpp"
#include "utility.hpp"
#include "exception.hpp"

namespace cstd
{
	struct adopt_lock_t   { explicit adopt_lock_t()   = default; };
	struct defer_lock_t   { explicit defer_lock_t()   = default; };
	struct try_to_lock_t  { explicit try_to_lock_t()  = default; };

	inline constexpr adopt_lock_t  adopt_lock{};
	inline constexpr defer_lock_t  defer_lock{};
	inline constexpr try_to_lock_t try_to_lock{};

	class mutex
	{
	public:
		constexpr mutex() noexcept
				:	locked_(false) { }

		mutex(const mutex&) = delete;
		mutex& operator=(const mutex&) = delete;

		void lock() noexcept
		{
			for (;;)
			{
				// exchange returns the previous value: false means we flipped
				// false -> true and now own the lock. acquire pairs with unlock's release.
				if (!locked_.exchange(true, memory_order::acquire))
				{
					return;
				}

				// Spin on a cheap relaxed read (no bus-locking RMW, keeps the line Shared)
				// until the flag looks free, then retry the acquiring exchange above.
				while (locked_.load(memory_order::relaxed))
				{
					cpu_relax();
				}
			}
		}

		[[nodiscard]] bool try_lock() noexcept
		{
			return !locked_.exchange(true, memory_order::acquire);
		}

		void unlock() noexcept
		{
			// release publishes the critical section to the next acquirer.
			locked_.store(false, memory_order::release);
		}

	protected:
		atomic<bool> locked_;
	};

	template <class Mutex>
	class lock_guard
	{
	public:
		using mutex_type = Mutex;

		explicit lock_guard(mutex_type& owned)
				:	owned_(owned)
		{
			owned_.lock();
		}

		lock_guard(mutex_type& owned, adopt_lock_t) noexcept
				:	owned_(owned) { }

		lock_guard(const lock_guard&) = delete;
		lock_guard& operator=(const lock_guard&) = delete;

		~lock_guard()
		{
			owned_.unlock();
		}

	protected:
		mutex_type& owned_;
	};

	template <class Mutex>
	class unique_lock
	{
	public:
		using mutex_type = Mutex;

		unique_lock() noexcept
				:	device_(nullptr), owns_(false) { }

		explicit unique_lock(mutex_type& device)
				:	device_(&device), owns_(false)
		{
			device_->lock();
			owns_ = true;
		}

		unique_lock(mutex_type& device, defer_lock_t) noexcept
				:	device_(&device), owns_(false) { }

		unique_lock(mutex_type& device, try_to_lock_t)
				:	device_(&device), owns_(device.try_lock()) { }

		unique_lock(mutex_type& device, adopt_lock_t) noexcept
				:	device_(&device), owns_(true) { }

		unique_lock(unique_lock&& other) noexcept
				:	device_(other.device_), owns_(other.owns_)
		{
			other.device_ = nullptr;
			other.owns_ = false;
		}

		unique_lock& operator=(unique_lock&& other) noexcept
		{
			if (this != &other)
			{
				if (owns_)
				{
					device_->unlock();
				}

				device_ = other.device_;
				owns_ = other.owns_;
				other.device_ = nullptr;
				other.owns_ = false;
			}

			return *this;
		}

		unique_lock(const unique_lock&) = delete;
		unique_lock& operator=(const unique_lock&) = delete;

		~unique_lock()
		{
			if (owns_)
			{
				device_->unlock();
			}
		}

		void lock()
		{
			CSTD_ASSERT(device_ != nullptr, "[unique_lock] lock() with no associated mutex");
			CSTD_ASSERT(!owns_, "[unique_lock] lock() while already owning");
			device_->lock();
			owns_ = true;
		}

		[[nodiscard]] bool try_lock()
		{
			CSTD_ASSERT(device_ != nullptr, "[unique_lock] try_lock() with no associated mutex");
			CSTD_ASSERT(!owns_, "[unique_lock] try_lock() while already owning");
			owns_ = device_->try_lock();
			return owns_;
		}

		void unlock()
		{
			CSTD_ASSERT(owns_, "[unique_lock] unlock() while not owning");
			device_->unlock();
			owns_ = false;
		}

		void swap(unique_lock& other) noexcept
		{
			cstd::swap(device_, other.device_);
			cstd::swap(owns_, other.owns_);
		}

		// Detach the mutex association WITHOUT unlocking; caller becomes responsible.
		[[nodiscard]] mutex_type* release() noexcept
		{
			mutex_type* result = device_;
			device_ = nullptr;
			owns_ = false;
			return result;
		}

		[[nodiscard]] bool owns_lock() const noexcept
		{
			return owns_;
		}

		[[nodiscard]] explicit operator bool() const noexcept
		{
			return owns_;
		}

		[[nodiscard]] mutex_type* mutex() const noexcept
		{
			return device_;
		}

	protected:
		mutex_type* device_;
		bool owns_;
	};

	template <class Mutex>
	void swap(unique_lock<Mutex>& left, unique_lock<Mutex>& right) noexcept
	{
		left.swap(right);
	}
}
