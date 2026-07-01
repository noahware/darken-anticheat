#pragma once
#include "types.hpp"
#include "type_traits.hpp"
#include "utility.hpp"

namespace cstd
{
	// Memory-order values match the GCC/Clang __ATOMIC_* ABI so they can be passed
	// straight through to the builtins on that path.
	enum class memory_order : int
	{
		relaxed = 0,
		consume = 1,
		acquire = 2,
		release = 3,
		acq_rel = 4,
		seq_cst = 5,
	};
}

#if defined(_MSC_VER)

extern "C"
{
	char    _InterlockedCompareExchange8 (char volatile*,    char,    char);
	short   _InterlockedCompareExchange16(short volatile*,   short,   short);
	long    _InterlockedCompareExchange  (long volatile*,    long,    long);
	__int64 _InterlockedCompareExchange64(__int64 volatile*, __int64, __int64);

	void _mm_pause(void);
	void _mm_mfence(void);
	void _ReadWriteBarrier(void);
}

#pragma intrinsic(_InterlockedCompareExchange8)
#pragma intrinsic(_InterlockedCompareExchange16)
#pragma intrinsic(_InterlockedCompareExchange)
#pragma intrinsic(_InterlockedCompareExchange64)
#pragma intrinsic(_mm_pause)
#pragma intrinsic(_mm_mfence)
#pragma intrinsic(_ReadWriteBarrier)

#elif defined(__GNUC__) || defined(__clang__)
	// __atomic_* are compiler builtins; no declarations required.
#else
	#error "cstd::atomic: unsupported compiler"
#endif

namespace cstd
{
	// Spin-wait CPU relaxation hint (x86/x64 PAUSE, AArch64 YIELD). Yields the pipeline
	// inside a busy wait so a spinlock does not saturate the core or starve a sibling
	// hyperthread. A pure hint: omitting it stays correct, only less friendly. Lives in
	// this header because atomic.hpp is the compiler/arch seam; mutex.hpp calls it.
	inline void cpu_relax() noexcept
	{
#if defined(_MSC_VER)
		_mm_pause();
#elif (defined(__GNUC__) || defined(__clang__)) && (defined(__i386__) || defined(__x86_64__))
		__builtin_ia32_pause();
#elif (defined(__GNUC__) || defined(__clang__)) && defined(__aarch64__)
		__asm__ __volatile__("yield" ::: "memory");
#else
		// No relax primitive for this target; a plain busy spin is still correct.
#endif
	}

	template <class T>
	class atomic
	{
	protected:
		using bits_type =
			conditional_t<sizeof(T) == 1, uint8_t,
			conditional_t<sizeof(T) == 2, uint16_t,
			conditional_t<sizeof(T) == 4, uint32_t, uint64_t>>>;

	public:
		using value_type = T;

		static_assert(is_trivially_copyable_v<T>,
			"cstd::atomic<T> requires a trivially copyable type");
		static_assert(sizeof(T) == 1 || sizeof(T) == 2 || sizeof(T) == 4 || sizeof(T) == 8,
			"cstd::atomic<T> supports 1, 2, 4 or 8 byte types");

		static constexpr bool is_always_lock_free = true;

		constexpr atomic() noexcept
				:	value_(T{}) { }

		constexpr atomic(const T desired) noexcept
				:	value_(desired) { }

		atomic(const atomic&) = delete;
		atomic& operator=(const atomic&) = delete;

		[[nodiscard]] bool is_lock_free() const noexcept
		{
			return true;
		}

		[[nodiscard]] T load(const memory_order order = memory_order::seq_cst) const noexcept
		{
#if defined(_MSC_VER)
			(void)order;

			// A naturally-aligned 1/2/4/8-byte read is atomic, and unlike a CAS-based
			// load it never writes (so a const atomic stays read-only). On x86/x64 the
			// load already carries the required ordering; on weakly-ordered MSVC targets
			// it is a relaxed atomic load. The shared_ptr refcount only uses the
			// full-barrier RMW path (fetch_add/fetch_sub), never load(), so it is safe.
			return bit_cast<T>(raw_load(reinterpret_cast<const bits_type volatile*>(&value_)));
#else
			T result;

			__atomic_load(&value_, &result, static_cast<int>(order));

			return result;
#endif
		}

		void store(T desired, const memory_order order = memory_order::seq_cst) noexcept
		{
#if defined(_MSC_VER)
			(void)exchange(desired, order);
#else
			__atomic_store(&value_, &desired, static_cast<int>(order));
#endif
		}

		T exchange(T desired, const memory_order order = memory_order::seq_cst) noexcept
		{
#if defined(_MSC_VER)
			(void)order;

			bits_type volatile* const address = reinterpret_cast<bits_type volatile*>(&value_);
			const bits_type next = bit_cast<bits_type>(desired);

			bits_type expected = raw_load(address);

			for (;;)
			{
				const bits_type previous = raw_cas(address, next, expected);

				if (previous == expected)
				{
					return bit_cast<T>(previous);
				}

				expected = previous;
			}
#else
			T result;

			__atomic_exchange(&value_, &desired, &result, static_cast<int>(order));

			return result;
#endif
		}

		bool compare_exchange_strong(T& expected, T desired,
			const memory_order order = memory_order::seq_cst) noexcept
		{
#if defined(_MSC_VER)
			(void)order;

			bits_type volatile* const address = reinterpret_cast<bits_type volatile*>(&value_);
			const bits_type expected_bits = bit_cast<bits_type>(expected);

			const bits_type previous = raw_cas(address, bit_cast<bits_type>(desired), expected_bits);

			if (previous == expected_bits)
			{
				return true;
			}

			expected = bit_cast<T>(previous);

			return false;
#else
			return __atomic_compare_exchange(&value_, &expected, &desired, false,
				static_cast<int>(order), static_cast<int>(failure_order(order)));
#endif
		}

		bool compare_exchange_weak(T& expected, T desired,
			const memory_order order = memory_order::seq_cst) noexcept
		{
			return compare_exchange_strong(expected, desired, order);
		}

		T operator=(T desired) noexcept
		{
			store(desired);

			return desired;
		}

		[[nodiscard]] operator T() const noexcept
		{
			return load();
		}

		T fetch_add(const T operand, const memory_order order = memory_order::seq_cst) noexcept
		{
			static_assert(is_integral_v<T>, "cstd::atomic<T>::fetch_add requires an integral type");

#if defined(_MSC_VER)
			(void)order;

			bits_type volatile* const address = reinterpret_cast<bits_type volatile*>(&value_);
			const bits_type addend = bit_cast<bits_type>(operand);

			bits_type expected = raw_load(address);

			for (;;)
			{
				const bits_type previous = raw_cas(address, static_cast<bits_type>(expected + addend), expected);

				if (previous == expected)
				{
					return bit_cast<T>(previous);
				}

				expected = previous;
			}
#else
			return __atomic_fetch_add(&value_, operand, static_cast<int>(order));
#endif
		}

		T fetch_sub(const T operand, const memory_order order = memory_order::seq_cst) noexcept
		{
			static_assert(is_integral_v<T>, "cstd::atomic<T>::fetch_sub requires an integral type");

#if defined(_MSC_VER)
			(void)order;

			bits_type volatile* const address = reinterpret_cast<bits_type volatile*>(&value_);
			const bits_type subtrahend = bit_cast<bits_type>(operand);

			bits_type expected = raw_load(address);

			for (;;)
			{
				const bits_type previous = raw_cas(address, static_cast<bits_type>(expected - subtrahend), expected);

				if (previous == expected)
				{
					return bit_cast<T>(previous);
				}

				expected = previous;
			}
#else
			return __atomic_fetch_sub(&value_, operand, static_cast<int>(order));
#endif
		}

		T operator++() noexcept
		{
			static_assert(is_integral_v<T>, "cstd::atomic<T>::operator++ requires an integral type");

#if defined(_MSC_VER)
			return static_cast<T>(fetch_add(static_cast<T>(1)) + static_cast<T>(1));
#else
			return __atomic_add_fetch(&value_, static_cast<T>(1), static_cast<int>(memory_order::seq_cst));
#endif
		}

		T operator--() noexcept
		{
			static_assert(is_integral_v<T>, "cstd::atomic<T>::operator-- requires an integral type");

#if defined(_MSC_VER)
			return static_cast<T>(fetch_sub(static_cast<T>(1)) - static_cast<T>(1));
#else
			return __atomic_sub_fetch(&value_, static_cast<T>(1), static_cast<int>(memory_order::seq_cst));
#endif
		}

	protected:
#if defined(_MSC_VER)
		// Single hardware primitive: a width-correct compare-and-swap returning the
		// previous value. load/store/exchange/fetch_* are built on top of it.
		static bits_type raw_cas(bits_type volatile* const address,
			const bits_type desired, const bits_type expected) noexcept
		{
			if constexpr (sizeof(T) == 1)
			{
				return static_cast<bits_type>(_InterlockedCompareExchange8(
					reinterpret_cast<char volatile*>(address),
					static_cast<char>(desired), static_cast<char>(expected)));
			}
			else if constexpr (sizeof(T) == 2)
			{
				return static_cast<bits_type>(_InterlockedCompareExchange16(
					reinterpret_cast<short volatile*>(address),
					static_cast<short>(desired), static_cast<short>(expected)));
			}
			else if constexpr (sizeof(T) == 4)
			{
				return static_cast<bits_type>(_InterlockedCompareExchange(
					reinterpret_cast<long volatile*>(address),
					static_cast<long>(desired), static_cast<long>(expected)));
			}
			else
			{
				return static_cast<bits_type>(_InterlockedCompareExchange64(
					reinterpret_cast<__int64 volatile*>(address),
					static_cast<__int64>(desired), static_cast<__int64>(expected)));
			}
		}

		// An aligned read of a supported size is atomic on its own; used for load()
		// and to seed the compare-and-swap loops.
		static bits_type raw_load(const bits_type volatile* const address) noexcept
		{
			return *address;
		}
#else
		// A load cannot carry release semantics; clamp the failure order accordingly.
		static constexpr memory_order failure_order(const memory_order order) noexcept
		{
			if (order == memory_order::acq_rel)
			{
				return memory_order::acquire;
			}

			if (order == memory_order::release)
			{
				return memory_order::relaxed;
			}

			return order;
		}
#endif

		alignas(sizeof(T)) T value_;
	};

	inline void atomic_thread_fence(const memory_order order) noexcept
	{
#if defined(_MSC_VER)
		if (order == memory_order::relaxed)
		{
			return;
		}

		_ReadWriteBarrier();

		if (order == memory_order::seq_cst)
		{
			_mm_mfence();
		}

		_ReadWriteBarrier();
#else
		__atomic_thread_fence(static_cast<int>(order));
#endif
	}
}
