#pragma once
#include "types.hpp"

namespace cstd
{
	enum float_round_style
	{
		round_indeterminate       = -1,
		round_toward_zero         =  0,
		round_to_nearest          =  1,
		round_toward_infinity     =  2,
		round_toward_neg_infinity =  3,
	};

	enum float_denorm_style
	{
		denorm_indeterminate = -1,
		denorm_absent        =  0,
		denorm_present       =  1,
	};

	template <class T>
	struct numeric_limits
	{
		static constexpr bool is_specialized = false;
		static constexpr bool is_signed      = false;
		static constexpr bool is_integer     = false;
		static constexpr bool is_exact       = false;
		static constexpr bool is_bounded     = false;
		static constexpr bool is_modulo      = false;
		static constexpr int  digits         = 0;
		static constexpr int  digits10       = 0;
		static constexpr int  radix          = 0;

		static constexpr bool is_iec559        = false;
		static constexpr bool has_infinity     = false;
		static constexpr bool has_quiet_NaN    = false;
		static constexpr bool has_signaling_NaN = false;
		static constexpr bool has_denorm_loss  = false;
		static constexpr float_denorm_style has_denorm = denorm_absent;
		static constexpr float_round_style  round_style = round_toward_zero;

		[[nodiscard]] static constexpr T min()          noexcept { return T(); }
		[[nodiscard]] static constexpr T max()          noexcept { return T(); }
		[[nodiscard]] static constexpr T lowest()       noexcept { return T(); }
		[[nodiscard]] static constexpr T epsilon()      noexcept { return T(); }
		[[nodiscard]] static constexpr T infinity()     noexcept { return T(); }
		[[nodiscard]] static constexpr T quiet_NaN()    noexcept { return T(); }
		[[nodiscard]] static constexpr T signaling_NaN() noexcept { return T(); }
		[[nodiscard]] static constexpr T denorm_min()   noexcept { return T(); }
		[[nodiscard]] static constexpr T round_error()  noexcept { return T(); }
	};

	namespace detail
	{
		template <class T, bool Signed>
		struct integer_limits;

		template <class T>
		struct integer_limits<T, false>
		{
			static constexpr bool is_specialized = true;
			static constexpr bool is_signed      = false;
			static constexpr bool is_integer     = true;
			static constexpr bool is_exact       = true;
			static constexpr bool is_bounded     = true;
			static constexpr bool is_modulo      = true;
			static constexpr int  digits         = static_cast<int>(sizeof(T) * 8);
			static constexpr int  digits10       = static_cast<int>(digits * 30103L / 100000L);
			static constexpr int  radix          = 2;

			static constexpr bool is_iec559        = false;
			static constexpr bool has_infinity     = false;
			static constexpr bool has_quiet_NaN    = false;
			static constexpr bool has_signaling_NaN = false;
			static constexpr bool has_denorm_loss  = false;
			static constexpr float_denorm_style has_denorm = denorm_absent;
			static constexpr float_round_style  round_style = round_toward_zero;

			[[nodiscard]] static constexpr T min()     noexcept { return static_cast<T>(0); }
			[[nodiscard]] static constexpr T max()     noexcept { return static_cast<T>(~static_cast<T>(0)); }
			[[nodiscard]] static constexpr T lowest()  noexcept { return min(); }
			[[nodiscard]] static constexpr T epsilon()      noexcept { return static_cast<T>(0); }
			[[nodiscard]] static constexpr T infinity()     noexcept { return static_cast<T>(0); }
			[[nodiscard]] static constexpr T quiet_NaN()    noexcept { return static_cast<T>(0); }
			[[nodiscard]] static constexpr T signaling_NaN() noexcept { return static_cast<T>(0); }
			[[nodiscard]] static constexpr T denorm_min()   noexcept { return static_cast<T>(0); }
			[[nodiscard]] static constexpr T round_error()  noexcept { return static_cast<T>(0); }
		};

		template <class T>
		struct integer_limits<T, true>
		{
			static constexpr bool is_specialized = true;
			static constexpr bool is_signed      = true;
			static constexpr bool is_integer     = true;
			static constexpr bool is_exact       = true;
			static constexpr bool is_bounded     = true;
			static constexpr bool is_modulo      = false;
			static constexpr int  digits         = static_cast<int>(sizeof(T) * 8 - 1);
			static constexpr int  digits10       = static_cast<int>(digits * 30103L / 100000L);
			static constexpr int  radix          = 2;

			static constexpr bool is_iec559        = false;
			static constexpr bool has_infinity     = false;
			static constexpr bool has_quiet_NaN    = false;
			static constexpr bool has_signaling_NaN = false;
			static constexpr bool has_denorm_loss  = false;
			static constexpr float_denorm_style has_denorm = denorm_absent;
			static constexpr float_round_style  round_style = round_toward_zero;

			[[nodiscard]] static constexpr T max() noexcept
			{
				return static_cast<T>((static_cast<unsigned long long>(1) << (sizeof(T) * 8 - 1)) - 1);
			}

			[[nodiscard]] static constexpr T min()     noexcept { return static_cast<T>(-max() - 1); }
			[[nodiscard]] static constexpr T lowest()  noexcept { return min(); }
			[[nodiscard]] static constexpr T epsilon()      noexcept { return static_cast<T>(0); }
			[[nodiscard]] static constexpr T infinity()     noexcept { return static_cast<T>(0); }
			[[nodiscard]] static constexpr T quiet_NaN()    noexcept { return static_cast<T>(0); }
			[[nodiscard]] static constexpr T signaling_NaN() noexcept { return static_cast<T>(0); }
			[[nodiscard]] static constexpr T denorm_min()   noexcept { return static_cast<T>(0); }
			[[nodiscard]] static constexpr T round_error()  noexcept { return static_cast<T>(0); }
		};
	}

	template <>
	struct numeric_limits<bool>
	{
		static constexpr bool is_specialized = true;
		static constexpr bool is_signed      = false;
		static constexpr bool is_integer     = true;
		static constexpr bool is_exact       = true;
		static constexpr bool is_bounded     = true;
		static constexpr bool is_modulo      = false;
		static constexpr int  digits         = 1;
		static constexpr int  digits10       = 0;
		static constexpr int  radix          = 2;

		static constexpr bool is_iec559        = false;
		static constexpr bool has_infinity     = false;
		static constexpr bool has_quiet_NaN    = false;
		static constexpr bool has_signaling_NaN = false;
		static constexpr bool has_denorm_loss  = false;
		static constexpr float_denorm_style has_denorm = denorm_absent;
		static constexpr float_round_style  round_style = round_toward_zero;

		[[nodiscard]] static constexpr bool min()     noexcept { return false; }
		[[nodiscard]] static constexpr bool max()     noexcept { return true; }
		[[nodiscard]] static constexpr bool lowest()  noexcept { return false; }
		[[nodiscard]] static constexpr bool epsilon()      noexcept { return false; }
		[[nodiscard]] static constexpr bool infinity()     noexcept { return false; }
		[[nodiscard]] static constexpr bool quiet_NaN()    noexcept { return false; }
		[[nodiscard]] static constexpr bool signaling_NaN() noexcept { return false; }
		[[nodiscard]] static constexpr bool denorm_min()   noexcept { return false; }
		[[nodiscard]] static constexpr bool round_error()  noexcept { return false; }
	};

	template <> struct numeric_limits<signed char>        : detail::integer_limits<signed char, true> { };
	template <> struct numeric_limits<short>              : detail::integer_limits<short, true> { };
	template <> struct numeric_limits<int>                : detail::integer_limits<int, true> { };
	template <> struct numeric_limits<long>               : detail::integer_limits<long, true> { };
	template <> struct numeric_limits<long long>          : detail::integer_limits<long long, true> { };

	template <> struct numeric_limits<unsigned char>      : detail::integer_limits<unsigned char, false> { };
	template <> struct numeric_limits<unsigned short>     : detail::integer_limits<unsigned short, false> { };
	template <> struct numeric_limits<unsigned int>       : detail::integer_limits<unsigned int, false> { };
	template <> struct numeric_limits<unsigned long>      : detail::integer_limits<unsigned long, false> { };
	template <> struct numeric_limits<unsigned long long> : detail::integer_limits<unsigned long long, false> { };

	template <> struct numeric_limits<char>      : detail::integer_limits<char, (static_cast<char>(-1) < 0)> { };
#ifdef _NATIVE_WCHAR_T_DEFINED
	template <> struct numeric_limits<wchar_t>   : detail::integer_limits<wchar_t, (static_cast<wchar_t>(-1) < 0)> { };
#endif
	template <> struct numeric_limits<char16_t>  : detail::integer_limits<char16_t, false> { };
	template <> struct numeric_limits<char32_t>  : detail::integer_limits<char32_t, false> { };

#if defined(__cpp_char8_t)
	template <> struct numeric_limits<char8_t>   : detail::integer_limits<char8_t, false> { };
#endif
}
