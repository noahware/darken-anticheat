#pragma once

namespace cstd
{
#if defined(_MSC_VER)
    template <class T>
    inline constexpr bool is_trivially_destructible_v = __is_trivially_destructible(T);
#else
    template <class T>
    inline constexpr bool is_trivially_destructible_v = __has_trivial_destructor(T);
#endif

    template <class T>
    inline constexpr bool is_trivially_copyable_v = __is_trivially_copyable(T);

    template <class T>
    struct is_integral
    {
        static constexpr bool value = false;
    };

    template <> struct is_integral<bool>               { static constexpr bool value = true; };
    template <> struct is_integral<char>               { static constexpr bool value = true; };
    template <> struct is_integral<signed char>        { static constexpr bool value = true; };
    template <> struct is_integral<unsigned char>      { static constexpr bool value = true; };
    template <> struct is_integral<char8_t>            { static constexpr bool value = true; };
    template <> struct is_integral<char16_t>           { static constexpr bool value = true; };
    template <> struct is_integral<char32_t>           { static constexpr bool value = true; };
#ifdef _NATIVE_WCHAR_T_DEFINED
    template <> struct is_integral<wchar_t>            { static constexpr bool value = true; };
#endif
    template <> struct is_integral<short>              { static constexpr bool value = true; };
    template <> struct is_integral<unsigned short>     { static constexpr bool value = true; };
    template <> struct is_integral<int>                { static constexpr bool value = true; };
    template <> struct is_integral<unsigned int>       { static constexpr bool value = true; };
    template <> struct is_integral<long>               { static constexpr bool value = true; };
    template <> struct is_integral<unsigned long>      { static constexpr bool value = true; };
    template <> struct is_integral<long long>          { static constexpr bool value = true; };
    template <> struct is_integral<unsigned long long> { static constexpr bool value = true; };

    template <class T> struct is_integral<const T> : is_integral<T> { };
    template <class T> struct is_integral<volatile T> : is_integral<T> { };
    template <class T> struct is_integral<const volatile T> : is_integral<T> { };

    template <class T>
    inline constexpr bool is_integral_v = is_integral<T>::value;

    template <class T, class U>
    struct is_same
	{
        static constexpr bool value = false;
    };

    template <class T>
    struct is_same<T, T>
	{
        static constexpr bool value = true;
    };

    template <class T, class U>
    inline constexpr bool is_same_v = is_same<T, U>::value;

    template <bool Condition, class T, class F>
    struct conditional
    {
        using type = T;
    };

    template <class T, class F>
    struct conditional<false, T, F>
    {
        using type = F;
    };

    template <bool Condition, class T, class F>
    using conditional_t = typename conditional<Condition, T, F>::type;

    template <class T, T Value>
    struct integral_constant
    {
        using value_type = T;
        static constexpr T value = Value;
    };

    using true_type = integral_constant<bool, true>;
    using false_type = integral_constant<bool, false>;

    template <bool Condition, class T = void>
    struct enable_if { };

    template <class T>
    struct enable_if<true, T>
    {
        using type = T;
    };

    template <bool Condition, class T = void>
    using enable_if_t = typename enable_if<Condition, T>::type;

    template <class...>
    using void_t = void;

    template <class T> struct remove_const { using type = T; };
    template <class T> struct remove_const<const T> { using type = T; };
    template <class T> using remove_const_t = typename remove_const<T>::type;

    template <class T> struct remove_volatile { using type = T; };
    template <class T> struct remove_volatile<volatile T> { using type = T; };
    template <class T> using remove_volatile_t = typename remove_volatile<T>::type;

    template <class T> struct remove_cv { using type = remove_volatile_t<remove_const_t<T>>; };
    template <class T> using remove_cv_t = typename remove_cv<T>::type;

    template <class T> struct remove_pointer { using type = T; };
    template <class T> struct remove_pointer<T*> { using type = T; };
    template <class T> struct remove_pointer<T* const> { using type = T; };
    template <class T> struct remove_pointer<T* volatile> { using type = T; };
    template <class T> struct remove_pointer<T* const volatile> { using type = T; };
    template <class T> using remove_pointer_t = typename remove_pointer<T>::type;

    template <class T> struct is_lvalue_reference : false_type { };
    template <class T> struct is_lvalue_reference<T&> : true_type { };
    template <class T> inline constexpr bool is_lvalue_reference_v = is_lvalue_reference<T>::value;

    template <class T> struct is_rvalue_reference : false_type { };
    template <class T> struct is_rvalue_reference<T&&> : true_type { };
    template <class T> inline constexpr bool is_rvalue_reference_v = is_rvalue_reference<T>::value;

    template <class T> struct is_reference : false_type { };
    template <class T> struct is_reference<T&> : true_type { };
    template <class T> struct is_reference<T&&> : true_type { };
    template <class T> inline constexpr bool is_reference_v = is_reference<T>::value;

    template <class T> struct is_const : false_type { };
    template <class T> struct is_const<const T> : true_type { };
    template <class T> inline constexpr bool is_const_v = is_const<T>::value;

    template <class T> struct is_void : integral_constant<bool, is_same_v<remove_cv_t<T>, void>> { };
    template <class T> inline constexpr bool is_void_v = is_void<T>::value;

    template <class T> struct is_pointer : false_type { };
    template <class T> struct is_pointer<T*> : true_type { };
    template <class T> struct is_pointer<T* const> : true_type { };
    template <class T> struct is_pointer<T* volatile> : true_type { };
    template <class T> struct is_pointer<T* const volatile> : true_type { };
    template <class T> inline constexpr bool is_pointer_v = is_pointer<T>::value;

    namespace detail
    {
        template <class T> struct type_identity { using type = T; };

        template <class T> type_identity<T&>  add_lvalue_ref(int);
        template <class T> type_identity<T>   add_lvalue_ref(long);

        template <class T> type_identity<T&&> add_rvalue_ref(int);
        template <class T> type_identity<T>   add_rvalue_ref(long);
    }

    template <class T> struct add_lvalue_reference : decltype(detail::add_lvalue_ref<T>(0)) { };
    template <class T> using add_lvalue_reference_t = typename add_lvalue_reference<T>::type;

    template <class T> struct add_rvalue_reference : decltype(detail::add_rvalue_ref<T>(0)) { };
    template <class T> using add_rvalue_reference_t = typename add_rvalue_reference<T>::type;

    template <class T>
    add_rvalue_reference_t<T> declval() noexcept;

    template <class T> struct decay { using type = remove_cv_t<T>; };
    template <class T> struct decay<T&> { using type = remove_cv_t<T>; };
    template <class T> struct decay<T&&> { using type = remove_cv_t<T>; };
    template <class T> using decay_t = typename decay<T>::type;

    template <class Base, class Derived>
    inline constexpr bool is_base_of_v = __is_base_of(Base, Derived);

    template <class Base, class Derived>
    struct is_base_of : integral_constant<bool, __is_base_of(Base, Derived)> { };

    template <class T, class... Args>
    inline constexpr bool is_constructible_v = __is_constructible(T, Args...);

    template <class T, class... Args>
    struct is_constructible : integral_constant<bool, __is_constructible(T, Args...)> { };

    template <class T> inline constexpr bool is_default_constructible_v = __is_constructible(T);
    template <class T> inline constexpr bool is_copy_constructible_v = __is_constructible(T, add_lvalue_reference_t<const T>);
    template <class T> inline constexpr bool is_move_constructible_v = __is_constructible(T, add_rvalue_reference_t<T>);

    template <class To, class From>
    inline constexpr bool is_assignable_v = __is_assignable(To, From);

    template <class T> inline constexpr bool is_copy_assignable_v = __is_assignable(add_lvalue_reference_t<T>, add_lvalue_reference_t<const T>);
    template <class T> inline constexpr bool is_move_assignable_v = __is_assignable(add_lvalue_reference_t<T>, add_rvalue_reference_t<T>);

    namespace detail
    {
        template <class To> void convertible_sink(To) noexcept;

        template <class From, class To, class = void>
        struct is_convertible_impl : false_type { };

        template <class From, class To>
        struct is_convertible_impl<From, To, void_t<decltype(convertible_sink<To>(declval<From>()))>> : true_type { };
    }

    template <class From, class To>
    inline constexpr bool is_convertible_v = detail::is_convertible_impl<From, To>::value;

    template <class From, class To>
    struct is_convertible : integral_constant<bool, is_convertible_v<From, To>> { };

    // Primary type categories

    template <class T> struct is_floating_point
        : integral_constant<bool,
            is_same_v<remove_cv_t<T>, float>
            || is_same_v<remove_cv_t<T>, double>
            || is_same_v<remove_cv_t<T>, long double>> { };
    template <class T> inline constexpr bool is_floating_point_v = is_floating_point<T>::value;

    template <class T> struct is_array : false_type { };
    template <class T> struct is_array<T[]> : true_type { };
    template <class T, decltype(sizeof(0)) N> struct is_array<T[N]> : true_type { };
    template <class T> inline constexpr bool is_array_v = is_array<T>::value;

    template <class T> struct is_enum : integral_constant<bool, __is_enum(T)> { };
    template <class T> inline constexpr bool is_enum_v = is_enum<T>::value;

    template <class T> struct is_union : integral_constant<bool, __is_union(T)> { };
    template <class T> inline constexpr bool is_union_v = is_union<T>::value;

    template <class T> struct is_class : integral_constant<bool, __is_class(T)> { };
    template <class T> inline constexpr bool is_class_v = is_class<T>::value;

    template <class T> struct is_null_pointer
        : integral_constant<bool, is_same_v<remove_cv_t<T>, decltype(nullptr)>> { };
    template <class T> inline constexpr bool is_null_pointer_v = is_null_pointer<T>::value;

    namespace detail
    {
        template <class T> struct is_member_pointer_impl : false_type { };
        template <class T, class C> struct is_member_pointer_impl<T C::*> : true_type { };
    }

    template <class T> struct is_member_pointer : detail::is_member_pointer_impl<remove_cv_t<T>> { };
    template <class T> inline constexpr bool is_member_pointer_v = is_member_pointer<T>::value;

    // Composite type categories

    template <class T> struct is_arithmetic
        : integral_constant<bool, is_integral_v<T> || is_floating_point_v<T>> { };
    template <class T> inline constexpr bool is_arithmetic_v = is_arithmetic<T>::value;

    template <class T> struct is_fundamental
        : integral_constant<bool, is_arithmetic_v<T> || is_void_v<T> || is_null_pointer_v<T>> { };
    template <class T> inline constexpr bool is_fundamental_v = is_fundamental<T>::value;

    template <class T> struct is_scalar
        : integral_constant<bool, is_arithmetic_v<T> || is_enum_v<T> || is_pointer_v<T>
            || is_member_pointer_v<T> || is_null_pointer_v<T>> { };
    template <class T> inline constexpr bool is_scalar_v = is_scalar<T>::value;

    template <class T> struct is_object
        : integral_constant<bool, is_scalar_v<T> || is_array_v<T> || is_union_v<T> || is_class_v<T>> { };
    template <class T> inline constexpr bool is_object_v = is_object<T>::value;

    // Every type is exactly one of object / reference / function / void, so a
    // function type is whatever is left once the other three are excluded.
    // Stated this way it never forms `const` on a function type (which warns).
    template <class T> struct is_function
        : integral_constant<bool, !is_object_v<T> && !is_reference_v<T> && !is_void_v<T>> { };
    template <class T> inline constexpr bool is_function_v = is_function<T>::value;

    namespace detail
    {
        template <class T> struct is_member_function_pointer_impl : false_type { };
        template <class T, class C> struct is_member_function_pointer_impl<T C::*>
            : integral_constant<bool, is_function_v<T>> { };
    }

    template <class T> struct is_member_function_pointer : detail::is_member_function_pointer_impl<remove_cv_t<T>> { };
    template <class T> inline constexpr bool is_member_function_pointer_v = is_member_function_pointer<T>::value;

    template <class T> struct is_member_object_pointer
        : integral_constant<bool, is_member_pointer_v<T> && !is_member_function_pointer_v<T>> { };
    template <class T> inline constexpr bool is_member_object_pointer_v = is_member_object_pointer<T>::value;

    template <class T> struct is_compound : integral_constant<bool, !is_fundamental_v<T>> { };
    template <class T> inline constexpr bool is_compound_v = is_compound<T>::value;

    // Type properties

    template <class T> struct is_volatile : false_type { };
    template <class T> struct is_volatile<volatile T> : true_type { };
    template <class T> inline constexpr bool is_volatile_v = is_volatile<T>::value;

    namespace detail
    {
        template <class T, bool = is_arithmetic_v<T>>
        struct is_signed_impl : integral_constant<bool, (T(-1) < T(0))> { };
        template <class T> struct is_signed_impl<T, false> : false_type { };

        template <class T, bool = is_arithmetic_v<T>>
        struct is_unsigned_impl : integral_constant<bool, (T(0) < T(-1))> { };
        template <class T> struct is_unsigned_impl<T, false> : false_type { };
    }

    template <class T> struct is_signed : detail::is_signed_impl<T> { };
    template <class T> inline constexpr bool is_signed_v = is_signed<T>::value;

    template <class T> struct is_unsigned : detail::is_unsigned_impl<T> { };
    template <class T> inline constexpr bool is_unsigned_v = is_unsigned<T>::value;

    template <class T> struct is_empty : integral_constant<bool, __is_empty(T)> { };
    template <class T> inline constexpr bool is_empty_v = is_empty<T>::value;

    template <class T> struct is_polymorphic : integral_constant<bool, __is_polymorphic(T)> { };
    template <class T> inline constexpr bool is_polymorphic_v = is_polymorphic<T>::value;

    template <class T> struct is_abstract : integral_constant<bool, __is_abstract(T)> { };
    template <class T> inline constexpr bool is_abstract_v = is_abstract<T>::value;

    template <class T> struct is_final : integral_constant<bool, __is_final(T)> { };
    template <class T> inline constexpr bool is_final_v = is_final<T>::value;

    template <class T> struct is_aggregate : integral_constant<bool, __is_aggregate(T)> { };
    template <class T> inline constexpr bool is_aggregate_v = is_aggregate<T>::value;

    template <class T> struct is_standard_layout : integral_constant<bool, __is_standard_layout(T)> { };
    template <class T> inline constexpr bool is_standard_layout_v = is_standard_layout<T>::value;

    template <class T> struct is_trivial : integral_constant<bool, __is_trivial(T)> { };
    template <class T> inline constexpr bool is_trivial_v = is_trivial<T>::value;

#if defined(_MSC_VER)
    template <class T> struct is_destructible : integral_constant<bool, __is_destructible(T)> { };
#else
    namespace detail
    {
        struct is_destructible_helper
        {
            template <class T, class = decltype(declval<T&>().~T())>
            static true_type test(int);

            template <class>
            static false_type test(...);
        };
    }

    template <class T> struct is_destructible
        : decltype(detail::is_destructible_helper::test<T>(0)) { };

    template <class T> struct is_destructible<T&> : true_type { };
    template <class T> struct is_destructible<T&&> : true_type { };
    template <> struct is_destructible<void> : false_type { };
    template <> struct is_destructible<const void> : false_type { };
    template <> struct is_destructible<volatile void> : false_type { };
    template <> struct is_destructible<const volatile void> : false_type { };
#endif
    template <class T> inline constexpr bool is_destructible_v = is_destructible<T>::value;

    template <class T> struct has_virtual_destructor : integral_constant<bool, __has_virtual_destructor(T)> { };
    template <class T> inline constexpr bool has_virtual_destructor_v = has_virtual_destructor<T>::value;
}
