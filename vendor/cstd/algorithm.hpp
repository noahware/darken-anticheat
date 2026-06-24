#pragma once
#include "types.hpp"
#include "utility.hpp"

namespace cstd
{
	namespace detail
	{
		template <class Proj, class T>
		constexpr auto invoke(Proj proj, T& arg) -> decltype(proj(arg))
		{
			return proj(arg);
		}

		template <class M, class C>
		constexpr M& invoke(M C::* pm, C& obj) noexcept
		{
			return obj.*pm;
		}

		template <class M, class C>
		constexpr const M& invoke(M C::* pm, const C& obj) noexcept
		{
			return obj.*pm;
		}

		template <class M, class C, class T>
		constexpr auto invoke(M C::* pm, T& obj) -> decltype((*obj).*pm)
		{
			return (*obj).*pm;
		}
	}

	// Non-modifying sequence operations over iterator ranges [first, last).
	// `find`-family returns `last` on miss (std semantics), so the results compose
	// with the erase-remove idiom and with each other.

	template <class Iter, class T>
	[[nodiscard]] constexpr Iter find(Iter first, const Iter last, const T& value)
	{
		for (; first != last; ++first)
		{
			if (*first == value)
			{
				return first;
			}
		}

		return last;
	}

	template <class Iter, class UnaryPredicate>
	[[nodiscard]] constexpr Iter find_if(Iter first, const Iter last, UnaryPredicate predicate)
	{
		for (; first != last; ++first)
		{
			if (predicate(*first))
			{
				return first;
			}
		}

		return last;
	}

	template <class Iter, class UnaryPredicate>
	[[nodiscard]] constexpr Iter find_if_not(Iter first, const Iter last, UnaryPredicate predicate)
	{
		for (; first != last; ++first)
		{
			if (!predicate(*first))
			{
				return first;
			}
		}

		return last;
	}

	template <class Iter, class T>
	[[nodiscard]] constexpr bool contains(Iter first, const Iter last, const T& value)
	{
		return find(first, last, value) != last;
	}

	template <class Iter, class T, class Proj>
	[[nodiscard]] constexpr bool contains(Iter first, const Iter last, const T& value, Proj proj)
	{
		return find(first, last, value, proj) != last;
	}

	template <class Iter1, class Iter2>
	[[nodiscard]] constexpr Iter1 find_first_of(Iter1 first, const Iter1 last, Iter2 s_first, const Iter2 s_last)
	{
		for (; first != last; ++first)
		{
			for (Iter2 s = s_first; s != s_last; ++s)
			{
				if (*first == *s)
				{
					return first;
				}
			}
		}

		return last;
	}

	template <class Iter1, class Iter2, class BinaryPredicate>
	[[nodiscard]] constexpr Iter1 find_first_of(Iter1 first, const Iter1 last, Iter2 s_first, const Iter2 s_last, BinaryPredicate predicate)
	{
		for (; first != last; ++first)
		{
			for (Iter2 s = s_first; s != s_last; ++s)
			{
				if (predicate(*first, *s))
				{
					return first;
				}
			}
		}

		return last;
	}

	template <class Iter>
	[[nodiscard]] constexpr Iter adjacent_find(Iter first, const Iter last)
	{
		if (first == last)
		{
			return last;
		}

		Iter next = first;
		++next;

		for (; next != last; ++first, ++next)
		{
			if (*first == *next)
			{
				return first;
			}
		}

		return last;
	}

	template <class Iter, class BinaryPredicate>
	[[nodiscard]] constexpr Iter adjacent_find(Iter first, const Iter last, BinaryPredicate predicate)
	{
		if (first == last)
		{
			return last;
		}

		Iter next = first;
		++next;

		for (; next != last; ++first, ++next)
		{
			if (predicate(*first, *next))
			{
				return first;
			}
		}

		return last;
	}

	template <class Iter, class T>
	[[nodiscard]] constexpr size_t count(Iter first, const Iter last, const T& value)
	{
		size_t total = 0;

		for (; first != last; ++first)
		{
			if (*first == value)
			{
				++total;
			}
		}

		return total;
	}

	template <class Iter, class UnaryPredicate>
	[[nodiscard]] constexpr size_t count_if(Iter first, const Iter last, UnaryPredicate predicate)
	{
		size_t total = 0;

		for (; first != last; ++first)
		{
			if (predicate(*first))
			{
				++total;
			}
		}

		return total;
	}

	template <class Iter, class UnaryPredicate>
	[[nodiscard]] constexpr bool all_of(Iter first, const Iter last, UnaryPredicate predicate)
	{
		for (; first != last; ++first)
		{
			if (!predicate(*first))
			{
				return false;
			}
		}

		return true;
	}

	template <class Iter, class UnaryPredicate>
	[[nodiscard]] constexpr bool any_of(Iter first, const Iter last, UnaryPredicate predicate)
	{
		for (; first != last; ++first)
		{
			if (predicate(*first))
			{
				return true;
			}
		}

		return false;
	}

	template <class Iter, class UnaryPredicate>
	[[nodiscard]] constexpr bool none_of(Iter first, const Iter last, UnaryPredicate predicate)
	{
		return !any_of(first, last, predicate);
	}

	template <class Iter, class UnaryFunction>
	constexpr UnaryFunction for_each(Iter first, const Iter last, UnaryFunction function)
	{
		for (; first != last; ++first)
		{
			function(*first);
		}

		return function;
	}

	template <class Iter1, class Iter2>
	[[nodiscard]] constexpr bool equal(Iter1 first1, const Iter1 last1, Iter2 first2)
	{
		for (; first1 != last1; ++first1, ++first2)
		{
			if (!(*first1 == *first2))
			{
				return false;
			}
		}

		return true;
	}

	template <class Iter1, class Iter2, class BinaryPredicate>
	[[nodiscard]] constexpr bool equal(Iter1 first1, const Iter1 last1, Iter2 first2, BinaryPredicate predicate)
	{
		for (; first1 != last1; ++first1, ++first2)
		{
			if (!predicate(*first1, *first2))
			{
				return false;
			}
		}

		return true;
	}

	template <class Iter>
	[[nodiscard]] constexpr Iter min_element(Iter first, const Iter last)
	{
		if (first == last)
		{
			return last;
		}

		Iter smallest = first;

		for (++first; first != last; ++first)
		{
			if (*first < *smallest)
			{
				smallest = first;
			}
		}

		return smallest;
	}

	template <class Iter, class Compare>
	[[nodiscard]] constexpr Iter min_element(Iter first, const Iter last, Compare compare)
	{
		if (first == last)
		{
			return last;
		}

		Iter smallest = first;

		for (++first; first != last; ++first)
		{
			if (compare(*first, *smallest))
			{
				smallest = first;
			}
		}

		return smallest;
	}

	template <class Iter>
	[[nodiscard]] constexpr Iter max_element(Iter first, const Iter last)
	{
		if (first == last)
		{
			return last;
		}

		Iter largest = first;

		for (++first; first != last; ++first)
		{
			if (*largest < *first)
			{
				largest = first;
			}
		}

		return largest;
	}

	template <class Iter, class Compare>
	[[nodiscard]] constexpr Iter max_element(Iter first, const Iter last, Compare compare)
	{
		if (first == last)
		{
			return last;
		}

		Iter largest = first;

		for (++first; first != last; ++first)
		{
			if (compare(*largest, *first))
			{
				largest = first;
			}
		}

		return largest;
	}

	// Modifying sequence operations. Element-wise assignment / swap (never memcpy), so
	// they stay correct for non-trivially-copyable T. copy/transform take an output
	// iterator and return one-past-the-last written; the caller guarantees its capacity.

	template <class InputIter, class OutputIter>
	constexpr OutputIter copy(InputIter first, const InputIter last, OutputIter destination)
	{
		for (; first != last; ++first, ++destination)
		{
			*destination = *first;
		}

		return destination;
	}

	template <class InputIter, class OutputIter, class UnaryPredicate>
	constexpr OutputIter copy_if(InputIter first, const InputIter last, OutputIter destination, UnaryPredicate predicate)
	{
		for (; first != last; ++first)
		{
			if (predicate(*first))
			{
				*destination = *first;

				++destination;
			}
		}

		return destination;
	}

	template <class Iter, class T>
	constexpr void fill(Iter first, const Iter last, const T& value)
	{
		for (; first != last; ++first)
		{
			*first = value;
		}
	}

	template <class OutputIter, class T>
	constexpr OutputIter fill_n(OutputIter first, const size_t count, const T& value)
	{
		for (size_t i = 0; i < count; ++i, ++first)
		{
			*first = value;
		}

		return first;
	}

	template <class InputIter, class OutputIter, class UnaryOperation>
	constexpr OutputIter transform(InputIter first, const InputIter last, OutputIter destination, UnaryOperation operation)
	{
		for (; first != last; ++first, ++destination)
		{
			*destination = operation(*first);
		}

		return destination;
	}

	template <class InputIter1, class InputIter2, class OutputIter, class BinaryOperation>
	constexpr OutputIter transform(InputIter1 first1, const InputIter1 last1, InputIter2 first2, OutputIter destination, BinaryOperation operation)
	{
		for (; first1 != last1; ++first1, ++first2, ++destination)
		{
			*destination = operation(*first1, *first2);
		}

		return destination;
	}

	template <class Iter>
	constexpr void reverse(Iter first, Iter last)
	{
		while (first != last)
		{
			--last;

			if (first == last)
			{
				break;
			}

			cstd::swap(*first, *last);
			++first;
		}
	}

	template <class Iter, class T>
	constexpr void replace(Iter first, const Iter last, const T& old_value, const T& new_value)
	{
		for (; first != last; ++first)
		{
			if (*first == old_value)
			{
				*first = new_value;
			}
		}
	}

	template <class Iter, class UnaryPredicate, class T>
	constexpr void replace_if(Iter first, const Iter last, UnaryPredicate predicate, const T& new_value)
	{
		for (; first != last; ++first)
		{
			if (predicate(*first))
			{
				*first = new_value;
			}
		}
	}

	// Stable in-place compaction: keeps the elements that do not match, returns the new
	// logical end. The physical tail is left intact (use erase / pop_back to drop it).

	template <class Iter, class T>
	[[nodiscard]] constexpr Iter remove(Iter first, const Iter last, const T& value)
	{
		Iter new_end = first;

		for (; first != last; ++first)
		{
			if (!(*first == value))
			{
				if (new_end != first)
				{
					*new_end = move(*first);
				}

				++new_end;
			}
		}

		return new_end;
	}

	template <class Iter, class UnaryPredicate>
	[[nodiscard]] constexpr Iter remove_if(Iter first, const Iter last, UnaryPredicate predicate)
	{
		Iter new_end = first;

		for (; first != last; ++first)
		{
			if (!predicate(*first))
			{
				if (new_end != first)
				{
					*new_end = move(*first);
				}

				++new_end;
			}
		}

		return new_end;
	}

	// Stable in-place dedup of consecutive equal runs: keeps the first of each run and
	// returns the new logical end (physical tail left intact, like remove).

	template <class Iter>
	[[nodiscard]] constexpr Iter unique(Iter first, const Iter last)
	{
		if (first == last)
		{
			return last;
		}

		Iter result = first;

		while (++first != last)
		{
			if (!(*result == *first))
			{
				++result;

				if (result != first)
				{
					*result = move(*first);
				}
			}
		}

		++result;
		return result;
	}

	template <class Iter, class BinaryPredicate>
	[[nodiscard]] constexpr Iter unique(Iter first, const Iter last, BinaryPredicate predicate)
	{
		if (first == last)
		{
			return last;
		}

		Iter result = first;

		while (++first != last)
		{
			if (!predicate(*result, *first))
			{
				++result;

				if (result != first)
				{
					*result = move(*first);
				}
			}
		}

		++result;
		return result;
	}

	// Default ordering functors (no <functional>). Heterogeneous operands so a single
	// comparator can compare, e.g., a flat_map entry against a bare key.

	struct less
	{
		template <class A, class B>
		[[nodiscard]] constexpr bool operator()(const A& left, const B& right) const
		{
			return left < right;
		}
	};

	struct greater
	{
		template <class A, class B>
		[[nodiscard]] constexpr bool operator()(const A& left, const B& right) const
		{
			return right < left;
		}
	};

	// Binary search over a sorted range (random-access iterators only). lower_bound:
	// first position not ordered before value; upper_bound: first position value is
	// ordered before. Iterative, no recursion.

	template <class Iter, class V, class Compare>
	[[nodiscard]] constexpr Iter lower_bound(Iter first, const Iter last, const V& value, Compare compare)
	{
		size_t count = static_cast<size_t>(last - first);

		while (count > 0)
		{
			const size_t half = count / 2;
			const Iter middle = first + half;

			if (compare(*middle, value))
			{
				first = middle + 1;
				count -= half + 1;
			}
			else
			{
				count = half;
			}
		}

		return first;
	}

	template <class Iter, class V>
	[[nodiscard]] constexpr Iter lower_bound(Iter first, const Iter last, const V& value)
	{
		return lower_bound(first, last, value, less{});
	}

	template <class Iter, class V, class Compare>
	[[nodiscard]] constexpr Iter upper_bound(Iter first, const Iter last, const V& value, Compare compare)
	{
		size_t count = static_cast<size_t>(last - first);

		while (count > 0)
		{
			const size_t half = count / 2;
			const Iter middle = first + half;

			if (compare(value, *middle))
			{
				count = half;
			}
			else
			{
				first = middle + 1;
				count -= half + 1;
			}
		}

		return first;
	}

	template <class Iter, class V>
	[[nodiscard]] constexpr Iter upper_bound(Iter first, const Iter last, const V& value)
	{
		return upper_bound(first, last, value, less{});
	}

	template <class Iter, class V, class Compare>
	[[nodiscard]] constexpr bool binary_search(Iter first, const Iter last, const V& value, Compare compare)
	{
		const Iter found = lower_bound(first, last, value, compare);

		return found != last && !compare(value, *found);
	}

	template <class Iter, class V>
	[[nodiscard]] constexpr bool binary_search(Iter first, const Iter last, const V& value)
	{
		return binary_search(first, last, value, less{});
	}

	namespace detail
	{
		template <class Iter, class Compare>
		constexpr void insertion_sort(const Iter first, const Iter last, Compare compare)
		{
			if (first == last)
			{
				return;
			}

			for (Iter current = first + 1; current != last; ++current)
			{
				auto key = move(*current);
				Iter hole = current;

				while (hole != first && compare(key, *(hole - 1)))
				{
					*hole = move(*(hole - 1));
					--hole;
				}

				*hole = move(key);
			}
		}

		template <class Iter, class Compare>
		constexpr void sift_down(const Iter first, const size_t start, const size_t count, Compare compare)
		{
			size_t root = start;

			for (;;)
			{
				size_t child = root * 2 + 1;

				if (child >= count)
				{
					break;
				}

				if (child + 1 < count && compare(first[child], first[child + 1]))
				{
					++child;
				}

				if (compare(first[root], first[child]))
				{
					cstd::swap(first[root], first[child]);

					root = child;
				}
				else
				{
					break;
				}
			}
		}

		template <class Iter, class Compare>
		constexpr void heap_sort(const Iter first, const Iter last, Compare compare)
		{
			const size_t count = static_cast<size_t>(last - first);

			for (size_t node = count / 2; node-- > 0; )
			{
				sift_down(first, node, count, compare);
			}

			for (size_t end = count; end-- > 1; )
			{
				cstd::swap(first[0], first[end]);

				sift_down(first, 0, end, compare);
			}
		}
	}

	// Unstable sort (random-access iterators only): insertion sort for small ranges,
	// heapsort otherwise. Heapsort is iterative with O(1) auxiliary space and guaranteed
	// O(n log n) — no recursion, no allocation, no worst-case blow-up.
	template <class Iter, class Compare>
	constexpr void sort(Iter first, Iter last, Compare compare)
	{
		const size_t count = static_cast<size_t>(last - first);

		if (count < 2)
		{
			return;
		}

		if (count <= 16)
		{
			detail::insertion_sort(first, last, compare);
		}
		else
		{
			detail::heap_sort(first, last, compare);
		}
	}

	template <class Iter>
	constexpr void sort(Iter first, Iter last)
	{
		sort(first, last, less{});
	}

	template <class Iter, class Compare>
	[[nodiscard]] constexpr bool is_sorted(Iter first, const Iter last, Compare compare)
	{
		if (first == last)
		{
			return true;
		}

		Iter next = first;
		++next;

		for (; next != last; ++next, ++first)
		{
			if (compare(*next, *first))
			{
				return false;
			}
		}

		return true;
	}

	template <class Iter>
	[[nodiscard]] constexpr bool is_sorted(Iter first, const Iter last)
	{
		return is_sorted(first, last, less{});
	}

	// Projected iterator-pair overloads. The projection (last param) is applied to each
	// element before comparison or predicate evaluation. Accepts any callable or a
	// pointer-to-member-data (&Class::field).

	template <class Iter, class T, class Proj>
	[[nodiscard]] constexpr Iter find(Iter first, const Iter last, const T& value, Proj proj)
	{
		for (; first != last; ++first)
		{
			if (detail::invoke(proj, *first) == value)
			{
				return first;
			}
		}

		return last;
	}

	template <class Iter, class UnaryPredicate, class Proj>
	[[nodiscard]] constexpr Iter find_if(Iter first, const Iter last, UnaryPredicate predicate, Proj proj)
	{
		for (; first != last; ++first)
		{
			if (predicate(detail::invoke(proj, *first)))
			{
				return first;
			}
		}

		return last;
	}

	template <class Iter, class UnaryPredicate, class Proj>
	[[nodiscard]] constexpr Iter find_if_not(Iter first, const Iter last, UnaryPredicate predicate, Proj proj)
	{
		for (; first != last; ++first)
		{
			if (!predicate(detail::invoke(proj, *first)))
			{
				return first;
			}
		}

		return last;
	}

	template <class Iter, class T, class Proj>
	[[nodiscard]] constexpr size_t count(Iter first, const Iter last, const T& value, Proj proj)
	{
		size_t total = 0;

		for (; first != last; ++first)
		{
			if (detail::invoke(proj, *first) == value)
			{
				++total;
			}
		}

		return total;
	}

	template <class Iter, class UnaryPredicate, class Proj>
	[[nodiscard]] constexpr size_t count_if(Iter first, const Iter last, UnaryPredicate predicate, Proj proj)
	{
		size_t total = 0;

		for (; first != last; ++first)
		{
			if (predicate(detail::invoke(proj, *first)))
			{
				++total;
			}
		}

		return total;
	}

	template <class Iter, class UnaryPredicate, class Proj>
	[[nodiscard]] constexpr bool all_of(Iter first, const Iter last, UnaryPredicate predicate, Proj proj)
	{
		for (; first != last; ++first)
		{
			if (!predicate(detail::invoke(proj, *first)))
			{
				return false;
			}
		}

		return true;
	}

	template <class Iter, class UnaryPredicate, class Proj>
	[[nodiscard]] constexpr bool any_of(Iter first, const Iter last, UnaryPredicate predicate, Proj proj)
	{
		for (; first != last; ++first)
		{
			if (predicate(detail::invoke(proj, *first)))
			{
				return true;
			}
		}

		return false;
	}

	template <class Iter, class UnaryPredicate, class Proj>
	[[nodiscard]] constexpr bool none_of(Iter first, const Iter last, UnaryPredicate predicate, Proj proj)
	{
		return !any_of(first, last, predicate, proj);
	}

	template <class Iter, class UnaryFunction, class Proj>
	constexpr UnaryFunction for_each(Iter first, const Iter last, UnaryFunction function, Proj proj)
	{
		for (; first != last; ++first)
		{
			function(detail::invoke(proj, *first));
		}

		return function;
	}

	// Range-based overloads. Each forwards to the iterator-pair version above
	// using range.begin() / range.end().

	template <class Range, class T>
	[[nodiscard]] constexpr auto find(Range& range, const T& value)
	{
		return find(range.begin(), range.end(), value);
	}

	template <class Range, class UnaryPredicate>
	[[nodiscard]] constexpr auto find_if(Range& range, UnaryPredicate predicate)
	{
		return find_if(range.begin(), range.end(), predicate);
	}

	template <class Range, class UnaryPredicate>
	[[nodiscard]] constexpr auto find_if_not(Range& range, UnaryPredicate predicate)
	{
		return find_if_not(range.begin(), range.end(), predicate);
	}

	template <class Range, class T>
	[[nodiscard]] constexpr bool contains(Range& range, const T& value)
	{
		return find(range.begin(), range.end(), value) != range.end();
	}

	template <class Range, class T, class Proj>
	[[nodiscard]] constexpr bool contains(Range& range, const T& value, Proj proj)
	{
		return find(range.begin(), range.end(), value, proj) != range.end();
	}

	template <class Range1, class Range2>
	[[nodiscard]] constexpr auto find_first_of(Range1& range, Range2& targets)
	{
		return find_first_of(range.begin(), range.end(), targets.begin(), targets.end());
	}

	template <class Range1, class Range2, class BinaryPredicate>
	[[nodiscard]] constexpr auto find_first_of(Range1& range, Range2& targets, BinaryPredicate predicate)
	{
		return find_first_of(range.begin(), range.end(), targets.begin(), targets.end(), predicate);
	}

	template <class Range>
	[[nodiscard]] constexpr auto adjacent_find(Range& range)
	{
		return adjacent_find(range.begin(), range.end());
	}

	template <class Range, class BinaryPredicate>
	[[nodiscard]] constexpr auto adjacent_find(Range& range, BinaryPredicate predicate)
	{
		return adjacent_find(range.begin(), range.end(), predicate);
	}

	template <class Range, class T>
	[[nodiscard]] constexpr size_t count(Range& range, const T& value)
	{
		return count(range.begin(), range.end(), value);
	}

	template <class Range, class UnaryPredicate>
	[[nodiscard]] constexpr size_t count_if(Range& range, UnaryPredicate predicate)
	{
		return count_if(range.begin(), range.end(), predicate);
	}

	template <class Range, class UnaryPredicate>
	[[nodiscard]] constexpr bool all_of(Range& range, UnaryPredicate predicate)
	{
		return all_of(range.begin(), range.end(), predicate);
	}

	template <class Range, class UnaryPredicate>
	[[nodiscard]] constexpr bool any_of(Range& range, UnaryPredicate predicate)
	{
		return any_of(range.begin(), range.end(), predicate);
	}

	template <class Range, class UnaryPredicate>
	[[nodiscard]] constexpr bool none_of(Range& range, UnaryPredicate predicate)
	{
		return none_of(range.begin(), range.end(), predicate);
	}

	template <class Range, class UnaryFunction>
	constexpr UnaryFunction for_each(Range& range, UnaryFunction function)
	{
		return for_each(range.begin(), range.end(), function);
	}

	template <class Range1, class Range2>
	[[nodiscard]] constexpr bool equal(Range1& left, Range2& right)
	{
		return equal(left.begin(), left.end(), right.begin());
	}

	template <class Range1, class Range2, class BinaryPredicate>
	[[nodiscard]] constexpr bool equal(Range1& left, Range2& right, BinaryPredicate predicate)
	{
		return equal(left.begin(), left.end(), right.begin(), predicate);
	}

	template <class Range>
	[[nodiscard]] constexpr auto min_element(Range& range)
	{
		return min_element(range.begin(), range.end());
	}

	template <class Range, class Compare>
	[[nodiscard]] constexpr auto min_element(Range& range, Compare compare)
	{
		return min_element(range.begin(), range.end(), compare);
	}

	template <class Range>
	[[nodiscard]] constexpr auto max_element(Range& range)
	{
		return max_element(range.begin(), range.end());
	}

	template <class Range, class Compare>
	[[nodiscard]] constexpr auto max_element(Range& range, Compare compare)
	{
		return max_element(range.begin(), range.end(), compare);
	}

	template <class Range, class OutputIter>
	constexpr auto copy(Range& range, OutputIter destination)
	{
		return copy(range.begin(), range.end(), destination);
	}

	template <class Range, class OutputIter, class UnaryPredicate>
	constexpr auto copy_if(Range& range, OutputIter destination, UnaryPredicate predicate)
	{
		return copy_if(range.begin(), range.end(), destination, predicate);
	}

	template <class Range, class T>
	constexpr void fill(Range& range, const T& value)
	{
		fill(range.begin(), range.end(), value);
	}

	template <class Range, class OutputIter, class UnaryOperation>
	constexpr auto transform(Range& range, OutputIter destination, UnaryOperation operation)
	{
		return transform(range.begin(), range.end(), destination, operation);
	}

	template <class Range>
	constexpr void reverse(Range& range)
	{
		reverse(range.begin(), range.end());
	}

	template <class Range, class T>
	constexpr void replace(Range& range, const T& old_value, const T& new_value)
	{
		replace(range.begin(), range.end(), old_value, new_value);
	}

	template <class Range, class UnaryPredicate, class T>
	constexpr void replace_if(Range& range, UnaryPredicate predicate, const T& new_value)
	{
		replace_if(range.begin(), range.end(), predicate, new_value);
	}

	template <class Range, class T>
	[[nodiscard]] constexpr auto remove(Range& range, const T& value)
	{
		return remove(range.begin(), range.end(), value);
	}

	template <class Range, class UnaryPredicate>
	[[nodiscard]] constexpr auto remove_if(Range& range, UnaryPredicate predicate)
	{
		return remove_if(range.begin(), range.end(), predicate);
	}

	template <class Range>
	[[nodiscard]] constexpr auto unique(Range& range)
	{
		return unique(range.begin(), range.end());
	}

	template <class Range, class BinaryPredicate>
	[[nodiscard]] constexpr auto unique(Range& range, BinaryPredicate predicate)
	{
		return unique(range.begin(), range.end(), predicate);
	}

	template <class Range, class V>
	[[nodiscard]] constexpr auto lower_bound(Range& range, const V& value)
	{
		return lower_bound(range.begin(), range.end(), value);
	}

	template <class Range, class V, class Compare>
	[[nodiscard]] constexpr auto lower_bound(Range& range, const V& value, Compare compare)
	{
		return lower_bound(range.begin(), range.end(), value, compare);
	}

	template <class Range, class V>
	[[nodiscard]] constexpr auto upper_bound(Range& range, const V& value)
	{
		return upper_bound(range.begin(), range.end(), value);
	}

	template <class Range, class V, class Compare>
	[[nodiscard]] constexpr auto upper_bound(Range& range, const V& value, Compare compare)
	{
		return upper_bound(range.begin(), range.end(), value, compare);
	}

	template <class Range, class V>
	[[nodiscard]] constexpr bool binary_search(Range& range, const V& value)
	{
		return binary_search(range.begin(), range.end(), value);
	}

	template <class Range, class V, class Compare>
	[[nodiscard]] constexpr bool binary_search(Range& range, const V& value, Compare compare)
	{
		return binary_search(range.begin(), range.end(), value, compare);
	}

	template <class Range>
	constexpr void sort(Range& range)
	{
		sort(range.begin(), range.end());
	}

	template <class Range, class Compare>
	constexpr void sort(Range& range, Compare compare)
	{
		sort(range.begin(), range.end(), compare);
	}

	template <class Range>
	[[nodiscard]] constexpr bool is_sorted(Range& range)
	{
		return is_sorted(range.begin(), range.end());
	}

	template <class Range, class Compare>
	[[nodiscard]] constexpr bool is_sorted(Range& range, Compare compare)
	{
		return is_sorted(range.begin(), range.end(), compare);
	}

	// Projected range overloads.

	template <class Range, class T, class Proj>
	[[nodiscard]] constexpr auto find(Range& range, const T& value, Proj proj)
	{
		return find(range.begin(), range.end(), value, proj);
	}

	template <class Range, class UnaryPredicate, class Proj>
	[[nodiscard]] constexpr auto find_if(Range& range, UnaryPredicate predicate, Proj proj)
	{
		return find_if(range.begin(), range.end(), predicate, proj);
	}

	template <class Range, class UnaryPredicate, class Proj>
	[[nodiscard]] constexpr auto find_if_not(Range& range, UnaryPredicate predicate, Proj proj)
	{
		return find_if_not(range.begin(), range.end(), predicate, proj);
	}

	template <class Range, class T, class Proj>
	[[nodiscard]] constexpr size_t count(Range& range, const T& value, Proj proj)
	{
		return count(range.begin(), range.end(), value, proj);
	}

	template <class Range, class UnaryPredicate, class Proj>
	[[nodiscard]] constexpr size_t count_if(Range& range, UnaryPredicate predicate, Proj proj)
	{
		return count_if(range.begin(), range.end(), predicate, proj);
	}

	template <class Range, class UnaryPredicate, class Proj>
	[[nodiscard]] constexpr bool all_of(Range& range, UnaryPredicate predicate, Proj proj)
	{
		return all_of(range.begin(), range.end(), predicate, proj);
	}

	template <class Range, class UnaryPredicate, class Proj>
	[[nodiscard]] constexpr bool any_of(Range& range, UnaryPredicate predicate, Proj proj)
	{
		return any_of(range.begin(), range.end(), predicate, proj);
	}

	template <class Range, class UnaryPredicate, class Proj>
	[[nodiscard]] constexpr bool none_of(Range& range, UnaryPredicate predicate, Proj proj)
	{
		return none_of(range.begin(), range.end(), predicate, proj);
	}

	template <class Range, class UnaryFunction, class Proj>
	constexpr UnaryFunction for_each(Range& range, UnaryFunction function, Proj proj)
	{
		return for_each(range.begin(), range.end(), function, proj);
	}
}
