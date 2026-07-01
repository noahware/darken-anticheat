#pragma once
#include "pair.hpp"
#include "types.hpp"
#include "vector.hpp"
#include "algorithm.hpp"

namespace cstd
{
	// Entries are kept sorted by key, so lookups are O(log n) binary searches and
	// insertions land at the sorted position. find() keeps the nullptr-on-miss contract.
	template <class Key, class T>
	class flat_map
	{
	public:
		using size_type = size_t;
		using key_type = Key;
		using mapped_type = T;
		using mapped_reference = mapped_type&;
		using const_mapped_reference = const mapped_type&;
		using value_type = pair<key_type, mapped_type>;
		using pointer = value_type*;
		using const_pointer = const value_type*;
		using reference = value_type&;
		using const_reference = const value_type&;

		flat_map() = default;

		template <class Y>
		flat_map(const initializer_list<Y> list)
		{
			for (const Y& entry : list)
			{
				elements_.push_back(static_cast<value_type>(entry));
			}

			sort(elements_.begin(), elements_.end(), entry_less{});
		}

		[[nodiscard]] pointer begin() noexcept
		{
			return elements_.data();
		}

		[[nodiscard]] pointer end() noexcept
		{
			return elements_.data() + elements_.size();
		}

		[[nodiscard]] const_pointer begin() const noexcept
		{
			return elements_.data();
		}

		[[nodiscard]] const_pointer end() const noexcept
		{
			return elements_.data() + elements_.size();
		}

		[[nodiscard]] pointer front()
		{
			CSTD_ASSERT(!empty(), "[flat_map] front() called on an empty flat map");

			return begin();
		}

		[[nodiscard]] const_pointer front() const
		{
			CSTD_ASSERT(!empty(), "[flat_map] front() called on an empty flat map");

			return begin();
		}

		[[nodiscard]] pointer back()
		{
			CSTD_ASSERT(!empty(), "[flat_map] back() called on an empty flat map");

			return end() - 1;
		}

		[[nodiscard]] const_pointer back() const
		{
			CSTD_ASSERT(!empty(), "[flat_map] back() called on an empty flat map");

			return end() - 1;
		}

		[[nodiscard]] mapped_reference operator[](const key_type& key)
		{
			pointer entry = lower_bound_entry(key);

			const size_type index = static_cast<size_type>(entry - begin());

			if (entry != end() && entry->first == key)
			{
				return entry->second;
			}

			elements_.insert(elements_.begin() + index, value_type(key, mapped_type{}));

			return elements_[index].second;
		}

		[[nodiscard]] const_mapped_reference operator[](const key_type& key) const
		{
			const_pointer entry = find(key);

			CSTD_ASSERT(entry != nullptr, "[flat_map] unable to find key");

			return entry->second;
		}

		[[nodiscard]] mapped_reference at(const key_type& key)
		{
			pointer entry = find(key);

			CSTD_ASSERT(entry != nullptr, "[flat_map] at() key not found");

			return entry->second;
		}

		[[nodiscard]] const_mapped_reference at(const key_type& key) const
		{
			const_pointer entry = find(key);

			CSTD_ASSERT(entry != nullptr, "[flat_map] at() key not found");

			return entry->second;
		}

		[[nodiscard]] pointer find(const key_type& key)
		{
			pointer entry = lower_bound_entry(key);

			if (entry != end() && entry->first == key)
			{
				return entry;
			}

			return nullptr;
		}

		[[nodiscard]] const_pointer find(const key_type& key) const
		{
			const value_type probe(key, mapped_type{});
			const_pointer entry = lower_bound(begin(), end(), probe, entry_less{});

			if (entry != end() && entry->first == key)
			{
				return entry;
			}

			return nullptr;
		}

		[[nodiscard]] bool contains(const key_type& key) const
		{
			return find(key) != nullptr;
		}

		[[nodiscard]] size_type count(const key_type& key) const
		{
			return contains(key) ? 1 : 0;
		}

		size_type erase(const key_type& key)
		{
			pointer entry = find(key);

			if (entry == nullptr)
			{
				return 0;
			}

			elements_.erase(entry);

			return 1;
		}

		void clear()
		{
			elements_.clear();
		}

		[[nodiscard]] size_type size() const noexcept
		{
			return elements_.size();
		}

		[[nodiscard]] bool empty() const
		{
			return elements_.empty();
		}

	protected:
		struct entry_less
		{
			[[nodiscard]] constexpr bool operator()(const value_type& left, const value_type& right) const
			{
				return left.first < right.first;
			}
		};

		pointer lower_bound_entry(const key_type& key)
		{
			const value_type probe(key, mapped_type{});

			return lower_bound(begin(), end(), probe, entry_less{});
		}

		vector<value_type> elements_;
	};
}
