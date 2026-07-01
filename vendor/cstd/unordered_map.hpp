#pragma once
#include "algorithm.hpp"
#include "hash.hpp"
#include "vector.hpp"
#include "pair.hpp"
#include "exception.hpp"

namespace cstd
{
	template <class Key, class T>
	class unordered_map
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
		using bucket_type = vector<value_type>;

		class iterator
		{
		public:
			iterator() noexcept = default;

			iterator(bucket_type* bucket, bucket_type* end, pointer element) noexcept
				:	bucket_(bucket),
					end_(end),
					element_(element)
			{
			}

			[[nodiscard]] reference operator*() const noexcept
			{
				return *element_;
			}

			[[nodiscard]] pointer operator->() const noexcept
			{
				return element_;
			}

			iterator& operator++() noexcept
			{
				++element_;

				if (element_ == bucket_->end())
				{
					skip_empty();
				}

				return *this;
			}

			iterator operator++(int) noexcept
			{
				iterator copy = *this;
				++(*this);
				return copy;
			}

			[[nodiscard]] bool operator==(const iterator& other) const noexcept
			{
				return element_ == other.element_;
			}

			[[nodiscard]] bool operator!=(const iterator& other) const noexcept
			{
				return element_ != other.element_;
			}

		private:
			friend class unordered_map;

			void skip_empty() noexcept
			{
				++bucket_;

				while (bucket_ != end_)
				{
					if (!bucket_->empty())
					{
						element_ = bucket_->begin();
						return;
					}

					++bucket_;
				}

				element_ = nullptr;
			}

			bucket_type* bucket_ = nullptr;
			bucket_type* end_ = nullptr;
			pointer element_ = nullptr;
		};

		class const_iterator
		{
		public:
			const_iterator() noexcept = default;

			const_iterator(const bucket_type* bucket, const bucket_type* end, const_pointer element) noexcept
				:	bucket_(bucket),
					end_(end),
					element_(element)
			{
			}

			const_iterator(const iterator& it) noexcept
				:	bucket_(it.bucket_),
					end_(it.end_),
					element_(it.element_)
			{
			}

			[[nodiscard]] const_reference operator*() const noexcept
			{
				return *element_;
			}

			[[nodiscard]] const_pointer operator->() const noexcept
			{
				return element_;
			}

			const_iterator& operator++() noexcept
			{
				++element_;

				if (element_ == bucket_->end())
				{
					skip_empty();
				}

				return *this;
			}

			const_iterator operator++(int) noexcept
			{
				const_iterator copy = *this;
				++(*this);
				return copy;
			}

			[[nodiscard]] bool operator==(const const_iterator& other) const noexcept
			{
				return element_ == other.element_;
			}

			[[nodiscard]] bool operator!=(const const_iterator& other) const noexcept
			{
				return element_ != other.element_;
			}

		private:
			friend class unordered_map;

			void skip_empty() noexcept
			{
				++bucket_;

				while (bucket_ != end_)
				{
					if (!bucket_->empty())
					{
						element_ = bucket_->begin();
						return;
					}

					++bucket_;
				}

				element_ = nullptr;
			}

			const bucket_type* bucket_ = nullptr;
			const bucket_type* end_ = nullptr;
			const_pointer element_ = nullptr;
		};

		unordered_map()
			:	buckets_(default_bucket_count)
		{
		}

		explicit unordered_map(const size_type initial_bucket_count)
			:	buckets_(initial_bucket_count > 0 ? initial_bucket_count : default_bucket_count)
		{
		}

		template <class Y>
		unordered_map(const initializer_list<Y> list)
			:	buckets_(default_bucket_count)
		{
			for (const Y& entry : list)
			{
				insert(static_cast<value_type>(entry));
			}
		}

		unordered_map(const unordered_map& other)
			:	buckets_(other.buckets_),
				size_(other.size_),
				max_load_factor_(other.max_load_factor_)
		{
		}

		unordered_map(unordered_map&& other) noexcept
			:	buckets_(cstd::move(other.buckets_)),
				size_(other.size_),
				max_load_factor_(other.max_load_factor_)
		{
			other.size_ = 0;
		}

		unordered_map& operator=(const unordered_map& other)
		{
			if (this != &other)
			{
				buckets_ = other.buckets_;
				size_ = other.size_;
				max_load_factor_ = other.max_load_factor_;
			}

			return *this;
		}

		unordered_map& operator=(unordered_map&& other) noexcept
		{
			if (this != &other)
			{
				buckets_ = cstd::move(other.buckets_);
				size_ = other.size_;
				max_load_factor_ = other.max_load_factor_;
				other.size_ = 0;
			}

			return *this;
		}

		[[nodiscard]] iterator begin() noexcept
		{
			for (size_type i = 0; i < buckets_.size(); ++i)
			{
				if (!buckets_[i].empty())
				{
					return iterator(
						buckets_.data() + i,
						buckets_.data() + buckets_.size(),
						buckets_[i].begin()
					);
				}
			}

			return end();
		}

		[[nodiscard]] const_iterator begin() const noexcept
		{
			for (size_type i = 0; i < buckets_.size(); ++i)
			{
				if (!buckets_[i].empty())
				{
					return const_iterator(
						buckets_.data() + i,
						buckets_.data() + buckets_.size(),
						buckets_[i].begin()
					);
				}
			}

			return end();
		}

		[[nodiscard]] iterator end() noexcept
		{
			return iterator(
				buckets_.data() + buckets_.size(),
				buckets_.data() + buckets_.size(),
				nullptr
			);
		}

		[[nodiscard]] const_iterator end() const noexcept
		{
			return const_iterator(
				buckets_.data() + buckets_.size(),
				buckets_.data() + buckets_.size(),
				nullptr
			);
		}

		[[nodiscard]] size_type size() const noexcept
		{
			return size_;
		}

		[[nodiscard]] bool empty() const noexcept
		{
			return size_ == 0;
		}

		[[nodiscard]] mapped_reference operator[](const key_type& key)
		{
			pointer entry = find(key);

			if (!entry)
			{
				entry = insert_entry(key);
			}

			return entry->second;
		}

		[[nodiscard]] const_mapped_reference operator[](const key_type& key) const
		{
			const_pointer entry = find(key);

			CSTD_ASSERT(entry != nullptr, "[unordered_map] unable to find key");

			return entry->second;
		}

		[[nodiscard]] mapped_reference at(const key_type& key)
		{
			pointer entry = find(key);

			CSTD_ASSERT(entry != nullptr, "[unordered_map] at() key not found");

			return entry->second;
		}

		[[nodiscard]] const_mapped_reference at(const key_type& key) const
		{
			const_pointer entry = find(key);

			CSTD_ASSERT(entry != nullptr, "[unordered_map] at() key not found");

			return entry->second;
		}

		[[nodiscard]] pointer find(const key_type& key)
		{
			return const_cast<pointer>(static_cast<const unordered_map*>(this)->find(key));
		}

		[[nodiscard]] const_pointer find(const key_type& key) const
		{
			const size_type idx = bucket_index(key);
			const bucket_type& bucket = buckets_[idx];
			const_pointer it = cstd::find(bucket.begin(), bucket.end(), key, &value_type::first);

			return it != bucket.end() ? it : nullptr;
		}

		[[nodiscard]] bool contains(const key_type& key) const
		{
			return find(key) != nullptr;
		}

		[[nodiscard]] size_type count(const key_type& key) const
		{
			return contains(key) ? 1 : 0;
		}

		pair<pointer, bool> insert(const value_type& entry)
		{
			pointer existing = find(entry.first);

			if (existing)
			{
				return pair<pointer, bool>(existing, false);
			}

			pointer created = insert_entry(entry.first, entry.second);

			return pair<pointer, bool>(created, true);
		}

		pair<pointer, bool> insert(const key_type& key, const mapped_type& value)
		{
			pointer existing = find(key);

			if (existing)
			{
				return pair<pointer, bool>(existing, false);
			}

			pointer created = insert_entry(key, value);

			return pair<pointer, bool>(created, true);
		}

		template <class... Args>
		pair<pointer, bool> emplace(const key_type& key, Args&&... args)
		{
			pointer existing = find(key);

			if (existing)
			{
				return pair<pointer, bool>(existing, false);
			}

			pointer created = insert_entry(key, mapped_type(cstd::forward<Args>(args)...));

			return pair<pointer, bool>(created, true);
		}

		size_type erase(const key_type& key)
		{
			const size_type idx = bucket_index(key);
			bucket_type& bucket = buckets_[idx];

			for (pointer it = bucket.begin(); it != bucket.end(); ++it)
			{
				if (it->first == key)
				{
					bucket.erase(it);
					--size_;
					return 1;
				}
			}

			return 0;
		}

		void clear() noexcept
		{
			for (size_type i = 0; i < buckets_.size(); ++i)
			{
				buckets_[i].clear();
			}

			size_ = 0;
		}

		void swap(unordered_map& other) noexcept
		{
			buckets_.swap(other.buckets_);

			const size_type tmp_size = size_;
			size_ = other.size_;
			other.size_ = tmp_size;

			const size_type tmp_mlf = max_load_factor_;
			max_load_factor_ = other.max_load_factor_;
			other.max_load_factor_ = tmp_mlf;
		}

		[[nodiscard]] size_type bucket_count() const noexcept
		{
			return buckets_.size();
		}

		[[nodiscard]] size_type bucket_size(const size_type n) const
		{
			CSTD_ASSERT(n < buckets_.size(), "[unordered_map] bucket index out of range");

			return buckets_[n].size();
		}

		[[nodiscard]] size_type bucket(const key_type& key) const
		{
			return bucket_index(key);
		}

		[[nodiscard]] size_type max_load_factor() const noexcept
		{
			return max_load_factor_;
		}

		void max_load_factor(const size_type mlf)
		{
			CSTD_ASSERT(mlf > 0, "[unordered_map] max_load_factor must be > 0");

			max_load_factor_ = mlf;
		}

		void rehash(const size_type new_bucket_count)
		{
			const size_type required = size_ / max_load_factor_ + 1;
			const size_type actual = new_bucket_count > required ? new_bucket_count : required;

			if (actual == buckets_.size())
			{
				return;
			}

			vector<bucket_type> new_buckets(actual);

			for (size_type i = 0; i < buckets_.size(); ++i)
			{
				for (size_type j = 0; j < buckets_[i].size(); ++j)
				{
					const hash_type h = hash_key(buckets_[i][j].first);
					const size_type idx = h % new_buckets.size();

					new_buckets[idx].push_back(cstd::move(buckets_[i][j]));
				}
			}

			buckets_ = cstd::move(new_buckets);
		}

		void reserve(const size_type element_count)
		{
			rehash(element_count / max_load_factor_ + 1);
		}

	protected:
		static constexpr size_type default_bucket_count = 16;

		[[nodiscard]] static hash_type hash_key(const key_type& key)
		{
			constexpr hash<key_type> h;

			return h(key);
		}

		[[nodiscard]] size_type bucket_index(const key_type& key) const
		{
			CSTD_ASSERT(!buckets_.empty(), "[unordered_map] bucket array is empty");

			return hash_key(key) % buckets_.size();
		}

		pointer insert_entry(const key_type& key)
		{
			maybe_rehash();

			const size_type idx = bucket_index(key);
			buckets_[idx].push_back(value_type(key, mapped_type{}));
			++size_;

			return &buckets_[idx].back();
		}

		pointer insert_entry(const key_type& key, const mapped_type& value)
		{
			maybe_rehash();

			const size_type idx = bucket_index(key);
			buckets_[idx].push_back(value_type(key, value));
			++size_;

			return &buckets_[idx].back();
		}

		void maybe_rehash()
		{
			if ((size_ + 1) > buckets_.size() * max_load_factor_)
			{
				rehash(buckets_.size() * 2);
			}
		}

		vector<bucket_type> buckets_;
		size_type size_ = 0;
		size_type max_load_factor_ = 1;
	};

	template <class Key, class T>
	void swap(unordered_map<Key, T>& left, unordered_map<Key, T>& right) noexcept
	{
		left.swap(right);
	}

	template <class Key, class T>
	[[nodiscard]] bool operator==(const unordered_map<Key, T>& left, const unordered_map<Key, T>& right)
	{
		if (left.size() != right.size())
		{
			return false;
		}

		for (auto it = left.begin(); it != left.end(); ++it)
		{
			auto found = right.find(it->first);

			if (!found || !(found->second == it->second))
			{
				return false;
			}
		}

		return true;
	}

	template <class Key, class T>
	[[nodiscard]] bool operator!=(const unordered_map<Key, T>& left, const unordered_map<Key, T>& right)
	{
		return !(left == right);
	}
}
