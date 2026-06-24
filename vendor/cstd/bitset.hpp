#pragma once
#include "exception.hpp"
#include "types.hpp"

namespace cstd
{
	// Fixed-size bit array (a std::bitset analogue) over native 64-bit words, with one addition
	// std::bitset lacks: iteration that visits only the *set* bits (the equivalent of the Linux
	// kernel's for_each_set_bit). Bit i lives in word i / 64 at offset i % 64; the unused high bits of
	// the final word are kept zero so count()/any()/all()/iteration stay exact.
	template <size_t N>
	class bitset
	{
	public:
		using word_type = uint64_t;

		static constexpr size_t bits_per_word = 64;
		static constexpr size_t word_count    = (N + bits_per_word - 1) / bits_per_word;

		constexpr bitset() noexcept
			:	words_{} { }

		[[nodiscard]] constexpr size_t size() const noexcept
		{
			return N;
		}

		[[nodiscard]] constexpr bool test(const size_t pos) const noexcept
		{
			CSTD_ASSERT(pos < N, "[bitset] test() position out of range");

			return (words_[pos / bits_per_word] >> (pos % bits_per_word) & word_type{1}) != 0;
		}

		[[nodiscard]] constexpr bool operator[](const size_t pos) const noexcept
		{
			return test(pos);
		}

		constexpr bitset& set(const size_t pos) noexcept
		{
			CSTD_ASSERT(pos < N, "[bitset] set() position out of range");

			words_[pos / bits_per_word] |= word_type{1} << (pos % bits_per_word);
			return *this;
		}

		constexpr bitset& reset(const size_t pos) noexcept
		{
			CSTD_ASSERT(pos < N, "[bitset] reset() position out of range");

			words_[pos / bits_per_word] &= ~(word_type{1} << (pos % bits_per_word));
			return *this;
		}

		constexpr bitset& flip(const size_t pos) noexcept
		{
			CSTD_ASSERT(pos < N, "[bitset] flip() position out of range");

			words_[pos / bits_per_word] ^= word_type{1} << (pos % bits_per_word);
			return *this;
		}

		constexpr bitset& set() noexcept   // every bit
		{
			for (size_t i = 0; i < word_count; ++i)
			{
				words_[i] = ~word_type{0};
			}
			trim();
			return *this;
		}

		constexpr bitset& reset() noexcept
		{
			for (size_t i = 0; i < word_count; ++i)
			{
				words_[i] = 0;
			}
			return *this;
		}

		constexpr bitset& flip() noexcept
		{
			for (size_t i = 0; i < word_count; ++i)
			{
				words_[i] = ~words_[i];
			}
			trim();
			return *this;
		}

		[[nodiscard]] constexpr size_t count() const noexcept
		{
			size_t total = 0;
			for (size_t i = 0; i < word_count; ++i)
			{
				total += static_cast<size_t>(__builtin_popcountll(words_[i]));
			}
			return total;
		}

		[[nodiscard]] constexpr bool any() const noexcept
		{
			for (size_t i = 0; i < word_count; ++i)
			{
				if (words_[i] != 0)
				{
					return true;
				}
			}
			return false;
		}

		[[nodiscard]] constexpr bool none() const noexcept
		{
			return !any();
		}

		[[nodiscard]] constexpr bool all() const noexcept
		{
			return count() == N;
		}

		constexpr bitset& operator&=(const bitset& other) noexcept
		{
			for (size_t i = 0; i < word_count; ++i)
			{
				words_[i] &= other.words_[i];
			}
			return *this;
		}

		constexpr bitset& operator|=(const bitset& other) noexcept
		{
			for (size_t i = 0; i < word_count; ++i)
			{
				words_[i] |= other.words_[i];
			}
			return *this;
		}

		constexpr bitset& operator^=(const bitset& other) noexcept
		{
			for (size_t i = 0; i < word_count; ++i)
			{
				words_[i] ^= other.words_[i];
			}
			return *this;
		}

		[[nodiscard]] constexpr bitset operator~() const noexcept
		{
			bitset result = *this;
			result.flip();
			return result;
		}

		[[nodiscard]] constexpr bool operator==(const bitset& other) const noexcept
		{
			for (size_t i = 0; i < word_count; ++i)
			{
				if (words_[i] != other.words_[i])
				{
					return false;
				}
			}
			return true;
		}

		[[nodiscard]] constexpr bool operator!=(const bitset& other) const noexcept
		{
			return !(*this == other);
		}

		// Forward iterator over the indices of the set bits, ascending, so `for (size_t i : bs)` visits
		// only set bits -- the cstd analogue of the kernel's for_each_set_bit, far cheaper than testing
		// every position when the set is sparse.
		class iterator
		{
		public:
			constexpr iterator(const bitset* const owner, const size_t pos) noexcept
				:	owner_(owner), pos_(owner->next_set(pos)) { }

			[[nodiscard]] constexpr size_t operator*() const noexcept
			{
				return pos_;
			}

			constexpr iterator& operator++() noexcept
			{
				pos_ = owner_->next_set(pos_ + 1);
				return *this;
			}

			[[nodiscard]] constexpr bool operator!=(const iterator& other) const noexcept
			{
				return pos_ != other.pos_;
			}

		private:
			const bitset* owner_;
			size_t        pos_;
		};

		[[nodiscard]] constexpr iterator begin() const noexcept
		{
			return iterator(this, 0);
		}

		[[nodiscard]] constexpr iterator end() const noexcept
		{
			return iterator(this, N);
		}

	private:
		// Index of the lowest set bit at position >= from, or N if there is none.
		[[nodiscard]] constexpr size_t next_set(const size_t from) const noexcept
		{
			if (from >= N)
			{
				return N;
			}

			size_t    wi  = from / bits_per_word;
			word_type cur = words_[wi] & (~word_type{0} << (from % bits_per_word));

			while (cur == 0)
			{
				if (++wi >= word_count)
				{
					return N;
				}
				cur = words_[wi];
			}

			const size_t bit = wi * bits_per_word + static_cast<size_t>(__builtin_ctzll(cur));
			return bit < N ? bit : N;
		}

		// Clear the unused high bits of the final word, so a whole-word set()/flip() cannot leave bits
		// >= N set (which would corrupt count()/all()/iteration).
		constexpr void trim() noexcept
		{
			if constexpr (N % bits_per_word != 0)
			{
				words_[word_count - 1] &= (word_type{1} << (N % bits_per_word)) - 1;
			}
		}

		word_type words_[word_count];
	};

	template <size_t N>
	[[nodiscard]] constexpr bitset<N> operator&(bitset<N> left, const bitset<N>& right) noexcept
	{
		return left &= right;
	}

	template <size_t N>
	[[nodiscard]] constexpr bitset<N> operator|(bitset<N> left, const bitset<N>& right) noexcept
	{
		return left |= right;
	}

	template <size_t N>
	[[nodiscard]] constexpr bitset<N> operator^(bitset<N> left, const bitset<N>& right) noexcept
	{
		return left ^= right;
	}
}
