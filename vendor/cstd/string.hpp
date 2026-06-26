#pragma once
#include "crt.hpp"
#include "vector.hpp"
#include "exception.hpp"
#include "string_view.hpp"

namespace cstd
{
	template <class T>
	class base_string
	{
	public:
		using size_type = size_t;
		using character_type = T;
		using pointer = character_type*;
		using const_pointer = const character_type*;
		using reference = character_type&;
		using const_reference = const character_type&;

		constexpr static size_type npos = static_cast<size_type>(-1);

		base_string() noexcept
		{
			elements_.push_back(T('\0'));
		}

		explicit base_string(const_pointer const data, const size_type size) noexcept
				:	elements_(size + 1)
		{
			crt::memcpy(elements_.data(), data, size * sizeof(T));

			elements_[size] = T('\0');
		}

		void push_back(const character_type c)
		{
			elements_.back() = c;
			elements_.push_back(T('\0'));
		}

		base_string& append(const_pointer const data, const size_type count)
		{
			append_raw(data, count);

			return *this;
		}

		base_string& append(const base_string& other)
		{
			append_raw(other.data(), other.size());

			return *this;
		}

		base_string& append(const character_type c)
		{
			push_back(c);

			return *this;
		}

		base_string& operator+=(const base_string& other)
		{
			return append(other);
		}

		base_string& operator+=(const character_type c)
		{
			return append(c);
		}

		void clear()
		{
			elements_.clear();
			elements_.push_back(T('\0'));
		}

		void resize(const size_type new_size, const character_type fill = T('\0'))
		{
			const size_type old_size = size();

			elements_.resize(new_size + 1);

			for (size_type i = old_size; i < new_size; ++i)
			{
				elements_[i] = fill;
			}

			elements_[new_size] = T('\0');
		}

		[[nodiscard]] pointer begin() noexcept
		{
			return elements_.begin();
		}

		[[nodiscard]] pointer end() noexcept
		{
			return elements_.begin() + size();
		}

		[[nodiscard]] const_pointer begin() const noexcept
		{
			return elements_.begin();
		}

		[[nodiscard]] const_pointer end() const noexcept
		{
			return elements_.begin() + size();
		}

		[[nodiscard]] reference operator[](const size_type index)
		{
			CSTD_ASSERT(index < size(), "[base_string] attempted to access outside of range of data");

			return elements_[index];
		}

		[[nodiscard]] const_reference operator[](const size_type index) const
		{
			CSTD_ASSERT(index < size(), "[base_string] attempted to access outside of range of data");

			return elements_[index];
		}

		[[nodiscard]] pointer data() noexcept
		{
			return elements_.data();
		}

		[[nodiscard]] const_pointer data() const noexcept
		{
			return elements_.data();
		}

		[[nodiscard]] const_pointer c_str() const noexcept
		{
			return elements_.data();
		}

		[[nodiscard]] size_type size() const
		{
			return elements_.size() - 1;
		}

		[[nodiscard]] size_type length() const
		{
			return size();
		}

		[[nodiscard]] bool empty() const
		{
			return size() == 0;
		}

		[[nodiscard]] reference front()
		{
			CSTD_ASSERT(!empty(), "[base_string] front() called on an empty string");

			return elements_[0];
		}

		[[nodiscard]] const_reference front() const
		{
			CSTD_ASSERT(!empty(), "[base_string] front() called on an empty string");

			return elements_[0];
		}

		[[nodiscard]] reference back()
		{
			CSTD_ASSERT(!empty(), "[base_string] back() called on an empty string");

			return elements_[size() - 1];
		}

		[[nodiscard]] const_reference back() const
		{
			CSTD_ASSERT(!empty(), "[base_string] back() called on an empty string");

			return elements_[size() - 1];
		}

		[[nodiscard]] reference at(const size_type index)
		{
			CSTD_ASSERT(index < size(), "[base_string] at() index out of range");

			return elements_[index];
		}

		[[nodiscard]] const_reference at(const size_type index) const
		{
			CSTD_ASSERT(index < size(), "[base_string] at() index out of range");

			return elements_[index];
		}

		[[nodiscard]] size_type find(const base_string_view<character_type>& needle, const size_type offset = 0) const
		{
			return as_view().find(needle, offset);
		}

		[[nodiscard]] size_type find(const character_type character, const size_type offset = 0) const
		{
			return as_view().find(character, offset);
		}

		[[nodiscard]] size_type rfind(const base_string_view<character_type>& needle, const size_type offset = npos) const
		{
			return as_view().rfind(needle, offset);
		}

		[[nodiscard]] size_type rfind(const character_type character, const size_type offset = npos) const
		{
			return as_view().rfind(character, offset);
		}

		[[nodiscard]] size_type find_first_of(const base_string_view<character_type>& set, const size_type offset = 0) const
		{
			return as_view().find_first_of(set, offset);
		}

		[[nodiscard]] size_type find_first_of(const character_type character, const size_type offset = 0) const
		{
			return as_view().find_first_of(character, offset);
		}

		[[nodiscard]] size_type find_last_of(const base_string_view<character_type>& set, const size_type offset = npos) const
		{
			return as_view().find_last_of(set, offset);
		}

		[[nodiscard]] size_type find_last_of(const character_type character, const size_type offset = npos) const
		{
			return as_view().find_last_of(character, offset);
		}

		[[nodiscard]] size_type find_first_not_of(const base_string_view<character_type>& set, const size_type offset = 0) const
		{
			return as_view().find_first_not_of(set, offset);
		}

		[[nodiscard]] size_type find_first_not_of(const character_type character, const size_type offset = 0) const
		{
			return as_view().find_first_not_of(character, offset);
		}

		[[nodiscard]] size_type find_last_not_of(const base_string_view<character_type>& set, const size_type offset = npos) const
		{
			return as_view().find_last_not_of(set, offset);
		}

		[[nodiscard]] size_type find_last_not_of(const character_type character, const size_type offset = npos) const
		{
			return as_view().find_last_not_of(character, offset);
		}

		[[nodiscard]] bool contains(const base_string_view<character_type>& needle) const
		{
			return as_view().contains(needle);
		}

		[[nodiscard]] bool contains(const character_type character) const
		{
			return as_view().contains(character);
		}

	protected:
		[[nodiscard]] base_string_view<character_type> as_view() const noexcept
		{
			return base_string_view<character_type>(data(), size());
		}

		void append_raw(const_pointer const data, const size_type count)
		{
			for (size_type i = 0; i < count; ++i)
			{
				push_back(data[i]);
			}
		}

		vector<character_type> elements_;
	};

	class string : public base_string<char>
	{
	public:
		using character_type = char;
		using pointer = character_type*;
		using const_pointer = const character_type*;

		using base_string<char>::append;
		using base_string<char>::operator+=;

		string() noexcept = default;

		string(const_pointer const data) noexcept
				:	base_string(data, crt::strlen(data)) {}

		string(const_pointer const data, const size_type size) noexcept
				:	base_string(data, size) {}

		[[nodiscard]] string_view view() const noexcept
		{
			return string_view(data(), size());
		}

		operator string_view() const noexcept
		{
			return view();
		}

		string& append(const_pointer const data)
		{
			append_raw(data, crt::strlen(data));

			return *this;
		}

		string& append(const string_view& view)
		{
			append_raw(view.data(), view.size());

			return *this;
		}

		string& operator+=(const_pointer const data)
		{
			return append(data);
		}

		string& operator+=(const string_view& view)
		{
			return append(view);
		}

		[[nodiscard]] string substr(const size_type position = 0, size_type count = npos) const
		{
			CSTD_ASSERT(position <= size(), "[string] substr position out of range");

			const size_type available = size() - position;

			if (count > available)
			{
				count = available;
			}

			return string(data() + position, count);
		}

		[[nodiscard]] bool starts_with(const string_view& prefix) const
		{
			return view().starts_with(prefix);
		}

		[[nodiscard]] bool starts_with(const character_type character) const
		{
			return view().starts_with(character);
		}

		[[nodiscard]] bool ends_with(const string_view& suffix) const
		{
			return view().ends_with(suffix);
		}

		[[nodiscard]] bool ends_with(const character_type character) const
		{
			return view().ends_with(character);
		}

		[[nodiscard]] bool operator==(const string_view& right) const
		{
			return view() == right;
		}

		[[nodiscard]] bool operator!=(const string_view& right) const
		{
			return view() != right;
		}

		[[nodiscard]] bool operator<(const string_view& right) const
		{
			return view() < right;
		}

		[[nodiscard]] bool operator>(const string_view& right) const
		{
			return view() > right;
		}

		[[nodiscard]] bool operator<=(const string_view& right) const
		{
			return view() <= right;
		}

		[[nodiscard]] bool operator>=(const string_view& right) const
		{
			return view() >= right;
		}
	};

	[[nodiscard]] inline string operator+(const string& left, const string& right)
	{
		string result(left);
		result.append(right);

		return result;
	}

	[[nodiscard]] inline string operator+(const string& left, const string::const_pointer right)
	{
		string result(left);
		result.append(right);

		return result;
	}

	[[nodiscard]] inline string operator+(const string::const_pointer left, const string& right)
	{
		string result(left);
		result.append(right);

		return result;
	}

	[[nodiscard]] inline string operator+(const string& left, const string::character_type right)
	{
		string result(left);
		result.push_back(right);

		return result;
	}

	class wstring : public base_string<wchar_t>
	{
	public:
		using character_type = wchar_t;
		using pointer = character_type*;
		using const_pointer = const character_type*;

		using base_string<wchar_t>::append;
		using base_string<wchar_t>::operator+=;

		wstring() noexcept = default;

		wstring(const_pointer const data) noexcept
				:	base_string(data, crt::wcslen(data)) {}

		wstring(const_pointer const data, const size_type size) noexcept
				:	base_string(data, size) {}

		[[nodiscard]] wstring_view view() const noexcept
		{
			return wstring_view(data(), size());
		}

		operator wstring_view() const noexcept
		{
			return view();
		}

		wstring& append(const_pointer const data)
		{
			append_raw(data, crt::wcslen(data));

			return *this;
		}

		wstring& append(const wstring_view& view)
		{
			append_raw(view.data(), view.size());

			return *this;
		}

		wstring& operator+=(const_pointer const data)
		{
			return append(data);
		}

		wstring& operator+=(const wstring_view& view)
		{
			return append(view);
		}

		[[nodiscard]] wstring substr(const size_type position = 0, size_type count = npos) const
		{
			CSTD_ASSERT(position <= size(), "[wstring] substr position out of range");

			const size_type available = size() - position;

			if (count > available)
			{
				count = available;
			}

			return wstring(data() + position, count);
		}

		[[nodiscard]] bool starts_with(const wstring_view& prefix) const
		{
			return view().starts_with(prefix);
		}

		[[nodiscard]] bool starts_with(const character_type character) const
		{
			return view().starts_with(character);
		}

		[[nodiscard]] bool ends_with(const wstring_view& suffix) const
		{
			return view().ends_with(suffix);
		}

		[[nodiscard]] bool ends_with(const character_type character) const
		{
			return view().ends_with(character);
		}

		[[nodiscard]] bool operator==(const wstring_view& right) const
		{
			return view() == right;
		}

		[[nodiscard]] bool operator!=(const wstring_view& right) const
		{
			return view() != right;
		}

		[[nodiscard]] bool operator<(const wstring_view& right) const
		{
			return view() < right;
		}

		[[nodiscard]] bool operator>(const wstring_view& right) const
		{
			return view() > right;
		}

		[[nodiscard]] bool operator<=(const wstring_view& right) const
		{
			return view() <= right;
		}

		[[nodiscard]] bool operator>=(const wstring_view& right) const
		{
			return view() >= right;
		}
	};

	[[nodiscard]] inline wstring operator+(const wstring& left, const wstring& right)
	{
		wstring result(left);
		result.append(right);

		return result;
	}

	[[nodiscard]] inline wstring operator+(const wstring& left, const wstring::const_pointer right)
	{
		wstring result(left);
		result.append(right);

		return result;
	}

	[[nodiscard]] inline wstring operator+(const wstring::const_pointer left, const wstring& right)
	{
		wstring result(left);
		result.append(right);

		return result;
	}

	[[nodiscard]] inline wstring operator+(const wstring& left, const wstring::character_type right)
	{
		wstring result(left);
		result.push_back(right);

		return result;
	}
}
