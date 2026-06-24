#pragma once
#include "crt.hpp"
#include "exception.hpp"
#include "types.hpp"
#include "utility.hpp"

namespace cstd
{
	namespace detail
	{
		template <class T, class Base>
		struct list_node : Base
		{
			T value_;

			template <class... Args>
			explicit list_node(Args&&... args)
					:	Base(), value_(cstd::forward<Args>(args)...) { }
		};

		template <class Node, class... Args>
		Node* create_list_node(Args&&... args)
		{
			void* mem = crt::malloc(sizeof(Node));
			return new (mem) Node(cstd::forward<Args>(args)...);
		}

		template <class Node>
		void destroy_list_node(Node* n) noexcept
		{
			n->~Node();
			crt::free(n);
		}

		template <class List>
		bool list_equal(const List& a, const List& b)
		{
			if (a.size() != b.size())
			{
				return false;
			}
			auto ai = a.begin();
			auto bi = b.begin();
			while (ai != a.end())
			{
				if (!(*ai == *bi))
				{
					return false;
				}
				++ai;
				++bi;
			}
			return true;
		}

		template <class List>
		bool list_less(const List& a, const List& b)
		{
			auto ai = a.begin();
			auto bi = b.begin();
			while (ai != a.end() && bi != b.end())
			{
				if (*ai < *bi) { return true; }
				if (*bi < *ai) { return false; }
				++ai;
				++bi;
			}
			return ai == a.end() && bi != b.end();
		}

		template <class NodeBase, class T, bool IsConst, bool IsBidir = false>
		class list_iterator
		{
			using node_cast = conditional_t<IsConst,
				const list_node<T, NodeBase>*, list_node<T, NodeBase>*>;
			using reference_type = conditional_t<IsConst, const T&, T&>;
			using pointer_type = conditional_t<IsConst, const T*, T*>;

		public:
			NodeBase* node_;

			list_iterator() noexcept
					:	node_(nullptr) { }

			explicit list_iterator(NodeBase* n) noexcept
					:	node_(n) { }

			template <bool C = IsConst, class = enable_if_t<C>>
			list_iterator(const list_iterator<NodeBase, T, false, IsBidir>& other) noexcept
					:	node_(other.node_) { }

			[[nodiscard]] reference_type operator*() const noexcept
			{
				return static_cast<node_cast>(node_)->value_;
			}

			[[nodiscard]] pointer_type operator->() const noexcept
			{
				return &static_cast<node_cast>(node_)->value_;
			}

			list_iterator& operator++() noexcept
			{
				node_ = node_->next_;
				return *this;
			}

			list_iterator operator++(int) noexcept
			{
				list_iterator tmp = *this;
				node_ = node_->next_;
				return tmp;
			}

			template <bool B = IsBidir, class = enable_if_t<B>>
			list_iterator& operator--() noexcept
			{
				node_ = node_->prev_;
				return *this;
			}

			template <bool B = IsBidir, class = enable_if_t<B>>
			list_iterator operator--(int) noexcept
			{
				list_iterator tmp = *this;
				node_ = node_->prev_;
				return tmp;
			}

			[[nodiscard]] bool operator==(const list_iterator& other) const noexcept
			{
				return node_ == other.node_;
			}

			[[nodiscard]] bool operator!=(const list_iterator& other) const noexcept
			{
				return node_ != other.node_;
			}
		};

		template <class Derived>
		struct list_comparisons
		{
			[[nodiscard]] friend bool operator==(const Derived& a, const Derived& b)
			{
				return list_equal(a, b);
			}

			[[nodiscard]] friend bool operator!=(const Derived& a, const Derived& b) { return !(a == b); }

			[[nodiscard]] friend bool operator<(const Derived& a, const Derived& b)
			{
				return list_less(a, b);
			}

			[[nodiscard]] friend bool operator>(const Derived& a, const Derived& b) { return b < a; }
			[[nodiscard]] friend bool operator<=(const Derived& a, const Derived& b) { return !(b < a); }
			[[nodiscard]] friend bool operator>=(const Derived& a, const Derived& b) { return !(a < b); }
		};
	}

	template <class T>
	class single_linked_list : protected detail::list_comparisons<single_linked_list<T>>
	{
	protected:
		struct node_base;

	public:
		using size_type = size_t;
		using value_type = T;
		using pointer = value_type*;
		using const_pointer = const value_type*;
		using reference = value_type&;
		using const_reference = const value_type&;
		using iterator = detail::list_iterator<node_base, T, false>;
		using const_iterator = detail::list_iterator<node_base, T, true>;

		single_linked_list() noexcept
				:	sentinel_(), tail_(&sentinel_), size_(0) { }

		single_linked_list(const single_linked_list& other)
				:	single_linked_list()
		{
			for (const auto& value : other)
			{
				push_back(value);
			}
		}

		single_linked_list(single_linked_list&& other) noexcept
				:	single_linked_list()
		{
			swap(other);
		}

		~single_linked_list()
		{
			clear();
		}

		single_linked_list& operator=(const single_linked_list& other)
		{
			if (this != &other)
			{
				clear();
				for (const auto& value : other)
				{
					push_back(value);
				}
			}
			return *this;
		}

		single_linked_list& operator=(single_linked_list&& other) noexcept
		{
			if (this != &other)
			{
				clear();
				swap(other);
			}
			return *this;
		}

		[[nodiscard]] reference front() noexcept
		{
			CSTD_ASSERT(!empty(), "[single_linked_list] front on empty list");
			return static_cast<node*>(sentinel_.next_)->value_;
		}

		[[nodiscard]] const_reference front() const noexcept
		{
			CSTD_ASSERT(!empty(), "[single_linked_list] front on empty list");
			return static_cast<const node*>(sentinel_.next_)->value_;
		}

		[[nodiscard]] reference back() noexcept
		{
			CSTD_ASSERT(!empty(), "[single_linked_list] back on empty list");
			return static_cast<node*>(tail_)->value_;
		}

		[[nodiscard]] const_reference back() const noexcept
		{
			CSTD_ASSERT(!empty(), "[single_linked_list] back on empty list");
			return static_cast<const node*>(tail_)->value_;
		}

		[[nodiscard]] iterator before_begin() noexcept { return iterator(&sentinel_); }
		[[nodiscard]] const_iterator before_begin() const noexcept { return const_iterator(&sentinel_); }
		[[nodiscard]] iterator begin() noexcept { return iterator(sentinel_.next_); }
		[[nodiscard]] iterator end() noexcept { return iterator(nullptr); }
		[[nodiscard]] const_iterator begin() const noexcept { return const_iterator(sentinel_.next_); }
		[[nodiscard]] const_iterator end() const noexcept { return const_iterator(nullptr); }

		[[nodiscard]] bool empty() const noexcept { return size_ == 0; }
		[[nodiscard]] size_type size() const noexcept { return size_; }

		void clear() noexcept
		{
			node_base* current = sentinel_.next_;
			while (current != nullptr)
			{
				node_base* next = current->next_;
				detail::destroy_list_node(static_cast<node*>(current));
				current = next;
			}
			sentinel_.next_ = nullptr;
			tail_ = &sentinel_;
			size_ = 0;
		}

		void push_front(const T& value) { link_front(detail::create_list_node<node>(value)); }
		void push_front(T&& value) { link_front(detail::create_list_node<node>(cstd::move(value))); }
		void push_back(const T& value) { link_back(detail::create_list_node<node>(value)); }
		void push_back(T&& value) { link_back(detail::create_list_node<node>(cstd::move(value))); }

		template <class... Args>
		reference emplace_front(Args&&... args)
		{
			node* n = detail::create_list_node<node>(cstd::forward<Args>(args)...);
			link_front(n);
			return n->value_;
		}

		template <class... Args>
		reference emplace_back(Args&&... args)
		{
			node* n = detail::create_list_node<node>(cstd::forward<Args>(args)...);
			link_back(n);
			return n->value_;
		}

		void pop_front() noexcept
		{
			CSTD_ASSERT(!empty(), "[single_linked_list] pop_front on empty list");
			node_base* n = sentinel_.next_;
			sentinel_.next_ = n->next_;
			if (n == tail_)
			{
				tail_ = &sentinel_;
			}
			detail::destroy_list_node(static_cast<node*>(n));
			--size_;
		}

		iterator insert_after(const_iterator pos, const T& value)
		{
			node* n = detail::create_list_node<node>(value);
			link_after(pos.node_, n);
			return iterator(n);
		}

		iterator insert_after(const_iterator pos, T&& value)
		{
			node* n = detail::create_list_node<node>(cstd::move(value));
			link_after(pos.node_, n);
			return iterator(n);
		}

		template <class... Args>
		iterator emplace_after(const_iterator pos, Args&&... args)
		{
			node* n = detail::create_list_node<node>(cstd::forward<Args>(args)...);
			link_after(pos.node_, n);
			return iterator(n);
		}

		iterator erase_after(const_iterator pos) noexcept
		{
			CSTD_ASSERT(pos.node_->next_ != nullptr, "[single_linked_list] erase_after at end");
			node_base* doomed = pos.node_->next_;
			pos.node_->next_ = doomed->next_;
			if (doomed == tail_)
			{
				tail_ = pos.node_;
			}
			detail::destroy_list_node(static_cast<node*>(doomed));
			--size_;
			return iterator(pos.node_->next_);
		}

		iterator erase_after(const_iterator first, const_iterator last) noexcept
		{
			node_base* current = first.node_->next_;
			node_base* const stop = last.node_;
			while (current != stop)
			{
				node_base* next = current->next_;
				detail::destroy_list_node(static_cast<node*>(current));
				--size_;
				current = next;
			}
			first.node_->next_ = stop;
			if (stop == nullptr)
			{
				tail_ = first.node_;
			}
			return iterator(stop);
		}

		size_type remove(const T& value)
		{
			size_type removed = 0;
			node_base* prev = &sentinel_;
			while (prev->next_ != nullptr)
			{
				node* current = static_cast<node*>(prev->next_);
				if (current->value_ == value)
				{
					prev->next_ = current->next_;
					if (current == tail_)
					{
						tail_ = prev;
					}
					detail::destroy_list_node(current);
					++removed;
					--size_;
				}
				else
				{
					prev = prev->next_;
				}
			}
			return removed;
		}

		template <class Predicate>
		size_type remove_if(Predicate pred)
		{
			size_type removed = 0;
			node_base* prev = &sentinel_;
			while (prev->next_ != nullptr)
			{
				node* current = static_cast<node*>(prev->next_);
				if (pred(current->value_))
				{
					prev->next_ = current->next_;
					if (current == tail_)
					{
						tail_ = prev;
					}
					detail::destroy_list_node(current);
					++removed;
					--size_;
				}
				else
				{
					prev = prev->next_;
				}
			}
			return removed;
		}

		void reverse() noexcept
		{
			if (size_ <= 1)
			{
				return;
			}
			tail_ = sentinel_.next_;
			node_base* prev = nullptr;
			node_base* current = sentinel_.next_;
			while (current != nullptr)
			{
				node_base* next = current->next_;
				current->next_ = prev;
				prev = current;
				current = next;
			}
			sentinel_.next_ = prev;
		}

		void swap(single_linked_list& other) noexcept
		{
			cstd::swap(sentinel_.next_, other.sentinel_.next_);
			cstd::swap(tail_, other.tail_);
			cstd::swap(size_, other.size_);

			if (tail_ == &other.sentinel_)
			{
				tail_ = &sentinel_;
			}
			if (other.tail_ == &sentinel_)
			{
				other.tail_ = &other.sentinel_;
			}
		}

	protected:
		struct node_base
		{
			node_base* next_;

			constexpr node_base() noexcept
					:	next_(nullptr) { }
		};

		using node = detail::list_node<T, node_base>;

		void link_front(node* n) noexcept
		{
			n->next_ = sentinel_.next_;
			sentinel_.next_ = n;
			if (tail_ == &sentinel_)
			{
				tail_ = n;
			}
			++size_;
		}

		void link_back(node* n) noexcept
		{
			n->next_ = nullptr;
			tail_->next_ = n;
			tail_ = n;
			++size_;
		}

		void link_after(node_base* pos, node* n) noexcept
		{
			n->next_ = pos->next_;
			pos->next_ = n;
			if (pos == tail_)
			{
				tail_ = n;
			}
			++size_;
		}

		mutable node_base sentinel_;
		node_base* tail_;
		size_type size_;
	};

	template <class T>
	void swap(single_linked_list<T>& left, single_linked_list<T>& right) noexcept
	{
		left.swap(right);
	}

	template <class T>
	class double_linked_list : protected detail::list_comparisons<double_linked_list<T>>
	{
	protected:
		struct node_base;

	public:
		using size_type = size_t;
		using value_type = T;
		using pointer = value_type*;
		using const_pointer = const value_type*;
		using reference = value_type&;
		using const_reference = const value_type&;
		using iterator = detail::list_iterator<node_base, T, false, true>;
		using const_iterator = detail::list_iterator<node_base, T, true, true>;

		double_linked_list() noexcept
				:	sentinel_(&sentinel_, &sentinel_), size_(0) { }

		double_linked_list(const double_linked_list& other)
				:	double_linked_list()
		{
			for (const auto& value : other)
			{
				push_back(value);
			}
		}

		double_linked_list(double_linked_list&& other) noexcept
				:	double_linked_list()
		{
			swap(other);
		}

		~double_linked_list()
		{
			clear();
		}

		double_linked_list& operator=(const double_linked_list& other)
		{
			if (this != &other)
			{
				clear();
				for (const auto& value : other)
				{
					push_back(value);
				}
			}
			return *this;
		}

		double_linked_list& operator=(double_linked_list&& other) noexcept
		{
			if (this != &other)
			{
				clear();
				swap(other);
			}
			return *this;
		}

		[[nodiscard]] reference front() noexcept
		{
			CSTD_ASSERT(!empty(), "[double_linked_list] front on empty list");
			return static_cast<node*>(sentinel_.next_)->value_;
		}

		[[nodiscard]] const_reference front() const noexcept
		{
			CSTD_ASSERT(!empty(), "[double_linked_list] front on empty list");
			return static_cast<const node*>(sentinel_.next_)->value_;
		}

		[[nodiscard]] reference back() noexcept
		{
			CSTD_ASSERT(!empty(), "[double_linked_list] back on empty list");
			return static_cast<node*>(sentinel_.prev_)->value_;
		}

		[[nodiscard]] const_reference back() const noexcept
		{
			CSTD_ASSERT(!empty(), "[double_linked_list] back on empty list");
			return static_cast<const node*>(sentinel_.prev_)->value_;
		}

		[[nodiscard]] iterator begin() noexcept { return iterator(sentinel_.next_); }
		[[nodiscard]] iterator end() noexcept { return iterator(&sentinel_); }
		[[nodiscard]] const_iterator begin() const noexcept { return const_iterator(sentinel_.next_); }
		[[nodiscard]] const_iterator end() const noexcept { return const_iterator(&sentinel_); }

		[[nodiscard]] bool empty() const noexcept { return size_ == 0; }
		[[nodiscard]] size_type size() const noexcept { return size_; }

		void clear() noexcept
		{
			node_base* current = sentinel_.next_;
			while (current != &sentinel_)
			{
				node_base* next = current->next_;
				detail::destroy_list_node(static_cast<node*>(current));
				current = next;
			}
			sentinel_.next_ = &sentinel_;
			sentinel_.prev_ = &sentinel_;
			size_ = 0;
		}

		void push_back(const T& value) { insert(end(), value); }
		void push_back(T&& value) { insert(end(), cstd::move(value)); }

		void push_front(const T& value) { insert(begin(), value); }
		void push_front(T&& value) { insert(begin(), cstd::move(value)); }

		template <class... Args>
		reference emplace_back(Args&&... args)
		{
			node* n = detail::create_list_node<node>(cstd::forward<Args>(args)...);
			link_before(&sentinel_, n);
			++size_;
			return n->value_;
		}

		template <class... Args>
		reference emplace_front(Args&&... args)
		{
			node* n = detail::create_list_node<node>(cstd::forward<Args>(args)...);
			link_before(sentinel_.next_, n);
			++size_;
			return n->value_;
		}

		void pop_back() noexcept
		{
			CSTD_ASSERT(!empty(), "[double_linked_list] pop_back on empty list");
			node_base* n = sentinel_.prev_;
			unlink(n);
			detail::destroy_list_node(static_cast<node*>(n));
			--size_;
		}

		void pop_front() noexcept
		{
			CSTD_ASSERT(!empty(), "[double_linked_list] pop_front on empty list");
			node_base* n = sentinel_.next_;
			unlink(n);
			detail::destroy_list_node(static_cast<node*>(n));
			--size_;
		}

		iterator insert(const_iterator pos, const T& value)
		{
			node* n = detail::create_list_node<node>(value);
			link_before(pos.node_, n);
			++size_;
			return iterator(n);
		}

		iterator insert(const_iterator pos, T&& value)
		{
			node* n = detail::create_list_node<node>(cstd::move(value));
			link_before(pos.node_, n);
			++size_;
			return iterator(n);
		}

		iterator erase(const_iterator pos) noexcept
		{
			CSTD_ASSERT(pos.node_ != &sentinel_, "[double_linked_list] erase at end");
			node_base* n = pos.node_;
			node_base* next = n->next_;
			unlink(n);
			detail::destroy_list_node(static_cast<node*>(n));
			--size_;
			return iterator(next);
		}

		iterator erase(const_iterator first, const_iterator last) noexcept
		{
			node_base* current = first.node_;
			node_base* const stop = last.node_;
			while (current != stop)
			{
				node_base* next = current->next_;
				unlink(current);
				detail::destroy_list_node(static_cast<node*>(current));
				--size_;
				current = next;
			}
			return iterator(stop);
		}

		size_type remove(const T& value)
		{
			size_type removed = 0;
			auto it = begin();
			while (it != end())
			{
				if (*it == value)
				{
					it = erase(it);
					++removed;
				}
				else
				{
					++it;
				}
			}
			return removed;
		}

		template <class Predicate>
		size_type remove_if(Predicate pred)
		{
			size_type removed = 0;
			auto it = begin();
			while (it != end())
			{
				if (pred(*it))
				{
					it = erase(it);
					++removed;
				}
				else
				{
					++it;
				}
			}
			return removed;
		}

		void reverse() noexcept
		{
			node_base* current = sentinel_.next_;
			while (current != &sentinel_)
			{
				node_base* next = current->next_;
				cstd::swap(current->prev_, current->next_);
				current = next;
			}
			cstd::swap(sentinel_.prev_, sentinel_.next_);
		}

		void swap(double_linked_list& other) noexcept
		{
			cstd::swap(sentinel_.next_, other.sentinel_.next_);
			cstd::swap(sentinel_.prev_, other.sentinel_.prev_);

			if (sentinel_.next_ == &other.sentinel_)
			{
				sentinel_.next_ = &sentinel_;
				sentinel_.prev_ = &sentinel_;
			}
			else
			{
				sentinel_.next_->prev_ = &sentinel_;
				sentinel_.prev_->next_ = &sentinel_;
			}

			if (other.sentinel_.next_ == &sentinel_)
			{
				other.sentinel_.next_ = &other.sentinel_;
				other.sentinel_.prev_ = &other.sentinel_;
			}
			else
			{
				other.sentinel_.next_->prev_ = &other.sentinel_;
				other.sentinel_.prev_->next_ = &other.sentinel_;
			}

			cstd::swap(size_, other.size_);
		}

	protected:
		struct node_base
		{
			node_base* prev_;
			node_base* next_;

			constexpr node_base() noexcept
					:	prev_(nullptr), next_(nullptr) { }

			constexpr node_base(node_base* prev, node_base* next) noexcept
					:	prev_(prev), next_(next) { }
		};

		using node = detail::list_node<T, node_base>;

		static void link_before(node_base* pos, node_base* n) noexcept
		{
			n->prev_ = pos->prev_;
			n->next_ = pos;
			pos->prev_->next_ = n;
			pos->prev_ = n;
		}

		static void unlink(node_base* n) noexcept
		{
			n->prev_->next_ = n->next_;
			n->next_->prev_ = n->prev_;
		}

		mutable node_base sentinel_;
		size_type size_;
	};

	template <class T>
	void swap(double_linked_list<T>& left, double_linked_list<T>& right) noexcept
	{
		left.swap(right);
	}
}
