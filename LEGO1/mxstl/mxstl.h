// clang-format off

#ifndef MXSTL_H
#define MXSTL_H

#include <use_ansi.h>
#include <algorithm>
#include <deque>
#include <functional>
#include <iterator>
#include <list>
#include <map>
#include <memory>
#include <numeric>
#include <queue>
#include <set>
#include <stack>
#include <utility>
#include <vector>


#ifdef  _MSC_VER
/*
 * Currently, all MS C compilers for Win32 platforms default to 8 byte
 * alignment.
 */
#pragma pack(push,8)
#endif // _MSC_VER

template<class _TYPE>
class Deque : public deque<_TYPE, allocator<_TYPE> >
{
public:
  typedef Deque<_TYPE> _Myt;
  typedef allocator<_TYPE> _A;

  explicit Deque(const _A& _Al = _A()) : deque<_TYPE, _A>(_Al)
  {}

  explicit Deque(size_type _N, const _TYPE& _V = _TYPE()) : deque<_TYPE, _A>(_N, _V)
  {}

  void swap(_Myt& _X)
  {
    deque<_TYPE, _A>::swap((deque<_TYPE, _A>&)_X);
  }

  friend void swap(_Myt& _X, _Myt& _Y)
  {
    _X.swap(_Y);
  }
};

template<class _TYPE>
class List : public list<_TYPE, allocator<_TYPE> >
{
public:
  typedef List<_TYPE> _Myt;
  typedef allocator<_TYPE> _A;

  explicit List() : list<_TYPE, _A>()
  {}

  explicit List(size_type _N, const _TYPE& _V = _TYPE()) : list<_TYPE, _A>(_N, _V)
  {}

  void swap(_Myt& _X)
  {
    list<_TYPE, _A>::swap((list<_TYPE, _A>&)_X);
  }

  friend void swap(_Myt& _X, _Myt& _Y)
  {
    _X.swap(_Y);
  }
};

template<class _K, class _TYPE, class _Pr>
class Map : public map<_K, _TYPE, _Pr, allocator<_TYPE> >
{
public:
  typedef Map<_K, _TYPE, _Pr> _Myt;
  typedef allocator<_TYPE> _A;

  explicit Map(const _Pr& _Pred = _Pr())
    : map<_K, _TYPE, _Pr, _A>(_Pred)
  {}

  void swap(_Myt& _X)
  {
    map<_K, _TYPE, _Pr, _A>::swap((map<_K, _TYPE, _Pr, _A>&)_X);
  }

  friend void swap(_Myt& _X, _Myt& _Y)
  {
    _X.swap(_Y);
  }
};

template<class _K, class _TYPE, class _Pr>
class Multimap : public multimap<_K, _TYPE, _Pr, allocator<_TYPE> >
{
public:
  typedef Multimap<_K, _TYPE, _Pr> _Myt;
  typedef allocator<_TYPE> _A;

  explicit Multimap(const _Pr& _Pred = _Pr()) : multimap<_K, _TYPE, _Pr, _A>(_Pred)
  {}

  void swap(_Myt& _X)
  {
    multimap<_K, _TYPE, _Pr, _A>::swap((multimap<_K, _TYPE, _Pr, _A>&)_X);
  }

  friend void swap(_Myt& _X, _Myt& _Y)
  {
    _X.swap(_Y);
  }
};

template<class _K, class _Pr>
class Set : public set<_K, _Pr, allocator<_K> >
{
public:
  typedef Set<_K, _Pr> _Myt;
  typedef allocator<_K> _A;

  explicit Set(const _Pr& _Pred = _Pr()) : set<_K, _Pr, _A>(_Pred)
  {}

  void swap(_Myt& _X)
  {
    set<_K, _Pr, _A>::swap((set<_K, _Pr, _A>&)_X);
  }

  friend void swap(_Myt& _X, _Myt& _Y)
  {
    _X.swap(_Y);
  }
};

template<class _K, class _Pr>
class Multiset : public multiset<_K, _Pr, allocator<_K> >
{
public:
  typedef Multiset<_K, _Pr> _Myt;
  typedef allocator<_K> _A;

  explicit Multiset(const _Pr& _Pred = _Pr())
    : multiset<_K, _Pr, _A>(_Pred)
  {}

  void swap(_Myt& _X)
  {
    multiset<_K, _Pr, _A>::swap((multiset<_K, _Pr, _A>&)_X);
  }

  friend void swap(_Myt& _X, _Myt& _Y)
  {
    _X.swap(_Y);
  }
};

template<class _TYPE>
class Vector : public vector<_TYPE, allocator<_TYPE> >
{
public:
  typedef Vector<_TYPE> _Myt;
  typedef allocator<_TYPE> _A;

  explicit Vector(const _A& _Al = _A()) : vector<_TYPE, _A>(_Al)
  {}

  void swap(_Myt& _X)
  {
    vector<_TYPE, _A>::swap((vector<_TYPE, _A>&)_X);
  }

  friend void swap(_Myt& _X, _Myt& _Y)
  {
    _X.swap(_Y);
  }
};

template<class _C, class _Pr>
class Priority_queue : public priority_queue<_C::value_type, _C, _Pr, _C::allocator_type>
{
public:
  typedef _C::value_type _TYPE;
  typedef _C::allocator_type _A;
  typedef _C::allocator_type allocator_type;

  explicit Priority_queue(const _Pr& _X = _Pr(), const _C::allocator_type& _Al = _C::allocator_type()) : priority_queue<_C::value_type, _C, _Pr, _C::allocator_type>(_X, _Al)
  {}
};

template<class _C>
class Queue : public queue<_C::value_type, _C, _C::allocator_type>
{};

template<class _C>
class Stack : public stack<_C::value_type, _C, _C::allocator_type>
{};

#define deque Deque
#define list List
#define map Map
#define multimap Multimap
#define set Set
#define multiset Multiset
#define vector Vector
#define priority_queue Priority_queue
#define queue Queue
#define stack Stack

#ifdef _MSC_VER
#pragma pack(pop)
#endif

#endif // MXSTL_H

// clang-format on
