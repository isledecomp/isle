#ifndef STLCOMPAT_H
#define STLCOMPAT_H

#ifndef ISLE_COMPAT
#include <STL.H>
#else
#include <algorithm>
#include <list>
using namespace std;
template <class T>
using List = list<T>;
#endif

#endif // STLCOMPAT_H
