#ifndef ISLECOMPAT_H
#define ISLECOMPAT_H

// Various macros to enable compiling with other/newer compilers.

// Use `COMPAT_CONST` where something ought to be 'const', and a newer compiler would complain if it
// wasn't, but we know it isn't 'const' in the original code.
#ifdef __MINGW32__
#define COMPAT_CONST const
#else
#define COMPAT_CONST
#endif

// DIsable "nonstandard extension used : 'bool'" warning spam
#pragma warning( disable : 4237 )

// Disable "identifier was truncated to '255' characters" warning.
// Impossible to avoid this if using STL map or set.
// This removes most (but not all) occurrences of the warning.
#pragma warning( disable : 4786 )

#define MSVC420_VERSION 1020

// STL compatibility.
#if defined(_MSC_VER) && _MSC_VER <= MSVC420_VERSION
#include "mxstl.h"
#else
#include <algorithm>
#include <list>
#include <set>
using namespace std;
#endif

// We use `override` so newer compilers can tell us our vtables are valid,
// however this keyword was added in C++11, so we define it as empty for
// compatibility with older compilers.
#if defined(_MSC_VER) && _MSC_VER <= 1200 // 1200 corresponds to VC6.0 but "override" was probably added even later
#define override
#endif

#endif // ISLECOMPAT_H
