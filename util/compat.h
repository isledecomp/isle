#ifndef COMPAT_H
#define COMPAT_H

// Various macros to enable compiling with other/newer compilers.

#if defined(__MINGW32__) || (defined(_MSC_VER) && _MSC_VER >= 1100)
#define COMPAT_MODE
#endif

// Disable "identifier was truncated to '255' characters" warning.
// Impossible to avoid this if using STL map or set.
// This removes most (but not all) occurrences of the warning.
#pragma warning(disable : 4786)

#define MSVC420_VERSION 1020

// We use `override` so newer compilers can tell us our vtables are valid,
// however this keyword was added in C++11, so we define it as empty for
// compatibility with older compilers.
#if __cplusplus < 201103L
#define override
#define static_assert(expr, msg)
#endif

#endif // COMPAT_H
