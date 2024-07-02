#ifndef MXDEBUG_H
#define MXDEBUG_H

#include "compat.h"

#ifdef _DEBUG

// In debug mode, replace the macro with the function call.
#define MxTrace _MxTrace

void _MxTrace(const char* format, ...);
int DebugHeapState();

#else

// If not debug, MxTrace is a no-op.

#ifdef COMPAT_MODE

// Use variadic args for macro (C99)
#define MxTrace(...)

#else

// MSVC 4.20 does not have variadic args for macros
#define MxTrace(args)

#endif // COMPAT_MODE

#endif // _DEBUG

#endif // MXDEBUG_H
