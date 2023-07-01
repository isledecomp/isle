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

#endif // ISLECOMPAT_H