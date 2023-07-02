#ifndef MXTYPE_H
#define MXTYPE_H

typedef unsigned char MxU8;
typedef signed char MxS8;
typedef unsigned short MxU16;
typedef signed short MxS16;
typedef unsigned int MxU32;
typedef signed int MxS32;
typedef unsigned __int64 MxU64;
typedef signed __int64 MxS64;
typedef float MxFloat;
typedef double MxDouble;

// On MSVC, a long is 32-bit, but on GCC/Clang, it's 64-bit. LEGO Island obviously
// assumes the former in all cases, which could become an issue in the future.
// The "longs" can't all be changed to "ints" (which are 32-bit on both) because
// this will break DLL export compatibility. Therefore, we define MxLong/MxULong,
// which is guaranteed to be 32-bit, and guaranteed to be a "long" on MSVC.
#if defined(_MSC_VER)
typedef long MxLong;
typedef unsigned long MxULong;
#else
typedef int MxLong;
typedef unsigned int MxULong;
#endif

typedef MxLong MxResult;
const MxResult SUCCESS = 0;
const MxResult FAILURE = -1;

typedef MxU8 MxBool;

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#if defined(_MSC_VER) && _MSC_VER <= 1200 // 1200 corresponds to VC6.0 but "override" was probably added even later
#define override
#endif

#endif // MXTYPE_H
