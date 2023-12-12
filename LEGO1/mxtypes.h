#ifndef MXTYPES_H
#define MXTYPES_H

typedef unsigned char MxU8;
typedef signed char MxS8;
typedef unsigned short MxU16;
typedef signed short MxS16;
typedef unsigned int MxU32;
typedef signed int MxS32;
#ifdef _MSC_VER
typedef unsigned __int64 MxU64;
typedef signed __int64 MxS64;
#else
typedef unsigned long long int MxU64;
typedef signed long long int MxS64;
#endif
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

typedef MxS32 MxTime;

typedef MxLong MxResult;

#ifndef SUCCESS
#define SUCCESS 0
#endif

#ifndef FAILURE
#define FAILURE -1
#endif

typedef MxU8 MxBool;

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#define TWOCC(a, b) (((a) << 0) | ((b) << 8))
#define FOURCC(a, b, c, d) (((a) << 0) | ((b) << 8) | ((c) << 16) | ((d) << 24))

// Must be union with struct for match.
typedef union {
	struct {
		MxU8 m_bit0 : 1;
		MxU8 m_bit1 : 1;
		MxU8 m_bit2 : 1;
		MxU8 m_bit3 : 1;
		MxU8 m_bit4 : 1;
		MxU8 m_bit5 : 1;
		MxU8 m_bit6 : 1;
		MxU8 m_bit7 : 1;
	};
	// BYTE all; // ?
} FlagBitfield;

#endif // MXTYPES_H
