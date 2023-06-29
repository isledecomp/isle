#ifndef MXTYPE_H
#define MXTYPE_H

typedef unsigned char MxU8;
typedef char MxS8;
typedef unsigned short MxU16;
typedef short MxS16;
typedef unsigned int MxU32;
typedef int MxS32;

typedef unsigned long MxResult;
const MxResult SUCCESS = 0;
const MxResult FAILURE = 0xFFFFFFFFL;

typedef unsigned char MxBool;

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
