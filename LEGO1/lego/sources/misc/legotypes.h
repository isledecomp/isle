/*
	This unpublished source code contains trade secrets and
	copyrighted materials which are the property of Mindscape, Inc.
	Unauthorized use, copying or distribution is a violation of U.S.
	and international laws and is strictly prohibited.
*/

#ifndef __LEGOTYPES_H
#define __LEGOTYPES_H

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#ifndef NULL
#define NULL 0
#endif

#ifndef SUCCESS
#define SUCCESS 0
#endif

#ifndef FAILURE
#define FAILURE -1
#endif

typedef char LegoS8;
typedef unsigned char LegoU8;
typedef short LegoS16;
typedef unsigned short LegoU16;
typedef long LegoS32;
typedef unsigned long LegoU32;
typedef float LegoFloat;
typedef char LegoChar;

typedef LegoU8 LegoBool;
typedef LegoS32 LegoTime;
typedef LegoS32 LegoResult;

#endif // __LEGOTYPES_H
