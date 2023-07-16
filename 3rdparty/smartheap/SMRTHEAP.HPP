// smrtheap.hpp -- SmartHeap public C++ header file
// Professional Memory Management Library
//
// Copyright (C) 1991-1996 by Arthur D. Applegate
// All Rights Reserved.
//
// No part of this source code may be copied, modified or reproduced
// in any form without retaining the above copyright notice.
// This source code, or source code derived from it, may not be redistributed
// without express written permission of the author.
//
// COMMENTS:
// - Include this header file to call the SmartHeap-specific versions of
//   operators new (i.e. with placement syntax), to:
//     o allocate from a specific memory pool;
//     o specify allocation flags, such as zero-initialization;
//     o resize an allocation.
//
// - If you include this header file, you must compile and link shnew.cpp, or
//   link with one of the SmartHeap static operator new libraries:
//   sh[l|d]XXXX.lib
//
// - Can be used in both EXEs and DLLs.
//
// - For 16-bit x86 platforms, use only in large or compact memory model.
//
// - If you do not want to use SmartHeap's global operator new but you do
//   want to use SmartHeap's other facilities in a C++ application, then 
//   include the smrtheap.h header file but do not include this header file,
//   and do not link with shnew.cpp.  The two ".Xpp" files are present
//   ONLY for the purpose of defining operator new and operator delete.
//
// - Use the MemDefaultPool global variable to refer to a memory pool to pass
//   to SmartHeap functions that accept a pool as a parameter,
//   e.g. MemPoolCount, MemPoolSize, MemPoolWalk, etc.
//

#if !defined(_SMARTHEAP_HPP)
#define _SMARTHEAP_HPP

#if defined(_MSC_VER) \
   && (defined(M_I86LM) || defined(M_I86CM) || defined(M_I86HM)) \
   && !defined(MEM_HUGE)
#define MEM_HUGE 0x8000u
#endif

#ifndef __BORLANDC__
/* Borland C++ does not treat extern "C++" correctly */
extern "C++"
{
#endif /* __BORLANDC__ */

#if defined(_MSC_VER) && _MSC_VER >= 900
#pragma warning(disable : 4507)
#endif

#if defined(new)
#if defined(MEM_DEBUG)
#undef new
#endif
#endif

#include <new.h>

#include "smrtheap.h"
   
#if defined(new)
#if defined(MEM_DEBUG)
#undef new
#endif
#endif

#if ((defined(__BORLANDC__) && (__BORLANDC__ >= 0x450)) \
   || (defined(__WATCOMC__) && __WATCOMC__ >= 1000) \
   || (defined(__IBMCPP__) && __IBMCPP__ >= 250))
#define SHI_ARRAY_NEW 1
#endif

void MEM_FAR * MEM_ENTRY_ANSI shi_New(unsigned long sz, unsigned flags=0, MEM_POOL pool=0);

// operator new variants:


// version of new that passes memory allocation flags
// (e.g. MEM_ZEROINIT to zero-initialize memory)
// call with syntax 'ptr = new (flags) <type>'
inline void MEM_FAR *operator new(size_t sz, unsigned flags)
   { return shi_New(sz, flags); }

// version of new that allocates from a specified memory pool with alloc flags
// call with the syntax 'ptr = new (pool, [flags=0]) <type>'
inline void MEM_FAR *operator new(size_t sz, MEM_POOL pool, unsigned flags=0)
   { return shi_New(sz, flags, pool); }
#ifdef SHI_ARRAY_NEW
inline void MEM_FAR *operator new[](size_t sz, MEM_POOL pool, unsigned flags=0)
   { return shi_New(sz, flags, pool); }
#endif

// version of new that changes the size of a memory block previously allocated
// from an SmartHeap memory pool
// call with the syntax 'ptr = new (ptr, flags) <type>'
#if !defined(MEM_DEBUG) || !defined(__HIGHC__)
/* bug in MetaWare High C++ parser confuses this with new(file,line) */
inline void MEM_FAR *operator new(size_t new_sz, void MEM_FAR *lpMem,
                                  unsigned flags)
   { return MemReAllocPtr(lpMem, new_sz, flags); }
#ifdef SHI_ARRAY_NEW
inline void MEM_FAR *operator new[](size_t new_sz, void MEM_FAR *lpMem,
                                  unsigned flags)
   { return MemReAllocPtr(lpMem, new_sz, flags); }
#endif // SHI_ARRAY_NEW
#endif


// new_handler prototypes: note that MSC/C++ prototype differs from the
// protosed ANSI standard prototype for set_new_handler
#ifdef __MWERKS__
#define MEM_CPP_THROW throw()
#else
#define MEM_CPP_THROW
#endif // __MWERKS__
#ifndef _CRTIMP
#define _CRTIMP
#endif // _CRTIMP
#ifdef _MSC_VER
_CRTIMP _PNH MEM_ENTRY_ANSI _set_new_handler(_PNH);
#if UINT_MAX == 0xFFFFu
_PNH MEM_ENTRY_ANSI _set_fnew_handler(_PNH);
_PNHH MEM_ENTRY_ANSI _set_hnew_handler(_PNHH);
#endif // UINT_MAX
#endif // _MSC_VER
typedef void (MEM_ENTRY_ANSI * pnh)();
_CRTIMP pnh MEM_ENTRY_ANSI set_new_handler(pnh) MEM_CPP_THROW;

#ifndef DBG_FORMAL
#define DBG_FORMAL
#define DBG_ACTUAL
#ifndef DEBUG_NEW
#define DEBUG_NEW new
#endif // DEBUG_NEW
#define DEBUG_NEW1(x_) new(x_)
#define DEBUG_NEW2(x_, y_) new(x_, y_)
#define DEBUG_NEW3(x_, y_, z_) new(x_, y_, z_)
#define DEBUG_DELETE delete
#endif

#ifdef DEFINE_NEW_MACRO
#define new DEBUG_NEW
#endif

#if defined(_MSC_VER) && _MSC_VER >= 900
#pragma warning(default : 4507)
#endif

#ifndef __BORLANDC__
}
#endif /* __BORLANDC__ */

#endif /* !defined(_SMARTHEAP_HPP) */
