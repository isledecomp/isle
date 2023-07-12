/* shmalloc.h -- SmartHeap ANSI Standard C memory API
 * Professional Memory Management Library
 *
 * Copyright (C) 1991-1996 by Arthur D. Applegate.  All Rights Reserved.
 * All Rights Reserved.
 *
 * No part of this source code may be copied, modified or reproduced
 * in any form without retaining the above copyright notice.
 * This source code, or source code derived from it, may not be redistributed
 * without express written permission of the author.
 */

#if !(defined(_SHMALLOC_H))
#define _SHMALLOC_H

#include "smrtheap.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ANSI Standard Memory Management API */

#if (!defined(MEM_DEBUG) && !defined(NO_MALLOC_MACRO)) || defined(MALLOC_MACRO)
#ifdef malloc
#undef malloc
#endif
#define malloc(s) MEM_malloc(s)
#ifdef calloc
#undef calloc
#endif
#define calloc(s,c) MEM_calloc(s,c)
#ifdef realloc
#undef realloc
#endif
#define realloc(p,s) MEM_realloc(p,s)
#ifdef free
#undef free
#endif
#define free(p) MEM_free(p)

#endif  /* NO_MALLOC_MACRO */

#ifndef MEM_malloc
void MEM_FAR * MEM_ENTRY_ANSI MEM_malloc(size_t size);
void MEM_FAR * MEM_ENTRY_ANSI MEM_calloc(size_t nobj, size_t size);
void MEM_FAR * MEM_ENTRY_ANSI MEM_realloc(void MEM_FAR *p, size_t size);
void MEM_ENTRY_ANSI MEM_free(void MEM_FAR *p);
#endif /* MEM_malloc */

#if defined(__WATCOMC__) && defined(__SW_3S)
/* Watcom stack calling convention */
   #pragma aux (syscall) MEM_malloc
   #pragma aux (syscall) MEM_realloc
   #pragma aux (syscall) MEM_calloc
   #pragma aux (syscall) MEM_free
#endif  /* __WATCOMC__ */

#ifdef __cplusplus
}
#endif

#endif /* !defined(_SHMALLOC_H) */
