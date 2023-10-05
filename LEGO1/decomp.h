#ifndef DECOMP_H
#define DECOMP_H

#define DECOMP_STATIC_ASSERT(V) namespace { typedef int foo[(V)?1:-1]; }
#define DECOMP_SIZE_ASSERT(T, S) DECOMP_STATIC_ASSERT(sizeof(T) == S)

#ifndef _countof
#define _countof(arr) sizeof(arr) / sizeof(arr[0])
#endif

typedef unsigned char undefined;
typedef unsigned short undefined2;
typedef unsigned int undefined4;

#ifdef ISLE_BUILD_PATCH

class PatchHook
{
public:
  PatchHook(void *p_ourFunc, void *p_origFunc);
};

#define PATCH_HOOK(ourFunc, origFunc) \
  static PatchHook _patchHook_##__COUNTER__ ((void *)ourFunc, (void *)origFunc)

#else

#define PATCH_HOOK(ourFunc, origFunc)

#endif

#endif // DECOMP_H
