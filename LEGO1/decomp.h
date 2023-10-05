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

void DecompPatchAdd(void *origFunc, void *newFunc);

#define DECOMP_METHOD_HOOK(origFunc, cls, method, retv, args) \
namespace _DecompPatchHook_##__COUNTER__ \
{ \
  class DecompPatchHook \
  { \
  public: \
    DecompPatchHook() \
    { \
      retv(cls :: *method) args = cls::method; \
      DecompPatchAdd((void*)origFunc, (void*)&_patchHook); \
    } \
  } _patchHook; \
}

#else

#define DECOMP_METHOD_HOOK()

#endif

#endif // DECOMP_H
