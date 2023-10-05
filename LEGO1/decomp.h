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

// Function called to add a patch to the list of patches
void DecompPatchAdd(void *origFunc, void *newFunc);

// Class decomp hook macros
#define DECOMP_HOOK_DECL_CLS() \
  static void _ExportHooks()

#define DECOMP_HOOK_START_CLS(cls) \
  void cls::_ExportHooks() {
#define DECOMP_HOOK_END_CLS(cls) \
  } static struct _ExportHooks_##cls { _ExportHooks_##cls () { cls::_ExportHooks(); } } _exportHooks_##cls

#define DECOMP_HOOK_EXPORT_CLS(origFunc, cls, retv, method, args) \
  { \
    retv(cls :: * _ourFunc ) args = cls::method; \
    DecompPatchAdd((void*)origFunc, (void*)*((DWORD*)& _ourFunc )); \
  }

#else

#define DECOMP_METHOD_HOOK()

#define DECOMP_HOOK_DECL_EXPORT()
#define DECOMP_HOOK_DEFN_EXPORT()
#define DECOMP_HOOK_EXPORT()

#endif

#endif // DECOMP_H
