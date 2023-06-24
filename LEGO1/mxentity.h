#ifndef MXENTITY_H
#define MXENTITY_H

#include "mxcore.h"

#ifndef undefined4
#define undefined4 int
#endif

class MxAtomId;

class MxEntity : public MxCore
{
public:
  virtual const char* GetClassName() const; // vtable+0xc
  virtual MxBool IsClass(const char *name) const; // vtable+0x10

  virtual undefined4 VTable0x14(undefined4 param_1, MxAtomId* param_2); // vtable+0x14

  // VTABLE 0x100d53a4
  // 0x8: MxResult
  // 0xc MxAtomId
};

#endif // MXENTITY_H
