#ifndef MXENTITY_H
#define MXENTITY_H

#include "mxcore.h"

// VTABLE 0x100d5390
class MxEntity : public MxCore
{
public:
  MxEntity();
  virtual ~MxEntity() override;

  // OFFSET: LEGO1 0x1000c180
  inline virtual const char* ClassName() const override // vtable+0xc
  {
    // 0x100f0070
    return "MxEntity";
  }

  // OFFSET: LEGO1 0x1000c190
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, MxEntity::ClassName()) || MxCore::IsA(name);
  }

  // 0x8: MxResult
  // 0xc MxAtomId
};

#endif // MXENTITY_H
