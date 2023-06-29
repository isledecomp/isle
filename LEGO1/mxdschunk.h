#ifndef MXDSCHUNK_H
#define MXDSCHUNK_H

#include "mxcore.h"

class MxDSChunk : public MxCore
{
public:
  MxDSChunk();
  virtual ~MxDSChunk() override;

  // OFFSET: LEGO1 0x100be0c0
  inline virtual const char *ClassName() const override // vtable+0x0c
  {
    // 0x10101e6c
    return "MxDSChunk";
  }

  // OFFSET: LEGO1 0x100be0d0
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, MxDSChunk::ClassName()) || MxCore::IsA(name);
  }
};

#endif // MXDSCHUNK_H
